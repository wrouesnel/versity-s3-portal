package minioiam

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path"
)

// MinIO keeps each object as a directory holding xl.meta: "XL2 ", a version,
// the metadata as a msgpack bin, its CRC, then (for small objects, as IAM's
// all are) the data itself, inline. The inline data is a version byte and a
// msgpack map of version ID to bytes, each a bitrot checksum (32 bytes of
// HighwayHash) before every block of the data. A larger object's data is in
// <data dir>/part.1 instead, checksummed the same way. On one drive every
// block is whole (no erasure coding splits it). Before MinIO stored objects
// this way (its "fs" mode, and old single-drive installs), the object was a
// plain file.

const (
	xlHeader   = "XL2 "
	hashSize   = 32      // HighwayHash256S, before each block
	xlBlockLen = 1 << 20 // MinIO's erasure block size, which one drive's shard keeps whole
)

var errNoInlineData = errors.New("no inline data")

// readObject is the bytes of the object stored at name: a plain file (fs
// mode), or a directory holding xl.meta.
func readObject(fsys fs.FS, name string) ([]byte, error) {
	st, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return fs.ReadFile(fsys, name)
	}
	meta, err := fs.ReadFile(fsys, path.Join(name, "xl.meta"))
	if err != nil {
		return nil, err
	}
	data, err := xlInlineData(meta)
	if err == nil {
		return stripBitrot(data)
	}
	if !errors.Is(err, errNoInlineData) {
		return nil, fmt.Errorf("%s/xl.meta: %w", name, err)
	}
	// Not inline: the data is in its data directory's part.1.
	parts, _ := fs.Glob(fsys, path.Join(name, "*", "part.1"))
	if len(parts) != 1 {
		return nil, fmt.Errorf("%s: no inline data, and %d part.1 files", name, len(parts))
	}
	data, err = fs.ReadFile(fsys, parts[0])
	if err != nil {
		return nil, err
	}
	return stripBitrot(data)
}

// xlInlineData is the inline data of an xl.meta's one version.
func xlInlineData(b []byte) ([]byte, error) {
	if len(b) < 8 || string(b[:4]) != xlHeader {
		return nil, errors.New("not an xl.meta file")
	}
	if major := binary.LittleEndian.Uint16(b[4:6]); major != 1 {
		return nil, fmt.Errorf("xl.meta version %d, not 1", major)
	}
	r := &msgp{b: b[8:]}
	if _, err := r.bin(); err != nil { // the metadata
		return nil, fmt.Errorf("metadata: %w", err)
	}
	if minor := binary.LittleEndian.Uint16(b[6:8]); minor >= 1 { // a CRC after it, from 1.1
		if err := r.skipUint(); err != nil {
			return nil, fmt.Errorf("CRC: %w", err)
		}
	}
	if len(r.b) == 0 {
		return nil, errNoInlineData
	}
	if v := r.b[0]; v != 1 {
		return nil, fmt.Errorf("inline data version %d, not 1", v)
	}
	r.b = r.b[1:]
	n, err := r.mapLen()
	if err != nil {
		return nil, fmt.Errorf("inline data: %w", err)
	}
	if n == 0 {
		return nil, errNoInlineData
	}
	if n != 1 {
		return nil, fmt.Errorf("inline data of %d versions: expected one", n)
	}
	if _, err := r.str(); err != nil {
		return nil, fmt.Errorf("inline data's version: %w", err)
	}
	return r.bin()
}

// stripBitrot removes the checksum before each block.
func stripBitrot(b []byte) ([]byte, error) {
	var out bytes.Buffer
	for len(b) > 0 {
		if len(b) <= hashSize {
			return nil, errors.New("data shorter than its checksum")
		}
		b = b[hashSize:]
		n := min(len(b), xlBlockLen)
		out.Write(b[:n])
		b = b[n:]
	}
	return out.Bytes(), nil
}

// msgp reads the little of msgpack xl.meta needs.
type msgp struct{ b []byte }

var errShort = errors.New("truncated")

func (r *msgp) take(n int) ([]byte, error) {
	if n < 0 || len(r.b) < n {
		return nil, errShort
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, nil
}

func (r *msgp) uintN(n int) (int, error) {
	v, err := r.take(n)
	if err != nil {
		return 0, err
	}
	var x uint64
	for _, c := range v {
		x = x<<8 | uint64(c)
	}
	if x > 1<<31 {
		return 0, errors.New("length too large")
	}
	return int(x), nil
}

func (r *msgp) bin() ([]byte, error) {
	t, err := r.take(1)
	if err != nil {
		return nil, err
	}
	var n int
	switch t[0] {
	case 0xc4:
		n, err = r.uintN(1)
	case 0xc5:
		n, err = r.uintN(2)
	case 0xc6:
		n, err = r.uintN(4)
	default:
		return nil, fmt.Errorf("type 0x%02x, not bin", t[0])
	}
	if err != nil {
		return nil, err
	}
	return r.take(n)
}

func (r *msgp) str() (string, error) {
	t, err := r.take(1)
	if err != nil {
		return "", err
	}
	var n int
	switch {
	case t[0]&0xe0 == 0xa0:
		n = int(t[0] & 0x1f)
	case t[0] == 0xd9:
		n, err = r.uintN(1)
	case t[0] == 0xda:
		n, err = r.uintN(2)
	case t[0] == 0xdb:
		n, err = r.uintN(4)
	default:
		return "", fmt.Errorf("type 0x%02x, not str", t[0])
	}
	if err != nil {
		return "", err
	}
	v, err := r.take(n)
	return string(v), err
}

func (r *msgp) mapLen() (int, error) {
	t, err := r.take(1)
	if err != nil {
		return 0, err
	}
	switch {
	case t[0]&0xf0 == 0x80:
		return int(t[0] & 0x0f), nil
	case t[0] == 0xde:
		return r.uintN(2)
	case t[0] == 0xdf:
		return r.uintN(4)
	}
	return 0, fmt.Errorf("type 0x%02x, not map", t[0])
}

func (r *msgp) skipUint() error {
	t, err := r.take(1)
	if err != nil {
		return err
	}
	switch {
	case t[0] < 0x80:
		return nil
	case t[0] == 0xcc:
		_, err = r.take(1)
	case t[0] == 0xcd:
		_, err = r.take(2)
	case t[0] == 0xce:
		_, err = r.take(4)
	case t[0] == 0xcf:
		_, err = r.take(8)
	default:
		return fmt.Errorf("type 0x%02x, not uint", t[0])
	}
	return err
}
