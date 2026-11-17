package main

import (
	"encoding/binary"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// sid builds S-1-5-21-a-b-c-rid.
func sid(rid uint32) []byte {
	out := []byte{1, 5, 0, 0, 0, 0, 0, 5}
	for _, sub := range []uint32{21, 1111, 2222, 3333, rid} {
		out = binary.LittleEndian.AppendUint32(out, sub)
	}
	return out
}

func TestPrimaryGroupSID(t *testing.T) {
	e := ldap.NewEntry("CN=bob,DC=x", nil)
	e.Attributes = []*ldap.EntryAttribute{
		{Name: "objectSid", ByteValues: [][]byte{sid(1104)}, Values: []string{string(sid(1104))}},
		{Name: "primaryGroupID", Values: []string{"513"}, ByteValues: [][]byte{[]byte("513")}},
	}
	if got, want := primaryGroupSID(e), sid(513); string(got) != string(want) {
		t.Fatalf("got %x, want %x", got, want)
	}
	if string(e.GetRawAttributeValue("objectSid")) != string(sid(1104)) {
		t.Fatal("the account's own SID was changed")
	}
	for name, attrs := range map[string][]*ldap.EntryAttribute{
		"no primaryGroupID": {{Name: "objectSid", ByteValues: [][]byte{sid(1104)}}},
		"no objectSid":      {{Name: "primaryGroupID", Values: []string{"513"}}},
		"a short SID":       {{Name: "objectSid", ByteValues: [][]byte{{1, 5, 0}}}, {Name: "primaryGroupID", Values: []string{"513"}}},
	} {
		e := ldap.NewEntry("CN=x", nil)
		e.Attributes = attrs
		if got := primaryGroupSID(e); got != nil {
			t.Errorf("%s: %x", name, got)
		}
	}
}

func TestEscapeBinary(t *testing.T) {
	if got := escapeBinary([]byte{0x01, 0x05, 0x2a, 0x00, 0xff}); got != `\01\05\2a\00\ff` {
		t.Errorf("got %s", got)
	}
}
