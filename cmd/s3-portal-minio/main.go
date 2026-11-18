// s3-portal-minio moves a MinIO server's access keys to versity-s3-portal,
// with their IDs and secrets, so its clients keep working, and checks the
// portal's server is ready to take over MinIO's hostname before DNS moves.
//
//	s3-portal-minio plan   --drive DIR [--minio-env FILE] --out plan.json
//	s3-portal-minio import --drive DIR [--minio-env FILE] --plan plan.json --portal URL --token-file FILE [--apply]
//	s3-portal-minio check  --name OLD-NAME --address SERVER [--drive DIR --key ACCESS] [--after]
//
// It reads MinIO's records from its drive (or a copy of the drive's
// .minio.sys/config/iam), and never writes to them. See
// docs/minio-keys.md.
package main

import (
	"errors"
	"fmt"
	"os"
)

const usage = `usage: s3-portal-minio <command> [flags]

  plan     read MinIO's users, service accounts and policies, and write a plan
           of the keys to import: their owners and grants, for review
  import   import the plan's keys into the portal, with their IDs and secrets
           (without --apply, only shows what it would do)
  check    check the portal's server answers for MinIO's hostname, with a
           certificate for it and an imported key, before (and after) DNS moves

Run "s3-portal-minio <command> -h" for a command's flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "plan":
		err = planCmd(os.Args[2:])
	case "import":
		err = importCmd(os.Args[2:])
	case "check":
		err = checkCmd(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		var f failed
		if !errors.As(err, &f) {
			fmt.Fprintln(os.Stderr, "s3-portal-minio:", err)
		}
		os.Exit(1)
	}
}

// failed is an error already reported, line by line.
type failed struct{ n int }

func (f failed) Error() string { return fmt.Sprintf("%d failed", f.n) }
