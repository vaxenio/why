//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseTCPTable pins the /proc/net/tcp LISTEN-row parsing: hex
// local_address, network-order port, and the LISTEN state filter.
func TestParseTCPTable(t *testing.T) {
	// Header + one LISTEN row (st=0A) + one non-listen row (st=01 ESTABLISHED).
	const sample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F91 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 54321 1 0000000000000000 100 0 0 10 0
`
	path := filepath.Join(t.TempDir(), "tcp")
	if err := os.WriteFile(path, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	rows := parseTCPTable(path)
	if len(rows) != 1 {
		t.Fatalf("parseTCPTable rows = %d, want 1 (only the LISTEN row)", len(rows))
	}
	// 0x1F90 = 8080, stored in network byte order.
	if rows[0].port != 8080 {
		t.Errorf("port = %d, want 8080", rows[0].port)
	}
	if rows[0].inode != "12345" {
		t.Errorf("inode = %q, want 12345", rows[0].inode)
	}
}

// TestSocketInode pins extraction of the inode from an fd symlink target.
func TestSocketInode(t *testing.T) {
	if inode, ok := socketInode("socket:[12345]"); !ok || inode != "12345" {
		t.Errorf("socketInode(socket:[12345]) = %q, %v; want 12345, true", inode, ok)
	}
	if _, ok := socketInode("/proc/self/fd/0"); ok {
		t.Error("socketInode(non-socket) reported ok, want false")
	}
}
