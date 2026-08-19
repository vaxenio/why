//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"why/internal/evidence"
)

// linuxPorts parses /proc/net/tcp and /proc/net/tcp6 and returns the
// listening TCP ports with their owning PIDs (resolved from the socket inode
// via /proc/*/fd).
func linuxPorts() []evidence.PortInfo {
	inodes := map[string]string{} // socket inode -> owning pid
	if pids, err := os.ReadDir("/proc"); err == nil {
		for _, pid := range pids {
			if !pid.IsDir() {
				continue
			}
			fdDir := filepath.Join("/proc", pid.Name(), "fd")
			fds, err := os.ReadDir(fdDir)
			if err != nil {
				continue
			}
			for _, fd := range fds {
				link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
				if err != nil {
					continue
				}
				if inode, ok := socketInode(link); ok {
					inodes[inode] = pid.Name()
				}
			}
		}
	}

	var out []evidence.PortInfo
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		for _, row := range parseTCPTable(path) {
			owner := ""
			if pid, ok := inodes[row.inode]; ok {
				owner = pid
			}
			out = append(out, evidence.PortInfo{Port: row.port, Owner: owner})
		}
	}
	return out
}

// tcpRow is one listening entry from a /proc/net/tcp* table.
type tcpRow struct {
	port  uint16
	inode string
}

// parseTCPTable reads a /proc/net/tcp or tcp6 table and returns the LISTEN
// rows. local_address is "ADDR:PORT" with both in hex; PORT is network byte
// order.
func parseTCPTable(path string) []tcpRow {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []tcpRow
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[3] != "0A" { // TCP_LISTEN
			continue
		}
		addr, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		_ = addr
		p, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		out = append(out, tcpRow{port: uint16(p), inode: fields[9]})
	}
	return out
}

// socketInode extracts the socket inode from an fd symlink target like
// "socket:[12345]".
func socketInode(link string) (string, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(link, prefix), "]"), true
}
