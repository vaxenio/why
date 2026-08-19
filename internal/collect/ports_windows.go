//go:build windows

package collect

import (
	"strconv"
	"syscall"
	"unsafe"

	"why/internal/evidence"
)

// GetTcpTable2 is pulled from iphlpapi (not in x/sys/windows). It returns the
// IPv4 TCP table with owning-PID info for every TCP row.
var (
	iphlpapi     = syscall.NewLazyDLL("iphlpapi.dll")
	getTCPTable2 = iphlpapi.NewProc("GetTcpTable2")
)

// MIB_TCP_STATE_LISTEN is the TCP state of a listening socket.
const mibTCPStateListen = 2

// mibTCPRow2 is one row of MIB_TCPTABLE2 (24 bytes on 32 and 64-bit).
type mibTCPRow2 struct {
	state        uint32
	localAddr    uint32
	localPort    uint32 // network byte order
	remoteAddr   uint32
	remotePort   uint32
	owningPID    uint32
	offloadState uint32
}

// windowsPorts returns the listening TCP ports and their owning PIDs.
func windowsPorts() []evidence.PortInfo {
	const bufferStep = 4096
	size := uint32(bufferStep)
	var buf []byte
	for attempts := 0; attempts < 4; attempts++ {
		buf = make([]byte, size)
		rc, _, _ := getTCPTable2.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			1, // bOrder
		)
		if rc == 0 { // NO_ERROR
			break
		}
		if rc == 122 { // ERROR_INSUFFICIENT_BUFFER, size updated
			continue
		}
		return nil
	}
	if len(buf) < 4 {
		return nil
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []evidence.PortInfo
	for i := range n {
		off := 4 + int(i)*int(unsafe.Sizeof(mibTCPRow2{}))
		if off+int(unsafe.Sizeof(mibTCPRow2{})) > len(buf) {
			break
		}
		row := (*mibTCPRow2)(unsafe.Pointer(&buf[off]))
		if row.state != mibTCPStateListen {
			continue
		}
		out = append(out, evidence.PortInfo{
			Port:  uint16(row.localPort>>8) | uint16(row.localPort<<8), // htons
			Owner: pidString(row.owningPID),
		})
	}
	return out
}

// pidString renders a PID as a decimal string (the Owner field is a string
// so both platforms report owners uniformly).
func pidString(pid uint32) string { return strconv.FormatUint(uint64(pid), 10) }
