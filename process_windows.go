//go:build windows

package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPidAll = 5
	afInet              = 2
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type ProcessInfo struct {
	PID  uint32
	Name string
	Path string
}

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

func lookupProcessByClientAddr(clientAddr string) ProcessInfo {
	start := time.Now()
	stage := "start"
	defer func() {
		elapsed := time.Since(start)
		if elapsed > 10*time.Millisecond {
			log.Printf("process lookup slow: client=%s stage=%s cost=%s", clientAddr, stage, elapsed)
		} else {
			log.Printf("process lookup: client=%s stage=%s cost=%s", clientAddr, stage, elapsed)
		}
	}()
	host, portText, err := net.SplitHostPort(clientAddr)
	if err != nil || !isLocalHost(host) {
		stage = "skip_non_local"
		return ProcessInfo{}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		stage = "bad_port"
		return ProcessInfo{}
	}
	tableStart := time.Now()
	pid := lookupTCPPortPID(uint16(port))
	log.Printf("process lookup tcp table: client=%s port=%d pid=%d cost=%s", clientAddr, port, pid, time.Since(tableStart))
	if pid == 0 {
		stage = "pid_not_found"
		return ProcessInfo{}
	}
	processStart := time.Now()
	name, path := processNameAndPath(pid)
	log.Printf("process lookup image: client=%s pid=%d name=%s cost=%s", clientAddr, pid, name, time.Since(processStart))
	stage = "ok"
	return ProcessInfo{PID: pid, Name: name, Path: path}
}

func isLocalHost(host string) bool {
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return strings.EqualFold(host, "localhost")
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

func lookupTCPPortPID(localPort uint16) uint32 {
	var size uint32
	_, _, _ = procGetExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if size == 0 {
		return 0
	}
	buf := make([]byte, size)
	r1, _, _ := procGetExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if r1 != 0 || len(buf) < 4 {
		return 0
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	offset := uintptr(4)
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	for i := uint32(0); i < count; i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset + uintptr(i)*rowSize))
		port := uint16((row.LocalPort&0xff)<<8 | (row.LocalPort >> 8 & 0xff))
		if port == localPort {
			return row.OwningPID
		}
	}
	return 0
}

func processNameAndPath(pid uint32) (string, string) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return processNameFromProc(pid), ""
	}
	defer windows.CloseHandle(handle)
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err == nil && size > 0 {
		path := windows.UTF16ToString(buf[:size])
		name := path
		if idx := strings.LastIndexAny(path, `\\/`); idx >= 0 {
			name = path[idx+1:]
		}
		return name, path
	}
	return processNameFromProc(pid), ""
}

func processNameFromProc(pid uint32) string {
	link := `\\?\\C:\\Windows\\System32`
	_ = link
	if exe, err := os.Readlink(`C:\\proc\\` + strconv.FormatUint(uint64(pid), 10) + `\\exe`); err == nil {
		if idx := strings.LastIndexAny(exe, `\\/`); idx >= 0 {
			return exe[idx+1:]
		}
		return exe
	}
	return ""
}
