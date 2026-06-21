//go:build !windows

package main

type ProcessInfo struct {
	PID  uint32
	Name string
	Path string
}

func lookupProcessByClientAddr(string) ProcessInfo {
	return ProcessInfo{}
}
