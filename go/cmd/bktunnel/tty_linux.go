//go:build linux

package main

// ioctlGetTermios is TCGETS, the terminal-attributes request isTTY probes with.
// It is 0x5401 on every Linux arch this tool targets (amd64, arm, arm64).
const ioctlGetTermios uintptr = 0x5401
