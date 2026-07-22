//go:build darwin

package main

// ioctlGetTermios is TIOCGETA, the terminal-attributes request isTTY probes
// with on macOS (Intel and Apple Silicon).
const ioctlGetTermios uintptr = 0x40487413
