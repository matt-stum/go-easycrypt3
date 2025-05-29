//go:build !windows

package main

func getExitFunc() func() {
	return nil
}
