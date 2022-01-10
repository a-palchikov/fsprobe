package model

import "os"

func getCurrentPID() int {
	return os.Getpid()
}
