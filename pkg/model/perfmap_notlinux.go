//go:build !linux

package model

func (pm *PerfMap) Init(m *Monitor, dataHandler DataHandler) error {
	return errNotImplemented
}

type perfMapInternal struct{}
