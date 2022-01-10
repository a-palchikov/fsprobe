//go:build !linux

package model

// Start - Starts the monitor
func (m *Monitor) Start() error {
	return errNotImplemented
}

// Stop - Stops the monitor
func (m *Monitor) Stop() error {
	return errNotImplemented
}
