//go:build !linux

package model

func NewProcessResolver() *ProcessResolver {
	return nil
}

func (*ProcessResolver) Resolve(pid, tid uint32) *processCacheEntry {
	return nil
}

// unimplemented
type processResolver struct{}
type processCacheEntry struct{}
