/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package model

import (
	"fmt"
	"sync"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/utils"
)

// Monitor - Base monitor
type Monitor struct {
	ResolutionModeMaps []string
	DentryResolver     *PathFragmentsResolver
	FSProbe            FSProbe
	InodeFilterSection string
	Name               string
	Options            FSProbeOptions
	Probes             map[EventName][]*Probe
	PerfMaps           []*PerfMap

	wg         *sync.WaitGroup
	collection *ebpf.Collection
	// mounts maps mountID -> mount info
	mounts map[int]utils.MountInfo
}

// Configure - Configures the probes using the provided options
func (m *Monitor) Configure() {
	if len(m.Options.Events) == 0 {
		// Activate everything but the modification probe
		for name, probes := range m.Probes {
			if name == Modify {
				continue
			}
			for _, p := range probes {
				p.Enabled = true
			}
		}
	} else {
		// Activate the requested events
		for _, name := range m.Options.Events {
			probes, ok := m.Probes[name]
			if !ok {
				continue
			}
			for _, p := range probes {
				p.Enabled = true
			}
		}
	}
	// Setup dentry resolver
	m.DentryResolver, _ = NewPathFragmentsResolver(m)
}

// GetName - Returns the name of the monitor
func (m *Monitor) GetName() string {
	return m.Name
}

// GetMap - Returns the map at the provided section
func (m *Monitor) GetMap(section string) *ebpf.Map {
	return m.collection.Maps[section]
}

// Init - Initializes the monitor
func (m *Monitor) Init(fs FSProbe) error {
	m.FSProbe = fs
	m.wg = fs.GetWaitGroup()
	m.Options = fs.GetOptions()
	m.collection = fs.GetCollection()
	m.Configure()
	// Init probes
	for _, probes := range m.Probes {
		for _, p := range probes {
			if err := p.Init(m); err != nil {
				return err
			}
		}
	}
	// Prepare perf maps
	for _, pm := range m.PerfMaps {
		if err := pm.Init(m, fs.GetOptions().DataHandler); err != nil {
			return err
		}
	}
	return nil
}

func (m *Monitor) AddInodeFilter(inode uint32, path string) error {
	// Add inode filter
	filter := m.GetMap(m.InodeFilterSection)
	if filter == nil {
		return fmt.Errorf("invalid map %s", m.InodeFilterSection)
	}
	keyB := make([]byte, 4)
	utils.ByteOrder.PutUint32(keyB, inode)
	var valueB byte
	if err := filter.Put(keyB, valueB); err != nil {
		return err
	}
	return nil
}
