package model

import (
	"github.com/sirupsen/logrus"
)

// Start - Starts the monitor
func (m *Monitor) Start() error {
	// start probes
	// depends maps probe name -> probe
	// TODO(dima): revisit this to hide the complexity of dealing with dependent probes
	depends := make(map[string]*Probe)
	for _, probes := range m.Probes {
		for _, p := range probes {
			for _, d := range p.DependsOn {
				depends[d.Name] = d
			}
			if err := p.Start(); err != nil {
				logrus.WithError(err).WithField("name", p.Name).Warn("Failed to start probe.")
				return err
			}
		}
	}
	for _, p := range depends {
		if err := p.Start(); err != nil {
			logrus.WithError(err).WithField("name", p.Name).Warn("Failed to start probe.")
			return err
		}
	}
	// start polling perf maps
	for _, pm := range m.PerfMaps {
		if err := pm.pollStart(); err != nil {
			return err
		}
	}
	return nil
}

// Stop - Stops the monitor
func (m *Monitor) Stop() error {
	// Stop probes
	for _, probes := range m.Probes {
		for _, p := range probes {
			if err := p.Stop(); err != nil {
				logrus.Errorf("couldn't stop probe \"%s\": %v", p.Name, err)
			}
		}
	}
	// stop polling perf maps
	for _, pm := range m.PerfMaps {
		if err := pm.pollStop(); err != nil {
			logrus.Errorf("couldn't close perf map %v gracefully: %v", pm.PerfOutputMapName, err)
		}
	}
	return nil
}
