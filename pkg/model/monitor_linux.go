package model

import (
	"go.uber.org/zap"
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
				zap.L().Warn("Failed to start probe.", zap.Error(err), zap.String("name", p.Name))
				return err
			}
		}
	}
	for _, p := range depends {
		if err := p.Start(); err != nil {
			zap.L().Warn("Failed to start probe.", zap.Error(err), zap.String("name", p.Name))
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
				zap.L().Error("Failed to stop probe", zap.String("name", p.Name), zap.Error(err))
			}
		}
	}
	// stop polling perf maps
	for _, pm := range m.PerfMaps {
		if err := pm.pollStop(); err != nil {
			zap.L().Error("Failed to gracefully close perf map", zap.String("name", pm.PerfOutputMapName), zap.Error(err))
		}
	}
	return nil
}
