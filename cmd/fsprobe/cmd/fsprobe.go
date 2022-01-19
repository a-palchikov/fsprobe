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
package cmd

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Gui774ume/fsprobe/pkg/fsprobe"
	"github.com/Gui774ume/fsprobe/pkg/fsprobe/monitor/fs"
	"github.com/Gui774ume/fsprobe/pkg/utils"
)

func runFSProbeCmd(cmd *cobra.Command, args []string) error {
	// 0) Sanitize the provided options
	if err := sanitizeOptions(args); err != nil {
		return err
	}

	// 1) Prepare events output handler
	output, err := NewOutput(options)
	if err != nil {
		return errors.Wrap(err, "failed to create FSEvent output")
	}

	// 2) Set the output channel to FSProbe's output channel
	options.FSOptions.EventChan = output.EvtChan
	options.FSOptions.LostChan = output.LostChan

	options.FSOptions.Mounts, err = readProcSelfMountinfoAsMap()
	if err != nil {
		return errors.Wrap(err, "failed to read mountinfo")
	}
	pathAxes := fs.ResolveMounts([]string{options.FSOptions.Path}, options.FSOptions.Mounts)
	options.FSOptions.DataHandler, err = fs.NewFSEventHandler(pathAxes)
	if err != nil {
		return errors.Wrap(err, "failed to create FS event handler")
	}

	// 3) Instantiates FSProbe
	probe := fsprobe.NewFSProbeWithOptions(options.FSOptions)

	// 4) Start listening for events
	if err := probe.Watch(args[0], pathAxes[0]); err != nil {
		return errors.Wrap(err, "failed to watch the filesystem")
	}

	// 5) Wait until interrupt signal
	wait()

	// Stop fsprobe
	if err := probe.Stop(); err != nil {
		return errors.Wrap(err, "failed to gracefully shutdown fsprobe")
	}

	// Close the output
	output.Close()
	return nil
}

func initLogging() *zap.Logger {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.TimeEncoder(func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.UTC().Format("2006-01-02T15:04:05Z0700"))
	})
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	if options.Systemd {
		encoderConfig.TimeKey = ""
	}

	level := zap.WarnLevel
	if options.Verbose {
		level = zap.DebugLevel
	}
	core := zapcore.NewCore(zapcore.NewConsoleEncoder(encoderConfig), os.Stdout, level)
	logger := zap.New(core,
		zap.ErrorOutput(os.Stderr),
		zap.AddCaller(),
	)
	zap.ReplaceGlobals(logger)
	return logger
}

// sanitizeOptions - Sanitizes the provided options
func sanitizeOptions(args []string) error {
	if options.FSOptions.Path == "" {
		return errors.New("path-filter is required")
	}
	if len(args) < 0 {
		return errors.New("base path is required")
	}
	basePath := args[0]
	if !strings.HasPrefix(options.FSOptions.Path, utils.MaybeAddSlash(basePath)) {
		return errors.New("path-filter needs to be along the base path")
	}
	return nil
}

// wait - Waits until an interrupt or terminate signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}

func readProcSelfMountinfoAsMap() (result map[int]utils.MountInfo, err error) {
	mounts, err := utils.ReadProcSelfMountinfo()
	if err != nil {
		return nil, errors.Wrap(err, "failed to read mounts")
	}
	result = make(map[int]utils.MountInfo, len(mounts))
	for _, mi := range mounts {
		result[mi.MountID] = mi
	}
	return result, nil
}
