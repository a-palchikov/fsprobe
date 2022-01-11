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
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

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
	options.FSOptions.DataHandler, err = fs.NewFSEventHandler(args, options.FSOptions.Paths, options.FSOptions.Mounts)
	if err != nil {
		return errors.Wrap(err, "failed to create FS event handler")
	}

	// 3) Instantiates FSProbe
	probe := fsprobe.NewFSProbeWithOptions(options.FSOptions)

	// 4) Start listening for events
	if err := probe.Watch(args...); err != nil {
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

func initLogging() {
	logrus.SetFormatter(&utils.TextFormatter{
		DisableTimestamp: options.Systemd,
	})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)
	if options.Verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
}

// sanitizeOptions - Sanitizes the provided options
func sanitizeOptions(args []string) error {
	if options.FSOptions.PathsFiltering && len(args) == 0 {
		return errors.New("paths filtering is activated but no path was provided")
	}
	if len(args) > 0 {
		options.FSOptions.PathsFiltering = true
	}
	if len(options.FSOptions.Paths) > 0 {
		options.FSOptions.Recursive = false
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
