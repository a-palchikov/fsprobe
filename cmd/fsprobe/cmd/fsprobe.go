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
	"github.com/spf13/cobra"

	"github.com/Gui774ume/fsprobe/pkg/fsprobe"
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

	// 3) Instantiates FSProbe
	probe := fsprobe.NewFSProbeWithOptions(options.FSOptions)

	// 4) Start listening for events
	if options.UsermodeFiltering {
		// 4.1) Turn on user-mode filtering
		args = []string(nil)
	}

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

// sanitizeOptions - Sanitizes the provided options
func sanitizeOptions(args []string) error {
	if options.FSOptions.PathsFiltering && len(args) == 0 {
		return errors.New("paths filtering is activated but no path was provided")
	}
	if len(args) > 0 {
		options.FSOptions.PathsFiltering = true
	}
	if options.UsermodeFiltering {
		options.FSOptions.PathsFiltering = false
	}
	return nil
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
