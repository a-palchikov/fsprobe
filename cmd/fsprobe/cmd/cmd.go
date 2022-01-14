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
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Gui774ume/fsprobe/pkg/utils"
	"github.com/Gui774ume/fsprobe/version"
)

// FSProbeCmd represents the base command when called without any subcommands
var FSProbeCmd = &cobra.Command{
	Use:   "fsprobe [paths]",
	Short: "A file system events notifier based on eBPF",
	Long: `FSProbe is a file system events notifier based on eBPF

FSProbe relies on eBPF to capture file system events on dentry kernel structures.
More information about the project can be found on github: https://github.com/Gui774ume/fsprobe`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := initLogging()
		defer logger.Sync()
		if options.Version {
			return printVersion()
		}
		if err := runFSProbeCmd(cmd, args); err != nil {
			utils.DebugReport(os.Stderr, err)
			return err
		}
		return nil
	},
	SilenceUsage: true,
	Example:      "sudo fsprobe /tmp",
}

// options - CLI options
var options CLIOptions

func init() {
	FSProbeCmd.Flags().StringSliceVar(
		&options.FSOptions.Paths,
		"path-filter",
		nil,
		`When specified, only event hits along this path will be generated.
For each path filter, only top-level watches along the filter are added.
If a filter specifies a file, in the file's directory only the file
will be watched (along with all files in all preceeding sub-directories).
Filter can specify a path that does not yet exist`)
	FSProbeCmd.Flags().BoolVarP(
		&options.FSOptions.Recursive,
		"recursive",
		"r",
		true,
		`Watches all subdirectories of any directory passed as argument.
Watches will be set up recursively to an unlimited depth.
Symbolic links are not traversed. Newly created subdirectories
will also be watched. When this option is not provided, only
the immediate children of a provided directory are watched`)
	FSProbeCmd.Flags().BoolVar(
		&options.FSOptions.PathsFiltering,
		"paths-filtering",
		true,
		`When activated, FSProbe will only notify events on the paths 
provided to the Watch function. When deactivated, FSProbe
will notify events on the entire file system`)
	FSProbeCmd.Flags().BoolVar(
		&options.FSOptions.FollowRenames,
		"follow",
		true,
		`When activated, FSProbe will keep watching the files that were
initially in a watched directory and were moved to a location
that is not necessarily watched. In other words, files are followed
even after a move`)
	FSProbeCmd.Flags().VarP(
		NewEventsValue(&options.FSOptions.Events),
		"event",
		"e",
		`Listens for specific event(s) only. This option can be specified
more than once. If omitted, all the events will be activated except the modify one.
Available options: open, mkdir, link, rename, setattr, unlink,
rmdir, modify`)
	FSProbeCmd.Flags().IntVarP(
		&options.FSOptions.UserSpaceChanSize,
		"chan-size",
		"s",
		1000,
		"User space channel size")
	FSProbeCmd.Flags().IntVar(
		&options.FSOptions.PerfBufferSize,
		"perf-buffer-size",
		128,
		`Perf ring buffer size for kernel-space to user-space
communication`)
	FSProbeCmd.Flags().StringVarP(
		&options.Format,
		"format",
		"f",
		"table",
		`Defines the output format.
Options are: table, json, none`)
	FSProbeCmd.Flags().StringVarP(
		&options.OutputFilePath,
		"output",
		"o",
		"",
		`Outputs events to the provided file rather than
stdout`)
	FSProbeCmd.Flags().BoolVarP(
		&options.Verbose,
		"verbose",
		"v",
		false,
		`Increase logging verbosity`)
	FSProbeCmd.Flags().BoolVarP(
		&options.Version,
		"version",
		"",
		false,
		`Output version information and exit`)
	FSProbeCmd.Flags().BoolVarP(
		&options.Systemd,
		"systemd",
		"",
		false,
		`Set up logging from a systemd unit`)
}

func printVersion() error {
	v := version.Get()
	bytes, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, string(bytes))
	return nil
}
