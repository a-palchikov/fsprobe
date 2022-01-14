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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"go.uber.org/zap"

	"github.com/Gui774ume/fsprobe/pkg/model"
)

type Output struct {
	EvtChan  chan *model.FSEvent
	LostChan chan *model.LostEvt

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
	writer OutputWriter
}

// NewOutput - Returns an output instance configured with the requested format & output
func NewOutput(options CLIOptions) (*Output, error) {
	writer, err := newOutputWriter(options)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	output := Output{
		EvtChan:  make(chan *model.FSEvent, options.FSOptions.UserSpaceChanSize),
		LostChan: make(chan *model.LostEvt, options.FSOptions.UserSpaceChanSize),
		ctx:      ctx,
		cancel:   cancel,
		writer:   writer,
	}
	output.Start()
	return &output, nil
}

func (o *Output) Callback() {
	o.wg.Add(1)
	defer o.wg.Done()
	for {
		select {
		case <-o.ctx.Done():
			return
		case lost, ok := <-o.LostChan:
			if !ok {
				return
			}
			zap.L().Warn("Lost events", zap.Uint64("count", lost.Count), zap.String("map", lost.Map))
		case evt, ok := <-o.EvtChan:
			if !ok {
				return
			}
			// Handle event
			if err := o.writer.Write(evt); err != nil {
				zap.L().Debug("Failed to write event to output.", zap.Error(err))
			}
		}
	}
}

func (o *Output) Start() {
	go o.Callback()
}

func (o *Output) Close() {
	o.cancel()
	// TODO(dima): these should be closed on the sender's side
	close(o.EvtChan)
	close(o.LostChan)
	o.wg.Wait()
}

// OutputWriter - Data output interface
type OutputWriter interface {
	Write(event *model.FSEvent) error
}

func newOutputWriter(options CLIOptions) (OutputWriter, error) {
	var writer io.Writer
	var err error
	if options.OutputFilePath == "" {
		writer = os.Stdout
	} else {
		writer, err = os.Open(options.OutputFilePath)
		if err != nil {
			return nil, err
		}
	}
	switch options.Format {
	case "json":
		return JSONOutput{output: writer}, nil
	case "none":
		return DummyOutput{}, nil
	default:
		return NewTableOutput(writer), nil
	}
}

// JSONOutput - JSON output writer
type JSONOutput struct {
	output io.Writer
}

// Write - Write the event to the output writer
func (so JSONOutput) Write(event *model.FSEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := so.output.Write(data); err != nil {
		return err
	}
	return nil
}

// TableOutput - Table output writer
type TableOutput struct {
	output io.Writer
	fmt    string
	tsFmt  string
}

func NewTableOutput(writer io.Writer) TableOutput {
	out := TableOutput{
		output: writer,
		fmt:    "%7v %7v %6v %6v %6v %6v %16v %6v %7v %6v %6v %16v %s\n",
		tsFmt:  "15:04:05.000000000",
	}
	out.PrintHeader()
	return out
}

// Write - Write the event to the output writer
func (to TableOutput) Write(event *model.FSEvent) error {
	fmt.Printf(
		to.fmt,
		event.EventType,
		event.Timestamp.Format(to.tsFmt),
		event.Pid,
		event.Tid,
		event.UID,
		event.GID,
		event.Comm,
		event.PrintInode(),
		event.SrcMountID,
		event.PrintMode(),
		event.PrintFlags(),
		event.PrintFilenames(),
		model.ErrValueToString(event.Retval),
	)
	return nil
}

// PrintHeader - Prints table header
func (to TableOutput) PrintHeader() {
	fmt.Printf(to.fmt, "EVT", "TS", "PID", "TID", "UID", "GID", "CMD", "INODE", "MOUNTID", "RET", "MODE", "FLAG", "PATH")
}

// DummyOutput - Dummy output for the none format
type DummyOutput struct{}

// Write - Write the event to the output writer
func (do DummyOutput) Write(event *model.FSEvent) error {
	return nil
}
