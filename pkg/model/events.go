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
	"C"
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/fsprobe/pkg/utils"
)

type Event uint32

const (
	EVENT_ANY Event = iota
	EVENT_FIRST_DISCARDER
	EVENT_OPEN = EVENT_FIRST_DISCARDER
)
const (
	EVENT_MKDIR = iota + EVENT_OPEN + 1
	EVENT_LINK
	EVENT_RENAME
	EVENT_UNLINK
	EVENT_RMDIR

	EVENT_CHMOD
	EVENT_CHOWN
	EVENT_UTIME
	EVENT_SETXATTR
	EVENT_REMOVEXATTR
	EVENT_LAST_DISCARDER = EVENT_REMOVEXATTR
)
const (
	EVENT_MOUNT = iota + EVENT_LAST_DISCARDER + 1
	EVENT_UMOUNT
	EVENT_FORK
	EVENT_EXEC
	EVENT_EXIT
	EVENT_INVALIDATE_DENTRY
	EVENT_SETUID
	EVENT_SETGID
	EVENT_CAPSET
	EVENT_ARGS_ENVS
	EVENT_MOUNT_RELEASED
	EVENT_SELINUX
	EVENT_BPF
	EVENT_MAX // has to be the last one
)

const (
	// Open - Open event
	Open string = "open"
	// Mkdir - Mkdir event
	Mkdir string = "mkdir"
	// Link - Soft link event
	Link string = "link"
	// Rename - Rename event
	Rename string = "rename"
	// SetAttr - Attribute update event
	SetAttr string = "setattr"
	// Unlink - File deletion event
	Unlink string = "unlink"
	// Rmdir - Directory deletion event
	Rmdir string = "rmdir"
	// Modify - File modification event
	Modify string = "modify"
	// Unknown - Unknown file event
	Unknown string = "unknown"
)

// GetEventType - Returns the event type
func GetEventType(evtType Event) string {
	switch evtType {
	case EVENT_OPEN:
		return Open
	case EVENT_MKDIR:
		return Mkdir
	case EVENT_LINK:
		return Link
	case EVENT_RENAME:
		return Rename
	case EVENT_UNLINK:
		return Unlink
	case EVENT_RMDIR:
		return Rmdir
	//case EVENT_MODIFY:
	//	return Modify
	case EVENT_SETXATTR:
		return SetAttr
	default:
		return Unknown
	}
}

// ParseFSEvent - Parses a new FSEvent using the data provided by the kernel
func ParseFSEvent(data []byte, monitor *Monitor) (*FSEvent, error) {
	evt := &FSEvent{}
	read, err := evt.UnmarshalBinary(data, monitor.FSProbe.GetBootTime())
	if err != nil {
		return nil, err
	}
	// Resolve paths
	if err := resolvePaths(data, evt, monitor, read); err != nil {
		return nil, err
	}
	return evt, nil
}

// resolvePaths - Resolves the paths of the event according to the configured method
func resolvePaths(data []byte, evt *FSEvent, monitor *Monitor, read int) (err error) {
	inode := evt.SrcInode
	if evt.SrcPathnameKey != 0 {
		inode = uint64(evt.SrcPathnameKey)
	}
	logger := logrus.WithFields(logrus.Fields{
		"type": evt.EventType,
		"comm": evt.Comm,
	})
	if evt.SrcMountID == 0 && inode == 0 {
		logger.Debug("Invalid mountID/inode tuple.")
		return nil
	}
	evt.SrcFilename, err = monitor.DentryResolver.ResolveInode(evt.SrcMountID, inode)
	if err != nil {
		return errors.Wrap(err, "failed to resolve src dentry path")
	}
	switch evt.EventType {
	case Link, Rename:
		if evt.TargetMountID == 0 && evt.TargetInode == 0 {
			logger.Debug("Invalid mountID/inode tuple.")
			return nil
		}
		evt.TargetFilename, err = monitor.DentryResolver.ResolveInode(evt.TargetMountID, evt.TargetInode)
		if err != nil {
			return errors.Wrap(err, "failed to resolve target dentry path")
		}
	}
	if evt.EventType == Link {
		// Remove cache entry for link events
		_ = monitor.DentryResolver.RemoveInode(evt.TargetMountID, evt.TargetInode)
		_ = monitor.DentryResolver.RemoveInode(evt.TargetMountID, evt.TargetInode)
	}
	return nil
}

// decodePath - Decode the raw path provided by the kernel
func decodePath(raw []byte) string {
	fragments := []string{}
	var fragment, path string
	// Isolate fragments
	for _, b := range raw {
		if b == 0 {
			// End of fragment, append to the end of the list of fragments
			if len(fragment) > 0 {
				fragments = append(fragments, fragment)
			} else {
				// stop resolution there, the rest of the buffer could be leftover from another path
				break
			}
			fragment = ""
		} else {
			fragment += string(b)
		}
	}
	// Check last fragment
	lastFrag := len(fragments) - 1
	if lastFrag < 0 {
		return ""
	}
	if fragments[lastFrag] == "/" {
		fragments = fragments[:lastFrag]
		lastFrag--
	}
	// Rebuild the entire path
	path = "/"
	for i := lastFrag; i >= 0; i-- {
		path += fragments[i] + "/"
	}
	return path[:len(path)-1]
}

// FSEvent - Raw event definition
type FSEvent struct {
	Timestamp            time.Time `json:"-"`
	Pid                  uint32    `json:"pid"`
	Tid                  uint32    `json:"tid"`
	UID                  uint32    `json:"uid"`
	GID                  uint32    `json:"gid"`
	Comm                 string    `json:"comm"`
	Flags                uint32    `json:"flags,omitempty"`
	Mode                 uint32    `json:"mode,omitempty"`
	SrcInode             uint64    `json:"src_inode,omitempty"`
	SrcPathnameLength    uint32    `json:"-"`
	SrcPathnameKey       uint32    `json:"-"`
	SrcFilename          string    `json:"src_filename,omitempty"`
	SrcMountID           uint32    `json:"src_mount_id,omitempty"`
	TargetInode          uint64    `json:"target_inode,omitempty"`
	TargetPathnameLength uint32    `json:"-"`
	TargetPathnameKey    uint32    `json:"-"`
	TargetFilename       string    `json:"target_filename,omitempty"`
	TargetMountID        uint32    `json:"target_mount_id,omitempty"`
	Retval               int32     `json:"retval"`
	EventType            string    `json:"event_type"`
}

func (e FSEvent) IsSuccess() bool {
	return e.Retval == 0
}

func (e *FSEvent) UnmarshalBinary(data []byte, bootTime time.Time) (int, error) {
	if len(data) < 96 {
		return 0, errors.Errorf("not enough data: %d", len(data))
	}
	// Process context data
	e.Timestamp = bootTime.Add(time.Duration(utils.ByteOrder.Uint64(data[0:8])) * time.Nanosecond)
	e.Pid = utils.ByteOrder.Uint32(data[8:12])
	e.Tid = utils.ByteOrder.Uint32(data[12:16])
	e.UID = utils.ByteOrder.Uint32(data[16:20])
	e.GID = utils.ByteOrder.Uint32(data[20:24])
	e.Comm = string(bytes.Trim(data[24:40], "\x00"))
	// File system event data
	e.Flags = utils.ByteOrder.Uint32(data[40:44])
	e.Mode = utils.ByteOrder.Uint32(data[44:48])
	e.SrcPathnameKey = utils.ByteOrder.Uint32(data[48:52])
	e.TargetPathnameKey = utils.ByteOrder.Uint32(data[52:56])
	e.SrcInode = utils.ByteOrder.Uint64(data[56:64])
	e.SrcPathnameLength = utils.ByteOrder.Uint32(data[64:68])
	e.SrcMountID = utils.ByteOrder.Uint32(data[68:72])
	e.TargetInode = utils.ByteOrder.Uint64(data[72:80])
	e.TargetPathnameLength = utils.ByteOrder.Uint32(data[80:84])
	e.TargetMountID = utils.ByteOrder.Uint32(data[84:88])
	e.Retval = int32(utils.ByteOrder.Uint32(data[88:92]))
	e.EventType = GetEventType(Event(utils.ByteOrder.Uint32(data[92:96])))
	return 96, nil
}

// PrintFilenames - Returns a string representation of the filenames of the event
func (fs *FSEvent) PrintFilenames() string {
	if fs.TargetFilename != "" {
		return fmt.Sprintf("%s -> %s", fs.SrcFilename, fs.TargetFilename)
	}
	return fs.SrcFilename
}

// PrintMode - Returns a string representation of the mode of the event
func (fs *FSEvent) PrintMode() string {
	switch fs.EventType {
	case Open, SetAttr:
		return fmt.Sprintf("%o", fs.Mode)
	default:
		return fmt.Sprintf("%v", fs.Mode)
	}
}

// PrintFlags - Returns a string representation of the flags of the event
func (fs *FSEvent) PrintFlags() string {
	switch fs.EventType {
	case Open:
		return strings.Join(OpenFlag(fs.Flags).Strings(), "|")
	case SetAttr:
		return strings.Join(SetAttrFlagsToString(fs.Flags), ",")
	default:
		return fmt.Sprintf("%v", fs.Flags)
	}
}
