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
package fs

import (
	"C"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/model"
	"github.com/Gui774ume/fsprobe/pkg/utils"
)

var (
	// Monitor - eBPF FIM event monitor
	Monitor = &model.Monitor{
		Name:               "FileSystem",
		InodeFilterSection: model.InodesFilterMap,
		ResolutionModeMaps: []string{
			model.PathFragmentsMap,
			model.FSEventsMap,
			model.DentryCacheMap,
			model.DentryCacheBuilderMap,
			model.InodesFilterMap,
		},
		Probes: map[model.EventName][]*model.Probe{
			model.Create: {
				{
					Name:        "create",
					SectionName: "kprobe/vfs_create",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "create_ret",
					SectionName: "kretprobe/vfs_create",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Open: {
				{
					Name:        "open",
					SectionName: "kprobe/vfs_open",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "open_ret",
					SectionName: "kretprobe/vfs_open",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Mkdir: {
				{
					Name:        "mkdir",
					SectionName: "kprobe/vfs_mkdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "mkdir_ret",
					SectionName: "kretprobe/vfs_mkdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.RecursiveModeConst,
					},
				},
			},
			model.Unlink: {
				{
					Name:        "unlink",
					SectionName: "kprobe/vfs_unlink",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "unlink_ret",
					SectionName: "kretprobe/vfs_unlink",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Rmdir: {
				{
					Name:        "rmdir",
					SectionName: "kprobe/vfs_rmdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "rmdir_ret",
					SectionName: "kretprobe/vfs_rmdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Link: {
				{
					Name:        "link",
					SectionName: "kprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "link_ret",
					SectionName: "kretprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Rename: {
				{
					Name:        "rename",
					SectionName: "kprobe/vfs_rename",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "rename_ret",
					SectionName: "kretprobe/vfs_rename",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.FollowModeConst,
					},
				},
			},
			model.Modify: {
				{
					Name:        "modify",
					SectionName: "kprobe/__fsnotify_parent",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "modify_ret",
					SectionName: "kretprobe/__fsnotify_parent",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.SetAttr: {
				{
					Name:        "setattr",
					SectionName: "kprobe/security_inode_setattr",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "setattr_ret",
					SectionName: "kretprobe/security_inode_setattr",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
		},
		PerfMaps: []*model.PerfMap{
			{
				UserSpaceBufferLen: 1000,
				PerfOutputMapName:  "fs_events",
				LostHandler:        LostFSEvent,
			},
		},
	}
)

// LostFSEvent - Handles a LostEvent
func LostFSEvent(count uint64, mapName string, monitor *model.Monitor) {
	// Dispatch event
	if monitor.Options.LostChan != nil {
		monitor.Options.LostChan <- &model.LostEvt{
			Count: count,
			Map:   mapName,
		}
	}
}

func NewFSEventHandler(paths, pathFilter []string) (*FSEventHandler, error) {
	mounts, err := utils.ReadProcSelfMountinfo()
	if err != nil {
		return nil, errors.Wrap(err, "failed to read mounts")
	}
	return &FSEventHandler{
		pathFilters: resolveMounts(pathFilter, mounts),
		paths:       paths,
	}, nil
}

type FSEventHandler struct {
	pathFilters []resolvedPath
	paths       []string
}

type openFlag = model.OpenFlag

// HandleFSEvent - Handles a file system event
func (r *FSEventHandler) Handle(monitor *model.Monitor, event *model.FSEvent) {
	// Take cleanup actions on the cache
	logger := logrus.WithFields(logrus.Fields{
		"path":   event.SrcFilename,
		"type":   event.EventType,
		"mnt_id": event.SrcMountID,
	})
	// logger.Info("New event.")
	var err error
	var matched bool
	switch event.EventType {
	case model.Open:
		if openFlag(event.Flags)&model.OCREAT != 0 {
			matched, err = r.maybeAddInodeFilter(monitor,
				uint32(event.SrcInode),
				int(event.SrcMountID),
				event.SrcFilename,
				logger)
			if err != nil {
				logger.WithError(err).Warn("Failed to add inode filter.")
			}
		}
	case model.Mkdir:
		matched, err = r.maybeAddInodeFilter(monitor,
			uint32(event.SrcInode),
			int(event.SrcMountID),
			event.SrcFilename,
			logger)
		if err != nil {
			logger.WithError(err).Warn("Failed to add inode filter.")
		}
	case model.Rename:
		matched, err = r.maybeAddInodeFilter(monitor,
			uint32(event.TargetInode),
			// source mount ID to trigger the event below
			int(event.SrcMountID),
			event.TargetFilename,
			logger.WithField("target", event.TargetFilename))
		if err != nil {
			logger.WithError(err).Warn("Failed to add inode filter.")
		}
		if err := removeCacheEntry(event, monitor); err != nil {
			logrus.WithError(err).Warn("Failed to remove entry from cache.")
		}
	case model.Unlink, model.Rmdir:
		if err := removeCacheEntry(event, monitor); err != nil {
			logrus.WithError(err).Warn("Failed to remove entry from cache.")
		}
	}

	if !matched {
		return
	}

	logger.Debug("Matched.")
	// Dispatch event
	select {
	case monitor.Options.EventChan <- event:
	default:
	}
}

// maybeAddInodeFilter adds a new inode filter at the specified path
// if the path matches one of the filters.
// Returns true for a match, false - otherwise
func (r *FSEventHandler) maybeAddInodeFilter(monitor *model.Monitor, inode uint32, mountID int, path string, logger logrus.FieldLogger) (matched bool, err error) {
	for _, f := range r.pathFilters {
		if f.matches(mountID, path) {
			err := monitor.AddInodeFilter(inode, path)
			logger.WithError(err).Info("Added new inode filter.")
			return true, err
		}
	}
	return false, nil
}

func removeCacheEntry(event *model.FSEvent, m *model.Monitor) error {
	return m.DentryResolver.RemoveInode(event.SrcMountID, event.SrcInode)
}

// matches determines whether filename matches any of the watched paths.
// expects filename != ""
func (r *FSEventHandler) matches(mountID int, path string) bool {
	for _, f := range r.pathFilters {
		if f.matches(mountID, path) {
			return true
		}
	}
	return false
}

func resolveMounts(paths []string, mounts []utils.MountInfo) (result []resolvedPath) {
	// path -> most specific mountpoint
	pathMap := make(map[string]utils.MountInfo, len(paths))
	for _, p := range paths {
		for _, m := range mounts {
			if m.MountPoint == "/" {
				// Ignore the root mount
				continue
			}
			if pathPrefix(p, m.MountPoint) {
				if mi, ok := pathMap[p]; !ok || len(m.MountPoint) > len(mi.MountPoint) {
					pathMap[p] = m
				}
			}
		}
		if _, ok := pathMap[p]; !ok {
			result = append(result, resolvedPath{path: p})
		}
	}
	for path, mi := range pathMap {
		mi := mi
		result = append(result, resolvedPath{path: path, mi: &mi})
	}
	return result
}

func (r *resolvedPath) matches(mountID int, path string) bool {
	if r.mi == nil {
		dir, _ := filepath.Split(path)
		return strings.HasPrefix(r.path, dir)
	}
	if r.mi.MountID != mountID {
		return false
	}
	dir := filepath.Dir(path)
	return strings.HasPrefix(r.path[len(r.mi.MountPoint):], dir)
}

func (r resolvedPath) String() string {
	var b strings.Builder
	fmt.Fprint(&b, "resolvedPath(")
	if r.mi != nil {
		fmt.Fprintf(&b, "mnt_id=%d,mntpoint=%s,", r.mi.MountID, r.mi.MountPoint)
	}
	fmt.Fprint(&b, "path=", r.path)
	fmt.Fprint(&b, ")")
	return b.String()
}

type resolvedPath struct {
	// mi optionally specifies the mount point for this path
	mi   *utils.MountInfo
	path string
}

func pathPrefix(path, prefix string) bool {
	maybeAddSlash := func(path string) string {
		if len(path) == 0 {
			return string(filepath.Separator)
		}
		if path[len(path)-1] != filepath.Separator {
			return path + string(filepath.Separator)
		}
		return path
	}
	switch {
	case len(prefix) > len(path):
		return false
	case len(prefix) == len(path):
		return path == prefix
	default:
		// Since prefix is assumed to be a directory,
		// add a slash for an exact match.
		return strings.HasPrefix(path, maybeAddSlash(prefix))
	}
}
