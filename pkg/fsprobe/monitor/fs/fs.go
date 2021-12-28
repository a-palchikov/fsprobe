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
	"path/filepath"
	"strings"

	"github.com/c9s/goprocinfo/linux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/model"
)

var (
	// Monitor - eBPF FIM event monitor
	Monitor = &model.Monitor{
		Name:               "FileSystem",
		InodeFilterSection: model.InodesFilterMap,
		ResolutionModeMaps: map[model.DentryResolutionMode][]string{
			model.DentryResolutionFragments: {
				model.PathFragmentsMap,
				model.FSEventsMap,
				model.DentryCacheMap,
				model.DentryCacheBuilderMap,
				model.InodesFilterMap,
			},
			model.DentryResolutionSingleFragment: {
				model.SingleFragmentsMap,
				model.CachedInodesMap,
				model.FSEventsMap,
				model.DentryCacheMap,
				model.DentryCacheBuilderMap,
				model.PathsBuilderMap,
				model.InodesFilterMap,
			},
			model.DentryResolutionPerfBuffer: {
				model.CachedInodesMap,
				model.FSEventsMap,
				model.DentryCacheMap,
				model.DentryCacheBuilderMap,
				model.PathsBuilderMap,
				model.InodesFilterMap,
			},
		},
		Probes: map[model.EventName][]*model.Probe{
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
					Constants: []string{
						model.DentryResolutionModeConst,
					},
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
						model.DentryResolutionModeConst,
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
					Constants: []string{
						model.DentryResolutionModeConst,
					},
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
					Constants: []string{
						model.DentryResolutionModeConst,
					},
				},
			},
			model.Link: {
				{
					Name:        "link",
					SectionName: "kprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "link_ret",
					SectionName: "kretprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
					},
				},
			},
			model.Rename: {
				{
					Name:        "rename",
					SectionName: "kprobe/vfs_rename",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "rename_ret",
					SectionName: "kretprobe/vfs_rename",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
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
					Constants: []string{
						model.DentryResolutionModeConst,
					},
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
					Constants: []string{
						model.DentryResolutionModeConst,
					},
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
	mounts, err := linux.ReadMounts("/proc/mounts")
	if err != nil {
		return nil, errors.Wrap(err, "failed to read mounts")
	}
	return &FSEventHandler{
		pathFilters: resolveMounts(pathFilter, mounts.Mounts),
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
		"path": event.SrcFilename,
		"type": event.EventType,
	})
	logger.Info("New event.")
	var err error
	var matched bool
	switch event.EventType {
	case model.Open:
		if openFlag(event.Flags)&model.OCREAT != 0 {
			matched, err = r.maybeAddInodeFilter(monitor, uint32(event.SrcInode), event.SrcFilename, logger)
			if err != nil {
				logger.WithError(err).Warn("Failed to add inode filter.")
			}
		}
	case model.Mkdir:
		matched, err = r.maybeAddInodeFilter(monitor, uint32(event.SrcInode), event.SrcFilename, logger)
		if err != nil {
			logger.WithError(err).Warn("Failed to add inode filter.")
		}
	case model.Rename:
		matched, err = r.maybeAddInodeFilter(monitor, uint32(event.TargetInode), event.TargetFilename, logger.WithField("target", event.TargetFilename))
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

	// Dispatch event
	select {
	case monitor.Options.EventChan <- event:
	default:
	}
}

// maybeAddInodeFilter adds a new inode filter at the specified path
// if the path matches one of the filters.
// Returns true for a match, false - otherwise
func (r *FSEventHandler) maybeAddInodeFilter(monitor *model.Monitor, inode uint32, path string, logger logrus.FieldLogger) (matched bool, err error) {
	for _, f := range r.pathFilters {
		if f.matches(path) {
			err := monitor.AddInodeFilter(inode, path)
			logger.WithError(err).Info("Added new inode filter.")
			return true, err
		}
	}
	logger.Info("No match.")
	return false, nil
}

func removeCacheEntry(event *model.FSEvent, m *model.Monitor) error {
	switch resolver := m.DentryResolver.(type) {
	case *model.SingleFragmentResolver:
		return resolver.RemoveEntry(event.SrcPathnameKey)
	case *model.PerfBufferResolver:
		return resolver.RemoveEntry(uint32(event.SrcInode))
	case *model.PathFragmentsResolver:
		return resolver.RemoveInode(event.SrcMountID, event.SrcInode)
	}
	return nil
}

// matches determines whether filename matches any of the watched paths.
// expects filename != ""
func (r *FSEventHandler) matches(filename string) bool {
	for _, f := range r.pathFilters {
		if f.matches(filename) {
			return true
		}
	}
	return false
}

func resolveMounts(paths []string, mounts []linux.Mount) (result []resolvedPath) {
	// path -> most specific mountpoint
	pathMap := make(map[string]string, len(paths))
	for _, p := range paths {
		for _, m := range mounts {
			if m.MountPoint == "/" {
				// Ignore the root mount
				continue
			}
			if pathPrefix(p, m.MountPoint) {
				if mountPoint, ok := pathMap[p]; !ok || len(m.MountPoint) > len(mountPoint) {
					pathMap[p] = m.MountPoint
				}
			}
		}
		if _, ok := pathMap[p]; !ok {
			result = append(result, resolvedPath{path: p})
		}
	}
	for path, mountPoint := range pathMap {
		result = append(result, resolvedPath{path: path, mountPoint: mountPoint})
	}
	return result
}

func (r *resolvedPath) matches(segment string) bool {
	dir, _ := filepath.Split(segment)
	return strings.HasPrefix(r.path[len(r.mountPoint):], dir)
}

type resolvedPath struct {
	// mointPoint optionally specifies the mount point for this path
	mountPoint string
	path       string
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
