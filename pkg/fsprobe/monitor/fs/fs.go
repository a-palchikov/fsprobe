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

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/model"
	"github.com/Gui774ume/fsprobe/pkg/utils"
)
import "fmt"

var (
	filenameCreateProbes = []*model.Probe{
		{
			Name:        "filename_create",
			SectionName: "kprobe/filename_create",
			Enabled:     false,
			Type:        ebpf.Kprobe,
		},
		{
			Name:        "filename_create_ret",
			SectionName: "kretprobe/filename_create",
			Enabled:     false,
			Type:        ebpf.Kprobe,
		},
	}
	mntWantWriteProbe = &model.Probe{
		Name:        "mnt_want_write",
		SectionName: "kprobe/mnt_want_write",
		Enabled:     false,
		Type:        ebpf.Kprobe,
	}
	linkPathWalkProbe = &model.Probe{
		Name:        "link_path_walk",
		SectionName: "kprobe/link_path_walk",
		Enabled:     false,
		Type:        ebpf.Kprobe,
	}

	// Monitor - eBPF FIM event monitor
	Monitor = &model.Monitor{
		Name:               "FileSystem",
		InodeFilterSection: model.InodesFilterMap,
		ResolutionModeMaps: []string{
			model.PathFragmentsMap,
			model.FSEventsMap,
			model.DentryCacheMap,
			model.DentryCacheBuilderMap,
			model.DentryOpenCacheMap,
			model.DentryOpenCacheBuilderMap,
			model.InodesFilterMap,
			model.SyscallsMap,
		},
		Probes: map[string][]*model.Probe{
			//model.Create: {
			//	{
			//		Name:        "create",
			//		SectionName: "kprobe/vfs_create",
			//		Enabled:     false,
			//		Type:        ebpf.Kprobe,
			//		Constants: []string{
			//			model.InodeFilteringModeConst,
			//		},
			//	},
			//	{
			//		Name:        "create_ret",
			//		SectionName: "kretprobe/vfs_create",
			//		Enabled:     false,
			//		Type:        ebpf.Kprobe,
			//	},
			//},
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
				{
					Name:        "path_openat",
					SectionName: "kprobe/path_openat",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				{
					Name:        "path_openat_ret",
					SectionName: "kretprobe/path_openat",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						// In path_openat we need to filter
						// in the return probe
						model.InodeFilteringModeConst,
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
					DependsOn: append([]*model.Probe{linkPathWalkProbe}, filenameCreateProbes...),
				},
				{
					Name:        "mkdir_ret",
					SectionName: "kretprobe/vfs_mkdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				//{
				//	Name:        "sys_mkdir",
				//	SectionName: "kprobe/__x64_sys_mkdir",
				//	Enabled:     false,
				//	Type:        ebpf.Kprobe,
				//},
				//{
				//	Name:        "sys_exit_mkdir",
				//	SectionName: "tracepoint/syscall__sys_exit_mkdir",
				//	Enabled:     false,
				//	Type:        ebpf.TracePoint,
				//},
				{
					Name:        "do_mkdirat",
					SectionName: "kprobe/do_mkdirat",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				{
					Name:        "do_mkdirat_ret",
					SectionName: "kretprobe/do_mkdirat",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				//{
				//	Name:        "sys_exit_mkdir",
				//	SectionName: "tracepoint/syscall__sys_exit_mkdir",
				//	Enabled:     false,
				//	Type:        ebpf.TracePoint,
				//},
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
					DependsOn: []*model.Probe{mntWantWriteProbe},
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
					DependsOn: []*model.Probe{mntWantWriteProbe},
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
					Name:        "linkat",
					SectionName: "kprobe/do_linkat",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				{
					Name:        "link",
					SectionName: "kprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
					//DependsOn: []*model.Probe{filenameCreateProbe},
					DependsOn: filenameCreateProbes,
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
					Name:        "renameat",
					SectionName: "kprobe/do_renameat2",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				{
					Name:        "rename",
					SectionName: "kprobe/vfs_rename",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
					DependsOn: []*model.Probe{mntWantWriteProbe},
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
				//{
				//	Name:        "modify",
				//	SectionName: "kprobe/__fsnotify_parent",
				//	Enabled:     false,
				//	Type:        ebpf.Kprobe,
				//	Constants: []string{
				//		model.InodeFilteringModeConst,
				//	},
				//},
				//{
				//	Name:        "modify_ret",
				//	SectionName: "kretprobe/__fsnotify_parent",
				//	Enabled:     false,
				//	Type:        ebpf.Kprobe,
				//},
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
				// TODO(dima): move to fs event handler
				LostHandler: LostFSEvent,
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

func NewFSEventHandler(paths, pathAxes []string, mounts map[int]utils.MountInfo) (*FSEventHandler, error) {
	return &FSEventHandler{
		pathAxes: resolveMounts(pathAxes, mounts),
		paths:    paths,
	}, nil
}

type FSEventHandler struct {
	pathAxes []resolvedPath
	paths    []string
}

type openFlag = model.OpenFlag

// HandleFSEvent - Handles a file system event
func (r *FSEventHandler) Handle(monitor *model.Monitor, event *model.FSEvent) {
	// Take cleanup actions on the cache
	logger := logrus.WithFields(logrus.Fields{
		"path":   event.SrcFilename,
		"type":   event.EventType,
		"mnt_id": event.SrcMountID,
		"comm":   event.Comm,
		"ret":    event.Retval,
	})
	//logger.Info("New event.")
	var matched bool
	switch event.EventType {
	case model.Open:
		matched = r.matches(int(event.SrcMountID), event.SrcFilename)
		if matched && openFlag(event.Flags)&model.O_CREAT != 0 {
			err := r.maybeAddInodeFilter(monitor,
				uint32(event.SrcInode),
				event.SrcFilename,
				logger)
			if err != nil {
				logger.WithError(err).Warn("Failed to add inode filter.")
			}
		}
	case model.Mkdir:
		matched = r.matches(int(event.SrcMountID), event.SrcFilename)
		if matched {
			err := r.maybeAddInodeFilter(monitor,
				uint32(event.SrcInode),
				event.SrcFilename,
				logger)
			if err != nil {
				logger.WithError(err).Warn("Failed to add inode filter.")
			}
		}
	case model.Rename:
		matchedSrc := r.matches(int(event.SrcMountID), event.SrcFilename)
		matchedTarget := r.matches(int(event.TargetMountID), event.TargetFilename)
		matched = matchedSrc || matchedTarget
		if matchedTarget {
			err := r.maybeAddInodeFilter(monitor,
				uint32(event.TargetInode),
				event.TargetFilename,
				logger.WithField("target", event.TargetFilename))
			if err != nil {
				logger.WithError(err).Warn("Failed to add inode filter.")
			}
		}
		if err := removeCacheEntry(event, monitor); err != nil {
			logrus.WithError(err).Warn("Failed to remove entry from cache.")
		}
	case model.Unlink, model.Rmdir:
		matched = r.matches(int(event.SrcMountID), event.SrcFilename)
		if err := removeCacheEntry(event, monitor); err != nil {
			logrus.WithError(err).Warn("Failed to remove entry from cache.")
		}
	default:
		logger.Warn("Unhandled event type.")
	}

	if !matched {
		//logger.Info("Unmatched.")
		return
	}

	//logger.Debug("Matched.")
	// Dispatch event
	select {
	case monitor.Options.EventChan <- event:
	default:
		logger.Debug("Dropped event.")
	}
}

// maybeAddInodeFilter adds a new inode filter at the specified path
// if the path matches one of the filters.
// Returns true for a match, false - otherwise
func (r *FSEventHandler) maybeAddInodeFilter(monitor *model.Monitor, inode uint32, path string, logger logrus.FieldLogger) error {
	err := monitor.AddInodeFilter(inode, path)
	logger.WithError(err).Info("Added new inode filter.")
	return err
}

func removeCacheEntry(event *model.FSEvent, m *model.Monitor) error {
	return m.DentryResolver.RemoveInode(event.SrcMountID, event.SrcInode)
}

// matches determines whether filename matches any of the watched paths.
// expects filename != ""
func (r *FSEventHandler) matches(mountID int, path string) bool {
	// TODO(dima): figure out the details on bogus mount IDs and
	// root paths
	if path == "" || path == "/" {
		return false
	}
	for _, f := range r.pathAxes {
		if f.matches(mountID, path) {
			return true
		}
	}
	return false
}

// resolveMounts maps the most specific mount to each path in paths.
// It uses prefix matching instead of stat since the paths might be non-existent
// at this point.
// Returns the list of resulting mappings
func resolveMounts(paths []string, mounts map[int]utils.MountInfo) (result []resolvedPath) {
	// path -> most specific mountpoint
	pathMap := make(map[string]utils.MountInfo, len(paths))
	for _, p := range paths {
		for _, m := range mounts {
			if pathPrefix(p, m.MountPoint) {
				if mi, ok := pathMap[p]; !ok || len(m.MountPoint) > len(mi.MountPoint) {
					pathMap[p] = m
				}
			}
		}
	}
	for path, mi := range pathMap {
		mi := mi
		result = append(result, resolvedPath{path: path, mi: mi})
	}
	return result
}

func (r *resolvedPath) matches(mountID int, path string) bool {
	if r.mi.MountID != mountID {
		return false
	}
	if r.path == path {
		return true
	}
	dir := filepath.Dir(path)
	if strings.HasPrefix(r.path, dir) {
		return true
	}
	return false
}

func (r resolvedPath) String() string {
	var b strings.Builder
	fmt.Fprint(&b, "resolvedPath(")
	fmt.Fprintf(&b, "mnt_id=%d,mntpoint=%s,path=%s",
		r.mi.MountID, r.mi.MountPoint, r.path)
	fmt.Fprint(&b, ")")
	return b.String()
}

type resolvedPath struct {
	mi   utils.MountInfo
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
