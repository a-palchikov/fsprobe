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

	"go.uber.org/zap"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/model"
	"github.com/Gui774ume/fsprobe/pkg/utils"
)

var (
	filenameCreateProbes = []*model.Probe{
		{
			Name:        "filename_create",
			SectionName: "kprobe/filename_create",
			Enabled:     false,
			Type:        ebpf.Kprobe,
		},
		//{
		//	Name:        "filename_create_ret",
		//	SectionName: "kretprobe/filename_create",
		//	Enabled:     false,
		//	Type:        ebpf.Kprobe,
		//},
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
			model.PathFragmentBuilderMap,
			model.FSEventsMap,
			model.DentryCacheMap,
			model.DentryCacheBuilderMap,
			model.DentryOpenCacheMap,
			model.DentryOpenCacheBuilderMap,
			model.InodesFilterMap,
			model.SyscallsMap,
		},
		Probes: map[string][]*model.Probe{
			model.Open: {
				{
					Name:        "sys_open",
					SectionName: "kprobe/do_sys_open",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				{
					Name:        "open",
					SectionName: "kprobe/vfs_open",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				{
					Name:        "open_ret",
					SectionName: "kretprobe/vfs_open",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
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
					DependsOn:   append([]*model.Probe{linkPathWalkProbe}, filenameCreateProbes...),
				},
				{
					Name:        "mkdir_ret",
					SectionName: "kretprobe/vfs_mkdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "do_mkdirat",
					SectionName: "kprobe/do_mkdirat",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					DependsOn:   append([]*model.Probe{mntWantWriteProbe}, filenameCreateProbes...),
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
			},
			model.Unlink: {
				{
					Name:        "unlinkat",
					SectionName: "tracepoint/syscalls/sys_enter_unlinkat",
					Enabled:     false,
					Type:        ebpf.TracePoint,
					DependsOn:   []*model.Probe{mntWantWriteProbe, linkPathWalkProbe},
				},
				{
					Name:        "unlinkat_ret",
					SectionName: "tracepoint/syscalls/sys_exit_unlinkat",
					Enabled:     false,
					Type:        ebpf.TracePoint,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
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
				{
					Name:        "do_rmdir",
					SectionName: "kprobe/do_rmdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					DependsOn:   append([]*model.Probe{mntWantWriteProbe}, filenameCreateProbes...),
				},
				{
					Name:        "do_rmdir_ret",
					SectionName: "kretprobe/do_rmdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
			},
			model.Link: {
				{
					Name:        "linkat",
					SectionName: "kprobe/do_linkat",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					DependsOn:   []*model.Probe{linkPathWalkProbe},
				},
				{
					Name:        "linkat_ret",
					SectionName: "kretprobe/do_linkat",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				{
					Name:        "link",
					SectionName: "kprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
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
					DependsOn:   []*model.Probe{linkPathWalkProbe},
				},
				{
					Name:        "renameat",
					SectionName: "kretprobe/do_renameat2",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
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
			//model.SetAttr: {
			//	{
			//		Name:        "setattr",
			//		SectionName: "kprobe/security_inode_setattr",
			//		Enabled:     false,
			//		Type:        ebpf.Kprobe,
			//		Constants: []string{
			//			model.InodeFilteringModeConst,
			//		},
			//	},
			//	{
			//		Name:        "setattr_ret",
			//		SectionName: "kretprobe/security_inode_setattr",
			//		Enabled:     false,
			//		Type:        ebpf.Kprobe,
			//	},
			//},
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

func NewFSEventHandler(pathAxes []ResolvedPath) (*FSEventHandler, error) {
	return &FSEventHandler{
		pathAxes: pathAxes,
	}, nil
}

type FSEventHandler struct {
	pathAxes []ResolvedPath
}

type openFlag = model.OpenFlag

// HandleFSEvent - Handles a file system event.
// TODO(dima): clean up cached entries for the pathnames
// that were never created for failed events.
func (r *FSEventHandler) Handle(monitor *model.Monitor, event *model.FSEvent) {
	// Take cleanup actions on the cache
	logger := zap.L().With(model.FieldsForEvent(event)...)
	logger.Debug("New event.")
	var matched bool
	switch event.EventType {
	case model.Open:
		matched = r.matches(int(event.SrcMountID), event.SrcFilename)
		if model.IsFakeInode(event.SrcInode) {
			_ = removeCacheEntry(event.SrcPathKey(), monitor)
		}
	case model.Mkdir:
		matched = r.matches(int(event.SrcMountID), event.SrcFilename)
		if model.IsFakeInode(event.SrcInode) {
			_ = removeCacheEntry(event.SrcPathKey(), monitor)
		}
	case model.Rename:
		matchedSrc := r.matches(int(event.SrcMountID), event.SrcFilename)
		matchedTarget := r.matches(int(event.TargetMountID), event.TargetFilename)
		matched = matchedSrc || matchedTarget
		_ = removeCacheEntry(event.SrcPathKey(), monitor)
		if model.IsFakeInode(event.TargetInode) {
			_ = removeCacheEntry(event.TargetPathKey(), monitor)
		}
	case model.Unlink, model.Rmdir:
		matched = r.matches(int(event.SrcMountID), event.SrcFilename)
		_ = removeCacheEntry(event.SrcPathKey(), monitor)
	case model.SetAttr, model.Link:
		// Ignore for now
	default:
		logger.Debug("Unhandled event type.")
	}

	if !matched {
		logger.Debug("Unmatched.")
		return
	}

	monitor.ResolveProcessInfo(event)
	// Dispatch event
	monitor.Options.EventChan <- event
}

func removeCacheEntry(key model.PathKey, m *model.Monitor) error {
	if !key.HasFakeInode() {
		zap.L().Debug("Removing cache entry.", zap.String("key", key.String()))
		m.DentryResolver.DelCacheEntry(key)
	}
	return m.DentryResolver.Remove(key)
}

// matches determines whether filename matches any of the watched paths.
// expects filename != ""
func (r *FSEventHandler) matches(mountID int, path string) bool {
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

// ResolveMounts maps the most specific mount to each path in paths.
// It uses prefix matching instead of stat since the paths might be non-existent
// at this point.
// Returns the list of resulting mappings
func ResolveMounts(paths []string, mounts map[int]utils.MountInfo) (result []ResolvedPath) {
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
		result = append(result, ResolvedPath{path: path, mi: mi})
	}
	return result
}

func (r *ResolvedPath) matches(mountID int, path string) bool {
	if r.mi.MountID != mountID {
		return false
	}
	dir := filepath.Dir(path)
	if r.path == path || r.path == dir {
		return true
	}
	if strings.HasPrefix(r.path, dir+string(filepath.Separator)) {
		return true
	}
	return false
}

func (r ResolvedPath) Path() string {
	return r.path
}

func (r ResolvedPath) MountID() int {
	return r.mi.MountID
}

func (r ResolvedPath) String() string {
	var b strings.Builder
	fmt.Fprint(&b, "resolvedPath(")
	fmt.Fprintf(&b, "mnt_id=%d,mntpoint=%s,path=%s",
		r.mi.MountID, r.mi.MountPoint, r.path)
	fmt.Fprint(&b, ")")
	return b.String()
}

type ResolvedPath struct {
	mi   utils.MountInfo
	path string
}

func pathPrefix(path, prefix string) bool {
	switch {
	case len(prefix) > len(path):
		return false
	case len(prefix) == len(path):
		return path == prefix
	default:
		// Since prefix is assumed to be a directory,
		// add a slash for an exact match.
		return strings.HasPrefix(path, utils.MaybeAddSlash(prefix))
	}
}
