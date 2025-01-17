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

const (
	// FragmentsMap - This map holds the cache of resolved dentries for the path fragments method
	PathFragmentsMap = "path_fragments"
	// PathFragmentBuilderMap - Array map used to share data between probes
	PathFragmentBuilderMap = "path_fragment_builder"
	// PathFragmentsSize - Size of the fragments used by the path fragments method
	PathFragmentsSize = 255
	// CachedInodesMap - This map holds the list of cached inodes so that the eBPF programs know we don't need
	// resolve them anymore. This is used by both the perf buffer method and the single fragment method.
	CachedInodesMap = "cached_inodes"
	// PerfBufferCachedInodesSize - Max number of cached inodes
	PerfBufferCachedInodesSize = 120000
	// FSEventsMap - Perf event buffer map used to retrieve events in userspace
	FSEventsMap = "fs_events"
	// DentryCacheMap - LRU Hashmap used to cache dentry data between kprobes
	DentryCacheMap = "dentry_cache"
	// DentryCacheBuilderMap - Array map used to reduce the amount of data on the stack
	DentryCacheBuilderMap = "dentry_cache_builder"
	// DentryOoenCacheMap - LRU Hashmap used to cache dentry data between kprobes
	DentryOpenCacheMap = "dentry_open_cache"
	// DentryOpenCacheBuilderMap - Array map used to reduce the amount of data on the stack
	DentryOpenCacheBuilderMap = "dentry_open_cache_builder"
	// InodesFilterMap - This map is used to push inode filters in kernel space.
	InodesFilterMap = "inodes_filter"

	// SyscallsMap caches syscall data between probes
	SyscallsMap = "syscalls"
)
