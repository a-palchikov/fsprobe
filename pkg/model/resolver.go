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
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/utils"
)

// PathMapResolver - Dentry resolver using memory cache/eBPF map
type PathResolver struct {
	pathnames ebpfMap
	// cache maps mountID -> path entries
	cache           map[uint32]*lru.Cache
	mounts          map[int]utils.MountInfo
	dentryCacheSize int

	pathEntryPool *sync.Pool
}

// NewPathResolver - Returns a new PathResolver instance
func NewPathResolver(monitor *Monitor) (*PathResolver, error) {
	pathnames := monitor.GetMap(PathFragmentsMap)
	if pathnames == nil {
		return nil, fmt.Errorf("invalid eBPF map: %s", PathFragmentsMap)
	}
	pathEntryPool := &sync.Pool{}
	pathEntryPool.New = func() interface{} {
		return &pathEntry{new: true}
	}
	return &PathResolver{
		pathnames:       ebpfMap{m: pathnames},
		cache:           make(map[uint32]*lru.Cache),
		mounts:          monitor.Options.Mounts,
		dentryCacheSize: 1024, // probe.config.DentryCacheSize,
		pathEntryPool:   pathEntryPool,
	}, nil
}

// NewPathKey creates a new PathKey for the given inode/mountID tuple
func NewPathKey(inode uint64, mountID uint32) PathKey {
	return PathKey{
		inode:   inode,
		mountID: mountID,
	}
}

// PathKey - Key of a dentry cache hashmap
type PathKey struct {
	inode     uint64
	mountID   uint32
	__padding uint32
}

func (r *PathKey) Write(buffer []byte) {
	utils.ByteOrder.PutUint64(buffer[0:8], r.inode)
	utils.ByteOrder.PutUint32(buffer[8:12], r.mountID)
	utils.ByteOrder.PutUint32(buffer[12:16], 0)
}

func (r *PathKey) MarshalBinary() []byte {
	buf := make([]byte, 16)
	r.Write(buf)
	return buf
}

func (r *PathKey) Read(buffer []byte) int {
	r.inode = utils.ByteOrder.Uint64(buffer[0:8])
	r.mountID = utils.ByteOrder.Uint32(buffer[8:12])
	return 16
}

func (r PathKey) HasFakeInode() bool {
	return IsFakeInode(r.inode)
}

func (r PathKey) IsNull() bool {
	return r.inode == 0 && r.mountID == 0
}

func (r PathKey) HasEmptyInode() bool {
	return r.inode == 0
}

func (r PathKey) String() string {
	if IsFakeInode(r.inode) {
		return fmt.Sprintf("%d/*%d", r.mountID, r.inode&(1<<32-1))
	}
	return fmt.Sprintf("%d/%d", r.mountID, r.inode)
}

// ResolveWithFallback - Resolves a pathname from the provided mount id and inode
// Assumes that mountID != 0 && inode != 0
func (r *PathResolver) ResolveWithFallback(leaf PathKey) (pathname string, err error) {
	logger := zap.L().With(zap.String("key", leaf.String()))
	logger.Debug("Resolve path.")

	if pathname, err = r.resolveFromCache(leaf, logger); err != nil {
		if pathname, err = r.resolveFromMap(leaf, logger); err != nil {
			return "", err
		}
	}
	return r.resolveWithMount(leaf.mountID, pathname), nil
}

// Resolve - Resolves a pathname from the provided mount id and inode
// Assumes that mountID != 0 && inode != 0
func (r *PathResolver) Resolve(leaf PathKey) (pathname string, err error) {
	var path *pathEntry
	var depth int64
	var keys []PathKey
	var entries []*pathEntry
	var resolutionErr error
	var absolutePath bool

	logger := zap.L().With(zap.String("key", leaf.String()))
	logger.Debug("Resolve path.")

	key := leaf
	// Fetch path recursively
	for i := 0; i <= maxPathDepth; i++ {
		depth++
		path, err = r.lookupInodeFromCache(key)
		if err != nil {
			if !errors.Is(err, ErrEntryNotFound) {
				logger.Debug("Failed to look up the key.", zap.Error(err))
				break
			}
			logger.Debug("Key not found in cache, fall back to map.")
			var pathLeaf pathLeaf
			pathLeaf, err = r.lookupInodeFromMap(key)
			if err != nil {
				pathname = ""
				err = ErrDentryPathKeyNotFound{key: key}
				logger.Debug("Key not found in map, bail.")
				break
			}
			if pathLeaf.name[0] == '\x00' {
				if depth >= maxPathDepth {
					resolutionErr = ErrTruncatedParents{key: key}
				} else {
					resolutionErr = ErrKernelMapResolution{key: key}
				}
				break
			}
			path = r.newPathEntryFromPool(pathLeaf.parent, pathLeaf.GetString())
			logger.Debug("New path elem.", zap.String("path", path.String()))
		}

		// Do not cache fake path keys in the case of rename events.
		// Also maintain the full chain in order to set
		// up parent links properly even though some entries might already
		// exist in the cache
		if !IsFakeInode(key.inode) {
			keys = append(keys, key)
			entries = append(entries, path)
		} else {
			// TODO(dima): for now, consider the absolute
			// form synthetic entries to be complete, so bail
			// out upon encountering one
			if path.name[0] == '/' {
				pathname = path.name
				// Avoid resolving with mounts
				absolutePath = true
				break
			}
		}

		// Don't append dentry name if this is the root dentry (i.d. name == '/')
		if path.name[0] != '\x00' && path.name[0] != '/' {
			// TODO(dima): synthetic paths can be absolute
			// as kprobe will not normalize it in case of a failed
			// syscall. Need a way to normalize upon receiving
			pathname = "/" + path.name + pathname
		}
		logger.Debug("Running pathname", zap.String("path", pathname))

		if path.parent.inode == 0 {
			break
		}

		// Prepare next key
		key = path.parent
		logger = zap.L().With(zap.String("key", key.String()))
		logger.Debug("Move to next key.")
	}

	if len(pathname) == 0 {
		pathname = "/"
	}

	// resolution errors are more important than regular map lookup errors
	if resolutionErr != nil {
		err = resolutionErr
	}

	if err == nil {
		r.cacheEntries(keys, entries)
		if absolutePath {
			return pathname, nil
		}
		return r.resolveWithMount(leaf.mountID, pathname), nil
	}
	// nothing inserted in cache, release everything
	for _, entry := range entries {
		r.pathEntryPool.Put(entry)
	}
	return pathname, err

}

// DelCacheEntry removes the entry specified with key
func (r *PathResolver) DelCacheEntry(key PathKey) {
	if entries, exists := r.cache[key.mountID]; exists {
		if _, exists := entries.Get(key.inode); exists {
			// this is also called by the onEvict function of LRU thus releasing the entry from the pool
			entries.Remove(key.inode)
		}
	}
}

// DelCacheEntryPath removes the path with the specified leaf key
func (r *PathResolver) DelCacheEntryPath(key PathKey) {
	if entries, exists := r.cache[key.mountID]; exists {
		// Delete path recursively
		for {
			path, exists := entries.Get(key.inode)
			if !exists {
				break
			}
			// this is also called by the onEvict function of LRU thus releasing the entry from the pool
			entries.Remove(key.inode)

			parent := path.(*pathEntry).parent
			if parent.inode == 0 {
				break
			}

			// Prepare next key
			key = parent
		}
	}
}

// DelCacheEntries removes all the entries belonging to a mountID
func (r *PathResolver) DelCacheEntries(mountID uint32) {
	delete(r.cache, mountID)
}

// Remove - Removes a pathname from the kernel cache for the provided key
func (r *PathResolver) Remove(key PathKey) error {
	return r.pathnames.Delete(key.MarshalBinary())
}

func (r *PathResolver) resolveWithMount(mountID uint32, path string) string {
	if mount, ok := r.mounts[int(mountID)]; ok && !strings.HasPrefix(path, mount.MountPoint) {
		return filepath.Join(mount.MountPoint, path)
	}
	return path
}

func (r *PathResolver) resolveFromMap(key PathKey, logger *zap.Logger) (pathname string, err error) {
	var cacheKey PathKey
	var cacheEntry *pathEntry
	var resolutionErr error
	var name string
	var path pathLeaf
	var depth int64
	var keys []PathKey
	var entries []*pathEntry

	// Fetch path recursively
	for i := 0; i <= maxPathDepth; i++ {
		if err = r.pathnames.Lookup(key, &path); err != nil {
			pathname = ""
			err = ErrDentryPathKeyNotFound{key: key}
			logger.Debug("Failed to lookup in map.", zap.Error(err))
			break
		}
		depth++

		cacheKey = key

		if path.name[0] == '\x00' {
			if depth >= maxPathDepth {
				resolutionErr = ErrTruncatedParents{key: key}
			} else {
				resolutionErr = ErrKernelMapResolution{key: key}
			}
			logger.Debug("Resolution error.", zap.Error(resolutionErr))
			break
		}

		// Don't append dentry name if this is the root dentry (i.d. name == '/')
		if path.name[0] == '/' {
			name = "/"
		} else {
			name = path.GetString()
			pathname = "/" + name + pathname
		}
		logger.Debug("Running pathname", zap.String("path", pathname))

		// do not cache fake path keys in the case of rename events
		if !IsFakeInode(key.inode) {
			logger.Debug("Add to cache.", zap.String("par", path.parent.String()), zap.String("name", name))
			cacheEntry = r.newPathEntryFromPool(path.parent, name)

			keys = append(keys, cacheKey)
			entries = append(entries, cacheEntry)
		}

		if path.parent.inode == 0 {
			logger.Debug("Reached root, bail.")
			break
		}

		// Prepare next key
		key = path.parent
		logger = zap.L().With(zap.String("key", key.String()))
		logger.Debug("Move to next key.")
	}

	if len(pathname) == 0 {
		pathname = "/"
	}

	// resolution errors are more important than regular map lookup errors
	if resolutionErr != nil {
		err = resolutionErr
	}

	if err == nil {
		r.cacheEntries(keys, entries)
	} else {
		// nothing inserted in cache, release everything
		for _, entry := range entries {
			r.pathEntryPool.Put(entry)
		}
	}

	return pathname, err
}

// resolveFromCache resolves a path from the cache
func (r *PathResolver) resolveFromCache(key PathKey, logger *zap.Logger) (pathname string, err error) {
	var path *pathEntry
	var depth int64

	// Fetch path recursively
	for i := 0; i <= maxPathDepth; i++ {
		path, err = r.lookupInodeFromCache(key)
		if err != nil {
			logger.Debug("Failed to lookup in cache, bail.", zap.Error(err))
			break
		}
		depth++

		// Don't append dentry name if this is the root dentry (i.d. name == '/')
		if path.name[0] != '\x00' && path.name[0] != '/' {
			pathname = "/" + path.name + pathname
		}
		logger.Debug("Running pathname", zap.String("path", pathname))

		if path.parent.inode == 0 {
			logger.Debug("Reached root, done.")
			break
		}

		// Prepare next key
		key = path.parent
		logger = zap.L().With(zap.String("key", key.String()))
		logger.Debug("Move to next key.")
	}

	if len(pathname) == 0 {
		pathname = "/"
	}

	return pathname, err
}

func (r *PathResolver) cacheInode(key PathKey, path *pathEntry) error {
	entries, exists := r.cache[key.mountID]
	if !exists {
		var err error

		entries, err = lru.NewWithEvict(r.dentryCacheSize, func(_, value interface{}) {
			r.pathEntryPool.Put(value)
		})
		if err != nil {
			return err
		}
		r.cache[key.mountID] = entries
	}

	// release before in case of override
	if prev, exists := entries.Get(key.inode); exists && path.new {
		prev.(*pathEntry).new = true
		r.pathEntryPool.Put(prev)
	}

	if path.new {
		path.new = false
		entries.Add(key.inode, path)
	}

	return nil
}

//func (r *PathResolver) resolveParentFromCache(mountID uint32, inode uint64) (uint32, uint64, error) {
//	path, err := r.lookupInodeFromCache(mountID, inode)
//	if err != nil {
//		return 0, 0, ErrEntryNotFound
//	}
//
//	return path.parent.mountID, path.parent.inode, nil
//}

func (r *PathResolver) lookupInodeFromCache(key PathKey) (*pathEntry, error) {
	entries, exists := r.cache[key.mountID]
	if !exists {
		return nil, ErrEntryNotFound
	}

	entry, exists := entries.Get(key.inode)
	if !exists {
		return nil, ErrEntryNotFound
	}

	return entry.(*pathEntry), nil
}

func (r *PathResolver) lookupInodeFromMap(key PathKey) (leaf pathLeaf, err error) {
	if err := r.pathnames.Lookup(key, &leaf); err != nil {
		return leaf, errors.Wrapf(err, "unable to get filename for %s", key)
	}
	return leaf, nil
}

func (r *PathResolver) newPathEntryFromPool(parent PathKey, name string) *pathEntry {
	entry := r.pathEntryPool.Get().(*pathEntry)
	entry.parent = parent
	entry.name = name

	return entry
}

func (r *PathResolver) cacheEntries(keys []PathKey, entries []*pathEntry) {
	var cacheEntry *pathEntry

	for i, k := range keys {
		if i >= len(entries) {
			break
		}

		cacheEntry = entries[i]
		if len(keys) > i+1 {
			cacheEntry.parent = keys[i+1]
		}

		if err := r.cacheInode(k, cacheEntry); err != nil {
			r.pathEntryPool.Put(cacheEntry)
		}
	}
}

var ErrEntryNotFound = errors.New("path entry not found")

// IsFakeInode returns whether the given inode is a fake inode
func IsFakeInode(inode uint64) bool {
	return inode>>32 == uint64(fakeInodeMSW)
}

func (r pathEntry) String() string {
	return fmt.Sprintf("pathEntry(par(%s), %s)", r.parent, r.name)
}

type pathEntry struct {
	parent PathKey
	name   string
	// new indicates the entry is new and is not available in cache
	new bool
}

type pathLeaf struct {
	parent PathKey
	name   [PathFragmentsSize]byte
	//len uint32
}

// Read - Reads the provided data into the buffer
func (r *pathLeaf) Read(data []byte) error {
	return binary.Read(bytes.NewBuffer(data), utils.ByteOrder, &r.name)
}

// IsRoot - Returns true if the current fragment is the root of a mount point
func (r *pathLeaf) IsRoot() bool {
	return r.name[0] == 47
}

// GetString - Returns the path as a string
func (r *pathLeaf) GetString() string {
	return C.GoString((*C.char)(unsafe.Pointer(&r.name)))
}

// ErrDentryPathKeyNotFound is used to notify that the request key is missing from the kernel maps
type ErrDentryPathKeyNotFound struct {
	key PathKey
}

func (err ErrDentryPathKeyNotFound) Error() string {
	return fmt.Sprint("dentry path not found for ", err.key)
}

// ErrTruncatedParents is used to notify that some parents of the path are missing
type ErrTruncatedParents struct {
	key PathKey
}

func (err ErrTruncatedParents) Error() string {
	return fmt.Sprint("truncated parents for ", err.key)
}

// ErrKernelMapResolution is used to notify that the Kernel maps resolution failed
type ErrKernelMapResolution struct {
	key PathKey
}

func (err ErrKernelMapResolution) Error() string {
	return fmt.Sprint("map resolution error for ", err.key)
}

const (
	fakeInodeMSW = 0xdeadc001

	// maxPathDepth defines the maximum depth of a path
	maxPathDepth = 1500
)

func (r *ebpfMap) Delete(key interface{}) error {
	return r.m.Delete(key)
}

func (r *ebpfMap) Lookup(key PathKey, value *pathLeaf) error {
	valueBytes, err := r.m.GetBytes(key.MarshalBinary())
	if err != nil {
		return err
	}
	if len(valueBytes) == 0 {
		return ErrDentryPathKeyNotFound{key: key}
	}
	offset := value.parent.Read(valueBytes)
	if err = value.Read(valueBytes[offset:]); err != nil {
		return errors.Wrap(err, "failed to decode fragment")
	}
	return nil
}

type ebpfMap struct {
	m *ebpf.Map
}
