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

import "C"
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/utils"
)

// PathFragmentsKey - Key of a dentry cache hashmap
type PathFragmentsKey struct {
	inode   uint64
	mountID uint32
}

func (pfk *PathFragmentsKey) Set(mountID uint32, inode uint64) {
	pfk.mountID = mountID
	pfk.inode = inode
}

func (pfk *PathFragmentsKey) Write(buffer []byte) {
	utils.ByteOrder.PutUint64(buffer[0:8], pfk.inode)
	utils.ByteOrder.PutUint32(buffer[8:12], pfk.mountID)
	utils.ByteOrder.PutUint32(buffer[12:16], 0)
}

func (pfk *PathFragmentsKey) GetKeyBytes() []byte {
	keyB := make([]byte, 16)
	pfk.Write(keyB)
	return keyB[:]
}

func (pfk *PathFragmentsKey) Read(buffer []byte) int {
	pfk.inode = utils.ByteOrder.Uint64(buffer[0:8])
	pfk.mountID = utils.ByteOrder.Uint32(buffer[8:12])
	return 16
}

func (pfk *PathFragmentsKey) IsNull() bool {
	return pfk.inode == 0 && pfk.mountID == 0
}

func (pfk *PathFragmentsKey) HasEmptyInode() bool {
	return pfk.inode == 0
}

func (pfk *PathFragmentsKey) String() string {
	return fmt.Sprintf("%x/%x", pfk.mountID, pfk.inode)
}

type PathFragmentsValue struct {
	parent   PathFragmentsKey
	Fragment [PathFragmentsSize]byte
}

// Read - Reads the provided data into the buffer
func (pfv *PathFragmentsValue) Read(data []byte) error {
	return binary.Read(bytes.NewBuffer(data), utils.ByteOrder, &pfv.Fragment)
}

// IsRoot - Returns true if the current fragment is the root of a mount point
func (pfv *PathFragmentsValue) IsRoot() bool {
	return pfv.Fragment[0] == 47
}

// GetString - Returns the path as a string
func (pfv *PathFragmentsValue) GetString() string {
	return C.GoString((*C.char)(unsafe.Pointer(&pfv.Fragment)))
}

// PathFragmentsResolver - Dentry resolver of the path fragments method
type PathFragmentsResolver struct {
	cache *ebpf.Map
	key   *PathFragmentsKey
	value *PathFragmentsValue
}

// NewPathFragmentsResolver - Returns a new PathFragmentsResolver instance
func NewPathFragmentsResolver(monitor *Monitor) (*PathFragmentsResolver, error) {
	cache := monitor.GetMap(PathFragmentsMap)
	if cache == nil {
		return nil, fmt.Errorf("invalid eBPF map: %s", PathFragmentsMap)
	}
	return &PathFragmentsResolver{
		cache: cache,
		key:   &PathFragmentsKey{},
		value: &PathFragmentsValue{},
	}, nil
}

// ResolveInode - Resolves a pathname from the provided mount id and inode
func (pfr *PathFragmentsResolver) ResolveInode(mountID uint32, inode uint64) (filename string, err error) {
	// Don't resolve path if pathnameKey isn't valid
	pfr.key.Set(mountID, inode)
	if pfr.key.IsNull() {
		return "", fmt.Errorf("invalid inode/dev tuple: %s", pfr.key.String())
	}

	keyB := pfr.key.GetKeyBytes()
	valueB := []byte{}
	done := false
	// Fetch path recursively
	for !done {
		if valueB, err = pfr.cache.GetBytes(keyB); err != nil || len(valueB) == 0 {
			filename = "*ERROR*" + filename
			break
		}
		// Read next key from valueB
		read := pfr.key.Read(valueB)
		// Read current fragment from valueB
		if err = pfr.value.Read(valueB[read:]); err != nil {
			err = errors.Wrap(err, "failed to decode fragment")
			break
		}

		// Don't append dentry name if this is the root dentry (i.e. name == '/')
		if !pfr.value.IsRoot() {
			filename = "/" + pfr.value.GetString() + filename
		}

		if pfr.key.HasEmptyInode() {
			break
		}

		// Prepare next key
		pfr.key.Write(keyB)
	}

	if len(filename) == 0 {
		filename = "/"
	}

	return filename, err
}

// RemoveInode - Removes a pathname from the kernel cache using the provided mount id and inode
func (pfr *PathFragmentsResolver) RemoveInode(mountID uint32, inode uint64) error {
	// Don't resolve path if pathnameKey isn't valid
	pfr.key.Set(mountID, inode)
	if pfr.key.IsNull() {
		return fmt.Errorf("invalid inode/dev couple: %s", pfr.key.String())
	}
	keyB := pfr.key.GetKeyBytes()
	// Delete entry
	return pfr.cache.Delete(keyB)
}
