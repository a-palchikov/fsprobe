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
	"io/ioutil"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/utils"
)

func NewPathKey(inode uint64, mountID uint32) PathFragmentsKey {
	return PathFragmentsKey{
		inode:   inode,
		mountID: mountID,
	}
}

// PathFragmentsKey - Key of a dentry cache hashmap
type PathFragmentsKey struct {
	inode     uint64
	mountID   uint32
	__padding uint32
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

func (pfk PathFragmentsKey) String() string {
	return fmt.Sprintf("%d/%d", pfk.mountID, pfk.inode)
}

type PathFragmentsValue struct {
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
	cache  *ebpf.Map
	mounts map[int]utils.MountInfo
}

// NewPathFragmentsResolver - Returns a new PathFragmentsResolver instance
func NewPathFragmentsResolver(monitor *Monitor) (*PathFragmentsResolver, error) {
	cache := monitor.GetMap(PathFragmentsMap)
	if cache == nil {
		return nil, fmt.Errorf("invalid eBPF map: %s", PathFragmentsMap)
	}
	return &PathFragmentsResolver{
		cache:  cache,
		mounts: monitor.Options.Mounts,
	}, nil
}

// ResolveInode - Resolves a pathname from the provided mount id and inode
// Assumes that mountID != 0 && inode != 0
func (pfr *PathFragmentsResolver) ResolveInode(leaf PathFragmentsKey) (filename string, err error) {
	log := logrus.New()
	log.SetOutput(ioutil.Discard)
	var debug bool
	if debug {
		log.SetOutput(os.Stdout)
		log.SetLevel(logrus.DebugLevel)
	}
	logger := log.WithField("key", leaf.String())
	logger.Debug("ResolveInode.")
	key := leaf
	keyB := key.GetKeyBytes()
	var value PathFragmentsValue
	var valueB []byte
	done := false
	// Fetch path recursively
	for !done {
		if valueB, err = pfr.cache.GetBytes(keyB); err != nil || len(valueB) == 0 {
			filename = "*ERROR*" + filename
			break
		}
		// Read next key from valueB (parent key)
		read := key.Read(valueB)
		// Read current fragment from valueB
		if err = value.Read(valueB[read:]); err != nil {
			err = errors.Wrap(err, "failed to decode fragment")
			break
		}
		logger := log.WithFields(logrus.Fields{
			"par/mnt_id": key.mountID,
			"par/ino":    key.inode,
			"frag":       value.GetString(),
		})
		logger.Debug("Decoded fragment value.")

		// Don't append dentry name if this is the root dentry (i.e. name == '/')
		if !value.IsRoot() {
			filename = "/" + value.GetString() + filename
		}

		if key.HasEmptyInode() {
			logger.Debug("Value has empty inode, bail.")
			break
		}

		logger.Debug("Move to next key.")
		// Prepare next key
		key.Write(keyB)
	}

	if len(filename) == 0 {
		filename = "/"
	}

	return pfr.resolveWithMount(leaf.mountID, filename), err
}

// RemoveInode - Removes a pathname from the kernel cache using the provided mount id and inode
func (pfr *PathFragmentsResolver) RemoveInode(key PathFragmentsKey) error {
	return pfr.cache.Delete(key.GetKeyBytes())
}

func (pfr *PathFragmentsResolver) resolveWithMount(mountID uint32, path string) string {
	if mount, ok := pfr.mounts[int(mountID)]; ok {
		return filepath.Join(mount.MountPoint, path)
	}
	return path
}

// IsFakeInode returns whether the given inode is a fake inode
func IsFakeInode(inode uint64) bool {
	return inode>>32 == uint64(fakeInodeMSW)
}

const fakeInodeMSW = 0xdeadc001
