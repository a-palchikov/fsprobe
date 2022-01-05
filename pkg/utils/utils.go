/*
Copyright © 2020 GUILLAUME FOURNIER
Copyright 2017 The Kubernetes Authors.

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
package utils

import (
	"C"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pkg/errors"
)

// GetPpid is a fallback to read the parent PID from /proc.
// Some kernel versions, like 4.13.0 return 0 getting the parent PID
// from the current task, so we need to use this fallback to have
// the parent PID in any kernel.
func GetPpid(pid uint32) uint32 {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/status", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		text := sc.Text()
		if strings.Contains(text, "PPid:") {
			f := strings.Fields(text)
			i, _ := strconv.ParseUint(f[len(f)-1], 10, 64)
			return uint32(i)
		}
	}
	return 0
}

// getNamespaceID - Returns the namespace id in brackets
func getNamespaceID(raw string) uint64 {
	i := strings.Index(raw, "[")
	if i > 0 {
		id, err := strconv.ParseUint(raw[i+1:len(raw)-1], 10, 64)
		if err != nil {
			return 0
		}
		return id
	}
	return 0
}

// GetPidnsFromPid - Returns the pid namespace of a process
func GetPidnsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/pid_for_children", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetNetnsFromPid - Returns the network namespace of a process
func GetNetnsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/net", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetUsernsFromPid - Returns the user namespace of a process
func GetUsernsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/user", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetMntnsFromPid - Returns the mount namespace of a process
func GetMntnsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/mnt", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetCgroupFromPid - Returns the cgroup of a process
func GetCgroupFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/cgroup", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetCommFromPid - Returns the comm of a process
func GetCommFromPid(pid uint32) string {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/comm", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return ""
	}
	defer f.Close()
	raw, err := ioutil.ReadAll(f)
	if err != nil {
		return ""
	}
	return strings.Replace(string(raw), "\n", "", -1)
}

// InterfaceToBytes - Tranforms an interface into a C bytes array
func InterfaceToBytes(data interface{}, byteOrder binary.ByteOrder) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, byteOrder, data); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

// GetHostByteOrder - Returns the host byte order
func GetHostByteOrder() binary.ByteOrder {
	if isBigEndian() {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}

func getHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// ByteOrder - host byte order
var ByteOrder binary.ByteOrder

func init() {
	ByteOrder = getHostByteOrder()
}

// String - No copy bytes to string conversion
func String(bytes []byte) string {
	hdr := *(*reflect.SliceHeader)(unsafe.Pointer(&bytes))
	return *(*string)(unsafe.Pointer(&reflect.StringHeader{
		Data: hdr.Data,
		Len:  hdr.Len,
	}))
}

// Bytes - No copy string to bytes conversion
func Bytes(str string) []byte {
	hdr := *(*reflect.StringHeader)(unsafe.Pointer(&str))
	return *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: hdr.Data,
		Len:  hdr.Len,
		Cap:  hdr.Len,
	}))
}

// DebugReport outputs the given error to the specifie writer.
// If the error supports stack trace capture, the output will
// include the stack trace
func DebugReport(w io.Writer, err error) {
	type stackTracer interface {
		StackTrace() errors.StackTrace
	}
	fmt.Fprintln(w, err.Error())
	if err, ok := err.(stackTracer); ok {
		for _, f := range err.StackTrace() {
			fmt.Fprintf(w, "%+s:%d\n", f, f)
		}
	}
}

// listProcSelfMountinfo (Available since Linux 2.6.26) lists information about mount points
// in the process's mount namespace. Ref: http://man7.org/linux/man-pages/man5/proc.5.html
// for /proc/[pid]/mountinfo
func listProcSelfMountinfo(mountFilePath string) ([]MountInfo, error) {
	content, err := ConsistentRead(mountFilePath, maxListTries)
	if err != nil {
		return nil, err
	}
	return parseProcSelfMountinfo(content)
}

// ReadProcSelfMountinfo lists information about mount points
// in the process's mount namespace.
// Ref: http://man7.org/linux/man-pages/man5/proc.5.html
// for /proc/[pid]/mountinfo
func ReadProcSelfMountinfo() ([]MountInfo, error) {
	content, err := ConsistentRead(procSelfMountinfoPath, maxListTries)
	if err != nil {
		return nil, err
	}
	return parseProcSelfMountinfo(content)
}

// ReadProcSelfMountinfoFromReader lists information about mount points
// in the process's mount namespace.
// Ref: http://man7.org/linux/man-pages/man5/proc.5.html
// for /proc/[pid]/mountinfo
func ReadProcSelfMountinfoFromReader(r io.Reader) ([]MountInfo, error) {
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseProcSelfMountinfo(content)
}

// MountInfo represents a single line in /proc/self/mountinfo.
type MountInfo struct {
	MountID      int
	ParentID     int
	DeviceID     string
	Root         string
	MountPoint   string
	MountOptions []string
	FsType       string
	MountSource  string
	SuperOptions []string
}

// ConsistentRead repeatedly reads a file until it gets the same content twice.
// This is useful when reading files in /proc that are larger than page size
// and kernel may modify them between individual read() syscalls.
func ConsistentRead(filename string, attempts int) ([]byte, error) {
	oldContent, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	for i := 0; i < attempts; i++ {
		newContent, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(oldContent, newContent) {
			return newContent, nil
		}
		// Files are different, continue reading
		oldContent = newContent
	}
	return nil, fmt.Errorf("could not get consistent content of %s after %d attempts", filename, attempts)
}

// parseProcSelfMountinfo parses the output of /proc/self/mountinfo file into a slice of MountInfo struct
func parseProcSelfMountinfo(content []byte) ([]MountInfo, error) {
	out := make([]MountInfo, 0)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if line == "" {
			// The last split() item is empty string following the last \n
			continue
		}
		fields := strings.Fields(line)
		numFields := len(fields)
		if numFields < minNumProcSelfMntInfoFieldsPerLine {
			return nil, fmt.Errorf("wrong number of fields (expected at least %d, got %d): %s",
				minNumProcSelfMntInfoFieldsPerLine, numFields, line)
		}

		// separator must be in the 4th position from the end for the line to contain fsType, mountSource, and
		//  superOptions
		if fields[numFields-4] != "-" {
			return nil, fmt.Errorf("malformed mountinfo (could not find separator): %s", line)
		}

		// If root value is marked deleted, skip the entry
		if strings.Contains(fields[3], "deleted") {
			continue
		}

		mp := MountInfo{
			DeviceID:     fields[2],
			Root:         fields[3],
			MountPoint:   fields[4],
			MountOptions: strings.Split(fields[5], ","),
		}

		mountId, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, err
		}
		mp.MountID = mountId

		parentId, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, err
		}
		mp.ParentID = parentId

		mp.FsType = fields[numFields-3]
		mp.MountSource = fields[numFields-2]
		mp.SuperOptions = strings.Split(fields[numFields-1], ",")

		out = append(out, mp)
	}
	return out, nil
}

const (
	// How many times to retry for a consistent read of /proc/mounts.
	maxListTries = 3
	// Minimum number of fields per line in /proc/self/mountinfo as per the proc man page.
	minNumProcSelfMntInfoFieldsPerLine = 10
	// Location of the mount file to use
	procSelfMountinfoPath = "/proc/self/mountinfo"
)
