//go:build linux

package model

import (
	"io/ioutil"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func NewProcessResolver() *ProcessResolver {
	return &ProcessResolver{
		processResolver: processResolver{
			entryCache:            make(map[uint32]*processCacheEntry),
			processCacheEntryPool: newProcessCacheEntryPool(),
		},
	}
}

// Resolve returns the cached entry for the given pid/tid tuple
func (r *ProcessResolver) Resolve(pid, tid uint32) *processCacheEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	logger := zap.L().With(zap.Uint32("pid", pid), zap.Uint32("tid", tid))
	logger.Debug("Resolve process info.")
	if entry := r.resolveFromCache(pid, tid); entry != nil {
		logger.Debug("Resolved process info from cache.")
		return entry
	}
	if entry := r.resolveWithProcfs(int(pid), procResolveMaxDepth); entry != nil {
		logger.Debug("Resolved process info from /proc.")
		return entry
	}
	logger.Debug("Unable to resolve process info.")
	return nil
}

func (r *ProcessResolver) resolveFromCache(pid, tid uint32) *processCacheEntry {
	entry, exists := r.entryCache[pid]
	if !exists {
		return nil
	}

	// make sure to update the tid with the one that triggers the resolution
	entry.Tid = tid

	return entry
}

func (r *ProcessResolver) resolveWithProcfs(pid int, maxDepth int) *processCacheEntry {
	if maxDepth < 1 || pid == 0 {
		return nil
	}

	logger := zap.L().With(zap.Int("pid", pid))
	p := filledProcess{pid: int32(pid)}
	err := p.fillFromStat()
	if err != nil {
		logger.Debug("Failed to resolve process from /proc.", zap.Error(err))
		return nil
	}
	err = p.fillFromStatus()
	if err != nil {
		logger.Debug("Failed to resolve process status from /proc.", zap.Error(err))
		return nil
	}
	err = p.fillFromCmdline()
	if err != nil {
		logger.Debug("Failed to resolve process cmdline from /proc.", zap.Error(err))
		return nil
	}
	// Get process filename and pre-fill the cache
	err = p.fillProcessPath()
	if err != nil {
		logger.Debug("Snapshot failed for process.",  zap.Error(err))
	}

	proc := Process{
		Pid:  uint32(p.pid),
		PPid: uint32(p.ppid),
		// TODO(dima): use the other types of uids/gids
		Uid:      uint32(p.uids[0]),
		Gid:      uint32(p.gids[0]),
		Comm:     p.name,
		Cmdline:  p.cmdline,
		Pathname: p.pathname,
	}

	parent := r.resolveWithProcfs(int(proc.PPid), maxDepth-1)
	entry, inserted := r.syncCache(proc)
	if inserted && entry != nil && parent != nil {
		entry.SetAncestor(parent)
	}

	return entry
}

func (r *ProcessResolver) syncCache(proc Process) (entry *processCacheEntry, inserted bool) {
	pid := uint32(proc.Pid)

	// Check if an entry is already in cache for the given pid.
	entry = r.entryCache[pid]
	if entry != nil {
		return nil, false
	}

	entry = r.newProcessCacheEntry()
	entry.ProcessContext.Process = proc

	parent := r.entryCache[entry.PPid]
	if parent != nil {
		entry.SetAncestor(parent)
	}

	if entry = r.insertEntry(pid, entry, r.entryCache[pid]); entry == nil {
		return nil, false
	}

	return entry, true
}

//// enrichEventFromProc uses /proc to enrich a ProcessCacheEntry with additional metadata
//func (r *ProcessResolver) enrichEventFromProc(entry *processCacheEntry, proc *Process) error {
//	filledProc := getFilledProcess(proc)
//	if filledProc == nil {
//		return errors.Errorf("snapshot failed for %d: binary was deleted", proc.Pid)
//	}
//
//	pid := uint32(proc.Pid)
//
//	// Get process filename and pre-fill the cache
//	procExecPath := procExePath(proc.Pid)
//	pathnameStr, err := os.Readlink(procExecPath)
//	if err != nil {
//		return errors.Wrapf(err, "snapshot failed for %d: couldn't readlink binary", proc.Pid)
//	}
//	if pathnameStr == "/ (deleted)" {
//		return errors.Errorf("snapshot failed for %d: binary was deleted", proc.Pid)
//	}
//
//	entry.Process.Pathname = pathnameStr
//	entry.Process.Basename = path.Base(pathnameStr)
//
//	entry.Comm = filledProc.Name
//	entry.PPid = uint32(filledProc.Ppid)
//	entry.ProcessContext.Pid = pid
//	entry.ProcessContext.Tid = pid
//
//	//if len(filledProc.Cmdline) > 0 {
//	//	entry.ArgsEntry = &model.ArgsEntry{
//	//		Values: filledProc.Cmdline[1:],
//	//	}
//	//}
//	//if envs, err := utils.EnvVars(proc.Pid); err == nil {
//	//	entry.EnvsEntry = &model.EnvsEntry{
//	//		Values: envs,
//	//	}
//	//}
//
//	return nil
//}

func (r *ProcessResolver) insertEntry(pid uint32, entry, prev *processCacheEntry) *processCacheEntry {
	r.entryCache[pid] = entry
	entry.Retain()

	if prev != nil {
		prev.Release()
	}

	return entry
}

//func (r *ProcessResolver) deleteEntry(pid uint32, exitTime time.Time) {
//	// Start by updating the exit timestamp of the pid cache entry
//	entry, ok := r.entryCache[pid]
//	if !ok {
//		return
//	}
//	//entry.Exit(exitTime)
//
//	delete(r.entryCache, entry.Pid)
//	entry.Release()
//}

func (r *ProcessResolver) newProcessCacheEntry() *processCacheEntry {
	return r.processCacheEntryPool.Get()
}

// processCacheEntryPool defines a pool for process entry allocations
type processCacheEntryPool struct {
	pool *sync.Pool
}

// Get returns a cache entry
func (r *processCacheEntryPool) Get() *processCacheEntry {
	return r.pool.Get().(*processCacheEntry)
}

// Put returns a cache entry
func (r *processCacheEntryPool) Put(entry *processCacheEntry) {
	entry.Reset()
	r.pool.Put(entry)
}

// newProcessCacheEntryPool returns a new ProcessCacheEntryPool pool
func newProcessCacheEntryPool() *processCacheEntryPool {
	pool := processCacheEntryPool{pool: &sync.Pool{}}
	pool.pool.New = func() interface{} {
		return newProcessCacheEntry(func(entry *processCacheEntry) {
			if entry.Ancestor != nil {
				entry.Ancestor.Release()
			}

			pool.Put(entry)
		})
	}
	return &pool
}

type ProcessContext struct {
	Process

	Ancestor *processCacheEntry
}

func (r Process) String() string {
	var b strings.Builder
	fmt.Fprint(&b, "(", r.Pid, "/", r.PPid, ",", r.Uid, "/", r.Gid,
		",", r.Cmdline, ")")
	return b.String()
}

type Process struct {
	Pid      uint32 // Process ID of the process (also called thread group ID)
	Tid      uint32 // Thread ID of the thread
	PPid     uint32 // Parent process ID
	Uid, Gid uint32
	Comm     string // Comm attribute of the process
	Pathname string // Process binary path
	Cmdline  string // Complete process command line
}

type processResolver struct {
	mu         sync.RWMutex
	entryCache map[uint32]*processCacheEntry

	processCacheEntryPool *processCacheEntryPool
}

type processCacheEntry struct {
	ProcessContext

	refCount  uint64
	onRelease func(_ *processCacheEntry)
}

// Reset the entry
func (r *processCacheEntry) Reset() {
	r.ProcessContext = ProcessContext{}
	r.refCount = 0
}

// SetAncestor set the ancestor
func (r *processCacheEntry) SetAncestor(parent *processCacheEntry) {
	r.Ancestor = parent
	parent.Retain()
}

// Retain increments ref counter
func (r *processCacheEntry) Retain() {
	r.refCount++
}

// Release decrements and eventually releases the entry
func (r *processCacheEntry) Release() {
	r.refCount--
	if r.refCount > 0 {
		return
	}

	if r.onRelease != nil {
		r.onRelease(r)
	}
}

// newProcessCacheEntry returns a new process cache entry
func newProcessCacheEntry(onRelease func(_ *processCacheEntry)) *processCacheEntry {
	return &processCacheEntry{
		onRelease: onRelease,
	}
}

const procResolveMaxDepth = 16

func (r *filledProcess) fillFromCmdline() error {
	pid := int(r.pid)
	cmdPath := hostProc(pid, "cmdline")
	cmdline, err := ioutil.ReadFile(cmdPath)
	if err != nil {
		return err
	}
	ret := strings.FieldsFunc(string(cmdline), func(r rune) bool {
		if r == '\u0000' {
			return true
		}
		return false
	})
	r.cmdline = strings.Join(ret, " ")
	return nil
}

// Adapted from https://github.com/DataDog/gopsutil/blob/18d4412b24f0a0d7218cbbfdf4242231eccfb295/process/process_linux.go#L863
func (r *filledProcess) fillFromStat() error {
	pid := int(r.pid)
	statPath := hostProc(pid, "stat")
	contents, err := ioutil.ReadFile(statPath)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(contents))

	i := 1
	for !strings.HasSuffix(fields[i], ")") {
		i++
	}

	ppid, err := strconv.ParseInt(fields[i+2], 10, 32)
	if err != nil {
		return err
	}
	r.ppid = int32(ppid)
	return nil
}

func (r *filledProcess) fillFromStatus() error {
	pid := int(r.pid)
	statPath := hostProc(pid, "status")
	contents, err := ioutil.ReadFile(statPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		tabParts := strings.SplitN(line, "\t", 2)
		if len(tabParts) < 2 {
			continue
		}
		value := tabParts[1]
		switch strings.TrimRight(tabParts[0], ":") {
		case "Name":
			r.name = strings.Trim(value, " \t")
		case "PPid", "Ppid":
			pval, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return err
			}
			r.ppid = int32(pval)
		case "Uid":
			for i, v := range strings.SplitN(value, "\t", 4) {
				n, err := strconv.ParseInt(v, 10, 32)
				if err != nil {
					return err
				}
				r.uids[i] = int32(n)
			}
		case "Gid":
			for i, v := range strings.SplitN(value, "\t", 4) {
				n, err := strconv.ParseInt(v, 10, 32)
				if err != nil {
					return err
				}
				r.gids[i] = int32(n)
			}
		}
	}
	return nil
}

func (r *filledProcess) fillProcessPath() (err error) {
	r.pathname, err = os.Readlink(procExePath(int(r.pid)))
	if err != nil {
		return errors.Wrap(err, "failed to readlink binary")
	}
	if r.pathname == "/ (deleted)" {
		return errBinaryDeleted
	}
	return nil
}

var errBinaryDeleted = errors.New("binary deleted")

type filledProcess struct {
	pid, ppid int32
	// Real, effective, saved set and file system uids (gids)
	// See https://man7.org/linux/man-pages/man5/proc.5.html
	uids, gids [4]int32
	cmdline    string
	name       string
	pathname   string
}

// procExePath returns the path to the exe file of a pid in /proc
func procExePath(pid int) string {
	return hostProc(pid, "exe")
}

func hostProc(pid int, elems ...string) string {
	args := []string{"/proc"}
	args = append(args, strconv.Itoa(pid))
	return path.Join(append(args, elems...)...)
}
