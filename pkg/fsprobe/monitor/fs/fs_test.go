package fs

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Gui774ume/fsprobe/pkg/utils"
)

func TestResolvesPaths(t *testing.T) {
	var rootMount = utils.MountInfo{
		MountID:    1,
		MountPoint: "/",
	}
	var testCases = []struct {
		comment  string
		mounts   []utils.MountInfo
		paths    []string
		expected []resolvedPath
	}{
		{
			comment: "selects the most specific mount point",
			mounts: []utils.MountInfo{
				{
					MountID:    1,
					MountPoint: "/path/to/dir",
				},
				{
					MountID:    2,
					MountPoint: "/path/to/dir/subdir",
				},
				{
					MountID:    3,
					MountPoint: "/path/to/dir/subdir/dir2",
				},
				{
					MountID:    4,
					MountPoint: "/path/to/dir/subdir2/dir",
				},
			},
			paths: []string{"/path/to/dir/subdir/dir2/file"},
			expected: []resolvedPath{
				{
					path: "/path/to/dir/subdir/dir2/file",
					mi: utils.MountInfo{
						MountID:    3,
						MountPoint: "/path/to/dir/subdir/dir2",
					},
				},
			},
		},
		{
			comment: "adds an entry without mountpoint if no match found",
			mounts: []utils.MountInfo{
				rootMount,
				{
					MountID:    2,
					MountPoint: "/path/to/dir",
				},
			},
			paths: []string{"/path/to/dir2", "/path/to/file2"},
			expected: []resolvedPath{
				{
					mi:   rootMount,
					path: "/path/to/dir2",
				},
				{
					mi:   rootMount,
					path: "/path/to/file2",
				},
			},
		},
		{
			comment: "correctly matches on boundary",
			mounts: []utils.MountInfo{
				rootMount,
				{
					MountID:    2,
					MountPoint: "/path/to/dir",
				},
			},
			paths: []string{"/path/to/dir", "/path/to/dir2"},
			expected: []resolvedPath{
				{
					mi:   rootMount,
					path: "/path/to/dir2",
				},
				{
					mi: utils.MountInfo{
						MountID:    2,
						MountPoint: "/path/to/dir",
					},
					path: "/path/to/dir",
				},
			},
		},
		{
			comment: "skips the root mount",
			mounts: []utils.MountInfo{
				rootMount,
			},
			paths: []string{"/path/to/dir"},
			expected: []resolvedPath{
				{
					mi:   rootMount,
					path: "/path/to/dir",
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.comment, func(t *testing.T) {
			paths := resolveMounts(tc.paths, asMap(tc.mounts))
			require.ElementsMatch(t, tc.expected, paths)
		})
	}
}

func TestCanMatchFromResolvedPaths(t *testing.T) {
	var rootMount = utils.MountInfo{
		MountID:    1,
		MountPoint: "/",
	}
	var mount = utils.MountInfo{
		MountID:    2,
		MountPoint: "/mount/point",
	}
	paths := []resolvedPath{
		{
			mi:   rootMount,
			path: "/path/to/watch",
		},
		{
			mi:   mount,
			path: "/mount/point/another/path/to/watch",
		},
	}
	type match struct {
		mountID int
		path    string
	}
	var testCases = []struct {
		comment  string
		input    []match
		expected []match
	}{
		{
			comment: "file in the boundary directory",
			input: []match{
				{
					mountID: rootMount.MountID,
					path:    "/path/to/file",
				},
			},
			expected: []match{
				{
					mountID: rootMount.MountID,
					path:    "/path/to/file",
				},
			},
		},
		{
			comment: "exact match",
			input: []match{
				{
					mountID: rootMount.MountID,
					path:    "/path/to/watch",
				},
			},
			expected: []match{
				{
					mountID: rootMount.MountID,
					path:    "/path/to/watch",
				},
			},
		},
		{
			comment: "file in the boundary directory with a mountpoint",
			input: []match{
				{
					mountID: mount.MountID,
					path:    "/mount/point/another/path/to/file",
				},
			},
			expected: []match{
				{
					mountID: mount.MountID,
					path:    "/mount/point/another/path/to/file",
				},
			},
		},
		{
			comment: "file in the descendant directory",
			input: []match{
				{
					mountID: mount.MountID,
					path:    "/mount/point/another/path/to/dir/file",
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.comment, func(t *testing.T) {
			var matches []match
			for _, input := range tc.input {
				for _, p := range paths {
					if p.matches(input.mountID, input.path) {
						matches = append(matches, match{path: input.path, mountID: mount.MountID})
					}
				}
			}
			require.Equal(t, tc.expected, matches)
		})
	}
}

func asMap(mounts []utils.MountInfo) (result map[int]utils.MountInfo) {
	result = make(map[int]utils.MountInfo, len(mounts))
	for _, m := range mounts {
		result[m.MountID] = m
	}
	return result
}
