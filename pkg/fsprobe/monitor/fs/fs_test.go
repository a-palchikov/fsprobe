package fs

import (
	"testing"

	"github.com/c9s/goprocinfo/linux"
	"github.com/stretchr/testify/require"
)

func TestResolvesPaths(t *testing.T) {
	var testCases = []struct {
		comment  string
		mounts   []linux.Mount
		paths    []string
		expected []resolvedPath
	}{
		{
			comment: "selects the most specific mount point",
			mounts: []linux.Mount{
				{
					Device:     "/dev/dev1",
					MountPoint: "/path/to/dir",
				},
				{
					Device:     "/dev/dev2",
					MountPoint: "/path/to/dir/subdir",
				},
				{
					Device:     "/dev/dev3",
					MountPoint: "/path/to/dir/subdir/dir2",
				},
				{
					Device:     "/dev/dev4",
					MountPoint: "/path/to/dir/subdir2/dir",
				},
			},
			paths: []string{"/path/to/dir/subdir/dir2/file"},
			expected: []resolvedPath{
				{
					path:       "/path/to/dir/subdir/dir2/file",
					mountPoint: "/path/to/dir/subdir/dir2",
				},
			},
		},
		{
			comment: "adds an entry without mountpoint if no match found",
			mounts: []linux.Mount{
				{
					Device:     "/dev/dev1",
					MountPoint: "/path/to/dir",
				},
			},
			paths: []string{"/path/to/dir2", "/path/to/file2"},
			expected: []resolvedPath{
				{
					path: "/path/to/dir2",
				},
				{
					path: "/path/to/file2",
				},
			},
		},
		{
			comment: "correctly matches on boundary",
			mounts: []linux.Mount{
				{
					Device:     "/dev/dev1",
					MountPoint: "/path/to/dir",
				},
			},
			paths: []string{"/path/to/dir", "/path/to/dir2"},
			expected: []resolvedPath{
				{
					path: "/path/to/dir2",
				},
				{
					mountPoint: "/path/to/dir",
					path:       "/path/to/dir",
				},
			},
		},
		{
			comment: "skips the root mount",
			mounts: []linux.Mount{
				{
					Device:     "/dev/dev1",
					MountPoint: "/",
				},
			},
			paths: []string{"/path/to/dir"},
			expected: []resolvedPath{
				{
					path: "/path/to/dir",
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.comment, func(t *testing.T) {
			paths := resolveMounts(tc.paths, tc.mounts)
			require.Equal(t, tc.expected, paths)
		})
	}
}

func TestCanMatchFromResolvedPaths(t *testing.T) {
	paths := []resolvedPath{
		{path: "/path/to/watch"},
		{mountPoint: "/mount/point", path: "/mount/point/another/path/to/watch"},
	}
	var testCases = []struct {
		comment string
		input   []string
		matches []string
	}{
		{
			comment: "file in the boundary directory",
			input:   []string{"/path/to/file"},
			matches: []string{"/path/to/file"},
		},
		{
			comment: "exact match",
			input:   []string{"/path/to/watch"},
			matches: []string{"/path/to/watch"},
		},
		{
			comment: "file in the boundary directory with a mountpoint",
			input:   []string{"/another/path/to/file"},
			matches: []string{"/another/path/to/file"},
		},
		{
			comment: "file in the boundary directory with a mountpoint",
			input:   []string{"/another/path/to/dir/file"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.comment, func(t *testing.T) {
			var matches []string
			for _, input := range tc.input {
				for _, p := range paths {
					if p.matches(input) {
						matches = append(matches, input)
					}
				}
			}
			require.Equal(t, tc.matches, matches)
		})
	}
}
