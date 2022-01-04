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

import "github.com/Gui774ume/fsprobe/pkg/utils"

// FSProbeOptions - Filesystem probe options
type FSProbeOptions struct {
	Recursive bool
	// Paths optionally specifies a list of path filters that will further
	// restrict the way the wathes are added. For each path filter, only
	// top-level watches along the filter are added.
	// If a filter specifies a file, in the file's directory only the file
	// will be watched (along with all files in all preceeding sub-directories).
	// Filter can specify a path that does not yet exist.
	Paths                []string
	Events               []EventName
	PerfBufferSize       int
	UserSpaceChanSize    int
	DentryResolutionMode DentryResolutionMode
	PathsFiltering       bool
	FollowRenames        bool
	EventChan            chan *FSEvent
	LostChan             chan *LostEvt

	DataHandler DataHandler
	Mounts      map[int]utils.MountInfo
}

type DataHandler interface {
	Handle(m *Monitor, evt *FSEvent)
}
