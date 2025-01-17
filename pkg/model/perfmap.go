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

type LostEvt struct {
	Count uint64
	Map   string
}

// PerfMap - Definition of a perf map, used to bring data back to user space
type PerfMap struct {
	UserSpaceBufferLen int
	PerfOutputMapName  string
	DataHandler        DataHandler
	LostHandler        func(count uint64, mapName string, m *Monitor)

	perfMapInternal
}
