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
#ifndef _CONST_H_
#define _CONST_H_

#include "defs.h"

// load_inode_filtering_mode - Loads the inode filtering mode
__attribute__((always_inline)) static u64 load_inode_filtering_mode() {
    u64 inode_filtering_mode = 0;
    LOAD_CONSTANT("inode_filtering_mode", inode_filtering_mode);
    return inode_filtering_mode;
}

// load_follow_mode - Loads the follow mode
__attribute__((always_inline)) static u64 load_follow_mode() {
    u64 follow_mode = 0;
    LOAD_CONSTANT("follow_mode", follow_mode);
    return follow_mode;
}

#endif
