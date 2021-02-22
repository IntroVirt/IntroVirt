/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include "const/const.hh"
#include "syscall/syscall.hh"
#include "util/util.hh"

#include "NtBuildLab.hh"
#include "NtKernel.hh"
#include "const/DeviceType.hh"
#include "const/KTHREAD_STATE.hh"
#include "const/MEMORY_ALLOCATION_TYPE.hh"
#include "const/ObjectType.hh"
#include "const/PAGE_PROTECTION.hh"
#include "const/REG_TYPE.hh"
#include "types/CLIENT_ID.hh"
#include "types/CONTROL_AREA.hh"
#include "types/DBGKD_GET_VERSION64.hh"
#include "types/HANDLE_TABLE.hh"
#include "types/HANDLE_TABLE_ENTRY.hh"
#include "types/KDDEBUGGER_DATA64.hh"
#include "types/KPCR.hh"
#include "types/LDR_DATA_TABLE_ENTRY.hh"
#include "types/MMVAD.hh"
#include "types/MM_SESSION_SPACE.hh"
#include "types/NT_TIB.hh"
#include "types/PEB.hh"
#include "types/PEB_LDR_DATA.hh"
#include "types/RTL_USER_PROCESS_PARAMETERS.hh"
#include "types/SEGMENT.hh"
#include "types/SID.hh"
#include "types/SID_AND_ATTRIBUTES.hh"
#include "types/TEB.hh"
#include "types/UNICODE_STRING.hh"
#include "types/access_mask/ACCESS_MASK.hh"
#include "types/access_mask/DIR_ACCESS_MASK.hh"
#include "types/access_mask/EVENT_ACCESS_MASK.hh"
#include "types/access_mask/FILE_ACCESS_MASK.hh"
#include "types/access_mask/KEY_ACCESS_MASK.hh"
#include "types/access_mask/MUTANT_ACCESS_MASK.hh"
#include "types/access_mask/PROCESS_ACCESS_MASK.hh"
#include "types/access_mask/SECTION_ACCESS_MASK.hh"
#include "types/access_mask/THREAD_ACCESS_MASK.hh"
#include "types/access_mask/TOKEN_ACCESS_MASK.hh"
#include "types/objects/CM_KEY_BODY.hh"
#include "types/objects/DEVICE_OBJECT.hh"
#include "types/objects/DISPATCHER_HEADER.hh"
#include "types/objects/DISPATCHER_OBJECT.hh"
#include "types/objects/DRIVER_OBJECT.hh"
#include "types/objects/FILE_OBJECT.hh"
#include "types/objects/KEVENT.hh"
#include "types/objects/OBJECT.hh"
#include "types/objects/OBJECT_DIRECTORY.hh"
#include "types/objects/OBJECT_HEADER.hh"
#include "types/objects/OBJECT_HEADER_CREATOR_INFO.hh"
#include "types/objects/OBJECT_HEADER_HANDLE_INFO.hh"
#include "types/objects/OBJECT_HEADER_NAME_INFO.hh"
#include "types/objects/OBJECT_HEADER_PROCESS_INFO.hh"
#include "types/objects/OBJECT_HEADER_QUOTA_INFO.hh"
#include "types/objects/OBJECT_SYMBOLIC_LINK.hh"
#include "types/objects/OBJECT_TYPE.hh"
#include "types/objects/PROCESS.hh"
#include "types/objects/SECTION.hh"
#include "types/objects/THREAD.hh"
#include "types/objects/TOKEN.hh"
#include "types/registry/CM_KEY_CONTROL_BLOCK.hh"
#include "types/registry/CM_KEY_NODE.hh"
#include "types/registry/CM_KEY_VALUE.hh"
#include "types/registry/HBASE_BLOCK.hh"
#include "types/registry/HIVE.hh"
#include "types/registry/KEY_VALUE.hh"
#include "types/registry/KEY_VALUE_DWORD.hh"
#include "types/registry/KEY_VALUE_EXPAND_STRING.hh"
#include "types/registry/KEY_VALUE_MULTI_STRING.hh"
#include "types/registry/KEY_VALUE_QWORD.hh"
#include "types/registry/KEY_VALUE_STRING.hh"
