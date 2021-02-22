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

#include <introvirt/windows/kernel/nt/syscall/fwd.hh>

#include <cstdint>

namespace introvirt {
namespace windows {

/**
 * @brief Classes related to the Windows NT kernel
 *
 * Namespace for parsing Windows NT Kernel structures
 */
namespace nt {

class ACCESS_MASK;
class CLIENT_ID;
class CM_KEY_BODY;
class CM_KEY_CONTROL_BLOCK;
class CM_KEY_NODE;
class CM_KEY_VALUE;
class CONTROL_AREA;
class DBGKD_GET_VERSION64;
class DEVICE_OBJECT;
class DISPATCHER_HEADER;
class DRIVER_OBJECT;
class FILE_OBJECT;
class HANDLE_TABLE_ENTRY;
class HANDLE_TABLE;
class HBASE_BLOCK;
class HIVE;
class KDDEBUGGER_DATA64;
class KEVENT;
class KEY_VALUE_DWORD;
class KEY_VALUE_EXPAND_STRING;
class KEY_VALUE_MULTI_STRING;
class KEY_VALUE_QWORD;
class KEY_VALUE_STRING;
class KEY_VALUE;
class KPCR;
class LDR_DATA_TABLE_ENTRY;
class MM_SESSION_SPACE;
class MMVAD;
class NT_TIB;
class NtBuildLab;
class NtKernel;
class OBJECT_DIRECTORY;
class OBJECT_HEADER_CREATOR_INFO;
class OBJECT_HEADER_HANDLE_INFO;
class OBJECT_HEADER_NAME_INFO;
class OBJECT_HEADER_PROCESS_INFO;
class OBJECT_HEADER_QUOTA_INFO;
class OBJECT_HEADER;
class OBJECT_SYMBOLIC_LINK;
class OBJECT_TYPE;
class OBJECT;
class PEB_LDR_DATA;
class PEB;
class PROCESS;
class RTL_USER_PROCESS_PARAMETERS;
class SECTION;
class SEGMENT;
class SID_AND_ATTRIBUTES;
class SID;
class TEB;
class THREAD;
class TOKEN;
class TypeTable;
class UNICODE_STRING;

enum class ObjectType : int;
enum class LPC_TYPE : int16_t;

} // namespace nt
} // namespace windows
} // namespace introvirt