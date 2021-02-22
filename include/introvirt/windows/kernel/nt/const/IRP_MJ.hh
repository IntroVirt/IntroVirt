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

#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

enum IRP_MJ {
    IRP_MJ_CREATE = 0x00,
    IRP_MJ_CREATE_NAMED_PIPE = 0x01,
    IRP_MJ_CLOSE = 0x02,
    IRP_MJ_READ = 0x03,
    IRP_MJ_WRITE = 0x04,
    IRP_MJ_QUERY_INFORMATION = 0x05,
    IRP_MJ_SET_INFORMATION = 0x06,
    IRP_MJ_QUERY_EA = 0x07,
    IRP_MJ_SET_EA = 0x08,
    IRP_MJ_FLUSH_BUFFERS = 0x09,
    IRP_MJ_QUERY_VOLUME_INFORMATION = 0x0a,
    IRP_MJ_SET_VOLUME_INFORMATION = 0x0b,
    IRP_MJ_DIRECTORY_CONTROL = 0x0c,
    IRP_MJ_FILE_SYSTEM_CONTROL = 0x0d,
    IRP_MJ_DEVICE_CONTROL = 0x0e,
    IRP_MJ_INTERNAL_DEVICE_CONTROL = 0x0f,
    IRP_MJ_SCSI = 0x0f,
    IRP_MJ_SHUTDOWN = 0x10,
    IRP_MJ_LOCK_CONTROL = 0x11,
    IRP_MJ_CLEANUP = 0x12,
    IRP_MJ_CREATE_MAILSLOT = 0x13,
    IRP_MJ_QUERY_SECURITY = 0x14,
    IRP_MJ_SET_SECURITY = 0x15,
    IRP_MJ_POWER = 0x16,
    IRP_MJ_SYSTEM_CONTROL = 0x17,
    IRP_MJ_DEVICE_CHANGE = 0x18,
    IRP_MJ_QUERY_QUOTA = 0x19,
    IRP_MJ_SET_QUOTA = 0x1a,
    IRP_MJ_PNP = 0x1b,
    IRP_MJ_PNP_POWER = 0x1b,
    IRP_MJ_MAX = IRP_MJ_PNP_POWER,
    IRP_MJ_UNKNOWN = 0xFFFFFFFF,
};

} // namespace nt
} // namespace windows
} // namespace introvirt