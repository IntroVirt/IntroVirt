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
#include <introvirt/windows/kernel/nt/types/access_mask/PROCESS_ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(ProcessAccessMaskFlag flag) {
    static const std::string PROCESS_TERMINATE_STR("PROCESS_TERMINATE");
    static const std::string PROCESS_CREATE_THREAD_STR("PROCESS_CREATE_THREAD");
    static const std::string PROCESS_VM_OPERATION_STR("PROCESS_VM_OPERATION");
    static const std::string PROCESS_VM_READ_STR("PROCESS_VM_READ");
    static const std::string PROCESS_VM_WRITE_STR("PROCESS_VM_WRITE");
    static const std::string PROCESS_DUP_HANDLE_STR("PROCESS_DUP_HANDLE");
    static const std::string PROCESS_CREATE_PROCESS_STR("PROCESS_CREATE_PROCESS");
    static const std::string PROCESS_SET_QUOTA_STR("PROCESS_SET_QUOTA");
    static const std::string PROCESS_SET_INFORMATION_STR("PROCESS_SET_INFORMATION");
    static const std::string PROCESS_QUERY_INFORMATION_STR("PROCESS_QUERY_INFORMATION");
    static const std::string PROCESS_SUSPEND_RESUME_STR("PROCESS_SUSPEND_RESUME");
    static const std::string PROCESS_QUERY_LIMITED_INFORMATION_STR(
        "PROCESS_QUERY_LIMITED_INFORMATION");
    static const std::string PROCESS_ALL_ACCESS_STR("PROCESS_ALL_ACCESS");
    const static std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case ProcessAccessMaskFlag::PROCESS_TERMINATE:
        return PROCESS_TERMINATE_STR;
    case ProcessAccessMaskFlag::PROCESS_CREATE_THREAD:
        return PROCESS_CREATE_THREAD_STR;
    case ProcessAccessMaskFlag::PROCESS_VM_OPERATION:
        return PROCESS_VM_OPERATION_STR;
    case ProcessAccessMaskFlag::PROCESS_VM_READ:
        return PROCESS_VM_READ_STR;
    case ProcessAccessMaskFlag::PROCESS_VM_WRITE:
        return PROCESS_VM_WRITE_STR;
    case ProcessAccessMaskFlag::PROCESS_DUP_HANDLE:
        return PROCESS_DUP_HANDLE_STR;
    case ProcessAccessMaskFlag::PROCESS_CREATE_PROCESS:
        return PROCESS_CREATE_PROCESS_STR;
    case ProcessAccessMaskFlag::PROCESS_SET_QUOTA:
        return PROCESS_SET_QUOTA_STR;
    case ProcessAccessMaskFlag::PROCESS_SET_INFORMATION:
        return PROCESS_SET_INFORMATION_STR;
    case ProcessAccessMaskFlag::PROCESS_QUERY_INFORMATION:
        return PROCESS_QUERY_INFORMATION_STR;
    case ProcessAccessMaskFlag::PROCESS_SUSPEND_RESUME:
        return PROCESS_SUSPEND_RESUME_STR;
    case ProcessAccessMaskFlag::PROCESS_QUERY_LIMITED_INFORMATION:
        return PROCESS_QUERY_LIMITED_INFORMATION_STR;
    case ProcessAccessMaskFlag::PROCESS_ALL_ACCESS:
        return PROCESS_ALL_ACCESS_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, ProcessAccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(PROCESS_ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
        mask.clear(flag);                                                                          \
    }

std::ostream& operator<<(std::ostream& os, PROCESS_ACCESS_MASK mask) {
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_ALL_ACCESS);

    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_TERMINATE);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_CREATE_THREAD);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_VM_OPERATION);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_VM_READ);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_VM_WRITE);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_DUP_HANDLE);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_CREATE_PROCESS);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_SET_QUOTA);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_SET_INFORMATION);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_QUERY_INFORMATION);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_SUSPEND_RESUME);
    WRITE_IF_ENABLED(ProcessAccessMaskFlag::PROCESS_QUERY_LIMITED_INFORMATION);

    // Now call the base class to handle any remaining bits
    ACCESS_MASK base(mask.value());
    os << base;

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
