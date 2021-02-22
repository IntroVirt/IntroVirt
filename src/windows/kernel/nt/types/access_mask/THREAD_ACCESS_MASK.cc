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
#include <introvirt/windows/kernel/nt/types/access_mask/THREAD_ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(ThreadAccessMaskFlag flag) {
    static const std::string THREAD_TERMINATE_STR("THREAD_TERMINATE");
    static const std::string THREAD_SUSPEND_RESUME_STR("THREAD_SUSPEND_RESUME");
    static const std::string THREAD_GET_CONTEXT_STR("THREAD_GET_CONTEXT");
    static const std::string THREAD_SET_CONTEXT_STR("THREAD_SET_CONTEXT");
    static const std::string THREAD_SET_INFORMATION_STR("THREAD_SET_INFORMATION");
    static const std::string THREAD_QUERY_INFORMATION_STR("THREAD_QUERY_INFORMATION");
    static const std::string THREAD_SET_THREAD_TOKEN_STR("THREAD_SET_THREAD_TOKEN");
    static const std::string THREAD_IMPERSONATE_STR("THREAD_IMPERSONATE");
    static const std::string THREAD_DIRECT_IMPERSONATION_STR("THREAD_DIRECT_IMPERSONATION");
    static const std::string THREAD_SET_LIMITED_INFORMATION_STR("THREAD_SET_LIMITED_INFORMATION");
    static const std::string THREAD_QUERY_LIMITED_INFORMATION_STR(
        "THREAD_QUERY_LIMITED_INFORMATION");
    static const std::string THREAD_ALL_ACCESS_STR("THREAD_ALL_ACCESS");
    static const std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case ThreadAccessMaskFlag::THREAD_TERMINATE:
        return THREAD_TERMINATE_STR;
    case ThreadAccessMaskFlag::THREAD_SUSPEND_RESUME:
        return THREAD_SUSPEND_RESUME_STR;
    case ThreadAccessMaskFlag::THREAD_GET_CONTEXT:
        return THREAD_GET_CONTEXT_STR;
    case ThreadAccessMaskFlag::THREAD_SET_CONTEXT:
        return THREAD_SET_CONTEXT_STR;
    case ThreadAccessMaskFlag::THREAD_SET_INFORMATION:
        return THREAD_SET_INFORMATION_STR;
    case ThreadAccessMaskFlag::THREAD_QUERY_INFORMATION:
        return THREAD_QUERY_INFORMATION_STR;
    case ThreadAccessMaskFlag::THREAD_SET_THREAD_TOKEN:
        return THREAD_SET_THREAD_TOKEN_STR;
    case ThreadAccessMaskFlag::THREAD_IMPERSONATE:
        return THREAD_IMPERSONATE_STR;
    case ThreadAccessMaskFlag::THREAD_DIRECT_IMPERSONATION:
        return THREAD_DIRECT_IMPERSONATION_STR;
    case ThreadAccessMaskFlag::THREAD_SET_LIMITED_INFORMATION:
        return THREAD_SET_LIMITED_INFORMATION_STR;
    case ThreadAccessMaskFlag::THREAD_QUERY_LIMITED_INFORMATION:
        return THREAD_QUERY_LIMITED_INFORMATION_STR;
    case ThreadAccessMaskFlag::THREAD_ALL_ACCESS:
        return THREAD_ALL_ACCESS_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, ThreadAccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(THREAD_ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
        mask.clear(flag);                                                                          \
    }

std::ostream& operator<<(std::ostream& os, THREAD_ACCESS_MASK mask) {
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_ALL_ACCESS);

    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_TERMINATE);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_SUSPEND_RESUME);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_GET_CONTEXT);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_SET_CONTEXT);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_SET_INFORMATION);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_QUERY_INFORMATION);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_SET_THREAD_TOKEN);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_IMPERSONATE);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_DIRECT_IMPERSONATION);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_SET_LIMITED_INFORMATION);
    WRITE_IF_ENABLED(ThreadAccessMaskFlag::THREAD_QUERY_LIMITED_INFORMATION);

    // Now call the base class to handle any remaining bits
    ACCESS_MASK base(mask.value());
    os << base;

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
