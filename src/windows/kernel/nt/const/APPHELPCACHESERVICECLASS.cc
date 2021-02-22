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

#include <introvirt/windows/kernel/nt/const/APPHELPCACHESERVICECLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(APPHELPCACHESERVICECLASS val) {
    static const std::string ApphelpCacheServiceLookupStr("ApphelpCacheServiceLookup");
    static const std::string ApphelpCacheServiceRemoveStr("ApphelpCacheServiceRemove");
    static const std::string ApphelpCacheServiceUpdateStr("ApphelpCacheServiceUpdate");
    static const std::string ApphelpCacheServiceFlushStr("ApphelpCacheServiceFlush");
    static const std::string ApphelpCacheServiceDumpStr("ApphelpCacheServiceDump");
    static const std::string ApphelpCacheServiceUnknownStr("ApphelpCacheServiceUnknown");

    switch (val) {
    case APPHELPCACHESERVICECLASS::ApphelpCacheServiceLookup:
        return ApphelpCacheServiceLookupStr;
    case APPHELPCACHESERVICECLASS::ApphelpCacheServiceRemove:
        return ApphelpCacheServiceRemoveStr;
    case APPHELPCACHESERVICECLASS::ApphelpCacheServiceUpdate:
        return ApphelpCacheServiceUpdateStr;
    case APPHELPCACHESERVICECLASS::ApphelpCacheServiceFlush:
        return ApphelpCacheServiceFlushStr;
    case APPHELPCACHESERVICECLASS::ApphelpCacheServiceDump:
        return ApphelpCacheServiceDumpStr;
    case APPHELPCACHESERVICECLASS::ApphelpCacheServiceUnknown:
    default:
        return ApphelpCacheServiceUnknownStr;
    }
}

std::ostream& operator<<(std::ostream& os, APPHELPCACHESERVICECLASS val) {
    os << to_string(val);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
