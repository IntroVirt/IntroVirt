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
#include "SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL.hh"

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL<PtrType>::write(std::ostream& os,
                                                           const std::string& linePrefix) const {

    boost::io::ios_flags_saver ifs(os);
    os << std::dec;

    os << linePrefix << "UniqueProcessId: " << UniqueProcessId() << '\n';
    os << linePrefix << "  NumberOfThreads: " << NumberOfThreads() << '\n';
    os << linePrefix << "  WorkingSetPrivateSize: " << WorkingSetPrivateSize() << '\n';
    os << linePrefix << "  HardFaultCount: " << HardFaultCount() << '\n';
    os << linePrefix << "  NumberOfThreadsHighWatermark: " << NumberOfThreadsHighWatermark()
       << '\n';
    os << linePrefix << "  CycleTime: " << CycleTime() << '\n';
    os << linePrefix << "  CreateTime: " << CreateTime() << '\n';
    os << linePrefix << "  UserTime: " << UserTime() << '\n';
    os << linePrefix << "  KernelTime: " << KernelTime() << '\n';
    os << linePrefix << "  ImageName: " << ImageName() << '\n';
    os << linePrefix << "  BasePriority: " << BasePriority() << '\n';
    os << linePrefix << "  InheritedFromUniqueProcessId: " << InheritedFromUniqueProcessId()
       << '\n';
    os << linePrefix << "  HandleCount: " << HandleCount() << '\n';
    os << linePrefix << "  SessionId: " << SessionId() << '\n';
    os << linePrefix << "  UniqueProcessKey: " << UniqueProcessKey() << '\n';
    os << linePrefix << "  VMCounters: \n";
    VMCounters().write(os, linePrefix + "    ");
    os << linePrefix << "  IOCounters: \n";
    IOCounters().write(os, linePrefix + "    ");
    os << linePrefix << "  Threads: \n";
    Threads().write(os, linePrefix + "    ");
}

template <typename PtrType>
Json::Value SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL<PtrType>::json() const {
    Json::Value result;

    result["UniqueProcessId"] = UniqueProcessId();
    result["NumberOfThreads"] = NumberOfThreads();
    result["WorkingSetPrivateSize"] = WorkingSetPrivateSize();
    result["HardFaultCount"] = HardFaultCount();
    result["NumberOfThreadsHighWatermark"] = NumberOfThreadsHighWatermark();
    result["CycleTime"] = CycleTime();
    result["CreateTime"] = CreateTime().unix_time();
    result["UserTime"] = UserTime();
    result["KernelTime"] = KernelTime();
    result["ImageName"] = ImageName();
    result["BasePriority"] = BasePriority();
    result["InheritedFromUniqueProcessId"] = InheritedFromUniqueProcessId();
    result["HandleCount"] = HandleCount();
    result["SessionId"] = SessionId();
    result["UniqueProcessKey"] = UniqueProcessKey();
    result["VMCounters"] = VMCounters().json();
    result["IOCounters"] = IOCounters().json();
    result["Threads"] = Threads().json();

    return result;
}

template class SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL<uint32_t>;
template class SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt