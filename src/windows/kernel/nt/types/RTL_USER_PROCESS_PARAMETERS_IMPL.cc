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
#include "RTL_USER_PROCESS_PARAMETERS_IMPL.hh"

#include <introvirt/windows/common/WStr.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr logger(
    log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.RTL_USER_PROCESS_PARAMETERS"));

template <typename PtrType>
GuestVirtualAddress RTL_USER_PROCESS_PARAMETERS_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
const std::map<std::string, std::string>&
RTL_USER_PROCESS_PARAMETERS_IMPL<PtrType>::Environment() const {
    if (environment.empty()) {
        GuestVirtualAddress pEnvironment = gva_.create(data_->Environment);
        GuestVirtualAddress keyStart = pEnvironment;
        PtrType keyLen = 0;
        GuestVirtualAddress valueStart;
        try {
            guest_ptr<uint16_t> pos(pEnvironment);
            while (true) {
                if (*pos == '=' && !valueStart) {
                    // We've hit the '=' between key and value
                    keyLen = pEnvironment - keyStart;
                    valueStart = pEnvironment + 2;
                } else if (*pos == 0) {
                    if (!valueStart && !keyLen) {
                        // End of the WCHAR array
                        break;
                    }

                    size_t valueLen = pEnvironment - valueStart;
                    if (keyLen && valueLen) {
                        // We've hit the end of a string
                        environment.emplace(std::make_pair(WStr(keyStart, keyLen).utf8(),
                                                           WStr(valueStart, valueLen).utf8()));
                    }
                    // Move up to the next string
                    keyStart = pEnvironment + 2;
                    keyLen = 0;
                    valueStart = GuestVirtualAddress();
                }
                pos.reset(pEnvironment += 2);
            }
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(logger, "Failed to get process environment: " << ex);
        }
    }

    return environment;
}

template <typename PtrType>
const std::string& RTL_USER_PROCESS_PARAMETERS_IMPL<PtrType>::CommandLine() const {
    if (commandLine.empty()) {
        const auto pCommandLine =
            gva_ + offsetof(structs::_RTL_USER_PROCESS_PARAMETERS<PtrType>, CommandLine);
        commandLine = UNICODE_STRING_IMPL<PtrType>(pCommandLine).utf8();
    }
    return commandLine;
}

template <typename PtrType>
const std::string& RTL_USER_PROCESS_PARAMETERS_IMPL<PtrType>::ImagePathName() const {
    if (imagePathName.empty()) {
        const auto pImagePathName =
            gva_ + offsetof(structs::_RTL_USER_PROCESS_PARAMETERS<PtrType>, ImagePathName);
        imagePathName = UNICODE_STRING_IMPL<PtrType>(pImagePathName).utf8();
    }
    return imagePathName;
}

template <typename PtrType>
const std::string& RTL_USER_PROCESS_PARAMETERS_IMPL<PtrType>::WindowTitle() const {
    if (windowTitle.empty()) {
        const auto pWindowTitle =
            gva_ + offsetof(structs::_RTL_USER_PROCESS_PARAMETERS<PtrType>, WindowTitle);
        windowTitle = UNICODE_STRING_IMPL<PtrType>(pWindowTitle).utf8();
    }
    return windowTitle;
}

template <typename PtrType>
void RTL_USER_PROCESS_PARAMETERS_IMPL<PtrType>::write(std::ostream& os,
                                                      const std::string& linePrefix) const {
    os << linePrefix << "ImagePathName: " << ImagePathName() << '\n';
    os << linePrefix << "CommandLine: " << CommandLine() << '\n';
}

template <typename PtrType>
Json::Value RTL_USER_PROCESS_PARAMETERS_IMPL<PtrType>::json() const {
    Json::Value result;
    result["ImagePathName"] = ImagePathName();
    result["CommandLine"] = CommandLine();
    return result;
}

template <typename PtrType>
RTL_USER_PROCESS_PARAMETERS_IMPL<PtrType>::RTL_USER_PROCESS_PARAMETERS_IMPL(
    const GuestVirtualAddress& gva)
    : gva_(gva), data_(gva_) {}

std::unique_ptr<RTL_USER_PROCESS_PARAMETERS>
RTL_USER_PROCESS_PARAMETERS::make_unique(const NtKernel& kernel, const GuestVirtualAddress& gva) {
    if (kernel.x64()) {
        return std::make_unique<RTL_USER_PROCESS_PARAMETERS_IMPL<uint64_t>>(gva);
    } else {
        return std::make_unique<RTL_USER_PROCESS_PARAMETERS_IMPL<uint32_t>>(gva);
    }
}

template class RTL_USER_PROCESS_PARAMETERS_IMPL<uint32_t>;
template class RTL_USER_PROCESS_PARAMETERS_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
