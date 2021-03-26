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

#include "UNICODE_STRING_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/RTL_USER_PROCESS_PARAMETERS.hh>

#include <introvirt/util/HexDump.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct __attribute__((__aligned__(sizeof(PtrType)), __ms_struct__)) _RTL_USER_PROCESS_PARAMETERS {
    uint32_t MaximumLength;
    uint32_t Length;
    uint32_t Flags;
    uint32_t DebugFlags;
    PtrType ConsoleHandle;
    uint32_t ConsoleFlags;
    PtrType StdInputHandle;
    PtrType StdOutputHandle;
    PtrType StdErrorHandle;
    _UNICODE_STRING<PtrType> CurrentDirectoryPath;
    PtrType CurrentDirectoryHandle;
    _UNICODE_STRING<PtrType> DllPath;
    _UNICODE_STRING<PtrType> ImagePathName;
    _UNICODE_STRING<PtrType> CommandLine;
    guest_member_ptr<char16_t, PtrType> Environment;
    uint32_t StartingPositionLeft;
    uint32_t StartingPositionTop;
    uint32_t Width;
    uint32_t Height;
    uint32_t CharWidth;
    uint32_t CharHeight;
    uint32_t ConsoleTextAttributes;
    uint32_t WindowFlags;
    uint32_t ShowWindowFlags;
    _UNICODE_STRING<PtrType> WindowTitle;
};

static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint32_t>, CommandLine) == 0x40);
static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint64_t>, CommandLine) == 0x70);

static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint32_t>, Environment) == 0x48);
static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint64_t>, Environment) == 0x80);

static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint32_t>, WindowTitle) == 0x70);
static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint64_t>, WindowTitle) == 0xb0);

} // namespace structs

template <typename PtrType>
class RTL_USER_PROCESS_PARAMETERS_IMPL final : public RTL_USER_PROCESS_PARAMETERS {
    using _RTL_USER_PROCESS_PARAMETERS = structs::_RTL_USER_PROCESS_PARAMETERS<PtrType>;

  public:
    const std::string& CommandLine() const override {
        if (commandLine_.empty()) {
            commandLine_ = UNICODE_STRING_IMPL<PtrType>(
                               base_ + offsetof(_RTL_USER_PROCESS_PARAMETERS, CommandLine))
                               .utf8();
        }
        return commandLine_;
    }
    const std::string& ImagePathName() const override {
        if (imagePathName_.empty()) {
            imagePathName_ = UNICODE_STRING_IMPL<PtrType>(
                                 base_ + offsetof(_RTL_USER_PROCESS_PARAMETERS, ImagePathName))
                                 .utf8();
        }
        return imagePathName_;
    }
    const std::string& WindowTitle() const override {
        if (windowTitle_.empty()) {
            windowTitle_ = UNICODE_STRING_IMPL<PtrType>(
                               base_ + offsetof(_RTL_USER_PROCESS_PARAMETERS, WindowTitle))
                               .utf8();
        }
        return windowTitle_;
    }

    guest_ptr<char16_t> pEnvironment() const override { return ptr_->Environment.get(ptr_); }

    std::map<std::string, std::string> EnvironmentMap() const override {
        // The environment itself is a series of null terminated char16_t strings,
        // followed by a zero length char16_t string

        std::map<std::string, std::string> result;

        // Follow the pointer to the start of the environment string
        guest_ptr<char16_t> pEnvironment = ptr_->Environment.get(ptr_);
        while (*pEnvironment != 0) {
            // Find the equals sign
            const guest_ptr<char16_t> keyStart = pEnvironment;
            size_t keyLen = 0;
            for (; *pEnvironment != '='; ++pEnvironment) {
                ++keyLen;
            }

            guest_ptr<char16_t[]> key(keyStart, keyLen);
            ++pEnvironment;

            // Find the null terminator
            const guest_ptr<char16_t> valStart = pEnvironment;
            size_t valLen = 0;
            for (; *pEnvironment != 0; ++pEnvironment) {
                ++valLen;
            }

            guest_ptr<char16_t[]> value(valStart, valLen);

            // Store this entry in the map
            if (key.length()) {
                result[key.str()] = value.str();
            }

            ++pEnvironment;
        }

        return result;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        os << linePrefix << "ImagePathName: " << ImagePathName() << '\n';
        os << linePrefix << "CommandLine: " << CommandLine() << '\n';
    }
    Json::Value json() const override {
        Json::Value result;
        result["ImagePathName"] = ImagePathName();
        result["CommandLine"] = CommandLine();
        return result;
    }

    RTL_USER_PROCESS_PARAMETERS_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr), base_(ptr) {}

    RTL_USER_PROCESS_PARAMETERS_IMPL(guest_ptr<_RTL_USER_PROCESS_PARAMETERS>&& ptr)
        : ptr_(std::move(ptr)), base_(ptr_) {}

  private:
    guest_ptr<_RTL_USER_PROCESS_PARAMETERS> ptr_;
    guest_ptr<void> base_;

    mutable std::string commandLine_;
    mutable std::string imagePathName_;
    mutable std::string windowTitle_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt