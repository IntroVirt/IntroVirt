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

#include "FILE_INFO_IMPL.hh"
#include "StringFileInfoImpl.hh"
#include "VS_FIXEDFILEINFO_IMPL.hh"
#include "VarFileInfoImpl.hh"

#include <introvirt/windows/common/Utf16String.hh>
#include <introvirt/windows/pe/exception/PeException.hh>
#include <introvirt/windows/pe/types/StringFileInfo.hh>
#include <introvirt/windows/pe/types/VS_FIXEDFILEINFO.hh>
#include <introvirt/windows/pe/types/VS_VERSIONINFO.hh>
#include <introvirt/windows/pe/types/VarFileInfo.hh>

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/compiler.hh>

#include <cassert>
#include <memory>
#include <optional>

namespace introvirt {
namespace windows {
namespace pe {

class VS_VERSIONINFO_IMPL final : public FILE_INFO_IMPL<VS_VERSIONINFO> {
  public:
    const VS_FIXEDFILEINFO& Value() const override { return *Value_; }

    const pe::StringFileInfo* StringFileInfo() const override {
        if (StringFileInfo_)
            return &(*StringFileInfo_);
        return nullptr;
    }

    const pe::VarFileInfo* VarFileInfo() const override {
        if (VarFileInfo_)
            return &(*VarFileInfo_);
        return nullptr;
    }

    VS_VERSIONINFO_IMPL(const GuestVirtualAddress& pVersionInfo)
        : FILE_INFO_IMPL<VS_VERSIONINFO>(pVersionInfo) {

        assert(this->szKey() == "VS_VERSION_INFO");

        const GuestVirtualAddress pValue = this->pChildren();
        Value_.emplace(pValue);

        // Remaining children
        GuestVirtualAddress pChildren = dword_align(pValue + sizeof(structs::_VS_FIXEDFILEINFO));

        const GuestVirtualAddress pEndChildren =
            pChildren + (wLength() - (pChildren - pVersionInfo));

        while (pChildren < pEndChildren) {
            FILE_INFO_IMPL<> fInfo(pChildren);

            if (fInfo.szKey() == "StringFileInfo") {
                StringFileInfo_.emplace(pChildren);
            } else if (fInfo.szKey() == "VarFileInfo") {
                VarFileInfo_.emplace(pChildren);
            }

            pChildren = dword_align(pChildren + fInfo.wLength());
        }
    }

  public:
    std::optional<VS_FIXEDFILEINFO_IMPL> Value_;

    std::optional<pe::StringFileInfoImpl> StringFileInfo_;
    std::optional<pe::VarFileInfoImpl> VarFileInfo_;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
