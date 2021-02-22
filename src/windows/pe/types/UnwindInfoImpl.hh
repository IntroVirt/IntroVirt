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

#include "UnwindCodeImpl.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/pe/types/UnwindInfo.hh>

namespace introvirt {
namespace windows {
namespace pe {

class IMAGE_EXCEPTION_SECTION_IMPL;

namespace structs {

struct _UnwindInfo {
    uint8_t Version : 3;
    uint8_t Flags : 5;
    uint8_t SizeOfProlog;
    uint8_t CountOfCodes;
    uint8_t FrameRegister : 4;
    uint8_t FrameOffset : 4;
    // UnwindCode UnwindCode[1];
} __attribute__((ms_struct));

} // namespace structs

class UnwindInfoImpl final : public UnwindInfo {
  public:
    uint8_t Version() const override { return data_->Version; }
    uint8_t Flags() const override { return data_->Flags; }
    uint8_t SizeOfProlog() const override { return data_->SizeOfProlog; }
    uint8_t CountOfCodes() const override { return data_->CountOfCodes; }
    uint8_t FrameRegister() const override { return data_->FrameRegister; }
    uint8_t FrameOffset() const override { return data_->FrameOffset; }
    const std::vector<std::unique_ptr<const UnwindCode>>& codes() const override { return codes_; }

    bool is_chained() const override {
        return (data_->Flags & UNWIND_FLAGS::UNW_FLAG_CHAININFO) != 0;
    }

    uint32_t exception_handler_rva() const override { return exception_handler_rva_; };

    UnwindInfoImpl(const GuestVirtualAddress& gva) : data_(gva) {

        if ((data_->Flags & UNWIND_FLAGS::UNW_FLAG_EHANDLER) != 0) {
            GuestVirtualAddress pRVA = gva + sizeof(structs::_UnwindInfo) +
                                       (data_->CountOfCodes * sizeof(structs::_UnwindCode));

            // TODO(pape): Look into this, can we just mask off some bits?
            if ((pRVA.virtual_address() % 4) != 0) {
                // should only be off by 2, but let's be safe
                pRVA += 4 - (pRVA.virtual_address() % 4);
            }

            exception_handler_rva_ = *guest_ptr<uint32_t>(pRVA);
        }

        int i = 0;
        GuestVirtualAddress nextAddress = gva + sizeof(structs::_UnwindInfo);
        while (i < data_->CountOfCodes) {
            auto code = std::make_unique<UnwindCodeImpl>(nextAddress);
            i += code->CodeCount();
            nextAddress += code->CodeCount() * sizeof(structs::_UnwindCode);
            codes_.push_back(std::move(code));
        }

        if (is_chained()) {
            pChained_ = nextAddress;
        }
    }

    const RUNTIME_FUNCTION* chained_function(const IMAGE_EXCEPTION_SECTION_IMPL* pdata) const;

  private:
    guest_ptr<structs::_UnwindInfo> data_;
    uint32_t exception_handler_rva_;
    std::vector<std::unique_ptr<const UnwindCode>> codes_;
    mutable GuestVirtualAddress pChained_;
    mutable std::unique_ptr<RUNTIME_FUNCTION> chained_function_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
