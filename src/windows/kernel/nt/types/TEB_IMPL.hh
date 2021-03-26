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

#include "CLIENT_ID_IMPL.hh"
#include "NT_TIB_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/TEB.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class TEB_IMPL final : public TEB {
  public:
    const NT_TIB& NtTib() const override {
        if (!NtTib_) {
            NtTib_.emplace(kernel_, ptr_ + teb_->NtTib.offset());
        }
        return *NtTib_;
    }
    const CLIENT_ID& ClientId() const override {
        if (!ClientId_) {
            ClientId_.emplace(ptr_ + teb_->ClientId.offset());
        }
        return *ClientId_;
    }

    WinError LastErrorValue() const override {
        return static_cast<WinError>(teb_->LastErrorValue.get<uint32_t>(buffer_));
    }
    void LastErrorValue(WinError LastErrorValue) override {
        teb_->LastErrorValue.set<uint32_t>(buffer_, static_cast<uint32_t>(LastErrorValue));
    }

    NTSTATUS LastStatusValue() const override {
        return NTSTATUS(teb_->LastStatusValue.get<uint32_t>(buffer_));
    }
    void LastStatusValue(NTSTATUS status) override {
        teb_->LastStatusValue.set<uint32_t>(buffer_, status.value());
    }

    guest_ptr<void> ptr() const override { return buffer_; }

    TEB_IMPL(const NtKernelImpl<PtrType>& kernel, const guest_ptr<void>& ptr)
        : kernel_(kernel), ptr_(ptr) {

        teb_ = LoadOffsets<structs::TEB>(kernel_);
        buffer_.reset(ptr, teb_->size());
    }

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const guest_ptr<void> ptr_;

    const structs::TEB* teb_;
    guest_ptr<char[]> buffer_;

    mutable std::optional<NT_TIB_IMPL<PtrType>> NtTib_;
    mutable std::optional<CLIENT_ID_IMPL<PtrType>> ClientId_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt