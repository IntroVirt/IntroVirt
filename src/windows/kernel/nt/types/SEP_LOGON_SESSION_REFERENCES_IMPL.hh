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

#include "LUID_IMPL.hh"
#include "UNICODE_STRING_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/windows/kernel/nt/types/SEP_LOGON_SESSION_REFERENCES.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class SEP_LOGON_SESSION_REFERENCES_IMPL : public SEP_LOGON_SESSION_REFERENCES {
  public:
    LUID& LogonId() override {
        if (!this->LogonId_) {
            this->LogonId_.emplace(this->buffer_ + this->offsets_->LogonId);
        }
        return *(this->LogonId_);
    }
    const LUID& LogonId() const override {
        auto* non_const_this = const_cast<SEP_LOGON_SESSION_REFERENCES_IMPL<PtrType>*>(this);
        return non_const_this->LogonId();
    }

    LUID& BuddyLogonId() override {
        if (!this->BuddyLogonId_) {
            this->BuddyLogonId_.emplace(this->buffer_ + this->offsets_->BuddyLogonId);
        }
        return *(this->BuddyLogonId_);
    }
    const LUID& BuddyLogonId() const override {
        auto* non_const_this = const_cast<SEP_LOGON_SESSION_REFERENCES_IMPL<PtrType>*>(this);
        return non_const_this->BuddyLogonId();
    }

    void ReferenceCount(int64_t ReferenceCount) override {
        this->offsets_->ReferenceCount.set<PtrType>(this->buffer_, ReferenceCount);
    }
    int64_t ReferenceCount() const override {
        return this->offsets_->ReferenceCount.get<PtrType>(this->buffer_);
    }

    uint32_t Flags() const override { return this->offsets_->Flags.get<uint32_t>(this->buffer_); }
    void Flags(uint32_t Flags) override {
        this->offsets_->Flags.set<uint32_t>(this->buffer_, Flags);
    }

    const std::string& AccountName() const override {
        if (!this->AccountName_) {
            guest_ptr<void> pAccountName = this->buffer_ + this->offsets_->AccountName;
            this->AccountName_.emplace(pAccountName);
        }
        return this->AccountName_->utf8();
    }

    const std::string& AuthorityName() const override {
        if (!this->AuthorityName_) {
            guest_ptr<void> pAuthorityName = this->buffer_ + this->offsets_->AuthorityName;
            this->AuthorityName_.emplace(pAuthorityName);
        }
        return this->AuthorityName_->utf8();
    }

    LUID& SiblingAuthId() override {
        if (!this->SiblingAuthId_) {
            this->SiblingAuthId_.emplace(this->buffer_ + this->offsets_->SiblingAuthId);
        }
        return *(this->SiblingAuthId_);
    }
    const LUID& SiblingAuthId() const override {
        auto* non_const_this = const_cast<SEP_LOGON_SESSION_REFERENCES_IMPL<PtrType>*>(this);
        return non_const_this->SiblingAuthId();
    }

    SEP_LOGON_SESSION_REFERENCES_IMPL(const NtKernelImpl<PtrType>& kernel,
                                      const guest_ptr<void>& ptr) {
        this->offsets_ = LoadOffsets<structs::SEP_LOGON_SESSION_REFERENCES>(kernel);
        buffer_.reset(ptr, this->offsets_->size());
    }

  private:
    const structs::SEP_LOGON_SESSION_REFERENCES* offsets_;
    guest_ptr<char[]> buffer_;

    std::optional<LUID_IMPL> LogonId_;
    std::optional<LUID_IMPL> BuddyLogonId_;
    mutable std::optional<UNICODE_STRING_IMPL<PtrType>> AccountName_;
    mutable std::optional<UNICODE_STRING_IMPL<PtrType>> AuthorityName_;
    std::optional<LUID_IMPL> SiblingAuthId_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt