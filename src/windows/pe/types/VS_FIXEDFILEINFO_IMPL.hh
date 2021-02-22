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

#include <introvirt/windows/pe/exception/PeException.hh>
#include <introvirt/windows/pe/types/VS_FIXEDFILEINFO.hh>

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/compiler.hh>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _VS_FIXEDFILEINFO {
    uint32_t dwSignature;
    uint32_t dwStrucVersion;
    uint32_t dwFileVersionMS;
    uint32_t dwFileVersionLS;
    uint32_t dwProductVersionMS;
    uint32_t dwProductVersionLS;
    uint32_t dwFileFlagsMask;
    uint32_t dwFileFlags;
    uint32_t dwFileOS;
    uint32_t dwFileType;
    uint32_t dwFileSubtype;
    uint32_t dwFileDateMS;
    uint32_t dwFileDateLS;
};

} // namespace structs

static const uint32_t FIXEDFILEINFO_SIGNATURE = 0xFEEF04BD;

class VS_FIXEDFILEINFO_IMPL final : public VS_FIXEDFILEINFO {
  public:
    uint32_t dwSignature() const override { return data_->dwSignature; }
    uint32_t dwStrucVersion() const override { return data_->dwStrucVersion; }
    uint64_t dwFileVersion() const override {
        return (data_->dwFileVersionMS << 16L) | data_->dwFileVersionLS;
    }
    uint64_t dwProductVersion() const override {
        return (data_->dwProductVersionMS << 16L) | data_->dwProductVersionLS;
    }
    uint32_t dwFileFlagsMask() const override { return data_->dwFileFlagsMask; }
    uint32_t dwFileFlags() const override { return data_->dwFileFlags; }
    uint32_t dwFileOS() const override { return data_->dwFileOS; }
    uint32_t dwFileType() const override { return data_->dwFileType; }
    uint32_t dwFileSubtype() const override { return data_->dwFileSubtype; }
    uint64_t dwFileDate() const override {
        return (data_->dwFileDateMS << 16L) | data_->dwFileDateLS;
    }

    VS_FIXEDFILEINFO_IMPL(const GuestVirtualAddress& pFixedFileInfo) : data_(pFixedFileInfo) {
        if (unlikely(data_->dwSignature != FIXEDFILEINFO_SIGNATURE))
            throw PeException("Bad VS_FIXEDFILEINFO signature");
    }

  private:
    guest_ptr<structs::_VS_FIXEDFILEINFO> data_;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
