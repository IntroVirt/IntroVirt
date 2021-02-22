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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/PS_CREATE_INFO.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _PS_CREATE_INFO {
    PtrType Size;
    PtrType State; // PS_CREATE_STATE
    union {
        // PsCreateInitialState
        struct {
            union {
                uint32_t InitFlags;
                struct {
                    uint8_t WriteOutputOnExit : 1;
                    uint8_t DetectManifest : 1;
                    uint8_t SpareBits1 : 6;
                    uint8_t IFEOKeyState : 2; // PS_IFEO_KEY_STATE
                    uint8_t SpareBits2 : 6;
                    uint16_t ProhibitedImageCharacteristics : 16;
                };
            };
            uint32_t AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct {
            PtrType FileHandle;
        } FailSection;

        // PsCreateFailExeName
        struct {
            PtrType IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct {
            union {
                uint32_t OutputFlags;
                struct {
                    uint8_t ProtectedProcess : 1;
                    uint8_t AddressSpaceOverride : 1;
                    uint8_t DevOverrideEnabled : 1; // from Image File Execution Options
                    uint8_t ManifestDetected : 1;
                    uint8_t SpareBits1 : 4;
                    uint8_t SpareBits2 : 8;
                    uint16_t SpareBits3 : 16;
                };
            };
            PtrType FileHandle;
            PtrType SectionHandle;
            uint64_t UserProcessParametersNative;
            uint32_t UserProcessParametersWow64;
            uint32_t CurrentParameterFlags;
            uint64_t PebAddressNative;
            uint32_t PebAddressWow64;
            uint64_t ManifestAddress;
            uint32_t ManifestSize;
        } SuccessState;
    };
};

} // namespace structs

template <typename PtrType>
class PS_CREATE_INFO_IMPL final : public PS_CREATE_INFO {
  public:
    virtual PS_CREATE_STATE State() const override {
        return static_cast<PS_CREATE_STATE>(data_->State);
    }
    virtual uint64_t Size() const override { return data_->Size; };

    /** Only valid for state == PsCreateSuccess || PsCreateFailOnSectionCreate */
    virtual uint64_t FileHandle() const override;

    /** Only valid for state == PsCreateSuccess */
    virtual uint64_t SectionHandle() const override;
    virtual uint64_t UserProcessParametersNative() const override;
    virtual uint32_t UserProcessParametersWow64() const override;
    virtual uint32_t CurrentParameterFlags() const override;
    virtual uint64_t PebAddressNative() const override;
    virtual uint32_t PebAddressWow64() const override;
    virtual uint64_t ManifestAddress() const override;
    virtual uint32_t ManifestSize() const override;
    virtual uint32_t OutputFlags() const override;

    /** Only valid for state == PsCreateFailExeName */
    virtual uint64_t IFEOKey() const override;

    /* Only valid for state == PsCreateInitialState */
    virtual uint32_t InitFlags() const override;
    virtual void InitFlags(uint32_t InitFlags) override;

    virtual FILE_ACCESS_MASK AdditionalFileAccess() const override;
    virtual void AdditionalFileAccess(FILE_ACCESS_MASK AdditionalFileAccess) override;

    virtual GuestVirtualAddress address() const override { return gva_; }
    virtual void write(std::ostream& os, const std::string& linePrefix = "") const override;
    virtual Json::Value json() const override;

    PS_CREATE_INFO_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva_) {}

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_PS_CREATE_INFO<PtrType>> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt