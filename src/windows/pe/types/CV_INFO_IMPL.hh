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
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/pe/exception/PeException.hh>
#include <introvirt/windows/pe/types/CV_INFO.hh>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {
struct _GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
};

struct _CV_INFO_PDB70 {
    uint32_t CvSignature;
    struct _GUID GUID;
    uint32_t Age;
    uint8_t PdbFileName[];
};
} // namespace structs

class CV_INFO_IMPL final : public CV_INFO {
  public:
    uint32_t CvSignature() const override { return data_->CvSignature; }
    const std::string& PdbGUID() const override { return PdbGUID_; }
    const std::string& PdbIdentifier() const override { return PdbIdentifier_; }
    const uint32_t Age() const override { return data_->Age; }
    const std::string& PdbFileName() const override { return PdbFileName_; }

    CV_INFO_IMPL(const GuestVirtualAddress& gva, uint32_t SizeOfData) : data_(gva) {
        if (unlikely(data_->CvSignature != 0x53445352)) /* "RSDS" */
            throw PeException("Invalid CvSignature");

        // Find the PDB identifier
        {
            char pdbid[128];

            snprintf(pdbid, sizeof(pdbid), "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%01x",
                     data_->GUID.Data1, data_->GUID.Data2, data_->GUID.Data3, data_->GUID.Data4[0],
                     data_->GUID.Data4[1], data_->GUID.Data4[2], data_->GUID.Data4[3],
                     data_->GUID.Data4[4], data_->GUID.Data4[5], data_->GUID.Data4[6],
                     data_->GUID.Data4[7], data_->Age & 0xf);

            PdbIdentifier_ = std::string(pdbid);
        }

        // Get the PDB file name
        {
            const GuestVirtualAddress pPdbFileName =
                gva + offsetof(structs::_CV_INFO_PDB70, PdbFileName);

            const uint32_t max_len = SizeOfData - sizeof(structs::_CV_INFO_PDB70);
            auto mapping = map_guest_cstr(pPdbFileName, max_len);
            PdbFileName_ = std::string(mapping.get(), mapping.length());
        }

        // Get the PDB GUID
        {
            char guid[128];

            snprintf(guid, sizeof(guid), "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     data_->GUID.Data1, data_->GUID.Data2, data_->GUID.Data3, data_->GUID.Data4[0],
                     data_->GUID.Data4[1], data_->GUID.Data4[2], data_->GUID.Data4[3],
                     data_->GUID.Data4[4], data_->GUID.Data4[5], data_->GUID.Data4[6],
                     data_->GUID.Data4[7]);

            PdbGUID_ = std::string(guid);
        }
    }

  private:
    guest_ptr<structs::_CV_INFO_PDB70> data_;
    std::string PdbIdentifier_;
    std::string PdbFileName_;
    std::string PdbGUID_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt