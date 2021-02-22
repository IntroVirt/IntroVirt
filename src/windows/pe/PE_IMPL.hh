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

#include "types/DOS_HEADER_IMPL.hh"
#include "types/IMAGE_DEBUG_DIRECTORY_IMPL.hh"
#include "types/IMAGE_FILE_HEADER_IMPL.hh"
#include "types/IMAGE_OPTIONAL_HEADER_IMPL.hh"
#include "types/IMAGE_SECTION_HEADER_IMPL.hh"

#include <introvirt/windows/PdbStore.hh>
#include <introvirt/windows/pe/PE.hh>
#include <introvirt/windows/pe/exception/PeException.hh>

#include <boost/algorithm/string.hpp>

namespace introvirt {
namespace windows {
namespace pe {

class PE_IMPL final : public PE {
  public:
    const DOS_HEADER& dos_header() const override { return *dos_header_; }
    const IMAGE_FILE_HEADER& file_header() const override { return *file_header_; }
    const IMAGE_OPTIONAL_HEADER& optional_header() const override { return *optional_header_; }
    const IMAGE_EXPORT_DIRECTORY* export_directory() const override {
        return optional_header_->export_directory();
    }

    const mspdb::PDB& pdb() const override {
        {
            std::lock_guard lock(pdb_init_);
            if (!pdb_) {
                const auto* debug_dir = optional_header().debug_directory();
                if (unlikely(!debug_dir))
                    throw PeException("Unable to get PE's IMAGE_DEBUG_DIRECTORY");

                const auto* cv_info = debug_dir->codeview_data();
                if (unlikely(!cv_info))
                    throw PeException("IMAGE_DEBUG_DIRECTORY does not contain CodeView data");

                const std::string& pdbFileName = cv_info->PdbFileName();
                std::string pdbIdentifier = cv_info->PdbIdentifier();
                boost::to_upper(pdbIdentifier);
                pdb_ = PdbStore::get().open_pdb(pdbFileName, pdbIdentifier);
                if (unlikely(!pdb_))
                    throw PeException("Failed to get PDB file: " + pdbFileName + "-" +
                                      pdbIdentifier);
            }
        }

        return *pdb_;
    }

    GuestVirtualAddress address() const override { return gva_; }

    const std::vector<std::unique_ptr<const IMAGE_SECTION_HEADER>>& sections() const override {
        if (section_headers_.empty()) {
            GuestVirtualAddress section_headers_ptr =
                optional_header_->address() + file_header_->SizeOfOptionalHeader();

            const uint16_t section_count = file_header_->NumberOfSections();
            for (uint16_t i = 0; i < section_count; ++i) {
                section_headers_.push_back(
                    std::make_unique<IMAGE_SECTION_HEADER_IMPL>(gva_, section_headers_ptr));
                section_headers_ptr += sizeof(structs::_IMAGE_SECTION_HEADER);
            }
        }
        return section_headers_;
    }

    PE_IMPL(const GuestVirtualAddress& gva) : gva_(gva) {
        dos_header_.emplace(gva_);
        file_header_.emplace(gva_, *dos_header_);
        optional_header_ = IMAGE_OPTIONAL_HEADER::make_unique(gva_, *file_header_);
    }

  private:
    GuestVirtualAddress gva_;
    std::optional<DOS_HEADER_IMPL> dos_header_;
    std::optional<IMAGE_FILE_HEADER_IMPL> file_header_;
    std::unique_ptr<IMAGE_OPTIONAL_HEADER> optional_header_;
    std::unique_ptr<IMAGE_EXCEPTION_SECTION_IMPL> image_exception_section_;

    mutable std::mutex pdb_init_;
    mutable std::unique_ptr<mspdb::PDB> pdb_;

    mutable std::vector<std::unique_ptr<const IMAGE_SECTION_HEADER>> section_headers_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt