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

#include "IMAGE_DEBUG_DIRECTORY_IMPL.hh"
#include "IMAGE_EXCEPTION_SECTION_IMPL.hh"
#include "IMAGE_EXPORT_DIRECTORY_IMPL.hh"
#include "IMAGE_RELOCATION_SECTION_IMPL.hh"
#include "IMAGE_RESOURCE_DIRECTORY_IMPL.hh"
#include "IMPORT_NAME_TABLE_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/pe/types/IMAGE_OPTIONAL_HEADER.hh>

#include <cassert>
#include <mutex>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

template <typename PtrSize>
struct _IMAGE_OPTIONAL_HEADER {};

template <>
struct _IMAGE_OPTIONAL_HEADER<uint32_t> {
    uint16_t Magic;                            // offset   0x0 size   0x2
    uint8_t MajorLinkerVersion;                // offset   0x2 size   0x1
    uint8_t MinorLinkerVersion;                // offset   0x3 size   0x1
    uint32_t SizeOfCode;                       // offset   0x4 size   0x4
    uint32_t SizeOfInitializedData;            // offset   0x8 size   0x4
    uint32_t SizeOfUninitializedData;          // offset   0xc size   0x4
    uint32_t AddressOfEntryPoint;              // offset  0x10 size   0x4
    uint32_t BaseOfCode;                       // offset  0x14 size   0x4
    uint32_t BaseOfData;                       // offset  0x18 size   0x4
    uint32_t ImageBase;                        // offset  0x1c size   0x4
    uint32_t SectionAlignment;                 // offset  0x20 size   0x4
    uint32_t FileAlignment;                    // offset  0x24 size   0x4
    uint16_t MajorOperatingSystemVersion;      // offset  0x28 size   0x2
    uint16_t MinorOperatingSystemVersion;      // offset  0x2a size   0x2
    uint16_t MajorImageVersion;                // offset  0x2c size   0x2
    uint16_t MinorImageVersion;                // offset  0x2e size   0x2
    uint16_t MajorSubsystemVersion;            // offset  0x30 size   0x2
    uint16_t MinorSubsystemVersion;            // offset  0x32 size   0x2
    uint32_t Win32VersionValue;                // offset  0x34 size   0x4
    uint32_t SizeOfImage;                      // offset  0x38 size   0x4
    uint32_t SizeOfHeaders;                    // offset  0x3c size   0x4
    uint32_t CheckSum;                         // offset  0x40 size   0x4
    uint16_t Subsystem;                        // offset  0x44 size   0x2
    uint16_t DllCharacteristics;               // offset  0x46 size   0x2
    uint32_t SizeOfStackReserve;               // offset  0x48 size   0x4
    uint32_t SizeOfStackCommit;                // offset  0x4c size   0x4
    uint32_t SizeOfHeapReserve;                // offset  0x50 size   0x4
    uint32_t SizeOfHeapCommit;                 // offset  0x54 size   0x4
    uint32_t LoaderFlags;                      // offset  0x58 size   0x4
    uint32_t NumberOfRvaAndSizes;              // offset  0x5c size   0x4
    _IMAGE_DATA_DIRECTORY DataDirectory[0x10]; // offset  0x60 size  0x80
};

template <>
struct _IMAGE_OPTIONAL_HEADER<uint64_t> {
    uint16_t Magic;                            // offset   0x0 size   0x2
    uint8_t MajorLinkerVersion;                // offset   0x2 size   0x1
    uint8_t MinorLinkerVersion;                // offset   0x3 size   0x1
    uint32_t SizeOfCode;                       // offset   0x4 size   0x4
    uint32_t SizeOfInitializedData;            // offset   0x8 size   0x4
    uint32_t SizeOfUninitializedData;          // offset   0xc size   0x4
    uint32_t AddressOfEntryPoint;              // offset  0x10 size   0x4
    uint32_t BaseOfCode;                       // offset  0x14 size   0x4
    uint64_t ImageBase;                        // offset  0x18 size   0x8
    uint32_t SectionAlignment;                 // offset  0x20 size   0x4
    uint32_t FileAlignment;                    // offset  0x24 size   0x4
    uint16_t MajorOperatingSystemVersion;      // offset  0x28 size   0x2
    uint16_t MinorOperatingSystemVersion;      // offset  0x2a size   0x2
    uint16_t MajorImageVersion;                // offset  0x2c size   0x2
    uint16_t MinorImageVersion;                // offset  0x2e size   0x2
    uint16_t MajorSubsystemVersion;            // offset  0x30 size   0x2
    uint16_t MinorSubsystemVersion;            // offset  0x32 size   0x2
    uint32_t Win32VersionValue;                // offset  0x34 size   0x4
    uint32_t SizeOfImage;                      // offset  0x38 size   0x4
    uint32_t SizeOfHeaders;                    // offset  0x3c size   0x4
    uint32_t CheckSum;                         // offset  0x40 size   0x4
    uint16_t Subsystem;                        // offset  0x44 size   0x2
    uint16_t DllCharacteristics;               // offset  0x46 size   0x2
    uint64_t SizeOfStackReserve;               // offset  0x48 size   0x8
    uint64_t SizeOfStackCommit;                // offset  0x50 size   0x8
    uint64_t SizeOfHeapReserve;                // offset  0x58 size   0x8
    uint64_t SizeOfHeapCommit;                 // offset  0x60 size   0x8
    uint32_t LoaderFlags;                      // offset  0x68 size   0x4
    uint32_t NumberOfRvaAndSizes;              // offset  0x6c size   0x4
    _IMAGE_DATA_DIRECTORY DataDirectory[0x10]; // offset  0x70 size  0x80
};

} // namespace structs

template <typename PtrType>
class IMAGE_OPTIONAL_HEADER_IMPL final : public IMAGE_OPTIONAL_HEADER {
  public:
    uint16_t Magic() const override { return ptr_->Magic; }
    uint8_t MajorLinkerVersion() const override { return ptr_->MajorLinkerVersion; }
    uint8_t MinorLinkerVersion() const override { return ptr_->MinorLinkerVersion; }
    uint32_t SizeOfCode() const override { return ptr_->SizeOfCode; }
    uint32_t SizeOfInitializedData() const override { return ptr_->SizeOfInitializedData; }
    uint32_t SizeOfUninitializedData() const override { return ptr_->SizeOfUninitializedData; }
    guest_ptr<void> AddressOfEntryPoint() const override {
        return image_base_ + ptr_->AddressOfEntryPoint;
    }
    guest_ptr<void> BaseOfCode() const override { return image_base_ + ptr_->BaseOfCode; }
    guest_ptr<void> BaseOfData() const override {
        if constexpr (std::is_same_v<PtrType, uint64_t>) {
            return nullptr;
        } else {
            return image_base_ + ptr_->BaseOfData;
        }
    }
    uint64_t ImageBase() const override { return ptr_->ImageBase; }
    uint32_t SectionAlignment() const override { return ptr_->SectionAlignment; }
    uint32_t FileAlignment() const override { return ptr_->FileAlignment; }
    uint16_t MajorOperatingSystemVersion() const override {
        return ptr_->MajorOperatingSystemVersion;
    }
    uint16_t MinorOperatingSystemVersion() const override {
        return ptr_->MinorOperatingSystemVersion;
    }
    uint16_t MajorImageVersion() const override { return ptr_->MajorImageVersion; }
    uint16_t MinorImageVersion() const override { return ptr_->MinorImageVersion; }
    uint16_t MajorSubsystemVersion() const override { return ptr_->MajorSubsystemVersion; }
    uint16_t MinorSubsystemVersion() const override { return ptr_->MinorSubsystemVersion; }
    uint32_t Win32VersionValue() const override { return ptr_->Win32VersionValue; }
    uint32_t SizeOfImage() const override { return ptr_->SizeOfImage; }
    uint32_t SizeOfHeaders() const override { return ptr_->SizeOfHeaders; }
    uint32_t CheckSum() const override { return ptr_->CheckSum; }
    uint16_t Subsystem() const override { return ptr_->Subsystem; }
    uint16_t DllCharacteristics() const override { return ptr_->DllCharacteristics; }
    uint64_t SizeOfStackReserve() const override { return ptr_->SizeOfStackReserve; }
    uint64_t SizeOfStackCommit() const override { return ptr_->SizeOfStackCommit; }
    uint64_t SizeOfHeapReserve() const override { return ptr_->SizeOfHeapReserve; }
    uint64_t SizeOfHeapCommit() const override { return ptr_->SizeOfHeapCommit; }
    uint32_t LoaderFlags() const override { return ptr_->LoaderFlags; }
    uint32_t NumberOfRvaAndSizes() const override { return ptr_->NumberOfRvaAndSizes; }

    const structs::_IMAGE_DATA_DIRECTORY& data_directory(ImageDirectoryType type) const {
        introvirt_assert(type <= IMAGE_DIRECTORY_ENTRY_MAX, "");
        return ptr_->DataDirectory[type];
    }

    const IMAGE_RELOCATION_SECTION* basereloc_directory() const override {
        {
            std::lock_guard lock(basereloc_directory_init_);
            if (!basereloc_directory_) {
                const auto& dir =
                    data_directory(ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_BASERELOC);
                if (dir.VirtualAddress) {
                    const auto ptr = image_base_ + dir.VirtualAddress;
                    debug_directory_.emplace(image_base_, ptr, dir.Size);
                }
            }
        }

        if (basereloc_directory_)
            return &(*basereloc_directory_);

        return nullptr;
    }

    const IMAGE_DEBUG_DIRECTORY* debug_directory() const override {
        {
            std::lock_guard lock(debug_directory_init_);
            if (!debug_directory_) {
                const auto& dir = data_directory(ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_DEBUG);
                if (dir.VirtualAddress) {
                    const auto ptr = image_base_ + dir.VirtualAddress;
                    debug_directory_.emplace(image_base_, ptr, dir.Size);
                }
            }
        }

        if (debug_directory_)
            return &(*debug_directory_);

        return nullptr;
    }

    const IMAGE_EXCEPTION_SECTION* exception_directory() const override {
        {
            std::lock_guard lock(exception_directory_init_);
            if (!exception_directory_) {
                const auto& dir =
                    data_directory(ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_EXCEPTION);
                if (dir.VirtualAddress) {
                    const auto ptr = image_base_ + dir.VirtualAddress;
                    exception_directory_.emplace(image_base_, ptr, dir.Size);
                }
            }
        }

        if (exception_directory_)
            return &(*exception_directory_);

        return nullptr;
    }

    const IMAGE_EXPORT_DIRECTORY* export_directory() const override {
        {
            std::lock_guard lock(export_directory_init_);
            if (!export_directory_) {
                const auto& dir = data_directory(ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_EXPORT);
                if (dir.VirtualAddress) {
                    const auto ptr = image_base_ + dir.VirtualAddress;
                    export_directory_.emplace(image_base_, ptr, dir.Size, BaseOfCode(),
                                              SizeOfCode());
                }
            }
        }

        if (export_directory_)
            return &(*export_directory_);

        return nullptr;
    }

    const IMAGE_RESOURCE_DIRECTORY* resource_directory() const override {
        {
            std::lock_guard lock(resource_directory_init_);
            if (!resource_directory_) {
                const auto& dir =
                    data_directory(ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_RESOURCE);
                if (dir.VirtualAddress) {
                    const auto ptr = image_base_ + dir.VirtualAddress;
                    resource_directory_.emplace(image_base_, ptr, ptr);
                }
            }
        }

        if (resource_directory_)
            return &(*resource_directory_);

        return nullptr;
    }

    const IMPORT_NAME_TABLE* import_directory() const override {
        {
            std::lock_guard lock(import_directory_init_);
            if (!import_directory_) {
                const auto& dir = data_directory(ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_IMPORT);
                if (dir.VirtualAddress) {
                    import_directory_.emplace(image_base_, image_base_ + dir.VirtualAddress,
                                              dir.Size);
                }
            }
        }

        if (import_directory_)
            return &(*import_directory_);

        return nullptr;
    }

    inline guest_ptr<void> ptr() const override { return ptr_; }
    inline bool x64() const override { return std::is_same_v<PtrType, uint64_t>; }

    IMAGE_OPTIONAL_HEADER_IMPL(const guest_ptr<void>& image_base, const guest_ptr<void>& ptr)
        : image_base_(image_base), ptr_(ptr) {}

  private:
    const guest_ptr<void> image_base_;
    guest_ptr<structs::_IMAGE_OPTIONAL_HEADER<PtrType>> ptr_;

    mutable std::mutex basereloc_directory_init_;
    mutable std::optional<IMAGE_RELOCATION_SECTION_IMPL> basereloc_directory_;

    mutable std::mutex debug_directory_init_;
    mutable std::optional<IMAGE_DEBUG_DIRECTORY_IMPL> debug_directory_;

    mutable std::mutex exception_directory_init_;
    mutable std::optional<IMAGE_EXCEPTION_SECTION_IMPL> exception_directory_;

    mutable std::mutex export_directory_init_;
    mutable std::optional<IMAGE_EXPORT_DIRECTORY_IMPL> export_directory_;

    mutable std::mutex resource_directory_init_;
    mutable std::optional<IMAGE_RESOURCE_DIRECTORY_IMPL> resource_directory_;

    mutable std::mutex import_directory_init_;
    mutable std::optional<IMPORT_NAME_TABLE_IMPL<PtrType>> import_directory_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt