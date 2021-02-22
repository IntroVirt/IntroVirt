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
#include "MMVAD_IMPL.hh"

#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.win.nt.MMVAD"));

template <typename PtrType>
static void inorder(const NtKernelImpl<PtrType>& kernel, std::shared_ptr<const MMVAD> vad,
                    std::vector<std::shared_ptr<const MMVAD>>& tree) {

    if (vad->LeftChild() != nullptr) {
        inorder(kernel, vad->LeftChild(), tree);
    }

    tree.push_back(vad);

    if (vad->RightChild() != nullptr) {
        inorder(kernel, vad->RightChild(), tree);
    }
}

template <typename PtrType>
VadStructure MMVAD_IMPL<PtrType>::structure() const {
    // TODO (papes): Make sure this is complete
    if (Type() == VadType::VadNone) {
        if (Private()) {
            return VadStructure::MMVAD_SHORT;
        } else {
            return VadStructure::MMVAD;
        }
    } else if (Type() == VadType::VadDevicePhysicalMemory) {
        if (Private()) {
            return VadStructure::MMVAD;
        }
    } else if (Type() == VadType::VadImageMap) {
        if (!Private()) {
            return VadStructure::MMVAD;
        }
    }
    return VadStructure::UNKNOWN;
}

template <typename PtrType>
GuestVirtualAddress MMVAD_IMPL<PtrType>::FirstPrototypePte() const {
    if (structure() == VadStructure::MMVAD) {
        return gva_.create(mmvad_->FirstPrototypePte.get<PtrType>(buffer_));
    } else {
        return GuestVirtualAddress();
    }
}

template <typename PtrType>
GuestVirtualAddress MMVAD_IMPL<PtrType>::LastContiguousPte() const {
    if (structure() == VadStructure::MMVAD) {
        return gva_.create(mmvad_->LastContiguousPte.get<PtrType>(buffer_));
    } else {
        return GuestVirtualAddress();
    }
}

template <typename PtrType>
std::vector<std::shared_ptr<const MMVAD>> MMVAD_IMPL<PtrType>::VadTreeInOrder() const {
    std::lock_guard lock(mtx_);
    std::vector<std::shared_ptr<const MMVAD>> result;
    inorder<PtrType>(kernel_, this->shared_from_this(), result);
    return result;
}

template <typename PtrType>
uint64_t MMVAD_IMPL<PtrType>::StartingVpn() const {
    const uint64_t StartingVpnHigh =
        (mmvad_short_->StartingVpnHigh.exists())
            ? (static_cast<uint64_t>(mmvad_short_->StartingVpnHigh.get<uint8_t>(buffer_)) << 32)
            : 0;
    return (StartingVpnHigh | mmvad_short_->StartingVpn.get<uint32_t>(buffer_));
}

template <typename PtrType>
uint64_t MMVAD_IMPL<PtrType>::EndingVpn() const {
    const uint64_t EndingVpnHigh =
        (mmvad_short_->EndingVpnHigh.exists())
            ? (static_cast<uint64_t>(mmvad_short_->EndingVpnHigh.get<uint8_t>(buffer_)) << 32)
            : 0;
    return (EndingVpnHigh | mmvad_short_->EndingVpn.get<uint32_t>(buffer_));
}

template <typename PtrType>
uint64_t MMVAD_IMPL<PtrType>::CommitCharge() const {
    const uint64_t CommitChargeHigh =
        (mmvad_short_->CommitChargeHigh.exists())
            ? (static_cast<uint64_t>(mmvad_short_->CommitChargeHigh.get<uint8_t>(buffer_)) << 32)
            : 0;
    return (CommitChargeHigh | mmvad_short_->CommitCharge.get<uint32_t>(buffer_));
}

template <typename PtrType>
bool MMVAD_IMPL<PtrType>::MemCommit() const {
    return mmvad_short_->MemCommit.get<uint8_t>(buffer_);
}

template <typename PtrType>
MMVAD::VadType MMVAD_IMPL<PtrType>::Type() const {
    return type_;
}

template <typename PtrType>
PAGE_PROTECTION MMVAD_IMPL<PtrType>::Protection() const {
    return PAGE_PROTECTION::fromVadProtection(mmvad_short_->Protection.get<uint32_t>(buffer_));
}

template <typename PtrType>
const MEMORY_ALLOCATION_TYPE& MMVAD_IMPL<PtrType>::Allocation() const {
    return Allocation_;
}

template <typename PtrType>
const FILE_OBJECT* MMVAD_IMPL<PtrType>::FileObject() const {
    if (structure() == VadStructure::MMVAD) {
        std::lock_guard lock(mtx_);
        const CONTROL_AREA* control_area_ = ControlArea();
        if (control_area_ == nullptr) {
            return nullptr;
        }

        const FILE_OBJECT* fileObj = control_area_->FileObject();
        return fileObj;
    }
    return nullptr;
}

template <typename PtrType>
bool MMVAD_IMPL<PtrType>::Private() const {
    return mmvad_short_->PrivateMemory.get<uint64_t>(buffer_);
}

template <typename PtrType>
bool MMVAD_IMPL<PtrType>::locked() const {
    return mmvad_short_->PushLock.Locked.get_bitfield<uint8_t>(buffer_);
}

template <typename PtrType>
std::shared_ptr<const MMVAD> MMVAD_IMPL<PtrType>::Parent() const {
    // TODO:
    return nullptr;
}

template <typename PtrType>
std::shared_ptr<const MMVAD> MMVAD_IMPL<PtrType>::LeftChild() const {
    if (LeftChildPtr()) {
        return std::make_shared<MMVAD_IMPL<PtrType>>(kernel_, LeftChildPtr());
    }
    return nullptr;
}

template <typename PtrType>
std::shared_ptr<const MMVAD> MMVAD_IMPL<PtrType>::RightChild() const {
    if (RightChildPtr()) {
        return std::make_shared<MMVAD_IMPL<PtrType>>(kernel_, RightChildPtr());
    }
    return nullptr;
}

template <typename PtrType>
const CONTROL_AREA* MMVAD_IMPL<PtrType>::ControlArea() const {
    std::lock_guard lock(mtx_);

    if (!control_area_ && !Private()) {
        const GuestVirtualAddress pControlArea = ControlAreaPtr();
        if (pControlArea)
            control_area_.emplace(kernel_, pControlArea);
        else
            return nullptr;
    }
    return &(*control_area_);
}

template <typename PtrType>
GuestVirtualAddress MMVAD_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
std::string MMVAD_IMPL<PtrType>::tag() const {
    if constexpr (std::is_same_v<PtrType, uint64_t>) {
        // 64-bit
        return std::string(guest_ptr<char[]>(gva_ - 0xC, 4).get(), 4);
    } else {
        // 32-bit
        return std::string(guest_ptr<char[]>(gva_ - 0x4, 4).get(), 4);
    }
};

template <typename PtrType>
GuestVirtualAddress MMVAD_IMPL<PtrType>::ControlAreaPtr() const {
    // Map in the full version of MMVAD
    // TODO: This is kind of weird but we don't know if we can do this directly.
    //       Not sure why MMVAD_SHORT exists.
    guest_ptr<char[]> mmvad_buffer(gva_, mmvad_->size());

    if (mmvad_->Subsection.exists()) {
        // Vista+
        // Map in the SUBSECTION structure the MMVAD points to
        const GuestVirtualAddress pSubsection =
            gva_.create(mmvad_->Subsection.get<PtrType>(mmvad_buffer));
        if (!pSubsection)
            return GuestVirtualAddress();

        guest_ptr<char[]> subsection_buffer(pSubsection, subsection_->size());
        return gva_.create(subsection_->ControlArea.get<PtrType>(subsection_buffer));
    } else {
        // XP
        // The MMVAD structure directly points to the CONTROL_AREA pointer
        return gva_.create(mmvad_->ControlArea.get<PtrType>(mmvad_buffer));
    }
}

template <typename PtrType>
inline GuestVirtualAddress MMVAD_IMPL<PtrType>::LeftChildPtr() const {
    return gva_.create(mmvad_short_->LeftChild.get<PtrType>(buffer_));
}

template <typename PtrType>
inline GuestVirtualAddress MMVAD_IMPL<PtrType>::RightChildPtr() const {
    return gva_.create(mmvad_short_->RightChild.get<PtrType>(buffer_));
}

template <typename PtrType>
MMVAD_IMPL<PtrType>::MMVAD_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva)
    : kernel_(kernel), gva_(gva) {

    // Load our structure offsets
    mmvad_short_ = LoadOffsets<structs::MMVAD_SHORT>(kernel);
    mmvad_ = LoadOffsets<structs::MMVAD>(kernel);
    subsection_ = LoadOffsets<structs::SUBSECTION>(kernel);

    // Map in the structure. Doing one mapping is a lot cheaper than mapping every field.
    buffer_.reset(gva, mmvad_short_->size());

    // Set the type field
    if (mmvad_short_->VadType.exists()) {
        // Vista and up, it's just a field we can read
        type_ = static_cast<MMVAD::VadType>(mmvad_short_->VadType.get<uint32_t>(buffer_));

        // Set some flags based on the type
        switch (type_) {
        case MMVAD_IMPL<PtrType>::VadLargePages:
        case MMVAD_IMPL<PtrType>::VadLargePageSection:
            Allocation_.MEM_LARGE_PAGES(true);
            break;
        case MMVAD_IMPL<PtrType>::VadDevicePhysicalMemory:
            Allocation_.MEM_PHYSICAL(true);
            break;
        default:
            // Don't do anything
            break;
        }

        if (CommitCharge() == 0) {
            Allocation_.MEM_RESERVE(true);
        } else if (MemCommit()) {
            Allocation_.MEM_COMMIT(true);
        }

        if (Private()) {
            Allocation_.MEM_PRIVATE(true);
        } else {
            Allocation_.MEM_MAPPED(true);
        }
    } else {
        // XP, there's no type field, so we figure it out based on the flags
        if (mmvad_short_->ImageMap.get<uint8_t>(buffer_)) {
            type_ = MMVAD::VadImageMap;
        } else if (mmvad_short_->PhysicalMapping.get<uint8_t>(buffer_)) {
            type_ = MMVAD::VadDevicePhysicalMemory;
        }
    }
}

template <typename PtrType>
uint64_t MMVAD_IMPL<PtrType>::RegionSize() const {
    return (EndingVpn() - StartingVpn() + 1) * 0x1000;
}

template <typename PtrType>
GuestVirtualAddress MMVAD_IMPL<PtrType>::StartingAddress() const {
    return address().create(StartingVpn() << 12ull);
}

template <typename PtrType>
GuestVirtualAddress MMVAD_IMPL<PtrType>::EndingAddress() const {
    return address().create((EndingVpn() << 12ull) | 0xFFF);
}

template <typename PtrType>
std::shared_ptr<const MMVAD> MMVAD_IMPL<PtrType>::search(const GuestVirtualAddress& gva) const {
    std::set<uint64_t> seen;
    return search(gva, seen);
}

template <typename PtrType>
std::shared_ptr<const MMVAD> MMVAD_IMPL<PtrType>::search(const GuestVirtualAddress& gva,
                                                         std::set<uint64_t>& seen) const {
    // Make sure we weren't already at this node
    const uint64_t my_addr = address().virtual_address();
    if (seen.count(my_addr)) {
        // Been here
        return nullptr;
    }
    // Add ourselves to the seen list
    seen.insert(my_addr);

    // Convert the address to a virtual page number
    const uint64_t vpn = gva.page_number();

    // Is it a lower range? Go left.
    if (vpn < StartingVpn()) {
        auto left = std::static_pointer_cast<const MMVAD_IMPL<PtrType>>(LeftChild());
        if (left == nullptr) {
            return nullptr; // No lower addresses
        }
        return left->search(gva, seen);
    }

    // Is it a higher range? Go right.
    if (vpn > EndingVpn()) {
        auto right = std::static_pointer_cast<const MMVAD_IMPL<PtrType>>(RightChild());
        if (right == nullptr) {
            return nullptr; // No higher addresses
        }
        return right->search(gva, seen);
    }

    // Neither lower nor higher, must be a match
    return this->shared_from_this();
}

const static std::string VadNoneStr = "VadNone";
const static std::string VadDevicePhysicalMemoryStr = "VadDevicePhysicalMemory";
const static std::string VadImageMapStr = "VadImageMap";
const static std::string VadAweStr = "VadAwe";
const static std::string VadWriteWatchStr = "VadWriteWatch";
const static std::string VadLargePagesStr = "VadLargePages";
const static std::string VadRotatePhysicalStr = "VadRotatePhysical";
const static std::string VadLargePageSectionStr = "VadLargePageSection";
const static std::string UnknownStr = "Unknown";

const std::string& to_string(MMVAD::VadType type) {
    switch (type) {
    case MMVAD::VadType::VadNone:
        return VadNoneStr;
    case MMVAD::VadType::VadDevicePhysicalMemory:
        return VadDevicePhysicalMemoryStr;
    case MMVAD::VadType::VadImageMap:
        return VadImageMapStr;
    case MMVAD::VadType::VadAwe:
        return VadAweStr;
    case MMVAD::VadType::VadWriteWatch:
        return VadWriteWatchStr;
    case MMVAD::VadType::VadLargePages:
        return VadLargePagesStr;
    case MMVAD::VadType::VadRotatePhysical:
        return VadRotatePhysicalStr;
    case MMVAD::VadType::VadLargePageSection:
        return VadLargePageSectionStr;
    default:
        break;
    }

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, MMVAD::VadType type) {
    os << to_string(type);
    return os;
}

const std::string& to_string(VadStructure structure) {
    static const std::string MMVAD_SHORT_STR("MMVAD_SHORT");
    static const std::string MMVAD_STR("MMVAD");
    static const std::string UNKNOWN_STR("UNKNOWN");

    switch (structure) {
    case VadStructure::MMVAD_SHORT:
        return MMVAD_SHORT_STR;
    case VadStructure::MMVAD:
        return MMVAD_STR;
    case VadStructure::UNKNOWN:
        return UNKNOWN_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, VadStructure structure) {
    os << to_string(structure);
    return os;
}

template class MMVAD_IMPL<uint32_t>;
template class MMVAD_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
