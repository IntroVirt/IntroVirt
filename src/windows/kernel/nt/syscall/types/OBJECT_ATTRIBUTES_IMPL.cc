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
#include "OBJECT_ATTRIBUTES_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE.hh>
#include <introvirt/windows/kernel/nt/types/KPCR.hh>
#include <introvirt/windows/kernel/nt/types/UNICODE_STRING.hh>
#include <introvirt/windows/kernel/nt/types/objects/CM_KEY_BODY.hh>
#include <introvirt/windows/kernel/nt/types/objects/FILE_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>

#include <boost/io/ios_state.hpp>

#include <log4cxx/logger.h>

#include <cstring>
#include <memory>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.OBJECT_ATTRIBUTES"));

template <typename PtrType>
const std::string& OBJECT_ATTRIBUTES_IMPL<PtrType>::FullPath(const KPCR& kpcr) const {
    if (full_path_.empty()) {
        if (RootDirectory() != 0u) {
            auto table = kpcr.CurrentThread().Process().ObjectTable();
            auto object = table->Object(RootDirectory());
            if (object != nullptr) {
                switch (object->header().type()) {
                case ObjectType::Key:
                    generateFullPathForKey(object);
                    break;
                case ObjectType::File:
                    generateFullPathForFile(object);
                    break;
                default:
                    break;
                }
            }
        }

        full_path_ += ObjectName();
    }
    return full_path_;
}

template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::generateFullPathForKey(
    std::shared_ptr<const OBJECT>& object) const {
    const auto* obj = dynamic_cast<const CM_KEY_BODY*>(object.get());
    full_path_ = obj->full_key_path();
    full_path_ += "\\";
}

template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::generateFullPathForFile(
    std::shared_ptr<const OBJECT>& object) const {
    const auto* obj = dynamic_cast<const FILE_OBJECT*>(object.get());
    full_path_ = obj->FileName();
    full_path_ += "\\";
}

template <typename PtrType>
std::string OBJECT_ATTRIBUTES_IMPL<PtrType>::ObjectName() const {
    if (!ObjectName_) {
        return std::string();
    }
    return ObjectName_->utf8();
}

template <typename PtrType>
uint64_t OBJECT_ATTRIBUTES_IMPL<PtrType>::RootDirectory() const {
    return header_->RootDirectory;
}

template <typename PtrType>
bool OBJECT_ATTRIBUTES_IMPL<PtrType>::isInheritable() const {
    return (header_->Attributes & 0x00000002L);
}

template <typename PtrType>
HANDLE_ATTRIBUTES OBJECT_ATTRIBUTES_IMPL<PtrType>::Attributes() const {
    return header_->Attributes;
}

template <typename PtrType>
uint32_t OBJECT_ATTRIBUTES_IMPL<PtrType>::Length() const {
    return header_->Length;
}

template <typename PtrType>
SECURITY_DESCRIPTOR* OBJECT_ATTRIBUTES_IMPL<PtrType>::SecurityDescriptor() {
    const auto* const_this = this;
    return const_cast<SECURITY_DESCRIPTOR*>(const_this->SecurityDescriptor());
}

template <typename PtrType>
const SECURITY_DESCRIPTOR* OBJECT_ATTRIBUTES_IMPL<PtrType>::SecurityDescriptor() const {
    if (!SecurityDescriptor_)
        return nullptr;
    return &(*SecurityDescriptor_);
}

template <typename PtrType>
SECURITY_QUALITY_OF_SERVICE* OBJECT_ATTRIBUTES_IMPL<PtrType>::SecurityQualityOfService() {
    if (SecurityQualityOfService_)
        return &(*SecurityQualityOfService_);
    return nullptr;
}

template <typename PtrType>
const SECURITY_QUALITY_OF_SERVICE*
OBJECT_ATTRIBUTES_IMPL<PtrType>::SecurityQualityOfService() const {
    if (SecurityQualityOfService_)
        return &(*SecurityQualityOfService_);
    return nullptr;
}

template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::ObjectNamePtr(const GuestVirtualAddress& pUnicodeString) {
    header_->ObjectName = pUnicodeString.virtual_address();
    if (header_->ObjectName) {
        ObjectName_.emplace(pUnicodeString);
    }
}

template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::SecurityQualityOfServicePtr(
    uint64_t pSecurityQualityOfService) {
    header_->SecurityQualityOfService = pSecurityQualityOfService;
    if (header_->SecurityQualityOfService) {
        SecurityQualityOfService_.emplace(gva_.create(header_->SecurityQualityOfService));
    } else {
        SecurityQualityOfService_.reset();
    }
}

template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::RootDirectory(uint64_t RootDirectory) {
    header_->RootDirectory = RootDirectory;
}

template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::ObjectName(const std::string& objectName) {
    if (ObjectName_) {
        ObjectName_->set(objectName);
    }
}

template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::Inheritable(bool Inheritable) {
    if (Inheritable) {
        header_->Attributes |= 0x00000002L;
    } else {
        header_->Attributes &= ~0x00000002L;
    }
}

template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::Attributes(HANDLE_ATTRIBUTES Attributes) {
    header_->Attributes = Attributes;
}

// If 0xFFFFFFFF, set the correct length
template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::Length(uint32_t Length) {
    if (Length == 0xFFFFFFFF) {
        header_->Length = sizeof(structs::_OBJECT_ATTRIBUTES<PtrType>);
    } else {
        header_->Length = Length;
    }
}

template <typename PtrType>
GuestVirtualAddress OBJECT_ATTRIBUTES_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
OBJECT_ATTRIBUTES_IMPL<PtrType>::OBJECT_ATTRIBUTES_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), header_(gva_) {

    if (header_->ObjectName) {
        ObjectName_.emplace(gva_.create(header_->ObjectName));
    }

    if (header_->SecurityDescriptor) {
        SecurityDescriptor_.emplace(gva_.create(header_->SecurityDescriptor));
    }

    if (header_->SecurityQualityOfService) {
        SecurityQualityOfService_.emplace(gva_.create(header_->SecurityQualityOfService));
    }
}

template <typename PtrType>
void OBJECT_ATTRIBUTES_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    if (RootDirectory() != 0u) {
        boost::io::ios_flags_saver ifs(os);
        os << std::hex;
        os << linePrefix << "Root Directory: 0x" << RootDirectory() << '\n';
    }
    if (!ObjectName().empty()) {
        os << linePrefix << "Object Name: " << ObjectName() << '\n';
    }
    os << linePrefix << "Attributes: " << to_string(Attributes()) << '\n';
}

template <typename PtrType>
Json::Value OBJECT_ATTRIBUTES_IMPL<PtrType>::json() const {
    Json::Value result;

    result["RootDirectory"] = RootDirectory();
    result["ObjectName"] = ObjectName();
    result["Attributes"] = Attributes();

    return result;
}

std::unique_ptr<OBJECT_ATTRIBUTES> OBJECT_ATTRIBUTES::make_unique(const NtKernel& kernel,
                                                                  const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_unique<OBJECT_ATTRIBUTES_IMPL<uint64_t>>(gva);
    else
        return std::make_unique<OBJECT_ATTRIBUTES_IMPL<uint32_t>>(gva);
}

template class OBJECT_ATTRIBUTES_IMPL<uint32_t>;
template class OBJECT_ATTRIBUTES_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */

namespace inject {

GuestAllocation<windows::nt::OBJECT_ATTRIBUTES>::GuestAllocation() {
    using namespace windows::nt;

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<windows::WindowsGuest*>(domain.guest());
    assert(guest != nullptr);
    auto& kernel = guest->kernel();

    // Get the size required for the structure
    const size_t structure_size = (kernel.x64()) ? sizeof(structs::_OBJECT_ATTRIBUTES<uint64_t>)
                                                 : sizeof(structs::_OBJECT_ATTRIBUTES<uint32_t>);

    // Allocate memory for the size of the structure plus the size of the string
    buffer_.emplace(structure_size);

    // Zero the buffer
    memset(buffer_->get(), 0, structure_size);

    // Create the string
    value_ = OBJECT_ATTRIBUTES::make_unique(kernel, buffer_->address());

    // Properly initialize the length
    value_->Length(structure_size);
}

} /* namespace inject */
} /* namespace introvirt */
