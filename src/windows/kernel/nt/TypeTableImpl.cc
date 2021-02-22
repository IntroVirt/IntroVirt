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

#include "TypeTableImpl.hh"
#include "NtKernelImpl.hh"

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/MemoryException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/json/json.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/exception/IncorrectTypeException.hh>
#include <introvirt/windows/exception/SymbolNotFoundException.hh>
#include <introvirt/windows/exception/TypeInformationException.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_TYPE.hh>

#include <log4cxx/logger.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <map>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.ObTypeIndexTable"));

template <typename PtrType>
int TypeTableImpl<PtrType>::parseObjectTypeTable(const GuestVirtualAddress& pObTypeIndexTable) {

    // Starting off after the three we pre-populate
    unsigned int idx = 3;

    // Arbitrary number that we should never reach
    while (idx < MaxTableSize) {
        // Get the address of the entry we want to read
        GuestVirtualAddress ppObjectType = pObTypeIndexTable + (sizeof(PtrType) * idx);

        try {
            // Read the entry. If it's 0, we're at the end of the table.
            guest_ptr<PtrType> pObjectType(ppObjectType);
            if (*pObjectType == 0) {
                return idx;
            }

            // Parse the object and print some information
            auto type = OBJECT_TYPE::make_shared(kernel_, pObTypeIndexTable.create(*pObjectType));
            LOG4CXX_DEBUG(logger,
                          "Found type " << static_cast<int>(type->Index()) << ": " << type->Name());

            ObjectType obtype = object_type_from_name(type->Name());

            to_normalized_.at(type->Index()) = obtype;
            to_native_.at(static_cast<size_t>(obtype)) = type->Index();
            type_table_.at(type->Index()) = std::move(type);
        } catch (introvirt::MemoryException& ex) {
            LOG4CXX_DEBUG(logger, "Failed to read object at index " << idx << ": " << ex.what());
        }

        ++idx;
    }

    throw GuestDetectionException(kernel_.guest().domain(), "Failed to parse ObTypeIndexTable");
}

template <typename PtrType>
ObjectType TypeTableImpl<PtrType>::normalize(uint32_t type) const {
    if (unlikely(table_size_ < type))
        throw IncorrectTypeException("Type index out of range: " + std::to_string(type));

    return to_normalized_[type];
}

template <typename PtrType>
ObjectType TypeTableImpl<PtrType>::normalize(const GuestVirtualAddress& address) const {
    auto iter = xp_to_normalized_.find(address.virtual_address());
    if (iter != xp_to_normalized_.end()) {
        return iter->second;
    }

    auto type = OBJECT_TYPE::make_shared(kernel_, address);
    const ObjectType index = normalize(type->Index());

    xp_to_normalized_[address.virtual_address()] = index;
    return index;
}

template <typename PtrType>
uint32_t TypeTableImpl<PtrType>::native(ObjectType type) const {
    return to_native_.at(static_cast<size_t>(type));
}

template <typename PtrType>
const OBJECT_TYPE& TypeTableImpl<PtrType>::type(uint8_t TypeIndex) const {
    try {
        const auto* result = type_table_.at(TypeIndex).get();
        if (unlikely(result == nullptr)) {
            throw TypeInformationException("Invalid TypeIndex");
        }
        type_table_.at(TypeIndex);
        return *result;
    } catch (std::out_of_range& ex) {
        throw TypeInformationException("TypeIndex out of range");
    }
}

static constexpr unsigned int JsonVersion = 1;

template <typename PtrType>
bool TypeTableImpl<PtrType>::load_from_json() {
    // Open the file
    std::ifstream file(kernel_.profile_path() + "/object_table.json", std::ifstream::binary);
    if (!file.good())
        return false;

    // Parse it
    Json::Value root;
    file >> root;

    // Check the version
    if (!root.isMember("version"))
        return false;
    if (root["version"].asUInt() != JsonVersion)
        return false;

    // Load the values
    if (!root.isMember("type_table"))
        return false;

    unsigned int imported = 0;

    Json::Value type_table = root["type_table"];
    for (auto iter = type_table.begin(); iter != type_table.end(); ++iter) {
        ObjectType type = object_type_from_name(iter.key().asString());
        uint32_t index = (*iter).asUInt();

        if (unlikely(index >= MaxTableSize)) {
            LOG4CXX_WARN(logger, "Bad object table file. Found index ==" << index);
            return false;
        }

        to_normalized_[index] = type;
        to_native_[static_cast<size_t>(type)] = index;
        table_size_ = std::max(table_size_, index);

        ++imported;
    }

    if (unlikely(imported < 5)) {
        LOG4CXX_WARN(logger, "Bad object table file. Only imported " << imported << " entries");
        return false;
    }

    LOG4CXX_DEBUG(logger, "Loaded type table from file");

    return true; // TODO
}

template <typename PtrType>
void TypeTableImpl<PtrType>::save_to_json() const {
    // Open the file
    std::ofstream file(kernel_.profile_path() + "/object_table.json",
                       std::ofstream::binary | std::ofstream::trunc);

    if (!file.good())
        return;

    // Build the JSON
    Json::Value root;
    root["version"] = JsonVersion;

    Json::Value type_table;
    for (unsigned int index = 0; index < MaxTableSize; ++index) {
        ObjectType type = to_normalized_[index];
        if (type != ObjectType::Unknown)
            type_table[to_string(type)] = index;
    }

    root["type_table"] = std::move(type_table);

    file << root;

    LOG4CXX_DEBUG(logger, "Saved type table to file");
}

template <typename PtrType>
TypeTableImpl<PtrType>::TypeTableImpl(const NtKernelImpl<PtrType>& kernel) : kernel_(kernel) {
    // Default to "Unknown"
    to_normalized_.fill(ObjectType::Unknown);
    to_native_.fill(1);

    // First, try to just load a cached profile
    // if (load_from_json())
    //    return;

    // The first three types are always the same, so we can bootstrap those.
    // Bootstrap the first two entries
    to_normalized_[0] = ObjectType::None;
    to_normalized_[1] = ObjectType::Unknown;
    to_normalized_[2] = ObjectType::Type;
    to_native_[static_cast<size_t>(ObjectType::None)] = 0;
    to_native_[static_cast<size_t>(ObjectType::Unknown)] = 1;
    to_native_[static_cast<size_t>(ObjectType::Type)] = 2;

    table_size_ = 3;

    if (kernel.MajorVersion() == 5) {
        LOG4CXX_DEBUG(logger, "Initializing XP object types");
        // XP is different and has no ObTypeIndexTable.
        // The numbers are static, so we can just put them in here.
        to_normalized_[0] = ObjectType::Unknown;
        to_normalized_[1] = ObjectType::Type;
        to_normalized_[2] = ObjectType::Directory;
        to_normalized_[3] = ObjectType::SymbolicLink;
        to_normalized_[4] = ObjectType::Token;
        to_normalized_[5] = ObjectType::Process;
        to_normalized_[6] = ObjectType::Thread;
        to_normalized_[7] = ObjectType::Job;
        to_normalized_[8] = ObjectType::DebugObject;
        to_normalized_[9] = ObjectType::Event;
        to_normalized_[10] = ObjectType::EventPair;
        to_normalized_[11] = ObjectType::Mutant;
        to_normalized_[12] = ObjectType::Callback;
        to_normalized_[13] = ObjectType::Semaphore;
        to_normalized_[14] = ObjectType::Timer;
        to_normalized_[15] = ObjectType::Profile;
        to_normalized_[16] = ObjectType::KeyedEvent;
        to_normalized_[17] = ObjectType::WindowStation;
        to_normalized_[18] = ObjectType::Desktop;
        to_normalized_[19] = ObjectType::Section;
        to_normalized_[20] = ObjectType::Key;
        to_normalized_[21] = ObjectType::Port;
        to_normalized_[22] = ObjectType::WaitablePort;
        to_normalized_[23] = ObjectType::Adapter;
        to_normalized_[24] = ObjectType::Controller;
        to_normalized_[25] = ObjectType::Device;
        to_normalized_[26] = ObjectType::Driver;
        to_normalized_[27] = ObjectType::IoCompletion;
        to_normalized_[28] = ObjectType::File;
        to_normalized_[29] = ObjectType::WmiGuid;
        to_normalized_[30] = ObjectType::FilterConnectionPort;
        to_normalized_[31] = ObjectType::FilterCommunicationPort;
        table_size_ = 32;

        // Load the reverse table
        for (unsigned int i = 0; i < table_size_; ++i) {
            ObjectType index = to_normalized_[i];
            to_native_[static_cast<size_t>(index)] = i;
        }

        // Load the initial object type
        const uint32_t pTypeObject = *guest_ptr<uint32_t>(kernel.symbol("ObpTypeObjectType"));
        xp_to_normalized_[pTypeObject] = ObjectType::Type;

        // We don't want to save this to a file for XP
        return;
    }

    try {
        const GuestVirtualAddress pObTypeIndexTable = kernel.symbol("ObTypeIndexTable");
        table_size_ = parseObjectTypeTable(pObTypeIndexTable);
        LOG4CXX_DEBUG(logger, "ObTypeIndexTable initialized: " << table_size_ << " entries");
    } catch (SymbolNotFoundException& ex) {
        throw GuestDetectionException(kernel.guest().domain(), "Failed to find ObTypeIndexTable");
    }

    // save_to_json();
}

template class TypeTableImpl<uint32_t>;
template class TypeTableImpl<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt