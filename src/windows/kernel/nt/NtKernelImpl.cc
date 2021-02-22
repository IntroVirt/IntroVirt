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
#include "NtKernelImpl.hh"

#include "windows/kernel/nt/types/HANDLE_TABLE_IMPL.hh"
#include "windows/kernel/nt/types/LDR_DATA_TABLE_ENTRY_IMPL.hh"

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/exception/SymbolNotFoundException.hh>
#include <introvirt/windows/kernel/ServiceDescriptorTable.hh>
#include <introvirt/windows/kernel/nt/types/CLIENT_ID.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE_ENTRY.hh>
#include <introvirt/windows/kernel/nt/types/objects/DEVICE_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/DRIVER_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_DIRECTORY.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER_NAME_INFO.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_SYMBOLIC_LINK.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>

#include <introvirt/util/compiler.hh>

#include "windows/kernel/nt/util/ListParser.hh"

#include <mspdb/PDB.hh>
#include <mspdb/pdb_exception.hh>

#include <boost/algorithm/string.hpp>
#include <log4cxx/logger.h>

#if __GNUC__ >= 8
#include <filesystem>
namespace filesystem = std::filesystem;
#else
#include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#endif

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.NtKernel"));

template <typename PtrType>
GuestVirtualAddress NtKernelImpl<PtrType>::symbol(const std::string& name) const {
    const auto* symbol = pe_->pdb().name_to_symbol(name);
    if (!symbol)
        throw SymbolNotFoundException(name);
    return base_address_ + symbol->image_offset();
}

template <typename PtrType>
std::unique_ptr<HANDLE_TABLE> NtKernelImpl<PtrType>::CidTable() {
    const auto* const_this = this;
    auto const_result = const_this->CidTable();
    return std::unique_ptr<HANDLE_TABLE>(const_cast<HANDLE_TABLE*>(const_result.release()));
}

template <typename PtrType>
std::unique_ptr<const HANDLE_TABLE> NtKernelImpl<PtrType>::CidTable() const {
    auto ppPspCidTable = symbol("PspCidTable");
    GuestVirtualAddress pPspCidTable = ppPspCidTable.create(*guest_ptr<PtrType>(ppPspCidTable));
    return std::make_unique<const HANDLE_TABLE_IMPL<PtrType>>(*this, pPspCidTable, true);
}

template <typename PtrType>
std::shared_ptr<OBJECT_DIRECTORY> NtKernelImpl<PtrType>::RootDirectoryObject() const {
    auto pObpRootDirectoryObject = symbol("ObpRootDirectoryObject");
    GuestVirtualAddress ObpRootDirectoryObject =
        pObpRootDirectoryObject.create(*guest_ptr<PtrType>(pObpRootDirectoryObject));

    return OBJECT_DIRECTORY::make_shared(*this, ObpRootDirectoryObject);
}

template <typename PtrType>
std::vector<std::shared_ptr<const LDR_DATA_TABLE_ENTRY>>
NtKernelImpl<PtrType>::PsLoadedModuleList() const {
    const auto* offsets = LoadOffsets<structs::LDR_DATA_TABLE_ENTRY>(*this);
    const uint16_t list_offset = offsets->InLoadOrderLinks.offset();

    auto pPsLoadedModuleList = symbol("PsLoadedModuleList");

    // TODO: Create IMPL class forLDR_DATA_TABLE_ENTRY so we can create it directly
    std::vector<std::shared_ptr<const LDR_DATA_TABLE_ENTRY>> result;
    std::vector<GuestVirtualAddress> addresses;

    // Parse all of the structure addresses
    if constexpr (is64Bit()) {
        addresses = parse_list_ptrtype<uint64_t>(pPsLoadedModuleList, list_offset);
    } else {
        addresses = parse_list_ptrtype<uint32_t>(pPsLoadedModuleList, list_offset);
    }

    // Create the entries
    for (const GuestVirtualAddress& addr : addresses) {
        result.emplace_back(std::make_shared<LDR_DATA_TABLE_ENTRY_IMPL<PtrType>>(addr));
    }
    return result;
}

template <typename PtrType>
void NtKernelImpl<PtrType>::reparse_drive_letters() {
    drive_letters_.clear();

    // Holds our search result
    std::string result;

    auto globalDir = OBJECT_DIRECTORY::make_shared(*this, global_directory_address_);
    for (const std::shared_ptr<OBJECT>& object : globalDir->objects()) {
        try {
            const OBJECT_HEADER& hdr = object->header();
            if (hdr.type() != ObjectType::SymbolicLink)
                continue; // We only care about symbolic links

            // Object has to be named
            if (!hdr.has_name_info())
                continue;

            std::string name(hdr.NameInfo().Name());
            if (name.length() != 2 || name[1] != ':')
                continue; // Doesn't look like a drive letter

            boost::to_upper(name);
            if (!(name[0] >= 'A' && name[0] <= 'Z'))
                continue; // First character isnt a letter

            // Check to see if this is our result
            const auto* symLink = dynamic_cast<const OBJECT_SYMBOLIC_LINK*>(object.get());
            std::string target = boost::to_lower_copy(symLink->LinkTarget());
            LOG4CXX_DEBUG(logger, "Found drive " << name << " -> " << target)
            drive_letters_[target] = symLink->address();
        } catch (VirtualAddressNotPresentException& ex) {
            LOG4CXX_DEBUG(logger, ex.what());
        }
    }
}

template <typename PtrType>
std::string NtKernelImpl<PtrType>::get_device_drive_letter(const nt::DEVICE_OBJECT& device) const {
    switch (device.DeviceType()) {
    case DeviceType::FILE_DEVICE_DISK:
    case DeviceType::FILE_DEVICE_CD_ROM:
        break;
    default:
        // Not a device that will have a drive letter
        return "";
    }

    std::lock_guard lock(drive_letters_mtx_);

    const std::string device_path("\\device\\" + boost::to_lower_copy(device.DeviceName()));

    auto iter = drive_letters_.find(device_path);
    if (iter != drive_letters_.end()) {
        // Possible match
        const GuestVirtualAddress& pSymbolicLink = iter->second;
        try {
            auto symbolicLink = OBJECT_SYMBOLIC_LINK::make_shared(*this, pSymbolicLink);
            return symbolicLink->header().NameInfo().Name();
        } catch (...) {
        }
    }

    // Didn't exist in our table, or the data was no longer valid
    // Update the entire table
    LOG4CXX_DEBUG(logger, "Reparsing drive letters for " << device_path);
    const_cast<NtKernelImpl<PtrType>*>(this)->reparse_drive_letters();

    // Look again
    iter = drive_letters_.find(device_path);
    if (iter != drive_letters_.end()) {
        // Possible match
        const GuestVirtualAddress& pSymbolicLink = iter->second;
        try {
            auto symbolicLink = OBJECT_SYMBOLIC_LINK::make_shared(*this, pSymbolicLink);
            return symbolicLink->header().NameInfo().Name();
        } catch (...) {
        }
    }

    return "";
}

template <typename PtrType>
const ServiceDescriptorTable& NtKernelImpl<PtrType>::KeServiceDescriptorTable() const {
    return *KeServiceDescriptorTable_;
}

template <typename PtrType>
const ServiceDescriptorTable& NtKernelImpl<PtrType>::KeServiceDescriptorTableShadow() const {
    return *KeServiceDescriptorTableShadow_;
}

template <typename PtrType>
unsigned int NtKernelImpl<PtrType>::cpu_count() const {
    return cpu_count_;
}

template <typename PtrType>
const TypeTable& NtKernelImpl<PtrType>::types() const {
    return *type_table_;
}

template <typename PtrType>
bool NtKernelImpl<PtrType>::hasObHeaderCookie() const {
    return hasObHeaderCookie_;
}

template <typename PtrType>
uint8_t NtKernelImpl<PtrType>::ObHeaderCookie() const {
    return ObHeaderCookie_;
}

template <typename PtrType>
const WindowsGuest& NtKernelImpl<PtrType>::guest() const {
    return guest_;
}

template <typename PtrType>
KPCR& NtKernelImpl<PtrType>::kpcr(const Vcpu& vcpu) {
    return kpcrs_[vcpu.id()];
}

template <typename PtrType>
const KPCR& NtKernelImpl<PtrType>::kpcr(const Vcpu& vcpu) const {
    return kpcrs_[vcpu.id()];
}

template <typename PtrType>
const nt::NtBuildLab& NtKernelImpl<PtrType>::NtBuildLab() const {
    return *NtBuildLab_;
}

template <typename PtrType>
uint16_t NtKernelImpl<PtrType>::NtBuildNumber() const {
    return NtBuildNumber_;
}

template <typename PtrType>
uint16_t NtKernelImpl<PtrType>::MajorVersion() const {
    return MajorVersion_;
}

template <typename PtrType>
uint16_t NtKernelImpl<PtrType>::MinorVersion() const {
    return MinorVersion_;
}

template <typename PtrType>
bool NtKernelImpl<PtrType>::x64() const {
    return is64Bit();
}

template <typename PtrType>
const pe::PE& NtKernelImpl<PtrType>::pe() const {
    return *pe_;
}

template <typename PtrType>
const mspdb::PDB& NtKernelImpl<PtrType>::pdb() const {
    return pe().pdb();
}

template <typename PtrType>
GuestVirtualAddress NtKernelImpl<PtrType>::base_address() const {
    return base_address_;
}

template <typename PtrType>
const DBGKD_GET_VERSION64& NtKernelImpl<PtrType>::KdVersionBlock() const {

    return *KdVersionBlock_;
}

template <typename PtrType>
const KDDEBUGGER_DATA64& NtKernelImpl<PtrType>::KdDebuggerDataBlock() const {
    return *KdDebuggerDataBlock_;
}

template <typename PtrType>
uint64_t NtKernelImpl<PtrType>::InvalidPteMask() const {
    return InvalidPteMask_;
}

template <typename PtrType>
std::shared_ptr<nt::THREAD>
NtKernelImpl<PtrType>::thread(const GuestVirtualAddress& address) const {
    std::lock_guard lock(threads_.mtx_);

    // TODO (papes): Need a way of expiring invalid weak pointers

    // Check if we already have an entry in the map
    auto iter = threads_.map_.find(address.value());
    if (iter != threads_.map_.end()) {
        // Yep, check if it's valid
        auto [tid, thread] = iter->second;
        if (thread->Cid().UniqueThread() == tid)
            return thread;
    }

    // Nope, create one
    auto result = nt::THREAD::make_shared(*this, address);
    threads_.map_[address.value()] = std::make_pair(result->Cid().UniqueThread(), result);

    return result;
}

template <typename PtrType>
std::shared_ptr<nt::PROCESS>
NtKernelImpl<PtrType>::process(const GuestVirtualAddress& address) const {
    std::lock_guard<decltype(procs_.mtx_)> lock(procs_.mtx_);

    // TODO (papes): Need a way of expiring invalid weak pointers

    // Check if we already have an entry in the map
    auto iter = procs_.map_.find(address.value());
    if (iter != procs_.map_.end()) {
        // Yep, check if it's valid
        auto [pid, proc] = iter->second;
        if (proc->UniqueProcessId() == pid)
            return proc;
    }

    // Nope, create one
    auto result = nt::PROCESS::make_shared(*this, address);
    procs_.map_[address.value()] = std::make_pair(result->UniqueProcessId(), result);
    return result;
}

template <typename PtrType>
std::string NtKernelImpl<PtrType>::profile_path() const {
    const auto* debug_directory = pe_->optional_header().debug_directory();
    assert(debug_directory->Type() == pe::ImageDebugType::IMAGE_DEBUG_TYPE_CODEVIEW);
    const auto* cv_data = debug_directory->codeview_data();

    std::string pdb_identifier = boost::to_upper_copy(cv_data->PdbIdentifier());
    return "/var/lib/introvirt/profiles/windows/" + cv_data->PdbFileName() + "/" + pdb_identifier +
           "/";
}

template <typename PtrType>
NtKernelImpl<PtrType>::NtKernelImpl(WindowsGuest& guest) : guest_(guest) {
    Domain& domain = guest.domain();
    Vcpu* vcpu = &domain.vcpu(0);

    // Try to find a VCPU that's in an event
    for (uint32_t i = 0; i < domain.vcpu_count(); ++i) {
        Vcpu& v = domain.vcpu(i);
        if (v.handling_event()) {
            vcpu = &v;
            LOG4CXX_DEBUG(logger, "Using event VCPU " << vcpu->id());
            break;
        }
    }

    /*
     * Find the kernel base address.
     *
     * The two MSRs should point to code in the kernel, so they're a good starting point.
     * MSR_LSTAR is for 64-bit and MSR_IA32_SYSENTER_EIP is for 32-bit.
     */
    const auto& registers = vcpu->registers();
    base_address_ =
        GuestVirtualAddress(*vcpu, std::max(registers.msr(x86::Msr::MSR_LSTAR),
                                            registers.msr(x86::Msr::MSR_IA32_SYSENTER_EIP)) &
                                       PageDirectory::PAGE_MASK);

    LOG4CXX_DEBUG(logger, "Starting NT kernel search at address " << base_address_);

    /*
     * TODO: Sometimes this fails. I think the processor is in usermode at the time, and
     *       spectre/meltdown protection is on, so the page tables don't map the kernel.
     */
    // Go down one page at a time and look for the MZ header
    static const uint64_t MaxRange = 0x1000000;
    const GuestVirtualAddress search_bottom = base_address_ - MaxRange;
    while (base_address_ > search_bottom) {
        try {
            if (unlikely(*guest_ptr<uint16_t>(base_address_) == 0x5a4D)) { // "MZ"
                LOG4CXX_DEBUG(logger, "Found MZ at " << base_address_);
                try {
                    /*
                     * Parse the PE of the image and make sure it's one we're expecting
                     */
                    static const std::set<std::string> ValidKernelNames{
                        "ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntoskrnl.pdb", "ntkrpamp.pdb"};
                    pe_.emplace(base_address_);

                    const auto* debug_directory = pe_->optional_header().debug_directory();

                    if (!debug_directory ||
                        debug_directory->Type() != pe::ImageDebugType::IMAGE_DEBUG_TYPE_CODEVIEW) {
                        LOG4CXX_DEBUG(logger, "Missing IMAGE_DEBUG_DIRECTORY, continuing scan...");
                        base_address_ -= PageDirectory::PAGE_SIZE;
                        continue;
                    }

                    const auto* cv_data = debug_directory->codeview_data();

                    const std::string pdb_filename = cv_data->PdbFileName();
                    if (ValidKernelNames.count(pdb_filename) == 0) {
                        LOG4CXX_DEBUG(logger, "Incorrect PDB file name: " << pdb_filename);
                        base_address_ -= PageDirectory::PAGE_SIZE;
                        continue; // Try again
                    }

                    LOG4CXX_DEBUG(logger, "Found PDB Filename: " << pdb_filename);
                    break;
                } catch (pe::PeException& ex) {
                    LOG4CXX_DEBUG(logger, "Failed to parse PE at " + to_string(base_address_));
                } catch (VirtualAddressNotPresentException& ex) {
                    LOG4CXX_DEBUG(logger, ex.what());
                }
            }
        } catch (VirtualAddressNotPresentException& ex) {
        }
        base_address_ -= PageDirectory::PAGE_SIZE;
    }

    if (!pe_)
        throw GuestDetectionException(domain, "Failed to find NT kernel base address");

    filesystem::create_directories(profile_path());

    /*
     * Parse debugging structures
     */

    KdVersionBlock_.emplace(*this);
    KdDebuggerDataBlock_.emplace(*this);

    // Sanity check to make sure both structures agree
    if (KdVersionBlock().PsLoadedModuleList() != KdDebuggerDataBlock().PsLoadedModuleList()) {
        throw GuestDetectionException(domain, "PsLoadedModuleList mismatch");
    }

    /*
     * Parse the NtBuildLab and the NtBuildNumber
     */
    NtBuildLab_.emplace(KdDebuggerDataBlock().NtBuildLab());
    try {
        NtBuildNumber_ = *guest_ptr<uint16_t>(symbol("NtBuildNumber"));
        if (NtBuildLab().MajorBuildNumber() != NtBuildNumber()) {
            LOG4CXX_WARN(logger, "NtBuildLab disagrees with NtBuildNumber");
        }
    } catch (SymbolNotFoundException& ex) {
        LOG4CXX_WARN(logger, "Failed to read NtBuildNumber");
        NtBuildNumber_ = NtBuildLab().MajorBuildNumber();
    }

    MajorVersion_ = pe().optional_header().MajorImageVersion();
    MinorVersion_ = pe().optional_header().MinorImageVersion();

    if (MajorVersion() >= 10) {
        // Windows 10 has this ObHeaderCookie for "security".
        // It's easy to figure out with XOR, but we can just read the symbols.
        /* obHeaderCookie = ((pObjectHeader >> 8) & 0xFF) ^ hdr.getTypeIndex() ^ OBJECT_INDEX::Type;
         */
        try {
            ObHeaderCookie_ = *guest_ptr<uint8_t>(symbol("ObHeaderCookie"));
            hasObHeaderCookie_ = true;
            LOG4CXX_DEBUG(logger, "ObHeaderCookie: 0x"
                                      << std::hex << (static_cast<int>(ObHeaderCookie_) & 0xFF));
        } catch (SymbolNotFoundException& ex) {
            LOG4CXX_WARN(logger, "Failed to read ObHeaderCookie");
        }
    }

    // Parse object types
    type_table_.emplace(*this);

    try {
        // TODO: Move MI_SYSTEM_INFORMATION into it's own class
        const auto* MiState = LoadOffsets<structs::MI_SYSTEM_INFORMATION>(*this);
        if (MiState->InvalidPteMask.exists()) {
            GuestVirtualAddress pMiState = symbol("MiState");
            guest_ptr<const char[]> MiStateBuffer(pMiState, MiState->size());
            if (MiState->InvalidPteMask.size() == 8) {
                InvalidPteMask_ = MiState->InvalidPteMask.template get<uint64_t>(MiStateBuffer);
            } else if (MiState->InvalidPteMask.size() == 4) {
                // Not 100% sure this can ever happen. Maybe on x32 with PAE disabled?
                InvalidPteMask_ = MiState->InvalidPteMask.template get<uint32_t>(MiStateBuffer);
            } else {
                LOG4CXX_WARN(logger, "Bad InvalidPteMask Size: " << MiState->InvalidPteMask.size());
            }
        }
    } catch (TypeInformationException& ex) {
        LOG4CXX_DEBUG(logger, ex.what());
    }

    // Find the GLOBAL?? directory for drive letter mappings
    auto RootDirectory = RootDirectoryObject();
    const auto& objects = RootDirectory->objects();
    for (const std::shared_ptr<OBJECT>& object : objects) {
        if (object->header().type() == ObjectType::Directory) {
            if (object->header().has_name_info() &&
                object->header().NameInfo().Name() == "GLOBAL??") {
                // Found it
                global_directory_address_ = object->address();
                LOG4CXX_DEBUG(logger, "Found \\GLOBAL?? : " << global_directory_address_);
                LOG4CXX_DEBUG(logger, "Parsing drive letters");
                reparse_drive_letters();
            }
        }
    }
    if (unlikely(!global_directory_address_)) {
        throw GuestDetectionException(guest.domain(), "Failed to find GLOBAL?? directory");
    }

    // Detect the number of CPUs that Windows is using
    // This is because for licensing reasons, Windows will sometimes refuse to use a CPU,
    // leaving its PCR as null.
    auto pKeNumberProcessors = symbol("KeNumberProcessors");
    cpu_count_ = *guest_ptr<uint32_t>(pKeNumberProcessors);

    if (unlikely(cpu_count() > domain.vcpu_count())) {
        throw GuestDetectionException(domain, "Guest reporting too many CPUs");
    }

    // Initialize the KPCRs
    /*
     * We do this in two stages, so that we can use the KernelDirectoryTableBase
     * from one to map in the others.
     *
     * This is to help with Spectre/Meltdown mitigations, where the CR3 value isn't
     * enough to let us map in the kernel address table.
     */
    const uint32_t vcpu_count = cpu_count();
    uint64_t KernelDirectoryTableBase = 0;
    kpcrs_.reserve(vcpu_count);

    // Stage one
    for (uint32_t i = 0; i < vcpu_count; ++i) {
        try {
            Vcpu& vcpu = guest.domain().vcpu(i);
            kpcrs_.emplace_back(*this, vcpu);
            if (!KernelDirectoryTableBase) {
                KernelDirectoryTableBase = kpcrs_.back().KernelDirectoryTableBase();
                if (!KernelDirectoryTableBase) {
                    // Meltdown/Spectre protection disabled. Use the CR3 value instead.
                    KernelDirectoryTableBase = vcpu.registers().cr3();
                }
            }
        } catch (TraceableException& ex) {
        }
    }

    // Stage two
    for (uint32_t i = kpcrs_.size(); i < vcpu_count; ++i) {
        Vcpu& vcpu = guest.domain().vcpu(i);
        kpcrs_.emplace_back(*this, vcpu, KernelDirectoryTableBase);
    }

    // Service tables
    KeServiceDescriptorTable_.emplace(symbol("KeServiceDescriptorTable"));
    LOG4CXX_DEBUG(logger, "Parsed KeServiceDescriptorTable with "
                              << KeServiceDescriptorTable().count() << " entries");

    GuestVirtualAddress pKeServiceDescriptorTableShadow(symbol("KeServiceDescriptorTableShadow"));

    // The shadow service table isn't present in all processes
    // Try it with a bunch of them
    auto cid_table = CidTable();
    for (auto& entry : cid_table->open_handles()) {
        auto header = entry->ObjectHeader();
        if (header->type() == ObjectType::Process) {
            try {
                auto process = PROCESS::make_shared(*this, std::move(header));
                pKeServiceDescriptorTableShadow.page_directory(process->DirectoryTableBase());
                KeServiceDescriptorTableShadow_.emplace(pKeServiceDescriptorTableShadow);
                break;
            } catch (VirtualAddressNotPresentException& ex) {
            }
        }
    }
    base_address_.page_directory(vcpu->registers().cr3());

    if (KeServiceDescriptorTableShadow_) {
        LOG4CXX_DEBUG(logger, "Parsed KeServiceDescriptorTableShadow with "
                                  << KeServiceDescriptorTableShadow().count() << " entries");
    } else {
        throw GuestDetectionException(domain, "Failed to parse KeServiceDescriptorTableShadow");
    }

    LOG4CXX_INFO(logger, "Detected Windows " << MajorVersion() << '.' << MinorVersion() << ' '
                                             << (is64Bit() ? "x64" : "x86") << " Build "
                                             << NtBuildNumber() << " Processors: " << cpu_count());
}

template <typename PtrType>
NtKernelImpl<PtrType>::~NtKernelImpl() = default;

template class NtKernelImpl<uint32_t>;
template class NtKernelImpl<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
