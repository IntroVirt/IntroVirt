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
#include "PROCESS_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"
#include "windows/kernel/nt/types/HANDLE_TABLE_IMPL.hh"
#include "windows/kernel/nt/types/MMVAD_IMPL.hh"
#include "windows/kernel/nt/util/ListParser.hh"

#include <introvirt/windows/exception/InvalidStructureException.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>
#include <introvirt/windows/kernel/nt/types/DBGKD_GET_VERSION64.hh>
#include <introvirt/windows/kernel/nt/types/KDDEBUGGER_DATA64.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>
#include <introvirt/windows/kernel/nt/types/objects/TOKEN.hh>
#include <introvirt/windows/util/WindowsTime.hh>

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>

#include <algorithm>
#include <cstring>
#include <log4cxx/logger.h>

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.PROCESS"));

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
const std::string& PROCESS_IMPL<PtrType>::ImageFileName() const {
    std::lock_guard lock(mtx_);
    if (ImageFileName_.empty()) {
        ImageFileName_ = eprocess_->ImageFileName.get_string(buffer_);
    }
    return ImageFileName_;
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::ImageFileName(const std::string& value) {
    std::lock_guard lock(mtx_);
    eprocess_->ImageFileName.set_string(buffer_, value);

    // Update our local copy, based on the actual size of the buffer_.
    ImageFileName_ = value.substr(0, eprocess_->ImageFileName.size());
}

template <typename PtrType>
const std::string& PROCESS_IMPL<PtrType>::full_path() const {
    std::lock_guard lock(full_path_mtx_);
    if (full_path_.empty()) {
        // Get the VaD
        auto vad = VadRoot();
        if (!vad) {
            LOG4CXX_DEBUG(logger, "Failed to find VaD for FullPath()")
            return full_path_;
        }

        auto vad_entry = vad->search(SectionBaseAddress());
        if (!vad_entry) {
            LOG4CXX_DEBUG(logger, "Failed to find SectionBaseAddress 0x"
                                      << std::hex << SectionBaseAddress()
                                      << " in VaD for FullPath()");
            return full_path_;
        }

        const FILE_OBJECT* file = vad_entry->FileObject();
        if (!file) {
            LOG4CXX_DEBUG(logger, "Failed to find FileObject in VaD for FullPath()")
            return full_path_;
        }

        full_path_ = file->full_path();
    }
    return full_path_;
}

template <typename PtrType>
const PEB* PROCESS_IMPL<PtrType>::Peb() const {
    std::lock_guard lock(mtx_);
    if (!peb_) {
        const auto pPEB = this->gva_.create(eprocess_->Peb.get<PtrType>(buffer_));
        // TODO: We shouldn't cache this
        if (pPEB)
            peb_.emplace(pPEB);
        else
            return nullptr;
    }
    return &(*peb_);
}

template <typename PtrType>
PEB* PROCESS_IMPL<PtrType>::Peb() {
    const auto* const_this = const_cast<const PROCESS_IMPL<PtrType>*>(this);
    return const_cast<PEB*>(const_this->Peb());
}

template <typename PtrType>
std::unique_ptr<const HANDLE_TABLE> PROCESS_IMPL<PtrType>::ObjectTable() const {
    const auto pObjectTable = this->gva_.create(eprocess_->ObjectTable.get<PtrType>(buffer_));

    if (pObjectTable)
        return std::make_unique<HANDLE_TABLE_IMPL<PtrType>>(kernel_, pObjectTable);
    else
        return nullptr;
}

template <typename PtrType>
std::unique_ptr<HANDLE_TABLE> PROCESS_IMPL<PtrType>::ObjectTable() {
    const auto* const_this = const_cast<const PROCESS_IMPL<PtrType>*>(this);
    return std::unique_ptr<HANDLE_TABLE>(
        const_cast<HANDLE_TABLE*>(const_this->ObjectTable().release()));
}

template <typename PtrType>
uint64_t PROCESS_IMPL<PtrType>::UniqueProcessId() const {
    return eprocess_->UniqueProcessId.get<PtrType>(buffer_);
}

template <typename PtrType>
uint64_t PROCESS_IMPL<PtrType>::InheritedFromUniqueProcessId() const {
    return eprocess_->InheritedFromUniqueProcessId.get<PtrType>(buffer_);
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::InheritedFromUniqueProcessId(uint64_t pid) {
    eprocess_->InheritedFromUniqueProcessId.set<PtrType>(buffer_, pid);
}

template <typename PtrType>
const TOKEN& PROCESS_IMPL<PtrType>::Token() const {
    constexpr uint64_t token_ptr_mask = (std::is_same_v<PtrType, uint64_t>) ? ~0xFull : ~0x7u;

    std::lock_guard lock(mtx_);

    GuestVirtualAddress pToken =
        this->gva_.create(eprocess_->Token.get<PtrType>(buffer_) & token_ptr_mask);

    if (token_) {
        // Invalidate it if things changed
        if (token_->address() == pToken)
            return *token_;
    }

    if (unlikely(!pToken))
        throw InvalidStructureException("PROCESS missing Token");

    token_.emplace(kernel_, pToken);
    return *token_;
}

template <typename PtrType>
TOKEN& PROCESS_IMPL<PtrType>::Token() {
    const auto* const_this = this;
    return const_cast<TOKEN&>(const_this->Token());
}

template <typename PtrType>
uint32_t PROCESS_IMPL<PtrType>::Cookie() const {
    return eprocess_->Cookie.get<uint32_t>(buffer_);
}

template <typename PtrType>
uint64_t PROCESS_IMPL<PtrType>::SectionBaseAddress() const {
    return eprocess_->SectionBaseAddress.get<PtrType>(buffer_);
}

template <typename PtrType>
const MM_SESSION_SPACE* PROCESS_IMPL<PtrType>::Session() const {
    std::lock_guard lock(mtx_);
    if (!session_) {
        const auto pSession = this->gva_.create(eprocess_->Session.get<PtrType>(buffer_));
        if (pSession)
            session_.emplace(kernel_, pSession);
        else
            return nullptr;
    }
    return &(*session_);
}

template <typename PtrType>
std::vector<std::shared_ptr<const THREAD>> PROCESS_IMPL<PtrType>::ThreadList() const {
    const auto pThreadListHead = this->address() + eprocess_->ThreadListHead;
    auto pThreads =
        parse_list_ptrtype<PtrType>(pThreadListHead, ethread_->ThreadListEntry.offset());

    std::vector<std::shared_ptr<const THREAD>> result;
    for (const GuestVirtualAddress& pThread : pThreads) {
        result.emplace_back(kernel_.thread(pThread));
    }
    return result;
}

template <typename PtrType>
std::vector<std::shared_ptr<THREAD>> PROCESS_IMPL<PtrType>::ThreadList() {
    const auto pThreadListHead = this->address() + eprocess_->ThreadListHead;
    auto pThreads =
        parse_list_ptrtype<PtrType>(pThreadListHead, ethread_->ThreadListEntry.offset());

    std::vector<std::shared_ptr<THREAD>> result;
    for (const GuestVirtualAddress& pThread : pThreads) {
        result.emplace_back(kernel_.thread(pThread));
    }
    return result;
}

template <typename PtrType>
bool PROCESS_IMPL<PtrType>::isWow64Process() const {
    if (eprocess_->Wow64Process.exists()) {
        const auto pWoW64Process = eprocess_->Wow64Process.get<PtrType>(buffer_);
        return pWoW64Process != 0;
    }
    return false;
}

template <typename PtrType>
const PEB* PROCESS_IMPL<PtrType>::WoW64Process() const {
    std::lock_guard lock(mtx_);
    if (!WoW64Process_) {
        if (eprocess_->Wow64Process.exists()) {
            const auto pWoW64Process =
                this->gva_.create(eprocess_->Wow64Process.get<PtrType>(buffer_));
            if (pWoW64Process) {
                try {
                    const auto pPeb32 = this->gva_.create(*guest_ptr<uint64_t>(pWoW64Process));
                    if (pPeb32)
                        WoW64Process_.emplace(pPeb32);
                } catch (VirtualAddressNotPresentException& ex) {
                    // Older version of Windows point directly to the WoW64Process
                    WoW64Process_.emplace(pWoW64Process);
                }
            } else {
                return nullptr;
            }
        }
    }
    return &(*WoW64Process_);
}

template <typename PtrType>
PEB* PROCESS_IMPL<PtrType>::WoW64Process() {
    const auto* const_this = const_cast<const PROCESS_IMPL<PtrType>*>(this);
    return const_cast<PEB*>(const_this->WoW64Process());
}

template <typename PtrType>
std::shared_ptr<const MMVAD> PROCESS_IMPL<PtrType>::VadRoot() const {
    const auto pVadTree = this->gva_.create(VadRootNodeAddress());
    if (pVadTree)
        return std::make_shared<MMVAD_IMPL<PtrType>>(kernel_, pVadTree);
    return nullptr;
}

template <typename PtrType>
bool PROCESS_IMPL<PtrType>::DisableDynamicCode() const {
    if (eprocess_->DisableDynamicCode.exists())
        return eprocess_->DisableDynamicCode.get_bitfield<uint32_t>(buffer_);
    return false;
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::DisableDynamicCode(bool enabled) {
    if (eprocess_->DisableDynamicCode.exists())
        eprocess_->DisableDynamicCode.set_bitfield<uint32_t>(buffer_, enabled);
}

template <typename PtrType>
bool PROCESS_IMPL<PtrType>::DisableDynamicCodeAllowOptOut() const {
    if (eprocess_->DisableDynamicCodeAllowOptOut.exists())
        return eprocess_->DisableDynamicCodeAllowOptOut.get_bitfield<uint32_t>(buffer_);

    return false;
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::DisableDynamicCodeAllowOptOut(bool enabled) {
    if (eprocess_->DisableDynamicCodeAllowOptOut.exists())
        eprocess_->DisableDynamicCodeAllowOptOut.set<uint32_t>(buffer_, enabled);
}

template <typename PtrType>
uint64_t PROCESS_IMPL<PtrType>::DirectoryTableBase() const {
    return eprocess_->Pcb.DirectoryTableBase.get<PtrType>(buffer_);
}

template <typename PtrType>
uint64_t PROCESS_IMPL<PtrType>::UserDirectoryTableBase() const {
    if (eprocess_->Pcb.UserDirectoryTableBase.exists()) {
        // Return the UserDirectoryTableBase entry
        const uint64_t result = eprocess_->Pcb.UserDirectoryTableBase.get<PtrType>(buffer_);
        if (result)
            return result;
    }

    // Kernel doesn't have a separate UserDirectoryTableBase
    return DirectoryTableBase();
}

template <typename PtrType>
uint32_t PROCESS_IMPL<PtrType>::ModifiedPageCount() const {
    return eprocess_->ModifiedPageCount.get<uint32_t>(buffer_);
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::ModifiedPageCount(uint32_t ModifiedPageCount) {
    eprocess_->ModifiedPageCount.set<uint32_t>(buffer_, ModifiedPageCount);
}

template <typename PtrType>
WindowsTime PROCESS_IMPL<PtrType>::CreateTime() const {
    return WindowsTime::from_windows_time(eprocess_->CreateTime.get<int64_t>(buffer_));
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::CreateTime(const WindowsTime& time) {
    eprocess_->CreateTime.set<int64_t>(buffer_, time.windows_time());
}

template <typename PtrType>
uint64_t PROCESS_IMPL<PtrType>::MinimumWorkingSetSize() const {
    return eprocess_->MinimumWorkingSetSize.get<PtrType>(buffer_);
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::MinimumWorkingSetSize(uint64_t MinimumWorkingSetSize) {
    return eprocess_->MinimumWorkingSetSize.set<PtrType>(buffer_, MinimumWorkingSetSize);
}

template <typename PtrType>
uint64_t PROCESS_IMPL<PtrType>::MaximumWorkingSetSize() const {
    return eprocess_->MaximumWorkingSetSize.get<PtrType>(buffer_);
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::MaximumWorkingSetSize(uint64_t MaximumWorkingSetSize) {
    return eprocess_->MaximumWorkingSetSize.set<PtrType>(buffer_, MaximumWorkingSetSize);
}

template <typename PtrType>
uint8_t PROCESS_IMPL<PtrType>::ProtectionLevel() const {
    if (eprocess_->Protection.exists()) {
        const auto ps_protection = LoadOffsets<structs::PS_PROTECTION>(kernel_);
        const auto* ps_protection_buffer = buffer_.get() + eprocess_->Protection.offset();
        return ps_protection->Level.template get<uint8_t>(ps_protection_buffer);
    }
    return 0;
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::ProtectionLevel(uint8_t Level) {
    if (eprocess_->Protection.exists()) {
        const auto ps_protection = LoadOffsets<structs::PS_PROTECTION>(kernel_);
        auto* ps_protection_buffer = buffer_.get() + eprocess_->Protection.offset();
        ps_protection->Level.template set<uint8_t>(ps_protection_buffer, Level);
    }
}

template <typename PtrType>
GuestVirtualAddress PROCESS_IMPL<PtrType>::Win32Process() const {
    return this->gva_.create(eprocess_->Win32Process.get<PtrType>(buffer_));
}

template <typename PtrType>
uint64_t PROCESS_IMPL<PtrType>::VadRootNodeAddress() const {
    /*
    Windows 7:
        VadRoot.RightChild (PtrSize)
    Windows 10:
        VadRoot.Root (PtrSize)
    */
    if (eprocess_->RightChild.exists()) {
        return eprocess_->RightChild.get<PtrType>(buffer_);
    }
    return eprocess_->VadRoot.get<PtrType>(buffer_);
}

template <typename PtrType>
void PROCESS_IMPL<PtrType>::init(const NtKernelImpl<PtrType>& kernel,
                                 const GuestVirtualAddress& gva) {
    // Load our offsets
    eprocess_ = LoadOffsets<structs::EPROCESS>(kernel);
    ethread_ = LoadOffsets<structs::ETHREAD>(kernel);

    // Map in the structure. Doing one mapping is a lot cheaper than mapping every field.
    buffer_.reset(gva, eprocess_->size());

    this->gva_.page_directory(DirectoryTableBase());
}

template <typename PtrType>
PROCESS_IMPL<PtrType>::PROCESS_IMPL(const NtKernelImpl<PtrType>& kernel,
                                    const GuestVirtualAddress& gva)
    : DISPATCHER_OBJECT_IMPL<PtrType, PROCESS>(kernel, gva, ObjectType::Process), kernel_(kernel) {

    init(kernel, gva);
}

template <typename PtrType>
PROCESS_IMPL<PtrType>::PROCESS_IMPL(const NtKernelImpl<PtrType>& kernel,
                                    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : DISPATCHER_OBJECT_IMPL<PtrType, PROCESS>(kernel, std::move(object_header),
                                               ObjectType::Process),
      kernel_(kernel) {

    init(kernel, OBJECT_IMPL<PtrType, PROCESS>::address());
}

std::shared_ptr<PROCESS> PROCESS::make_shared(const NtKernel& kernel,
                                              const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<PROCESS_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<PROCESS_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<PROCESS> PROCESS::make_shared(const NtKernel& kernel,
                                              std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<PROCESS_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<PROCESS_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

template class PROCESS_IMPL<uint32_t>;
template class PROCESS_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} /* namespace introvirt */
