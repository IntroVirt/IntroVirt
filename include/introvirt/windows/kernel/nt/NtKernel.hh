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

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/kernel/nt/types/LDR_DATA_TABLE_ENTRY.hh>

#include <introvirt/core/fwd.hh>
#include <introvirt/windows/fwd.hh>

#include <mspdb/PDB.hh>

#include <cstdint>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Abstraction for the Windows NT kernel
 */
class NtKernel {
  public:
    /**
     * @brief Get the KdVersionBlock from the kernel
     *
     * This is a structure used by debuggers
     *
     * @return The KdVersionBlock from the kernel
     */
    virtual const DBGKD_GET_VERSION64& KdVersionBlock() const = 0;

    /**
     * @brief Get the KdDebuggerDataBlock from the kernel
     *
     * This is a structure used by debuggers
     *
     * @return The KdDebuggerDataBlock from the kernel
     */
    virtual const KDDEBUGGER_DATA64& KdDebuggerDataBlock() const = 0;

    /**
     * @brief Get the KeServiceDescriptorTable
     *
     * This is the first system call table in the kernel.
     * It seems to only contain NT system call information.
     */
    virtual const ServiceDescriptorTable& KeServiceDescriptorTable() const = 0;

    /**
     * @brief Get the KeServiceDescriptorTableShadow
     *
     * This is the second system call table in the kernel.
     * It seems to contain NT + Win32k system call information.
     */
    virtual const ServiceDescriptorTable& KeServiceDescriptorTableShadow() const = 0;

    /**
     * @brief Check if the kernel has an ObHeaderCookieValue
     *
     * @return true If an ObHeaderCookie value is in use
     * @return false if the kernel does not have an ObHeaderCookie
     */
    virtual bool hasObHeaderCookie() const = 0;

    /**
     *
     * @brief Get the ObHeaderCookie if one exists
     *
     * @return The ObHeaderCookie from the kernel
     */
    virtual uint8_t ObHeaderCookie() const = 0;

    /**
     * @brief Get the build label
     *
     * @return The build label for the kernel
     */
    virtual const nt::NtBuildLab& NtBuildLab() const = 0;

    /**
     * @brief Get the build number
     *
     * @return The value of the NtBuildNumber symbol
     */
    virtual uint16_t NtBuildNumber() const = 0;

    /**
     * @brief Get the major version of the kernel
     *
     * @return The kernel's major version
     */
    virtual uint16_t MajorVersion() const = 0;

    /**
     * @brief Get the minor version of the kernel
     *
     * @return The kernel's minor version
     */
    virtual uint16_t MinorVersion() const = 0;

    /**
     * @brief Get the number of CPUs that Windows has configured
     *
     * @return unsigned int
     */
    virtual unsigned int cpu_count() const = 0;

    /**
     * @brief Return true if the kernel is a 64-bit version
     *
     * @return true If the kernel is 64-bit
     * @return false If the kernel is
     */
    // virtual bool x64() const = 0;

    /**
     * @brief Look up a symbol by name and return its address
     *
     * @param name The name of the symbol to retrieve
     * @return The address of the symbol
     * @throws SymbolNotFoundException If the symbol does not exist
     */
    virtual GuestVirtualAddress symbol(const std::string& name) const = 0;

    /**
     * @brief Get the base address of the kernel
     * @returns The base address of the kernel
     */
    virtual GuestVirtualAddress base_address() const = 0;

    /**
     * @brief Get the value of the InvalidPteMask field from MI_SYSTEM_INFORMATION
     *
     * @return uint64_t
     */
    virtual uint64_t InvalidPteMask() const = 0;

    /**
     * @brief Get the type table
     *
     * @return const TypeTable&
     */
    virtual const TypeTable& types() const = 0;

    /**
     * @brief Get the PE (Portable Executable) image of the kernel
     *
     * @return The PE of the kernel
     */
    virtual const pe::PE& pe() const = 0;

    /**
     * @brief Get the PDB for the kernel image
     *
     * This is just a helper call to pe().pdb().
     *
     * @return The PDB for the kernel image
     */
    // virtual const mspdb::PDB& pdb() const = 0;

    /**
     * @brief Get the RootDirectoryObject from the kernel
     *
     * @return The root directory object, which all kernel objects live under
     * @throws SymbolNotFoundException If the ObpRootDirectoryObject symbol does not exist
     */
    virtual std::shared_ptr<OBJECT_DIRECTORY> RootDirectoryObject() const = 0;

    /**
     * @brief Get the PspCidTable from the kernel
     *
     * The PspCidTable is a special HANDLE_TABLE,
     * containing all of the PROCESS and THREAD objects.
     *
     * @return The CidTable from the kernel
     * @throws SymbolNotFoundException If the PspCidTable symbol does not exist
     */
    virtual std::unique_ptr<HANDLE_TABLE> CidTable() = 0;

    /**
     * @copydoc NtKernel::CidTable()
     */
    virtual std::unique_ptr<const HANDLE_TABLE> CidTable() const = 0;

    /**
     * @brief Get the kernel's loaded module list
     *
     * @return std::vector<std::unique_ptr<const LDR_DATA_TABLE_ENTRY>>
     */
    virtual std::vector<std::shared_ptr<const LDR_DATA_TABLE_ENTRY>> PsLoadedModuleList() const = 0;

    /**
     * @brief Get the drive letter associated with a device
     *
     * @param device The device to get a drive letter for
     * @return A string containing the device's drive letter
     */
    virtual std::string get_device_drive_letter(const nt::DEVICE_OBJECT& device) const = 0;

    /**
     * @brief Get the KPCR for the given vcpu
     *
     * @param vcpu The vcpu to get the KPCR for
     * @return The KPCR that belongs to the given vcpu
     */
    virtual KPCR& kpcr(const Vcpu& vcpu) = 0;

    /**
     * @copydoc NtKernel::kpcr(Vcpu&)
     */
    virtual const KPCR& kpcr(const Vcpu& vcpu) const = 0;

    /**
     * @brief Get the guest the kernel is running on
     *
     * @return The guest the kernel is running on
     */
    virtual const WindowsGuest& guest() const = 0;

    /**
     * @brief Check if the kernel is for x64
     *
     * @return true If the kernel is for x64
     * @return false If the kernel is for x32
     */
    virtual bool x64() const = 0;

    /**
     * @brief Get the PDB file for this type container
     *
     * @return The PDB instance
     */
    virtual const mspdb::PDB& pdb() const = 0;

    /**
     * @brief Get the THRAD at the given address
     *
     * @param address
     * @return std::shared_ptr<nt::PROCESS>
     */
    virtual std::shared_ptr<THREAD> thread(const GuestVirtualAddress& address) const = 0;

    /**
     * @brief Get the PROCESS at the given address
     *
     * @param address
     * @return std::shared_ptr<nt::PROCESS>
     */
    virtual std::shared_ptr<PROCESS> process(const GuestVirtualAddress& address) const = 0;

    /**
     * @brief Get the introvirt profile directory for this kernel
     *
     * @return std::string
     */
    virtual std::string profile_path() const = 0;

    virtual ~NtKernel() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt