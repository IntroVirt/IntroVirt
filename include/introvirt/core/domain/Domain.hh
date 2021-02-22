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

#include <introvirt/core/arch/x86/PageDirectory.hh>
#include <introvirt/core/breakpoint/Breakpoint.hh>
#include <introvirt/core/breakpoint/SingleStep.hh>
#include <introvirt/core/breakpoint/Watchpoint.hh>
#include <introvirt/core/domain/Guest.hh>
#include <introvirt/core/event/EventCallback.hh>
#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/GuestAddress.hh>
#include <introvirt/core/memory/GuestMemoryMapping.hh>
#include <introvirt/util/compiler.hh>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace introvirt {

/**
 * @brief A class representing a single Domain
 *
 * A Domain object is the mechanism for interacting with a virtual machine.
 * It is subclassed for specific hypervisors, such as the KvmDomain and the
 * XenDomain.
 */
class Domain {
  public:
    /**
     * @brief Create an execution breakpoint
     *
     * @param address The address to place the breakpoint
     * @param callback The callback function to run
     * @return std::shared_ptr<Breakpoint> That clears the breakpoint when it goes off-scope
     */
    virtual std::shared_ptr<Breakpoint> create_breakpoint(const GuestAddress& address,
                                                          std::function<void(Event&)> callback) = 0;

    /**
     * @brief Create an execution breakpoint
     *
     * @param address The address to place the breakpoint
     * @param callback The callback function to run
     * @return std::shared_ptr<Breakpoint> That clears the breakpoint when it goes off-scope
     */
    virtual std::unique_ptr<Watchpoint> create_watchpoint(const GuestAddress& address,
                                                          uint64_t length, bool read, bool write,
                                                          bool execute,
                                                          std::function<void(Event&)> callback) = 0;

    /**
     * @brief Start single stepping a VCPU
     *
     * @param vcpu
     * @param callback
     * @return std::unique_ptr<SingleStepImpl>
     */
    virtual std::unique_ptr<SingleStep> single_step(Vcpu& vcpu,
                                                    std::function<void(Event&)> callback) = 0;

    /**
     * @brief Attempt guest OS detection
     *
     * Waits for an incoming event and attempts to detect the guest
     *
     * @return true if the guest OS was detected
     * @return false if the guest OS was not detected
     */
    virtual bool detect_guest() = 0;

    /**
     * @brief Get the guest detected by detect_guest()
     *
     * @return The guest instance, or nullptr of one has not been detected
     */
    virtual Guest* guest() = 0;

    /**
     * @copydoc Domain::guest()
     */
    virtual const Guest* guest() const = 0;

    /**
     * @brief Get the name of the Domain, if it exists.
     *
     * @return std::string containing the name of the Domain.
     */
    virtual std::string name() const = 0;

    /**
     * @brief Get the id of the Domain
     *
     * The Domain identifier is specific to a hypervisor.
     * On Xen, the ID increases each time a new one is created.
     * On KVM, the ID is the PID of the QEMU process.
     *
     * @return uint32_t id of the Domain
     */
    virtual uint32_t id() const = 0;

    /**
     * @brief Get a vcpu by index
     *
     * @param index The index of the vcpu to retreive
     * @return std::unique_ptr<Vcpu>
     * @throws InvalidVcpuException if the specified vcpu does not exist
     */
    virtual Vcpu& vcpu(uint32_t index) = 0;

    /**
     * @copydoc Domain::vcpu(uint32_t)
     */
    virtual const Vcpu& vcpu(uint32_t index) const = 0;

    /**
     * @brief Get the number of vcpus in the Domain
     *
     * @return int indicating the number of vcpus
     */
    virtual uint32_t vcpu_count() const = 0;

    /**
     * @brief Get the page directory for address translation
     *
     * @return The page directory
     */
    virtual const x86::PageDirectory& page_directory() const = 0;

    /**
     * @brief Poll for events and deliver them to the callback
     *
     * This is a single threaded event poller. One thread handles all Vcpus.
     *
     * @param callback The callback to deliver events to
     */
    virtual void poll(EventCallback& callback) = 0;

    /**
     * @brief Interrupt a poll() call
     */
    virtual void interrupt() = 0;

    /**
     * @brief Pause the entire Domain
     */
    virtual void pause() = 0;

    /**
     * @brief Resume the Domain
     */
    virtual void resume() = 0;

    /**
     * @brief Get the task filter for this domain
     *
     * The task filter can be used to filter events for specific threads and processes.
     */
    virtual TaskFilter& task_filter() = 0;

    /**
     * @brief Get the system call filter for this Domain
     *
     * This is the Domain-level system call filter.
     *
     * If enabled, it will be checked only if the vcpu-level filter doesn't match.
     *
     * @return The Domain system call filter
     */
    virtual SystemCallFilter& system_call_filter() = 0;

    /**
     * @copydoc Domain::system_call_filter()
     */
    virtual const SystemCallFilter& system_call_filter() const = 0;

    /**
     * @brief Gets the hypervisor that the Domain is running on
     *
     * @return The hypervisor running the Domain
     */
    virtual const Hypervisor& hypervisor() const = 0;

    /**
     * @brief Map a list of pfns into our address space
     *
     * Generally you will not use this directly. Use a guest_ptr instead.
     *
     * @param pfns An array of pfns to map
     * @param count The number of pfns in the array
     * @return The mapped memory
     * @throws BadPhysicalAddressException If the guest physical address could not be mapped
     */
    virtual GuestMemoryMapping map_pfns(const uint64_t* pfns, size_t count) const = 0;

    /**
     * @brief Toggle system call interception for all VCPUs
     *
     * Enables events of type EVENT_FAST_SYSCALL and EVENT_FAST_SYSCALL_RET.
     *
     * When system call interception is enabled, SYSCALL/SYSENTER instructions are intercepted by
     * the hypervisor. If the call number matches our SystemCallFilter (or the filter is disabled),
     * a EVENT_FAST_SYSCALL event will be delivered.
     *
     * While enabled, the hypervisor also intercept all SYSRET/SYSEXIT instructions.
     *
     * @param enabled If set to true, system calls and returns that match our filters will be
     * intercepted.
     * @throws NotImplementedException if system call hooking is not supported
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void intercept_system_calls(bool enabled) = 0;

    /**
     * @brief Toggle control register write interception on all VCPUs
     *
     * @param cr The control register to toggle interception for
     * @param enabled If set to true, writes to the given control register will be intercepted
     * @throws NotImplementedException if writes to the given CR cannot be intercepted
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void intercept_cr_writes(int cr, bool enabled) = 0;

    /**
     * @brief Mark an event as suspended
     *
     * @param event
     */
    virtual void suspend_event(Event& event) = 0;

    /**
     * @brief Mark an event as suspended for single step
     *
     * @param event
     */
    virtual void suspend_event_step(Event& event) = 0;

    /**
     * @brief Get the domain for the current thread
     *
     * @return Domain&
     * @throw TODO if domain is nullptr
     */
    static Domain& thread_local_domain();

    /**
     * @brief Destroy the instance
     */
    virtual ~Domain() = default;
};

} // namespace introvirt
