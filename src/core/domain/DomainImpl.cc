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
#include "DomainImpl.hh"

#include "core/breakpoint/BreakpointImpl.hh"
#include "core/breakpoint/SingleStepImpl.hh"
#include "core/breakpoint/WatchpointImpl.hh"
#include "core/domain/VcpuImpl.hh"
#include "core/event/EventImpl.hh"
#include "core/event/NoOsEvent.hh"
#include "core/event/SystemCallEventImpl.hh"
#include "windows/WindowsGuestImpl.hh"

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/event/EventFilter.hh>
#include <introvirt/core/event/ThreadLocalEvent.hh>
#include <introvirt/core/exception/EventPollException.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/InterruptedException.hh>
#include <introvirt/core/exception/NotImplementedException.hh>
#include <introvirt/core/syscall/SystemCall.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/WindowsGuest.hh>

#include <log4cxx/logger.h>

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <functional>
#include <pthread.h>
#include <sys/eventfd.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

namespace introvirt {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.domain.Domain"));

inline static int poll_fds(struct pollfd* fds, int nfds, int timeout, uint32_t domain_id);

void DomainImpl::step_breakpoints(Event& event) {
    auto& vcpu = event.vcpu();

    // Let these guys clean everything up
    breakpoint_manager_.step(event);
    watchpoint_manager_.step(event);

    // Let the single step manager do some stuff
    single_step_manager_.handle_event(event);

    // Resume our other VCPUs
    resume_all_other_vcpus(vcpu);
}

void DomainImpl::handle_breakpoint(Event& event) {
    std::unique_ptr<Event> new_event;
    Event* working_event = &event;
    auto& vcpu = event.vcpu();

    // We only want one of these to happen at a time
    std::lock_guard lock(bp_mutex_);

    pause_all_other_vcpus(vcpu);

    bool deliver_events;
    {
        std::lock_guard lock(injection_tids_.mtx_);
        deliver_events = injection_tids_.set_.count(event.task().tid()) == 0;
    }

retry:
    bool step_required = false;

    switch (working_event->type()) {
    case EventType::EVENT_EXCEPTION:
        step_required |= breakpoint_manager_.handle_int3_event(*working_event, deliver_events);
        break;
    case EventType::EVENT_MEM_ACCESS:
        step_required |= watchpoint_manager_.handle_mem_event(*working_event);
        break;
    default:
        break;
    }

    if (step_required == false) {
        step_breakpoints(event);
        resume_all_other_vcpus(event.vcpu());
        return;
    }

    const uint64_t old_rip = vcpu.registers().rip();

    LOG4CXX_TRACE(logger, "Stepping VCPU " << vcpu.id());
    new_event = event.impl().step();
    working_event = new_event.get();

    LOG4CXX_TRACE(logger, "Stepped VCPU: " << new_event->type() << std::hex << " rip: 0x" << old_rip
                                           << "->0x" << vcpu.registers().rip());

    if (old_rip != vcpu.registers().rip())
        goto done;

    switch (working_event->type()) {
    case EventType::EVENT_SINGLE_STEP:
        LOG4CXX_WARN(logger, "Failed to step, received event " << working_event->type());
        break;
    case EventType::EVENT_EXCEPTION:
        LOG4CXX_TRACE(logger, "Step exception type: " << new_event->exception().vector());
        // Fall through
    case EventType::EVENT_MEM_ACCESS:
        // We're still not fixed, try again.
        goto retry;
    default:
        // Not sure why we didn't step.
        LOG4CXX_WARN(logger, "Failed to step, received event " << working_event->type());
        break;
    }

done:
    step_breakpoints(event);
    resume_all_other_vcpus(event.vcpu());
}

std::unique_ptr<Event>
DomainImpl::get_guest_event(std::unique_ptr<HypervisorEvent>&& hypervisor_event) {
    if (guest_) {
        // We have guest support, wrap the hypervisor event
        return guest_->impl().filter_event(std::move(hypervisor_event));
    } else {
        // No guest support.
        return std::make_unique<NoOsEvent>(std::move(hypervisor_event));
    }
}

std::unique_ptr<Event>
DomainImpl::filter_event(std::unique_ptr<HypervisorEvent>&& hypervisor_event) {
    auto& vcpu = hypervisor_event->vcpu();

    // Before we do anything, check if there is a stepping event for the current vcpu
    {
        std::lock_guard lock(stepping_events_.mtx_);
        Event* stepping_event = stepping_events_.by_vcpu_[vcpu.id()];

        if (unlikely(stepping_event != nullptr)) {
            LOG4CXX_DEBUG(logger, "Delivering stepping event for VCPU "
                                      << vcpu.id() << ": " << hypervisor_event->type());

            auto event = get_guest_event(std::move(hypervisor_event));
            stepping_events_.by_vcpu_[vcpu.id()] = nullptr;
            event->impl().discard(true);
            stepping_event->impl().wake_step(std::move(event));
            return nullptr;

            // Note that the only things using this are breakpoint/watchpoint
            // managers. If there is a suspended thread for syscall/function
            // injection, it will still be woken up on this event, below, but in
            // another thread!
        }
    }

    // Check if there is another thread pending for this thread
    {
        std::unique_lock lock(suspended_events_.mtx_);
        if (guest_) {
            const uint64_t thread_id = guest_->impl().get_current_thread_id(vcpu);
            auto callbacks = suspended_events_.map_.equal_range(thread_id);
            if (callbacks.first != callbacks.second) {
                auto event = get_guest_event(std::move(hypervisor_event));
                WakeAction action;

                for (auto iter = callbacks.first; iter != callbacks.second; ++iter) {
                    action = iter->second->impl().wake(std::move(event));

                    switch (action) {
                    case WakeAction::ACCEPT:
                        suspended_events_.map_.erase(iter);
                        // Fall through
                    case WakeAction::DROP:
                        goto out;
                    case WakeAction::PASS:
                        // Let other stuff handle it
                        break;
                    }
                }

            out:
                if (action != WakeAction::PASS) {
                    if (event.get()) {
                        // If it's a breakpoint event, pass it through anyway.
                        // Callbacks won't be delivered, but we need to fix up the INT3.
                        switch (event->type()) {
                        case EventType::EVENT_EXCEPTION:
                            if (event->exception().vector() != x86::Exception::INT3)
                                break;
                        // Fall through
                        case EventType::EVENT_MEM_ACCESS:
                            return event;
                        default:
                            break;
                        }
                    }
                    return nullptr;
                } else {
                    hypervisor_event = event->impl().release();
                    hypervisor_event->discard(false);
                }
            }
        }
    }

    if (hypervisor_event->type() == EventType::EVENT_CR_WRITE) {
        // Verify the VCPU is configured to want it
        if (!hypervisor_event->vcpu().intercept_cr_writes(hypervisor_event->control_register())) {
            return nullptr;
        }
    }

    if (hypervisor_event->type() == EventType::EVENT_FAST_SYSCALL_RET) {
        // This would've been handled by a suspended thread above
        return nullptr;
    }

    std::unique_ptr<Event> event;

    // Filter out system calls that we don't want
    if (hypervisor_event->type() == EventType::EVENT_FAST_SYSCALL) {
        if (!vcpu.intercept_system_calls())
            return nullptr;

        /*
         * The correct operation here is to check the vcpu syscall filter first.
         * If that matches, just return true. Otherwise check the domain filter.
         */
        if (!matches_syscall_filters(vcpu))
            return nullptr;

        // Matches our filter, jump down to test the task filter
        event = get_guest_event(std::move(hypervisor_event));
        goto check_task_filter;
    }

    event = get_guest_event(std::move(hypervisor_event));

    switch (event->type()) {
    case EventType::EVENT_EXCEPTION:
        if (event->exception().vector() != x86::Exception::INT3)
            break;
    // Fall through
    case EventType::EVENT_MEM_ACCESS:
        // Don't check the task filter for breakpoint and mem_access events
        return event;
    default:
        break;
    }

check_task_filter:

    // Return the result if it matches our task filter
    if (task_filter_.matches(*event)) {
        return event;
    }

    return nullptr;
}

void DomainImpl::pause() {
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        vcpu(i).pause();
    }
}

void DomainImpl::resume() {
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        vcpu(i).resume();
    }
}

bool DomainImpl::detect_guest() {
    uint64_t efd_init = 0;
    if (unlikely(::write(efd_, &efd_init, sizeof(efd_init)) < 0)) {
        LOG4CXX_ERROR(logger, "Failed to clear eventfd");
    }

    std::unique_lock<std::shared_mutex> lock(event_filter_mtx_);

    LOG4CXX_DEBUG(logger, "Attempting OS detection...");

    pause();

    // Save the previous state
    std::vector<bool> vcpu_syscall_intercept;
    std::vector<bool> vcpu_cr3_intercept;
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        vcpu_syscall_intercept.push_back(vcpu(i).intercept_system_calls());
        vcpu_cr3_intercept.push_back(vcpu(i).intercept_cr_writes(3));
        vcpu(i).intercept_system_calls(false);
        vcpu(i).intercept_cr_writes(3, false);
    }
    vcpu(0).intercept_cr_writes(3, true);

    resume();

    bool result = false;

    try {
        for (int tries = 15; tries > 0; --tries) {
            // Poll for an event
            if (::poll(pollfds_.data(), pollfds_.size(), 5000) > 0) {

                // Check if we're interrupted
                if (pollfds_[pollfds_.size() - 1].revents & POLLIN) {
                    // Interrupted!
                    return false;
                }

                // An event is ready.
                // Determine which vcpu is ready
                for (uint32_t i = 0; i < pollfds_.size(); ++i) {
                    struct pollfd& fd_entry = pollfds_[i];
                    if (fd_entry.revents & POLLIN) {
                        // This vcpu has an active event
                        auto& v = static_cast<VcpuImpl&>(vcpu(i));
                        auto event = reinterpret_cast<VcpuImpl&>(v).event();
                        if (!event)
                            continue;

                        const bool is64bit = v.registers().efer().lme();
                        page_directory_.reconfigure(v);

                        // Try a Windows guest
                        try {
                            using namespace windows;

                            if (is64bit)
                                guest_ = std::make_unique<WindowsGuestImpl<uint64_t>>(*this);
                            else
                                guest_ = std::make_unique<WindowsGuestImpl<uint32_t>>(*this);

                            result = true;
                            goto done;
                        } catch (GuestDetectionException& ex) {
                            LOG4CXX_DEBUG(logger, "Failed to detect WindowsGuest: " << ex);
                        }
                    }
                }
            }
        }
    } catch (TraceableException& ex) {
        LOG4CXX_ERROR(logger, "Failed to detect OS: " << ex);
    }

done:

    // Restore the original state
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        vcpu(i).intercept_system_calls(vcpu_syscall_intercept[i]);
        vcpu(i).intercept_cr_writes(3, vcpu_cr3_intercept[i]);
    }

    return result;
}

Guest* DomainImpl::guest() { return guest_.get(); }
const Guest* DomainImpl::guest() const { return guest_.get(); }

void DomainImpl::intercept_system_calls(bool enabled) {
    for (unsigned int i = 0; i < vcpu_count(); ++i) {
        vcpu(i).intercept_system_calls(enabled);
    }
}

void DomainImpl::intercept_cr_writes(int cr, bool enabled) {
    for (unsigned int i = 0; i < vcpu_count(); ++i) {
        vcpu(i).intercept_cr_writes(cr, enabled);
    }
}

void DomainImpl::interrupt() {
    LOG4CXX_DEBUG(logger,
                  "Domain " << id() << " interrupted - Injection Count: " << injection_.count_);

    // Wait for no injection threads to be active
    std::unique_lock lock(injection_.mtx_);
    injection_.cv_.wait(lock, [this] { return injection_.count_ == 0; });

    // Notify managers
    breakpoint_manager_.interrupt();
    watchpoint_manager_.interrupt();
    single_step_manager_.interrupt();

    // Interrupt all of our threads
    interrupted_ = true;
    const uint64_t value = vcpu_count();
    if (unlikely(::write(efd_, &value, sizeof(value)) < 0)) {
        LOG4CXX_ERROR(logger, "Failed to notify eventfd");
    }
}

inline bool DomainImpl::matches_syscall_filters(const Vcpu& vcpu) const {
    /*
     * The correct operation here is to check the vcpu syscall filter first.
     * If that matches, just return true. Otherwise check the domain filter.
     */

    if (!vcpu.system_call_filter().enabled() || !vcpu.system_call_filter().matches(vcpu)) {
        if (system_call_filter().enabled() && !system_call_filter().matches(vcpu)) {
            return false;
        }
    }
    return true;
}

struct worker_thread_info {
    std::thread thread;
    std::mutex mtx;
    std::unique_ptr<Event> event;
    std::atomic_bool completed = false;
};

void DomainImpl::event_deliverer(EventCallback* callback, struct worker_thread_info* worker_info) {
restart:
    DomainImpl::thread_local_domain(*this);
    Event* event = worker_info->event.get();
    ThreadLocalEvent::set(*event);

    try {
        switch (event->type()) {
        case EventType::EVENT_EXCEPTION:
            if (event->exception().vector() != x86::Exception::INT3)
                break;
        // Fall through
        case EventType::EVENT_MEM_ACCESS:
            handle_breakpoint(*event);
            goto done;
        default:
            break;
        }

        if (event)
            callback->process_event(*event);

        if (event->type() == EventType::EVENT_FAST_SYSCALL) {

            if (event->impl().injection_performed()) {
                // If injection was performed, RIP was changed, so the instruction will not be
                // emulated automatically. We don't want to intercept the system call again, so we
                // need to inject a final system call to put the event back into the right state.
                switch (event->syscall().instruction()) {
                case FastCallType::FASTCALL_SYSCALL:
                    static_cast<VcpuImpl&>(event->vcpu()).inject_syscall();
                    /*
                     * This is necessary because SYSCALL can be either
                     * two or three bytes (REX prefix optional). By saving it and manually,
                     * loading it into RCX after the system call, we don't have to care about
                     * how the original instruction was executed.
                     */
                    event->vcpu().registers().rcx(event->syscall().return_address());
                    break;
                case FastCallType::FASTCALL_SYSENTER:
                    static_cast<VcpuImpl&>(event->vcpu()).inject_sysenter();
                    /*
                     * The return address for SYSENTER is held on the stack, so
                     * we don't have to do any trickery to fix it up here.
                     */
                    break;
                default:
                    LOG4CXX_WARN(logger,
                                 "Unknown system call type, unable to perform final injection");
                }
            }

            if (event->syscall().hook_return()) {
                if (event->syscall().handler() && event->syscall().handler()->will_return()) {

                    // Bad naming here, but we want to prevent system calls from being turned off
                    static_cast<VcpuImpl&>(event->vcpu()).syscall_injection_start();

                    const uint64_t return_rsp = event->vcpu().registers().rsp();
                    const uint64_t tid = event->task().tid();

                    // Wait for a return for this thread
                    auto return_event = event->impl().suspend(
                        [&event, return_rsp, tid](const introvirt::Event& new_event) {
                            if (new_event.type() == EventType::EVENT_FAST_SYSCALL_RET &&
                                new_event.vcpu().registers().rsp() == return_rsp) {
                                return WakeAction::ACCEPT;
                            }
                            // This is not necessarily a bug, but can happen when the kernel
                            // runs stuff in the context of the thread that is suspended.
                            LOG4CXX_TRACE(logger, "TID " << tid << " Incorrect return rsp: 0x"
                                                         << std::hex
                                                         << new_event.vcpu().registers().rsp()
                                                         << " Wanted 0x" << return_rsp);
                            return WakeAction::PASS;
                        });
                    event->impl().discard(true);
                    return_event->impl().discard(false);

                    // It's okay for system calls to be disabled now
                    static_cast<VcpuImpl&>(event->vcpu()).syscall_injection_end();

                    // If we see a system call event, we somehow missed the return.
                    // Check if it matches the filter and deliver it.
                    if (return_event->type() == EventType::EVENT_FAST_SYSCALL) {
                        LOG4CXX_DEBUG(logger, "Missed a system call return for "
                                                  << event->syscall().name());

                        event->impl().discard(true);
                        worker_info->event = std::move(return_event);

                        auto& vcpu = event->vcpu();
                        if (!vcpu.intercept_system_calls())
                            goto done;

                        /*
                         * The correct operation here is to check the vcpu syscall filter first.
                         * If that matches, just return true. Otherwise check the domain filter.
                         */
                        if (matches_syscall_filters(vcpu))
                            goto restart;

                        goto done;
                    }

                    // Set the system call index from the original call
                    return_event->syscall().impl().raw_index(event->syscall().raw_index());

                    // Take the handler out of the original event
                    auto handler = event->syscall().impl().release_handler();

                    // Give it the new data
                    handler->handle_return_event(*return_event);

                    // Pass it in to the new event
                    return_event->syscall().impl().handler(std::move(handler));

                    // Deliver the event
                    ThreadLocalEvent::set(*return_event);
                    callback->process_event(*return_event);
                }
            }
        }

    } catch (InterruptedException& ex) {
        LOG4CXX_DEBUG(logger,
                      "Vcpu " << event->vcpu().id() << " thread interrupted while suspended");
    } catch (TraceableException& ex) {
        LOG4CXX_WARN(logger, "Vcpu " << event->vcpu().id()
                                     << " poller threw an exception during delivery: " << ex);
        interrupt();
    }

done:
    std::lock_guard lock(worker_info->mtx);
    worker_info->event.reset();
    worker_info->completed = true;
}

void DomainImpl::vcpu_poller_thread(Vcpu* ivcpu, EventCallback* callback, int efd) {
    VcpuImpl& vcpu = reinterpret_cast<VcpuImpl&>(*ivcpu);
    DomainImpl::thread_local_domain(*this);

    struct pollfd fd_entries[2];
    std::list<worker_thread_info> threads;

    fd_entries[0].fd = vcpu.event_fd();
    fd_entries[0].events = POLLIN;

    fd_entries[1].fd = efd;
    fd_entries[1].events = POLLIN;

    while (true) {
        try {
            if (poll_fds(fd_entries, 2, -1, vcpu.id()) > 0) {

                // Check if the interrupt fd has been triggered
                if (unlikely(fd_entries[1].revents & POLLIN)) {
                    // Interrupted!
                    LOG4CXX_DEBUG(logger, "Thread " << std::hex << std::this_thread::get_id()
                                                    << ": Interrupted by eventfd");

                    // Interrupt all suspended threads
                    for (auto& entry : threads) {
                        std::lock_guard lock(entry.mtx);
                        if (!entry.completed) {
                            entry.event->impl().interrupt();
                            LOG4CXX_DEBUG(logger, "Interrupted suspended thread");
                        }
                    }

                    break;
                }

                // Check if the vcpu has an event
                if (likely(fd_entries[0].revents & POLLIN)) {
                    std::unique_ptr<HypervisorEvent> hypervisor_event = vcpu.event();

                    if (unlikely(hypervisor_event == nullptr))
                        continue;

                    auto event = filter_event(std::move(hypervisor_event));
                    if (!event)
                        continue;

                    try {
                        worker_thread_info& entry = threads.emplace_back();
                        entry.event = std::move(event);
                        entry.thread =
                            std::thread(&DomainImpl::event_deliverer, this, callback, &entry);

                    } catch (TraceableException& ex) {
                        LOG4CXX_WARN(logger, "Domain " << name() << " Vcpu " << vcpu.id()
                                                       << " poller threw an exception: " << ex);
                        break;
                    }
                }
            }

            // Expire dead threads
            for (auto iter = threads.begin(); iter != threads.end();) {
                auto& entry = *iter;

                std::unique_lock lock(entry.mtx, std::try_to_lock);
                if (lock.owns_lock() && entry.completed) {
                    if (entry.thread.joinable())
                        entry.thread.join();

                    lock.unlock();
                    iter = threads.erase(iter);
                } else {
                    ++iter;
                }
            }
        } catch (EventPollException& ex) {
            LOG4CXX_WARN(logger, "Vcpu " << vcpu.id() << " poll exception");
            vcpu.domain().interrupt();
            break;
        }
    }

    // Wait for all threads to exit
    for (auto& entry : threads) {
        if (entry.thread.joinable())
            entry.thread.join();
    }
}

void DomainImpl::poll(EventCallback& callback) {
    uint64_t efd_init = 0;
    if (unlikely(::write(efd_, &efd_init, sizeof(efd_init)) < 0)) {
        LOG4CXX_ERROR(logger, "Failed to clear eventfd");
    }
    interrupted_ = false;

    // Block all signals for our threads
    sigset_t oldset;
    sigset_t set = {};
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, &oldset);

    // Create a thread for each Vcpu
    std::vector<std::thread> pollers_threads;
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        VcpuImpl& v = static_cast<VcpuImpl&>(vcpu(i));
        pollers_threads.emplace_back(&DomainImpl::vcpu_poller_thread, this, &v, &callback, efd_);
        LOG4CXX_DEBUG(logger, "Domain " << id() << ": Started event poller thread 0x" << std::hex
                                        << pollers_threads.back().native_handle());
    }

    // Restore signals for this thread
    pthread_sigmask(SIG_SETMASK, &oldset, nullptr);

    // Wait for all of the threads to finish
    for (std::thread& thread : pollers_threads) {
        thread.join();
    }
}

void DomainImpl::initialize() {
    {
        auto& vcpu0 = vcpu(0);
        vcpu0.pause();
        page_directory_.reconfigure(vcpu0);
        vcpu0.resume();
    }

    try {
        for (uint32_t i = 0; i < vcpu_count(); ++i) {
            struct pollfd fd_entry;
            fd_entry.fd = static_cast<VcpuImpl&>(vcpu(i)).event_fd();
            fd_entry.events = POLLIN;
            fd_entry.revents = 0;
            pollfds_.push_back(fd_entry);

            stepping_events_.by_vcpu_.push_back(nullptr);
        }
        // Add the eventfd descriptor
        struct pollfd fd_entry;
        fd_entry.fd = efd_;
        fd_entry.events = POLLIN;
        fd_entry.revents = 0;
        pollfds_.push_back(fd_entry);
    } catch (NotImplementedException& ex) {
        // The base class should be overriding poll() if this happens
        LOG4CXX_ERROR(logger, "Domain " << id() << " does not support VCPU level polling");
        throw;
    }
}

TaskFilter& DomainImpl::task_filter() { return task_filter_; }

SystemCallFilter& DomainImpl::system_call_filter() { return system_call_filter_; }
const SystemCallFilter& DomainImpl::system_call_filter() const { return system_call_filter_; }

void DomainImpl::pause_all_other_vcpus(const Vcpu& v) {
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        if (i != v.id())
            vcpu(i).pause();
    }
}
void DomainImpl::resume_all_other_vcpus(const Vcpu& v) {
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        if (i != v.id())
            vcpu(i).resume();
    }
}

std::shared_ptr<Breakpoint> DomainImpl::create_breakpoint(const GuestAddress& address,
                                                          std::function<void(Event&)> callback) {

    auto result = std::make_shared<BreakpointImpl>(address, callback);
    breakpoint_manager_.add_ref(result);
    return result;
}

std::unique_ptr<Watchpoint> DomainImpl::create_watchpoint(const GuestAddress& address,
                                                          uint64_t length, bool read, bool write,
                                                          bool execute,
                                                          std::function<void(Event&)> callback) {
    auto result = std::make_unique<WatchpointImpl>(address, length, read, write, execute, callback);
    watchpoint_manager_.add_ref(*result);
    return result;
}

std::unique_ptr<SingleStep> DomainImpl::single_step(Vcpu& vcpu,
                                                    std::function<void(Event&)> callback) {
    auto result = std::make_unique<SingleStepImpl>(vcpu, callback);
    single_step_manager_.add_ref(*result);
    return result;
}

BreakpointManager& DomainImpl::breakpoint_manager() { return breakpoint_manager_; }
SingleStepManager& DomainImpl::single_step_manager() { return single_step_manager_; }
WatchpointManager& DomainImpl::watchpoint_manager() { return watchpoint_manager_; }

void DomainImpl::start_injection(Event& event) {
    if (unlikely(interrupted_)) {
        throw InterruptedException();
    }

    {
        std::lock_guard lock(injection_tids_.mtx_);
        auto [iter, inserted] = injection_tids_.set_.insert(event.task().tid());
        assert(inserted);
    }

    LOG4CXX_DEBUG(logger, "Starting injection on TID " << event.task().tid()
                                                       << " Event Type: " << event.type());

    std::lock_guard lock(injection_.mtx_);
    if (unlikely(interrupted_))
        throw InterruptedException();
    injection_.count_++;

    breakpoint_manager_.start_injection();

    switch (event.type()) {
    case EventType::EVENT_EXCEPTION:
        if (event.exception().vector() != x86::Exception::INT3)
            break;
        // Fall through
    case EventType::EVENT_MEM_ACCESS:
        resume_all_other_vcpus(event.vcpu());
        bp_mutex_.unlock();
        break;
    default:
        break;
    }
}

void DomainImpl::end_injection(Event& event) {
    {
        std::lock_guard lock(injection_tids_.mtx_);
        LOG4CXX_DEBUG(logger, "Searching for injection on TID " << event.task().tid());
        auto iter = injection_tids_.set_.find(event.task().tid());
        assert(iter != injection_tids_.set_.end());
        injection_tids_.set_.erase(iter);
    }

    LOG4CXX_DEBUG(logger, "Ending injection on TID " << event.task().tid()
                                                     << " Event Type: " << event.type());

    switch (event.type()) {
    case EventType::EVENT_EXCEPTION:
        if (event.exception().vector() != x86::Exception::INT3)
            break;
        // Fall through
    case EventType::EVENT_MEM_ACCESS:
        bp_mutex_.lock();
        pause_all_other_vcpus(event.vcpu());
        break;
    default:
        break;
    }

    std::lock_guard lock(injection_.mtx_);
    breakpoint_manager_.end_injection();

    injection_.count_--;
    assert(injection_.count_ >= 0);
    if (injection_.count_ == 0) {
        injection_.cv_.notify_all();
    }
}

void DomainImpl::suspend_event(Event& event) {
    std::lock_guard lock(suspended_events_.mtx_);
    suspended_events_.map_.insert(std::make_pair(event.impl().thread_id(), &event));
    LOG4CXX_TRACE(logger,
                  "Added thread 0x" << std::hex << event.impl().thread_id() << " to suspend map");
}

void DomainImpl::suspend_event_step(Event& event) {
    std::lock_guard lock(stepping_events_.mtx_);
    stepping_events_.by_vcpu_[event.vcpu().id()] = &event;
    LOG4CXX_TRACE(logger, "Added VCPU " << event.vcpu().id() << " to step suspend map");
}

const x86::PageDirectory& DomainImpl::page_directory() const { return page_directory_; }

DomainImpl::DomainImpl()
    : watchpoint_manager_(), breakpoint_manager_(), page_directory_(*this),
      efd_(eventfd(0, EFD_SEMAPHORE)) {}

DomainImpl::~DomainImpl() { close(efd_); }

inline static int poll_fds(struct pollfd* fds, int nfds, int timeout, uint32_t domain_id) {
    // Poll for an event
    int result = ::poll(fds, nfds, timeout);
    switch (result) {
    case 0: // Poll timeout
        return 0;
    case -1: // Error
        // Check if we were interrupted by a signal or something
        if (errno == EINTR) {
            LOG4CXX_DEBUG(logger, "poll() interrupted for Domain " << domain_id);
        } else {
            LOG4CXX_WARN(logger, "poll() error on Domain " << domain_id << ": " << strerror(errno));
        }
        throw EventPollException(errno);
    }
    return result;
}

static thread_local Domain* thread_local_domain_;

Domain& DomainImpl::thread_local_domain() { return *thread_local_domain_; }
void DomainImpl::thread_local_domain(Domain& d) { thread_local_domain_ = &d; }
void DomainImpl::clear_thread_local_domain() { thread_local_domain_ = nullptr; }
Domain& Domain::thread_local_domain() { return DomainImpl::thread_local_domain(); }

} // namespace introvirt