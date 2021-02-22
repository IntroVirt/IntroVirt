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
#include "KvmVcpu.hh"
#include "KvmDomain.hh"
#include "KvmEvent.hh"
#include "kvm_introspection.hh"

#include <introvirt/core/exception/CommandFailedException.hh>
#include <introvirt/core/exception/NotImplementedException.hh>
#include <introvirt/core/syscall/SystemCallFilter.hh>

#include <log4cxx/logger.h>

#include <cassert>
#include <cerrno>
#include <sys/ioctl.h>
#include <unistd.h>

namespace introvirt {
namespace kvm {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.kvm.KvmVcpu"));

KvmRegisters& KvmVcpu::registers() {
    std::lock_guard lock(mtx_);

    /*
     * If the vcpu is in an event, the register state should already be loaded.
     * Also if we've set pause_loaded_registers_, it should be loaded as well.
     */
    if (in_event_ || pause_loaded_registers_)
        return registers_;

    // If the vcpu is not in an active event, it must be paused before accessing registers.
    if (unlikely(pause_count_ == 0)) {
        throw CommandFailedException("Cannot access register state while VCPU is running", EBUSY);
    }

    LOG4CXX_DEBUG(logger, "Domain " << domain().name() << " Vcpu " << id()
                                    << ": Loading registers for paused VCPU");
    registers_.read();
    pause_loaded_registers_ = true;
    return registers_;
}

const KvmRegisters& KvmVcpu::registers() const {
    // Calling the non-const version because we may need to update the registers
    return const_cast<KvmVcpu*>(this)->registers();
}

void KvmVcpu::pause() {
    std::lock_guard lock(mtx_);
    const int count = ++pause_count_;
    if (count == 1) {
        if (unlikely(ioctl(fd_, KVM_VCPU_PAUSE) < 0)) {
            throw CommandFailedException("Failed to pause vcpu", errno);
        }
        LOG4CXX_TRACE(logger, "Domain " << domain().id() << " Vcpu " << id() << " paused");
        /*
         * If we're in an event, mark the registers as pause loaded.
         * That way if the event is completed, but the vpcu remains paused,
         * the registers don't get reloaded.
         */
        if (in_event_)
            pause_loaded_registers_ = true;
    }
}

void KvmVcpu::resume() {
    std::lock_guard lock(mtx_);

    const int count = --pause_count_;
    if (count == 0) {
        if (unlikely(ioctl(fd_, KVM_VCPU_UNPAUSE) < 0)) {
            throw CommandFailedException("Failed to resume vcpu", errno);
        }
        LOG4CXX_TRACE(logger, "Domain " << domain().id() << " Vcpu " << id() << " resumed");
        pause_loaded_registers_ = false;
    }
}

void KvmVcpu::intercept_system_calls(bool enabled) {
    std::lock_guard lock(mtx_);

    static const std::string error_string = "Failed to set vcpu system call intercept";

    if (enabled != syscall_intercept_) {
        if (syscall_injection_count_ == 0) {
            _send_command(KVM_SET_SYSCALL_HOOK, enabled, error_string);
            LOG4CXX_DEBUG(logger, "Domain " << domain().name() << " Vcpu " << id_
                                            << " intercept_system_calls(" << enabled << ")");
        }
        syscall_intercept_ = enabled;
    }
}

bool KvmVcpu::intercept_system_calls() const {
    std::lock_guard lock(mtx_);
    return syscall_intercept_;
}

void KvmVcpu::intercept_cr_writes(int cr, bool enabled) {
    std::lock_guard lock(mtx_);

    static const std::string error_string = "Failed to set control register intercept";

    switch (cr) {
    case 0:
    case 2:
    case 3:
    case 4:
    case 8: {
        struct kvm_cr_monitor cr_mon;
        cr_mon.cr = cr;
        cr_mon.mode = cr_hook_[cr];
        if (enabled) {
            cr_mon.mode |= KVM_MONITOR_CR_WRITE;
        } else {
            cr_mon.mode &= ~KVM_MONITOR_CR_WRITE;
        }

        // No change is being made
        if (cr_mon.mode == cr_hook_[cr])
            return;

        _send_command(KVM_SET_CR_MONITOR, reinterpret_cast<unsigned long>(&cr_mon), error_string);
        cr_hook_[cr] = cr_mon.mode;
        LOG4CXX_DEBUG(logger, "Domain " << domain().name() << " Vcpu " << id_
                                        << " intercept_cr_writes(" << cr << ", " << enabled << ")");
        break;
    }
    default:
        throw NotImplementedException("Invalid Control Register: " + std::to_string(cr));
    }
}

bool KvmVcpu::intercept_cr_writes(int cr) const {
    std::lock_guard lock(mtx_);

    switch (cr) {
    case 0:
    case 2:
    case 3:
    case 4:
    case 8:
        return cr_hook_[cr] & KVM_MONITOR_CR_WRITE;
    default:
        throw NotImplementedException("Invalid Control Register: " + std::to_string(cr));
    }
}

void KvmVcpu::intercept_exception(x86::Exception vector, bool enabled) {
    std::lock_guard lock(mtx_);

    switch (vector) {
    case x86::Exception::INT3: {
        static const std::string error_string = "Failed to set vcpu Int3 intercept";
        if (int3_intercept_ == enabled)
            return; // Already in the desired state.

        struct kvm_guest_debug dbg = {};
        if (enabled) {
            dbg.control = (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP);
        }

        _send_command(KVM_SET_GUEST_DEBUG, reinterpret_cast<unsigned long>(&dbg), error_string);
        int3_intercept_ = enabled;

        break;
    }
    default:
        throw NotImplementedException("Exception type not supported");
    }

    LOG4CXX_DEBUG(logger, "Domain " << domain().name() << " Vcpu" << id_ << " intercept_exception("
                                    << to_string(vector) << ", " << enabled << ")");
}

bool KvmVcpu::intercept_exception(x86::Exception vector) const {
    std::lock_guard lock(mtx_);

    switch (vector) {
    case x86::Exception::INT3:
        return int3_intercept_;
    default:
        return false;
    }
}

void KvmVcpu::single_step(bool enabled) {
    std::lock_guard lock(mtx_);

    static const std::string error_string = "Failed to set vcpu single stepping";
    _send_command(KVM_SET_MONITOR_TRAP_FLAG, enabled, error_string);
    single_stepping_ = enabled;
}

bool KvmVcpu::single_step() const {
    std::lock_guard lock(mtx_);
    return single_stepping_;
}

void KvmVcpu::inject_exception(x86::Exception vector) {
    KvmVcpu::inject_exception(vector, 0xFFFFFFFF);
}

void KvmVcpu::inject_exception(x86::Exception vector, int64_t error_code) {
    KvmVcpu::inject_exception(vector, error_code, 0);
}

void KvmVcpu::inject_exception(x86::Exception vector, int64_t error_code, uint64_t cr2) {
    std::lock_guard lock(mtx_);

    struct kvm_inject_trap kvm_inject_trap;
    kvm_inject_trap.cr2 = cr2;
    kvm_inject_trap.error_code = error_code;
    kvm_inject_trap.has_error = (error_code != 0xFFFFFFFF);
    kvm_inject_trap.vector = static_cast<uint32_t>(vector);

    static const std::string error_string = "Failed to set inject exception";
    _send_command(KVM_INJECT_TRAP, reinterpret_cast<unsigned long>(&kvm_inject_trap), error_string);

    LOG4CXX_DEBUG(logger, "Domain " << domain().name() << " Vcpu" << id_ << " inject_exception("
                                    << to_string(vector) << ", " << error_code << ", 0x" << std::hex
                                    << cr2 << ")");
}

void KvmVcpu::inject_syscall() {
    LOG4CXX_DEBUG(logger, "Vcpu " << id_ << ": Injecting SYSCALL")

    // Sync up our registers
    registers_.write();

    int r = ioctl(fd_, KVM_VCPU_INJECT_SYSCALL);
    if (unlikely(r != 0)) {
        // TODO: Errno isn't actually valid here, it's the result from x86_emulate_insn()
        throw CommandFailedException("Failed to inject SYSCALL instruction", errno);
    }

    // Reload the VCPU registers since we're now in the kernel
    registers_.read();
}

void KvmVcpu::inject_sysenter() {
    LOG4CXX_DEBUG(logger, "Vcpu " << id_ << ": Injecting SYSENTER")

    // Sync up our registers
    registers_.write();

    int r = ioctl(fd_, KVM_VCPU_INJECT_SYSENTER);

    if (unlikely(r != 0)) {
        // TODO: Errno isn't actually valid here, it's the result from x86_emulate_insn()
        throw CommandFailedException("Failed to inject SYSENTER instruction", errno);
    }

    // Reload the VCPU registers since we're now in the kernel
    registers_.read();
}

int KvmVcpu::event_fd() const { return fd_; }

void KvmVcpu::write_registers() {
    assert(fd_ != 0);
    registers().write();
}

std::unique_ptr<HypervisorEvent> KvmVcpu::event() {
    std::lock_guard lock(mtx_);

    if (unlikely(ioctl(fd_, KVM_GET_INTROSPECTION_EVENT, &event_data_) < 0)) {
        switch (errno) {
        case ENOENT:
            LOG4CXX_WARN(logger, "KvmVcpu::event() called with no pending event");
            return nullptr;
        default:
            LOG4CXX_WARN(logger, "KvmVcpu::event() failed");
            throw CommandFailedException("KvmVcpu::event() failed", errno);
        }
    }

    // We're in an event now, registers are loaded and valid
    in_event_ = true;

    LOG4CXX_TRACE(logger, "Received event for VCPU "
                              << id() << ":" << event_data_.event_id
                              << " Type: " << static_cast<EventType>(event_data_.event_type));

    // Create the event instance
    return create_kvm_event(*this, event_data_);
}

bool KvmVcpu::handling_event() const {
    std::lock_guard lock(mtx_);
    return in_event_;
}

void KvmVcpu::complete_event() {
    std::lock_guard lock(mtx_);

    if (likely(in_event_ == true)) {
        // Write out the registers
        registers_.write();

        // Mark the event as completed
        in_event_ = false;

        // Tell the hypervisor that we're done
        if (unlikely(ioctl(fd_, KVM_COMPLETE_INTROSPECTION_EVENT) < 0)) {
            LOG4CXX_ERROR(logger, "Failed to complete introspection event: " << strerror(errno));
        }
        LOG4CXX_TRACE(logger, "KvmVcpu::complete_event() completed");
    } else {
        LOG4CXX_ERROR(logger, "KvmVcpu::complete_event() called with no active event");
    }
}

std::unique_ptr<Vcpu> KvmVcpu::clone() const {
    std::lock_guard lock(mtx_);
    return std::make_unique<KvmVcpu>(*this);
}

void KvmVcpu::syscall_injection_start() {
    static const std::string err(
        "Failed to toggle system call intercept in syscall_injection_start()");

    std::lock_guard lock(mtx_);
    if (++syscall_injection_count_ == 1) {
        if (syscall_intercept_ != true)
            _send_command(KVM_SET_SYSCALL_HOOK, true, err);
    }
}

void KvmVcpu::syscall_injection_end() {
    static const std::string err(
        "Failed to toggle system call intercept in syscall_injection_end()");

    std::lock_guard lock(mtx_);
    if (--syscall_injection_count_ == 0) {
        if (syscall_intercept_ != true)
            _send_command(KVM_SET_SYSCALL_HOOK, false, err);
    }
}

void KvmVcpu::_send_command(unsigned long request, unsigned long value, const std::string& errstr) {
    pause();
    if (unlikely(ioctl(fd_, request, value) < 0)) {
        resume();
        throw CommandFailedException(errstr, errno);
    }
    resume();
}

void KvmVcpu::os_data(void* data) {
    std::lock_guard lock(mtx_);
    os_data_ = data;
}

void* KvmVcpu::os_data() const {
    std::lock_guard lock(mtx_);
    return os_data_;
}

KvmVcpu::KvmVcpu(KvmDomain& domain, uint32_t id, int fd)
    : VcpuImpl(domain, id), id_(id), fd_(fd), registers_(event_data_, fd) {

    static const std::string error_string = "Failed to set vmcall intercept";
    _send_command(KVM_SET_VMCALL_HOOK, 1, error_string);

    intercept_exception(x86::Exception::INT3, true);
}

// Intentionally setting fd_(0) so that commands don't work on a clone
KvmVcpu::KvmVcpu(const KvmVcpu& src)
    : VcpuImpl(src), id_(src.id_), fd_(0), registers_(src.registers_) {
    // Handle the case where the vcpu is not in an event, the registers haven't been loaded,
    // and clone() is called.
    if (!(src.in_event_ || src.pause_loaded_registers_)) {
        registers_.read();
    }
    pause_loaded_registers_ = true;
}

KvmVcpu::~KvmVcpu() {
    if (fd_) {
        LOG4CXX_DEBUG(logger, "~KvmVcpu()");
        pause();
        LOG4CXX_DEBUG(logger, "~pause");
        intercept_exception(x86::Exception::INT3, false);
        LOG4CXX_DEBUG(logger, "~intercept_exception");
        intercept_system_calls(false);
        LOG4CXX_DEBUG(logger, "~intercept_system_calls");
        if (single_step())
            single_step(false);

        resume();
        LOG4CXX_DEBUG(logger, "~resume");

        close(fd_);
        LOG4CXX_DEBUG(logger, "~close");
    }
}

} // namespace kvm
} // namespace introvirt