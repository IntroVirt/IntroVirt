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
#include "KvmRegisters.hh"

#include <introvirt/core/exception/CommandFailedException.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/util/compiler.hh>

#include <log4cxx/logger.h>

#include <sys/ioctl.h>

namespace introvirt {
namespace kvm {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.kvm.KvmRegisters"));

uint64_t KvmRegisters::rax() const { return regs_->rax; }
void KvmRegisters::rax(uint64_t val) {
    regs_->rax = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::rbx() const { return regs_->rbx; }
void KvmRegisters::rbx(uint64_t val) {
    regs_->rbx = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::rcx() const { return regs_->rcx; }
void KvmRegisters::rcx(uint64_t val) {
    regs_->rcx = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::rdx() const { return regs_->rdx; }
void KvmRegisters::rdx(uint64_t val) {
    regs_->rdx = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::r15() const { return regs_->r15; }
void KvmRegisters::r15(uint64_t val) {
    regs_->r15 = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::r14() const { return regs_->r14; }
void KvmRegisters::r14(uint64_t val) {
    regs_->r14 = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::r13() const { return regs_->r13; }
void KvmRegisters::r13(uint64_t val) {
    regs_->r13 = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::r12() const { return regs_->r12; }
void KvmRegisters::r12(uint64_t val) {
    regs_->r12 = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::r11() const { return regs_->r11; }
void KvmRegisters::r11(uint64_t val) {
    regs_->r11 = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::r10() const { return regs_->r10; }
void KvmRegisters::r10(uint64_t val) {
    regs_->r10 = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::r9() const { return regs_->r9; }
void KvmRegisters::r9(uint64_t val) {
    regs_->r9 = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::r8() const { return regs_->r8; }
void KvmRegisters::r8(uint64_t val) {
    regs_->r8 = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::rsi() const { return regs_->rsi; }
void KvmRegisters::rsi(uint64_t val) {
    regs_->rsi = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::rdi() const { return regs_->rdi; }
void KvmRegisters::rdi(uint64_t val) {
    regs_->rdi = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::rsp() const { return regs_->rsp; }
void KvmRegisters::rsp(uint64_t val) {
    regs_->rsp = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::rbp() const { return regs_->rbp; }
void KvmRegisters::rbp(uint64_t val) {
    regs_->rbp = val;
    changed_regs_ = true;
}

uint64_t KvmRegisters::rip() const { return regs_->rip; }
void KvmRegisters::rip(uint64_t val) {
    regs_->rip = val;
    changed_regs_ = true;
}

x86::Flags& KvmRegisters::rflags() { return rflags_; }
const x86::Flags& KvmRegisters::rflags() const { return rflags_; }
void KvmRegisters::rflags(const x86::Flags& val) { rflags_.value(val.value()); }

x86::Efer KvmRegisters::efer() const { return x86::Efer(sregs_->efer); }

x86::Cr0 KvmRegisters::cr0() const { return x86::Cr0(sregs_->cr0); }
uint64_t KvmRegisters::cr2() const { return sregs_->cr0; }
uint64_t KvmRegisters::cr3() const { return sregs_->cr3; }
x86::Cr4 KvmRegisters::cr4() const { return x86::Cr4(sregs_->cr4); }
uint64_t KvmRegisters::cr8() const { return sregs_->cr8; }

void KvmRegisters::cr3(uint64_t value) {
    sregs_->cr3 = value;
    changed_sregs_ = true;
}

uint64_t KvmRegisters::gdtr_base() const { return sregs_->gdt.base; }
uint32_t KvmRegisters::gdtr_limit() const { return sregs_->gdt.limit; }

uint64_t KvmRegisters::idtr_base() const { return sregs_->idt.base; }
uint32_t KvmRegisters::idtr_limit() const { return sregs_->idt.limit; }

bool KvmRegisters::cs_long_mode() const { return sregs_->cs.l; }

x86::Segment KvmRegisters::cs() const {
    auto& seg = sregs_->cs;
    return x86::Segment(x86::SegmentSelector(seg.selector), seg.base, seg.limit, seg.type,
                        seg.present, seg.dpl, seg.db, seg.s, seg.l, seg.g, seg.avl);
}

void KvmRegisters::cs(x86::Segment src) {
    auto& dst = sregs_->cs;
    dst.selector = src.selector().value();
    dst.base = src.base();
    dst.limit = src.limit();
    dst.type = src.type();
    dst.present = src.present();
    dst.dpl = src.dpl();
    dst.db = src.db();
    dst.s = src.s();
    dst.l = src.long_mode();
    dst.g = src.granularity();
    dst.avl = src.avl();

    changed_sregs_ = true;
}

x86::Segment KvmRegisters::ds() const {
    auto& seg = sregs_->ds;
    return x86::Segment(x86::SegmentSelector(seg.selector), seg.base, seg.limit, seg.type,
                        seg.present, seg.dpl, seg.db, seg.s, seg.l, seg.g, seg.avl);
}
x86::Segment KvmRegisters::es() const {
    auto& seg = sregs_->es;
    return x86::Segment(x86::SegmentSelector(seg.selector), seg.base, seg.limit, seg.type,
                        seg.present, seg.dpl, seg.db, seg.s, seg.l, seg.g, seg.avl);
}
x86::Segment KvmRegisters::fs() const {
    auto& seg = sregs_->fs;
    return x86::Segment(x86::SegmentSelector(seg.selector), seg.base, seg.limit, seg.type,
                        seg.present, seg.dpl, seg.db, seg.s, seg.l, seg.g, seg.avl);
}
x86::Segment KvmRegisters::gs() const {
    auto& seg = sregs_->gs;
    return x86::Segment(x86::SegmentSelector(seg.selector), seg.base, seg.limit, seg.type,
                        seg.present, seg.dpl, seg.db, seg.s, seg.l, seg.g, seg.avl);
}
x86::Segment KvmRegisters::ss() const {
    auto& seg = sregs_->ss;
    return x86::Segment(x86::SegmentSelector(seg.selector), seg.base, seg.limit, seg.type,
                        seg.present, seg.dpl, seg.db, seg.s, seg.l, seg.g, seg.avl);
}
x86::Segment KvmRegisters::tr() const {
    auto& seg = sregs_->tr;
    return x86::Segment(x86::SegmentSelector(seg.selector), seg.base, seg.limit, seg.type,
                        seg.present, seg.dpl, seg.db, seg.s, seg.l, seg.g, seg.avl);
}

x86::Segment KvmRegisters::ldt() const {
    auto& seg = sregs_->ldt;
    return x86::Segment(x86::SegmentSelector(seg.selector), seg.base, seg.limit, seg.type,
                        seg.present, seg.dpl, seg.db, seg.s, seg.l, seg.g, seg.avl);
}

void KvmRegisters::read() {
    if (unlikely(ioctl(fd_, KVM_GET_REGS, regs_))) {
        throw CommandFailedException("Failed to call KVM_GET_REGS", errno);
    }
    if (unlikely(ioctl(fd_, KVM_GET_SREGS, sregs_))) {
        throw CommandFailedException("Failed to call KVM_GET_SREGS", errno);
    }
    if (unlikely(ioctl(fd_, KVM_GET_DEBUGREGS, debugregs_))) {
        throw CommandFailedException("Failed to call KVM_GET_DEBUGREGS", errno);
    }
    changed_regs_ = false;
}

void KvmRegisters::write() {
    if (unlikely(event_data_ == nullptr)) {
        LOG4CXX_ERROR(logger, "Cannot write back registers on a cloned KvmVcpu");
        throw InvalidMethodException();
    }

    if (changed_regs_) {
        if (unlikely(ioctl(fd_, KVM_SET_REGS, regs_))) {
            throw CommandFailedException("Failed to call KVM_SET_REGS", errno);
        }
        changed_regs_ = false;
    }

    if (changed_sregs_) {
        if (unlikely(ioctl(fd_, KVM_SET_SREGS, sregs_))) {
            throw CommandFailedException("Failed to call KVM_SET_SREGS", errno);
        }
        changed_sregs_ = false;
    }

    // Disabled since we don't expose changing these yet.
    /*
    if (unlikely(ioctl(fd_, KVM_SET_DEBUGREGS, &debugregs_))) {
        throw CommandFailedException("Failed to call KVM_SET_DEBUGREGS", errno);
    }
    */
}

uint64_t KvmRegisters::msr(x86::Msr msr) const {
    std::array<char, sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry)> buffer;
    struct kvm_msrs* msrs = reinterpret_cast<struct kvm_msrs*>(buffer.data());
    msrs->nmsrs = 1;
    msrs->entries[0].index = static_cast<uint64_t>(msr);

    // vcpu should be paused if they were able to call registers()
    if (unlikely(ioctl(fd_, KVM_GET_MSRS, msrs) < 0)) {
        throw CommandFailedException("Failed to call KVM_GET_MSRS", errno);
    }

    return msrs->entries[0].data;
}

void KvmRegisters::msr(x86::Msr msr, uint64_t val) {
    std::array<char, sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry)> buffer;
    struct kvm_msrs* msrs = reinterpret_cast<struct kvm_msrs*>(buffer.data());
    msrs->nmsrs = 1;
    msrs->entries[0].index = static_cast<uint64_t>(msr);
    msrs->entries[0].data = val;

    // vcpu should be paused if they were able to call registers()
    if (unlikely(ioctl(fd_, KVM_SET_MSRS, msrs) < 0)) {
        throw CommandFailedException("Failed to call KVM_SET_MSRS", errno);
    }
}

KvmRegisters::KvmRegisters(struct kvm_introspection_event& event_data, int fd)
    : event_data_(&event_data),
      rflags_(reinterpret_cast<uint64_t&>(event_data_->regs.rflags), &changed_regs_), fd_(fd) {

    // This weirdness is because regs_->rflags is a __u64, which is defined slightly differently.
    static_assert(sizeof(regs_->rflags) == sizeof(uint64_t), "KVM rflags is not 64-bit");

    regs_ = &event_data_->regs;
    sregs_ = &event_data_->sregs;
    debugregs_ = &event_data_->debugregs;
}

KvmRegisters::KvmRegisters(const KvmRegisters& src)
    : copy_(std::make_unique<struct kvm_introspection_event>()),
      rflags_(reinterpret_cast<uint64_t&>(copy_->regs.rflags), &changed_regs_), fd_(src.fd_) {

    // Set up our pointers so they point to our copy
    event_data_ = nullptr;
    regs_ = &copy_->regs;
    sregs_ = &copy_->sregs;
    debugregs_ = &copy_->debugregs;

    // Copy over the data from the source
    *regs_ = *src.regs_;
    *sregs_ = *src.sregs_;
    *debugregs_ = *src.debugregs_;
}

KvmRegisters::~KvmRegisters() = default;

} // namespace kvm
} // namespace introvirt