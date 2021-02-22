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

#include <cstdint>
#include <linux/kvm.h>

namespace introvirt {
namespace kvm {

#define PFERR_PRESENT_BIT 0
#define PFERR_WRITE_BIT 1
#define PFERR_USER_BIT 2
#define PFERR_RSVD_BIT 3
#define PFERR_FETCH_BIT 4

#define PFERR_PRESENT_MASK (1U << PFERR_PRESENT_BIT)
#define PFERR_WRITE_MASK (1U << PFERR_WRITE_BIT)
#define PFERR_USER_MASK (1U << PFERR_USER_BIT)
#define PFERR_FETCH_MASK (1U << PFERR_FETCH_BIT)

/*
 * Introspection API (KVM_CAP_INTROSPECTION)
 */

//
// structs
//
struct kvm_introspection_patch_ver {
    char buffer[64];
};

struct kvm_inject_trap {
    __u32 vector;
    __u32 error_code;
    __u64 cr2;
    int has_error;
};

struct kvm_ept_permissions {
    __u64 gfn;
    __u8 perms : 3;
};

struct kvm_cr_monitor {
    int cr;
    int mode; // Bitmask of KVM_MONITOR_CR_[READ/WRITE]
};

struct kvm_introspection_event {
    __u64 event_id; // Increments with each event
    int event_type; // KVM_EVENT_TYPE_
    int vcpu_id;    // The ID of the VCPU that triggered the event

    // Registers
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    struct kvm_debugregs debugregs;

    union {
        struct {
            int cr;      // 0-8
            int mode;    // KVM_MONITOR_CR_[READ/WRITE]
            __u64 value; // Value being loaded/stored
        } cr_access;
        struct {
            int type; // KVM_EVENT_SYSTEM_CALL_TYPE_[X]
            __u64 return_address;
        } system_call;
        struct {
            int type;        // KVM_EVENT_SYSTEM_CALL_RET_TYPE_[X]
            __u64 thread_id; // The address of the kernel stack base for this thread (or 0 if not
                             // available)
        } system_call_ret;
        struct {
            int vector; // The vector that caused the trap, e.g. BP_VECTOR
        } trap;
        struct {
            __u64 gpa;
            __u32 error_code;
        } mem_event;
        struct {
            __u64 gva;
        } invlpg;
    };
};

//
// constants
//
#define KVM_EVENT_FAST_SYSCALL 0     // A system call event
#define KVM_EVENT_FAST_SYSCALL_RET 1 // A system call return event
#define KVM_EVENT_SW_INT 2           // A software interrupt event
#define KVM_EVENT_SW_IRET 3          // A software interrupt return event
#define KVM_EVENT_CR_READ 4          // A control register was read
#define KVM_EVENT_CR_WRITE 5         // A control register was written to
#define KVM_EVENT_MSR_READ 6         // An MSR was read
#define KVM_EVENT_MSR_WRITE 7        // An MSR was written to
#define KVM_EVENT_EXCEPTION 8        // An x86 exception event
#define KVM_EVENT_MEM_ACCESS 9       // Hardware assisted paging violation (memory breakpoints)
#define KVM_EVENT_SINGLE_STEP 10     // Single step event
#define KVM_EVENT_HYPERCALL 11       // An intercepted hypercall
#define KVM_EVENT_REBOOT 12          // The guest VM has rebooted
#define KVM_EVENT_SHUTDOWN 13        // The guest VM has shutdown
#define KVM_EVENT_INVLPG 14          // INVLPG instruction was executed

#define KVM_EVENT_SYSTEM_CALL_TYPE_SYSCALL 1
#define KVM_EVENT_SYSTEM_CALL_TYPE_SYSENTER 2

#define KVM_EVENT_SYSTEM_CALL_RET_TYPE_SYSRET 1
#define KVM_EVENT_SYSTEM_CALL_RET_TYPE_SYSEXIT 2

#define KVM_MONITOR_CR_READ (1u << 0)
#define KVM_MONITOR_CR_WRITE (1u << 1)

#define KVM_CAP_INTROSPECTION 20150308
#define KVM_INTROSPECTION_API_VERSION 5

#ifndef KVM_INTROSPECTION_PATCH_VERSION
#define KVM_INTROSPECTION_PATCH_VERSION "UNKNOWN_INTROVIRT_VERSION"
#endif

//
// ioctls
//

// kvm dev level
#define KVM_ATTACH_VM _IOW(KVMIO, 0xd0, pid_t)
#define KVM_GET_INTROSPECTION_PATCH_VERSION _IOR(KVMIO, 0xd1, struct kvm_introspection_patch_ver)

// VM Level
#define KVM_ATTACH_VCPU _IOW(KVMIO, 0xd2, unsigned long)
#define KVM_SET_MEM_ACCESS_ENABLED _IOW(KVMIO, 0xd4, unsigned long)
#define KVM_SET_MEM_ACCESS _IOW(KVMIO, 0xd5, struct kvm_ept_permissions)

// VCPU level
#define KVM_SET_CR_MONITOR _IOW(KVMIO, 0xd6, struct kvm_cr_monitor)
#define KVM_SET_SYSCALL_HOOK _IOW(KVMIO, 0xd7, unsigned long)
#define KVM_SET_VMCALL_HOOK _IOW(KVMIO, 0xd8, unsigned long)
#define KVM_VCPU_PAUSE _IO(KVMIO, 0xd9)
#define KVM_VCPU_UNPAUSE _IO(KVMIO, 0xda)
#define KVM_GET_INTROSPECTION_EVENT _IOR(KVMIO, 0xdb, struct kvm_introspection_event)
#define KVM_COMPLETE_INTROSPECTION_EVENT _IO(KVMIO, 0xdc)
#define KVM_INJECT_TRAP _IOW(KVMIO, 0xdd, struct kvm_inject_trap)
#define KVM_SET_MONITOR_TRAP_FLAG _IOW(KVMIO, 0xde, unsigned long)
#define KVM_SET_INVLPG_HOOK _IOW(KVMIO, 0xdf, unsigned long)
#define KVM_VCPU_INJECT_SYSCALL _IO(KVMIO, 0xf1)
#define KVM_VCPU_INJECT_SYSENTER _IO(KVMIO, 0xf2)

} // namespace kvm
} // namespace introvirt