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
#include "KvmEvent.hh"
#include "KvmRegisters.hh"
#include "KvmVcpu.hh"

#include "core/event/EventImpl.hh"

#include <introvirt/core/exception/InterruptedException.hh>

#include <log4cxx/logger.h>

#include <sys/ioctl.h>
#include <type_traits>

namespace introvirt {
namespace kvm {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.kvm.KvmEvent"));

void KvmEvent::discard(bool value) { discarded_ = value; }

KvmEvent::KvmEvent(KvmVcpu& vcpu, struct kvm_introspection_event& event_data)
    : vcpu_(vcpu), event_data_(event_data), event_id_(event_data_.event_id) {

    original_event_type_ = static_cast<EventType>(event_data_.event_type);

    switch (event_data_.event_type) {
    case KVM_EVENT_FAST_SYSCALL: {
        switch (event_data_.system_call.type) {
        case KVM_EVENT_SYSTEM_CALL_TYPE_SYSCALL:
            original_fastcall_type_ = FastCallType::FASTCALL_SYSCALL;
            break;
        case KVM_EVENT_SYSTEM_CALL_TYPE_SYSENTER:
            original_fastcall_type_ = FastCallType::FASTCALL_SYSENTER;
            break;
        default:
            original_fastcall_type_ = FastCallType::FASTCALL_UNKNOWN;
            break;
        }
        original_fastcall_return_ = event_data_.system_call.return_address;
        break;
    }
    case KVM_EVENT_FAST_SYSCALL_RET:
        switch (event_data_.system_call_ret.type) {
        case KVM_EVENT_SYSTEM_CALL_RET_TYPE_SYSRET:
            original_fastcall_type_ = FastCallType::FASTCALL_SYSRET;
            break;
        case KVM_EVENT_SYSTEM_CALL_RET_TYPE_SYSEXIT:
            original_fastcall_type_ = FastCallType::FASTCALL_SYSEXIT;
            break;
        default:
            original_fastcall_type_ = FastCallType::FASTCALL_UNKNOWN;
            break;
        }
        break;
    default:
        original_fastcall_type_ = FastCallType::FASTCALL_UNKNOWN;
        break;
    }
}

KvmEvent::~KvmEvent() {
    if (unlikely(discarded_)) {
        LOG4CXX_TRACE(logger, "Discarded event " << KvmEvent::id());
        return;
    }

    LOG4CXX_TRACE(logger, "Completing event " << KvmEvent::id());

    // Let the VCPU know that it's no longer in an event
    vcpu_.complete_event();
}

std::unique_ptr<HypervisorEvent> create_kvm_event(KvmVcpu& vcpu,
                                                  struct kvm_introspection_event& event_data) {
    return std::make_unique<KvmEvent>(vcpu, event_data);
}

} // namespace kvm
} // namespace introvirt