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

#include <introvirt/core/arch/arch.hh>

#include <introvirt/core/breakpoint/Breakpoint.hh>
#include <introvirt/core/breakpoint/SingleStep.hh>
#include <introvirt/core/breakpoint/Watchpoint.hh>

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Guest.hh>
#include <introvirt/core/domain/Hypervisor.hh>
#include <introvirt/core/domain/Vcpu.hh>

#include <introvirt/core/event/ControlRegisterEvent.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/event/EventCallback.hh>
#include <introvirt/core/event/EventFilter.hh>
#include <introvirt/core/event/EventTaskInformation.hh>
#include <introvirt/core/event/EventType.hh>
#include <introvirt/core/event/ExceptionEvent.hh>
#include <introvirt/core/event/MemAccessEvent.hh>
#include <introvirt/core/event/MsrAccessEvent.hh>
#include <introvirt/core/event/SystemCallEvent.hh>
#include <introvirt/core/event/ThreadLocalEvent.hh>

#include <introvirt/core/exception/AllocationFailedException.hh>
#include <introvirt/core/exception/BadPhysicalAddressException.hh>
#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/core/exception/CommandFailedException.hh>
#include <introvirt/core/exception/DomainBusyException.hh>
#include <introvirt/core/exception/EventPollException.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/InterruptedException.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/core/exception/InvalidVcpuException.hh>
#include <introvirt/core/exception/MemoryException.hh>
#include <introvirt/core/exception/NoSuchDomainException.hh>
#include <introvirt/core/exception/NotImplementedException.hh>
#include <introvirt/core/exception/NullAddressException.hh>
#include <introvirt/core/exception/SystemCallInjectionException.hh>
#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/core/exception/UnsupportedHypervisorException.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>

#include <introvirt/core/filter/TaskFilter.hh>

#include <introvirt/core/function/FunctionCall.hh>
#include <introvirt/core/function/FunctionCallFactory.hh>

#include <introvirt/core/injection/GuestAllocation.hh>
#include <introvirt/core/injection/function_call.hh>
#include <introvirt/core/injection/system_call.hh>

#include <introvirt/core/memory/GuestAddress.hh>
#include <introvirt/core/memory/GuestMemoryMapping.hh>
#include <introvirt/core/memory/GuestPhysicalAddress.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <introvirt/core/syscall/SystemCall.hh>
#include <introvirt/core/syscall/SystemCallFilter.hh>