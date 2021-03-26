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

#include <introvirt/core/arch/fwd.hh>
#include <type_traits>

/**
 * @brief Core IntroVirt classes
 *
 * The top-level introvirt namespace is for low-level operations,
 * like controlling domains and vcpus, mapping memory, etc.
 *
 */
namespace introvirt {

class Breakpoint;
class SingleStep;
class Watchpoint;

class Domain;
class Guest;
class Hypervisor;
class Vcpu;

class ControlRegisterEvent;
class Event;
class EventCallback;
class EventFilter;
class EventTaskInformation;
class ExceptionEvent;
class MemAccessEvent;
class MsrAccessEvent;
class SystemCallEvent;
enum class EventType : int;

class AllocationFailedException;
class BadPhysicalAddressException;
class BufferTooSmallException;
class CommandFailedException;
class DomainBusyException;
class EventPollException;
class GuestDetectionException;
class InterruptedException;
class InvalidMethodException;
class InvalidVcpuException;
class MemoryException;
class NoSuchDomainException;
class NotImplementedException;
class NullAddressException;
class SystemCallInjectionException;
class TraceableException;
class UnsupportedHypervisorException;
class VirtualAddressNotPresentException;

class TaskFilter;

class FunctionCall;

class GuestMemoryMapping;

class SystemCall;
class SystemCallFilter;

/* Dummy class used for automatically getting the correct size */
class guest_size_t;
using guest_ptr_t = guest_size_t;

template <typename _Tp>
struct identity {
    using type = _Tp;
};

template <typename _Tp>
struct remove_all_pointers
    : std::conditional_t<std::is_pointer_v<_Tp>, remove_all_pointers<std::remove_pointer_t<_Tp>>,
                         identity<_Tp>> {};

template <typename _Tp>
using remove_all_pointers_t = typename remove_all_pointers<_Tp>::type;

template <typename _Tp, typename Enable = void>
struct is_guest_size : std::false_type {};

template <typename _Tp>
struct is_guest_size<
    _Tp,
    std::enable_if_t<std::is_same_v<
        guest_size_t, std::remove_const_t<remove_all_pointers_t<std::remove_all_extents_t<_Tp>>>>>>
    : std::true_type {};

template <typename _Tp>
inline constexpr bool is_guest_size_v = is_guest_size<_Tp>::value;

// Some tests
static_assert(is_guest_size_v<guest_size_t>, "guest_size_t failed check");
static_assert(is_guest_size_v<guest_size_t[]>, "guest_size_t failed check");
static_assert(is_guest_size_v<const guest_size_t>, "guest_size_t failed check");
static_assert(is_guest_size_v<const guest_size_t[]>, "guest_size_t failed check");
static_assert(is_guest_size_v<guest_size_t*>, "guest_size_t failed check");
static_assert(is_guest_size_v<const guest_size_t**>, "guest_size_t failed check");
static_assert(is_guest_size_v<const guest_size_t*[]>, "guest_size_t failed check");

template <typename _Tp, typename _PtrType, bool _Physical, typename _Enabled = void>
class basic_guest_ptr;

template <typename _Tp, typename _PtrType, bool _Physical>
class basic_guest_ptr<_Tp, _PtrType, _Physical, std::enable_if_t<is_guest_size_v<_Tp>>>;

template <typename _Tp, typename _PtrType = void>
using guest_ptr = basic_guest_ptr<_Tp, _PtrType, false>;

template <typename _Tp, typename _PtrType = void>
using guest_phys_ptr = basic_guest_ptr<_Tp, _PtrType, true>;

} // namespace introvirt