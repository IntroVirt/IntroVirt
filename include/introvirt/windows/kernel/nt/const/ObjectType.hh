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

#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Enum for Windows kernel object types
 *
 * Kernel object types seem to change between versions of Windows.
 * This enum is used to normalize the types.
 */
enum class ObjectType : int {
    None = 0,
    Unknown = 1,
    Type = 2,
    Directory = 3,
    SymbolicLink = 4,
    Token = 5,
    Job = 6,
    Process = 7,
    Thread = 8,
    Partition = 9,
    UserApcReserve = 10,
    IoCompletionReserve = 11,
    ActivityReference = 12,
    PsSiloContextPaged = 13,
    PsSiloContextNonPaged = 14,
    DebugObject = 15,
    Event = 16,
    Mutant = 17,
    Callback = 18,
    Semaphore = 19,
    Timer = 20,
    IRTimer = 21,
    Profile = 22,
    KeyedEvent = 23,
    WindowStation = 24,
    Desktop = 25,
    Composition = 26,
    RawInputManager = 27,
    CoreMessaging = 28,
    TpWorkerFactory = 29,
    Adapter = 30,
    Controller = 31,
    Device = 32,
    Driver = 33,
    IoCompletion = 34,
    WaitCompletionPacket = 35,
    File = 36,
    TmTm = 37,
    TmTx = 38,
    TmRm = 39,
    TmEn = 40,
    Section = 41,
    Session = 42,
    Key = 43,
    RegistryTransaction = 44,
    ALPCPort = 45,
    EnergyTracker = 46,
    PowerRequest = 47,
    WmiGuid = 48,
    EtwRegistration = 49,
    EtwSessionDemuxEntry = 50,
    EtwConsumer = 51,
    CoverageSampler = 52,
    DmaAdapter = 53,
    PcwObject = 54,
    FilterConnectionPort = 55,
    FilterCommunicationPort = 56,
    NdisCmState = 57,
    DxgkSharedResource = 58,
    DxgkSharedKeyedMutexObject = 59,
    DxgkSharedSyncObject = 60,
    DxgkSharedSwapChainObject = 61,
    DxgkDisplayManagerObject = 62,
    DxgkCurrentDxgProcessObject = 63,
    DxgkSharedProtectedSessionObject = 64,
    DxgkSharedBundleObject = 65,
    DxgkCompositionObject = 66,
    VRegConfigurationContext = 67,
    EventPair = 68,
    DmaDomain = 69,
    NetworkNamespace = 70,
    Port = 71,
    VirtualKey = 72,
    WaitablePort = 73,

    ObjectTypeMax = WaitablePort,
};

/**
 * @brief Get the string representation of an ObjectType
 *
 * @param index
 * @return const std::string&
 */
const std::string& to_string(ObjectType index);

/**
 * @brief Stream operator overload for ObjectType
 */
std::ostream& operator<<(std::ostream&, ObjectType index);

/**
 * @brief Get an ObjectType by name
 *
 * @param object_name The string to parse
 * @return The object type, or ObjectType::Unknown if the string is not valid.
 */
ObjectType object_type_from_name(const std::string& object_name);

} // namespace nt
} // namespace windows
} // namespace introvirt