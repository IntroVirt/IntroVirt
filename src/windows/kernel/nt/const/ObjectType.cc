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

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>

#include <boost/algorithm/string.hpp>
#include <map>

namespace introvirt {
namespace windows {
namespace nt {

const static std::string ActivityReference("ActivityReference");
const static std::string Adapter("Adapter");
const static std::string AlpcPort("ALPC Port");
const static std::string Callback("Callback");
const static std::string Composition("Composition");
const static std::string Controller("Controller");
const static std::string CoreMessaging("CoreMessaging");
const static std::string CoverageSampler("CoverageSampler");
const static std::string DebugObject("DebugObject");
const static std::string Desktop("Desktop");
const static std::string Device("Device");
const static std::string Directory("Directory");
const static std::string DmaAdapter("DmaAdapter");
const static std::string DmaDomain("DmaDomain");
const static std::string Driver("Driver");
const static std::string DxgkCurrentDxgProcessObject("DxgkCurrentDxgProcessObject");
const static std::string DxgkSharedResource("DxgkSharedResource");
const static std::string DxgkSharedSwapChainObject("DxgkSharedSwapChainObject");
const static std::string DxgkSharedSyncObject("DxgkSharedSyncObject");
const static std::string EtwConsumer("EtwConsumer");
const static std::string EtwRegistration("EtwRegistration");
const static std::string EtwSessionDemuxEntry("EtwSessionDemuxEntry");
const static std::string Event("Event");
const static std::string EventPair("EventPair");
const static std::string File("File");
const static std::string FilterCommunicationPort("FilterCommunicationPort");
const static std::string FilterConnectionPort("FilterConnectionPort");
const static std::string IoCompletion("IoCompletion");
const static std::string IoCompletionReserve("IoCompletionReserve");
const static std::string IrTimer("IrTimer");
const static std::string Job("Job");
const static std::string Key("Key");
const static std::string KeyedEvent("KeyedEvent");
const static std::string Mutant("Mutant");
const static std::string NdisCmState("NdisCmState");
const static std::string NetworkNameSpace("NetworkNameSpace");
const static std::string None("None");
const static std::string Partition("Partition");
const static std::string PcwObject("PcwObject");
const static std::string Port("Port");
const static std::string PowerRequest("PowerRequest");
const static std::string Process("Process");
const static std::string Profile("Profile");
const static std::string PsSiloContextNonPaged("PsSiloContextNonPaged");
const static std::string PsSiloContextPaged("PsSiloContextPaged");
const static std::string RawInputManager("RawInputManager");
const static std::string RegistryTransaction("RegistryTransaction");
const static std::string Section("Section");
const static std::string Semaphore("Semaphore");
const static std::string Session("Session");
const static std::string SymbolicLink("SymbolicLink");
const static std::string Thread("Thread");
const static std::string Timer("Timer");
const static std::string TmEn("TmEn");
const static std::string TmRm("TmRm");
const static std::string TmTm("TmTm");
const static std::string TmTx("TmTx");
const static std::string Token("Token");
const static std::string TpWorkerFactory("TpWorkerFactory");
const static std::string Type("Type");
const static std::string Unknown("Unknown");
const static std::string UserApcReserve("UserApcReserve");
const static std::string VirtualKey("VirtualKey");
const static std::string VRegConfigurationContext("VRegConfigurationContext");
const static std::string WaitablePort("WaitablePort");
const static std::string WaitCompletionPacket("WaitCompletionPacket");
const static std::string WindowStation("WindowStation");
const static std::string WmiGuid("WmiGuid");
const static std::string ENERGY_TRACKER("EnergyTracker");
const static std::string DXGK_SHARED_KEYED_MUTEX_OBJECT("DxgkSharedKeyedMutexObject");
const static std::string DXGK_DISPLAY_MANAGER_OBJECT("DxgkDisplayManagerObject");
const static std::string DXGK_SHARED_PROTECTED_SESSION_OBJECT("DxgkSharedProtectedSessionObject");
const static std::string DXGK_SHARED_BUNDLE_OBJECT("DxgkSharedBundleObject");
const static std::string DXGK_COMPOSITION_OBJECT("DxgkCompositionObject");

const std::string& to_string(ObjectType index) {
    switch (index) {
    case ObjectType::Adapter:
        return Adapter;
    case ObjectType::ALPCPort:
        return AlpcPort;
    case ObjectType::Callback:
        return Callback;
    case ObjectType::Controller:
        return Controller;
    case ObjectType::CoverageSampler:
        return CoverageSampler;
    case ObjectType::DebugObject:
        return DebugObject;
    case ObjectType::Desktop:
        return Desktop;
    case ObjectType::Device:
        return Device;
    case ObjectType::Directory:
        return Directory;
    case ObjectType::Driver:
        return Driver;
    case ObjectType::EtwConsumer:
        return EtwConsumer;
    case ObjectType::EtwRegistration:
        return EtwRegistration;
    case ObjectType::Event:
        return Event;
    case ObjectType::EventPair:
        return EventPair;
    case ObjectType::File:
        return File;
    case ObjectType::FilterCommunicationPort:
        return FilterCommunicationPort;
    case ObjectType::FilterConnectionPort:
        return FilterConnectionPort;
    case ObjectType::IoCompletion:
        return IoCompletion;
    case ObjectType::IoCompletionReserve:
        return IoCompletionReserve;
    case ObjectType::Job:
        return Job;
    case ObjectType::Key:
        return Key;
    case ObjectType::KeyedEvent:
        return KeyedEvent;
    case ObjectType::Mutant:
        return Mutant;
    case ObjectType::NdisCmState:
        return NdisCmState;
    case ObjectType::None:
        return None;
    case ObjectType::PcwObject:
        return PcwObject;
    case ObjectType::Port:
        return Port;
    case ObjectType::PowerRequest:
        return PowerRequest;
    case ObjectType::Process:
        return Process;
    case ObjectType::Profile:
        return Profile;
    case ObjectType::Section:
        return Section;
    case ObjectType::Semaphore:
        return Semaphore;
    case ObjectType::Session:
        return Session;
    case ObjectType::SymbolicLink:
        return SymbolicLink;
    case ObjectType::Thread:
        return Thread;
    case ObjectType::Timer:
        return Timer;
    case ObjectType::TmEn:
        return TmEn;
    case ObjectType::TmRm:
        return TmRm;
    case ObjectType::TmTm:
        return TmTm;
    case ObjectType::TmTx:
        return TmTx;
    case ObjectType::Token:
        return Token;
    case ObjectType::TpWorkerFactory:
        return TpWorkerFactory;
    case ObjectType::Type:
        return Type;
    case ObjectType::Unknown:
        return Unknown;
    case ObjectType::UserApcReserve:
        return UserApcReserve;
    case ObjectType::WaitablePort:
        return WaitablePort;
    case ObjectType::WindowStation:
        return WindowStation;
    case ObjectType::WmiGuid:
        return WmiGuid;
    case ObjectType::IRTimer:
        return IrTimer;
    case ObjectType::Composition:
        return Composition;
    case ObjectType::RawInputManager:
        return RawInputManager;
    case ObjectType::WaitCompletionPacket:
        return WaitCompletionPacket;
    case ObjectType::Partition:
        return Partition;
    case ObjectType::DmaAdapter:
        return DmaAdapter;
    case ObjectType::DmaDomain:
        return DmaDomain;
    case ObjectType::NetworkNamespace:
        return NetworkNameSpace;
    case ObjectType::DxgkSharedResource:
        return DxgkSharedResource;
    case ObjectType::DxgkSharedSyncObject:
        return DxgkSharedSyncObject;
    case ObjectType::DxgkSharedSwapChainObject:
        return DxgkSharedSwapChainObject;
    case ObjectType::PsSiloContextNonPaged:
        return PsSiloContextNonPaged;
    case ObjectType::PsSiloContextPaged:
        return PsSiloContextPaged;
    case ObjectType::VirtualKey:
        return VirtualKey;
    case ObjectType::VRegConfigurationContext:
        return VRegConfigurationContext;
    case ObjectType::CoreMessaging:
        return CoreMessaging;
    case ObjectType::RegistryTransaction:
        return RegistryTransaction;
    case ObjectType::ActivityReference:
        return ActivityReference;
    case ObjectType::EtwSessionDemuxEntry:
        return EtwSessionDemuxEntry;
    case ObjectType::DxgkCurrentDxgProcessObject:
        return DxgkCurrentDxgProcessObject;
    case ObjectType::EnergyTracker:
        return ENERGY_TRACKER;
    case ObjectType::DxgkSharedKeyedMutexObject:
        return DXGK_SHARED_KEYED_MUTEX_OBJECT;
    case ObjectType::DxgkDisplayManagerObject:
        return DXGK_DISPLAY_MANAGER_OBJECT;
    case ObjectType::DxgkSharedProtectedSessionObject:
        return DXGK_SHARED_PROTECTED_SESSION_OBJECT;
    case ObjectType::DxgkSharedBundleObject:
        return DXGK_SHARED_BUNDLE_OBJECT;
    case ObjectType::DxgkCompositionObject:
        return DXGK_COMPOSITION_OBJECT;
    }

    return Unknown;
}

std::ostream& operator<<(std::ostream& os, ObjectType index) {
    os << to_string(index);
    return os;
}

ObjectType object_type_from_name(const std::string& objectName) {
    static std::map<std::string, ObjectType> NameToObjectIndex;
    if (unlikely(NameToObjectIndex.empty())) {
        // Build the initial object index table
        for (unsigned int i = 0; i < static_cast<unsigned int>(ObjectType::ObjectTypeMax); ++i) {
            const auto typeIndex = static_cast<ObjectType>(i);
            NameToObjectIndex[boost::to_lower_copy(to_string(typeIndex))] = typeIndex;
        }
    }

    std::string lowerObjectName(objectName);
    boost::to_lower(lowerObjectName);

    auto iter = NameToObjectIndex.find(lowerObjectName);
    if (iter != NameToObjectIndex.end()) {
        return iter->second;
    }

    return ObjectType::Unknown;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
