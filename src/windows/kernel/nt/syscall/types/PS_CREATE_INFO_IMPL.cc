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
#include "PS_CREATE_INFO_IMPL.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/exception/InvalidStructureException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void PS_CREATE_INFO_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);

    os << std::dec;
    os << linePrefix << "Size: " << Size() << '\n';
    os << std::hex;

    os << linePrefix << "State: " << to_string(State()) << '\n';
    switch (State()) {
    case PS_CREATE_STATE::PsCreateSuccess:
        os << linePrefix << "FileHandle: 0x" << FileHandle() << '\n';
        os << linePrefix << "SectionHandle: 0x" << SectionHandle() << '\n';
        os << linePrefix << "UserProcessParametersNative: 0x" << UserProcessParametersNative()
           << '\n';
        os << linePrefix << "UserProcessParametersWow64: 0x" << UserProcessParametersWow64()
           << '\n';
        os << linePrefix << "CurrentParameterFlags: 0x" << CurrentParameterFlags() << '\n';
        os << linePrefix << "PebAddressNative: 0x" << PebAddressNative() << '\n';
        os << linePrefix << "PebAddressWow64: 0x" << PebAddressWow64() << '\n';
        os << linePrefix << "ManifestAddress: 0x" << ManifestAddress() << '\n';
        os << linePrefix << "ManifestSize: 0x" << ManifestSize() << '\n';
        os << linePrefix << "OutputFlags: 0x" << OutputFlags() << '\n';
        break;
    case PS_CREATE_STATE::PsCreateInitialState:
        os << linePrefix << "InitFlags: 0x" << InitFlags() << '\n';
        os << linePrefix << "AdditionalFileAccess: " << AdditionalFileAccess() << " [0x"
           << AdditionalFileAccess().value() << "]\n";
        break;
    case PS_CREATE_STATE::PsCreateFailExeName:
        os << linePrefix << "IFEOKey: 0x" << IFEOKey() << '\n';
        break;
    case PS_CREATE_STATE::PsCreateFailOnSectionCreate:
        os << linePrefix << "FileHandle: 0x" << FileHandle() << '\n';
        break;

    case PS_CREATE_STATE::PsCreateFailExeFormat:
    case PS_CREATE_STATE::PsCreateFailMachineMismatch:
    case PS_CREATE_STATE::PsCreateFailOnFileOpen:
    default:
        break; /* No special handling */
    }
}

template <typename PtrType>
Json::Value PS_CREATE_INFO_IMPL<PtrType>::json() const {
    Json::Value result;
    result["State"] = to_string(State());

    switch (State()) {
    case PS_CREATE_STATE::PsCreateSuccess:
        result["FileHandle"] = FileHandle();
        result["SectionHandle"] = SectionHandle();
        result["UserProcessParametersNative"] = UserProcessParametersNative();
        result["UserProcessParametersWow64"] = UserProcessParametersWow64();
        result["CurrentParameterFlags"] = CurrentParameterFlags();
        result["PebAddressNative"] = PebAddressNative();
        result["PebAddressWow64"] = PebAddressWow64();
        result["ManifestAddress"] = ManifestAddress();
        result["ManifestSize"] = ManifestSize();
        result["OutputFlags"] = OutputFlags();
        break;
    case PS_CREATE_STATE::PsCreateInitialState:
        result["InitFlags"] = InitFlags();
        result["AdditionalFileAccess"] = AdditionalFileAccess().json();
        break;
    case PS_CREATE_STATE::PsCreateFailExeName:
        result["IFEOKey"] = IFEOKey();
        break;
    case PS_CREATE_STATE::PsCreateFailOnSectionCreate:
        result["FileHandle"] = FileHandle();
        break;

    case PS_CREATE_STATE::PsCreateFailExeFormat:
    case PS_CREATE_STATE::PsCreateFailMachineMismatch:
    case PS_CREATE_STATE::PsCreateFailOnFileOpen:
    default:
        break; /* No special handling */
    }

    return result;
}

/** Only valid for state == PsCreateSuccess || PsCreateFailOnSectionCreate */
template <typename PtrType>
uint64_t PS_CREATE_INFO_IMPL<PtrType>::FileHandle() const {
    switch (data_->State) {
    case PS_CREATE_STATE::PsCreateSuccess:
        return data_->SuccessState.FileHandle;
    case PS_CREATE_STATE::PsCreateFailOnSectionCreate:
        return data_->FailSection.FileHandle;
    default:
        break;
    }

    throw InvalidStructureException("current state does not have a file handle");
}

/** Only valid for state == PsCreateSuccess */
template <typename PtrType>
uint64_t PS_CREATE_INFO_IMPL<PtrType>::SectionHandle() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateSuccess)) {
        throw InvalidStructureException("current state does not have a section handle");
    }

    return data_->SuccessState.SectionHandle;
}
template <typename PtrType>
uint64_t PS_CREATE_INFO_IMPL<PtrType>::UserProcessParametersNative() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateSuccess)) {
        throw InvalidStructureException("current state does not have user process parameters");
    }
    return data_->SuccessState.UserProcessParametersNative;
}
template <typename PtrType>
uint32_t PS_CREATE_INFO_IMPL<PtrType>::UserProcessParametersWow64() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateSuccess)) {
        throw InvalidStructureException(
            "current state does not have user process parameters wow64");
    }
    return data_->SuccessState.UserProcessParametersWow64;
}
template <typename PtrType>
uint32_t PS_CREATE_INFO_IMPL<PtrType>::CurrentParameterFlags() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateSuccess)) {
        throw InvalidStructureException("current state does not have current parameter flags");
    }
    return data_->SuccessState.CurrentParameterFlags;
}
template <typename PtrType>
uint64_t PS_CREATE_INFO_IMPL<PtrType>::PebAddressNative() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateSuccess)) {
        throw InvalidStructureException("current state does not have peb address");
    }
    return data_->SuccessState.PebAddressNative;
}
template <typename PtrType>
uint32_t PS_CREATE_INFO_IMPL<PtrType>::PebAddressWow64() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateSuccess)) {
        throw InvalidStructureException("current state does not have peb address wow64");
    }
    return data_->SuccessState.PebAddressWow64;
}
template <typename PtrType>
uint64_t PS_CREATE_INFO_IMPL<PtrType>::ManifestAddress() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateSuccess)) {
        throw InvalidStructureException("current state does not have a manifest address");
    }
    return data_->SuccessState.ManifestAddress;
}
template <typename PtrType>
uint32_t PS_CREATE_INFO_IMPL<PtrType>::ManifestSize() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateSuccess)) {
        throw InvalidStructureException("current state does not have a manifest size");
    }
    return data_->SuccessState.ManifestSize;
}
template <typename PtrType>
uint32_t PS_CREATE_INFO_IMPL<PtrType>::OutputFlags() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateSuccess)) {
        throw InvalidStructureException("current state does not have output flags");
    }
    return data_->SuccessState.OutputFlags;
}

/** Only valid for state == PsCreateFailExeName */
template <typename PtrType>
uint64_t PS_CREATE_INFO_IMPL<PtrType>::IFEOKey() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateFailExeName)) {
        throw InvalidStructureException("current state does not have an ifeo key");
    }
    return data_->ExeName.IFEOKey;
}

/* Only valid for state == PsCreateInitialState */
template <typename PtrType>
uint32_t PS_CREATE_INFO_IMPL<PtrType>::InitFlags() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateInitialState)) {
        throw InvalidStructureException("current state does not have init flags");
    }
    return data_->InitState.InitFlags;
}
template <typename PtrType>
void PS_CREATE_INFO_IMPL<PtrType>::InitFlags(uint32_t InitFlags) {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateInitialState)) {
        throw InvalidStructureException("current state does not have init flags");
    }
    data_->InitState.InitFlags = InitFlags;
}

template <typename PtrType>
FILE_ACCESS_MASK PS_CREATE_INFO_IMPL<PtrType>::AdditionalFileAccess() const {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateInitialState)) {
        throw InvalidStructureException("current state does not have addition file access");
    }
    return FILE_ACCESS_MASK(data_->InitState.AdditionalFileAccess);
}
template <typename PtrType>
void PS_CREATE_INFO_IMPL<PtrType>::AdditionalFileAccess(FILE_ACCESS_MASK AdditionalFileAccess) {
    if (unlikely(data_->State != PS_CREATE_STATE::PsCreateInitialState)) {
        throw InvalidStructureException("current state does not have addition file access");
    }
    data_->InitState.AdditionalFileAccess = AdditionalFileAccess.value();
}

std::unique_ptr<PS_CREATE_INFO> PS_CREATE_INFO::make_unique(const NtKernel& kernel,
                                                            const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_unique<PS_CREATE_INFO_IMPL<uint64_t>>(gva);
    else
        return std::make_unique<PS_CREATE_INFO_IMPL<uint32_t>>(gva);
}

const std::string& to_string(PS_CREATE_STATE state) {
    const static std::string PsCreateInitialStateStr("PsCreateInitialState");
    const static std::string PsCreateFailOnFileOpenStr("PsCreateFailOnFileOpen");
    const static std::string PsCreateFailOnSectionCreateStr("PsCreateFailOnSectionCreate");
    const static std::string PsCreateFailExeFormatStr("PsCreateFailExeFormat");
    const static std::string PsCreateFailMachineMismatchStr("PsCreateFailMachineMismatch");
    const static std::string PsCreateFailExeNameStr("PsCreateFailExeName");
    const static std::string PsCreateSuccessStr("PsCreateSuccess");
    const static std::string UnknownStr("Unknown");

    switch (state) {
    case PS_CREATE_STATE::PsCreateInitialState:
        return PsCreateInitialStateStr;
    case PS_CREATE_STATE::PsCreateFailOnFileOpen:
        return PsCreateFailOnFileOpenStr;
    case PS_CREATE_STATE::PsCreateFailOnSectionCreate:
        return PsCreateFailOnSectionCreateStr;
    case PS_CREATE_STATE::PsCreateFailExeFormat:
        return PsCreateFailExeFormatStr;
    case PS_CREATE_STATE::PsCreateFailMachineMismatch:
        return PsCreateFailMachineMismatchStr;
    case PS_CREATE_STATE::PsCreateFailExeName:
        return PsCreateFailExeNameStr;
    case PS_CREATE_STATE::PsCreateSuccess:
        return PsCreateSuccessStr;
    case PS_CREATE_STATE::PsCreateMaximumStates: /* Not a real state, fall through */
    case PS_CREATE_STATE::PsCreateUnknown:
        return UnknownStr;
    }

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, PS_CREATE_STATE state) {
    os << to_string(state);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt