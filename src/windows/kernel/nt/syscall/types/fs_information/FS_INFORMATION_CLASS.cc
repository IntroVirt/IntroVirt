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

#include <introvirt/windows/kernel/nt/syscall/types/fs_information/FS_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(FS_INFORMATION_CLASS infoClass) {
    const static std::string FileFsVolumeInformationStr = "FileFsVolumeInformation";
    const static std::string FileFsLabelInformationStr = "FileFsLabelInformation";
    const static std::string FileFsSizeInformationStr = "FileFsSizeInformation";
    const static std::string FileFsDeviceInformationStr = "FileFsDeviceInformation";
    const static std::string FileFsAttributeInformationStr = "FileFsAttributeInformation";
    const static std::string FileFsControlInformationStr = "FileFsControlInformation";
    const static std::string FileFsFullSizeInformationStr = "FileFsFullSizeInformation";
    const static std::string FileFsObjectIdInformationStr = "FileFsObjectIdInformation";
    const static std::string FileFsDriverPathInformationStr = "FileFsDriverPathInformation";
    const static std::string FileFsVolumeFlagsInformationStr = "FileFsVolumeFlagsInformation";
    const static std::string FileFsSectorSizeInformationStr = "FileFsSectorSizeInformation";
    const static std::string UnknownStr = "Unknown";

    switch (infoClass) {
    case FS_INFORMATION_CLASS::FileFsVolumeInformation:
        return FileFsVolumeInformationStr;
    case FS_INFORMATION_CLASS::FileFsLabelInformation:
        return FileFsLabelInformationStr;
    case FS_INFORMATION_CLASS::FileFsSizeInformation:
        return FileFsSizeInformationStr;
    case FS_INFORMATION_CLASS::FileFsDeviceInformation:
        return FileFsDeviceInformationStr;
    case FS_INFORMATION_CLASS::FileFsAttributeInformation:
        return FileFsAttributeInformationStr;
    case FS_INFORMATION_CLASS::FileFsControlInformation:
        return FileFsControlInformationStr;
    case FS_INFORMATION_CLASS::FileFsFullSizeInformation:
        return FileFsFullSizeInformationStr;
    case FS_INFORMATION_CLASS::FileFsObjectIdInformation:
        return FileFsObjectIdInformationStr;
    case FS_INFORMATION_CLASS::FileFsDriverPathInformation:
        return FileFsDriverPathInformationStr;
    case FS_INFORMATION_CLASS::FileFsVolumeFlagsInformation:
        return FileFsVolumeFlagsInformationStr;
    case FS_INFORMATION_CLASS::FileFsSectorSizeInformation:
        return FileFsSectorSizeInformationStr;
    }

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, FS_INFORMATION_CLASS infoClass) {
    os << to_string(infoClass);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
