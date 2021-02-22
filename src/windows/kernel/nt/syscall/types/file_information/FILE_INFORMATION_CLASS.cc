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

#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(FILE_INFORMATION_CLASS infoClass) {
    const static std::string FileDirectoryInformationStr = "FileDirectoryInformation";
    const static std::string FileFullDirectoryInformationStr = "FileFullDirectoryInformation";
    const static std::string FileBothDirectoryInformationStr = "FileBothDirectoryInformation";
    const static std::string FileBasicInformationStr = "FileBasicInformation";
    const static std::string FileStandardInformationStr = "FileStandardInformation";
    const static std::string FileInternalInformationStr = "FileInternalInformation";
    const static std::string FileEaInformationStr = "FileEaInformation";
    const static std::string FileAccessInformationStr = "FileAccessInformation";
    const static std::string FileNameInformationStr = "FileNameInformation";
    const static std::string FileRenameInformationStr = "FileRenameInformation";
    const static std::string FileLinkInformationStr = "FileLinkInformation";
    const static std::string FileNamesInformationStr = "FileNamesInformation";
    const static std::string FileDispositionInformationStr = "FileDispositionInformation";
    const static std::string FilePositionInformationStr = "FilePositionInformation";
    const static std::string FileFullEaInformationStr = "FileFullEaInformation";
    const static std::string FileModeInformationStr = "FileModeInformation";
    const static std::string FileAlignmentInformationStr = "FileAlignmentInformation";
    const static std::string FileAllInformationStr = "FileAllInformation";
    const static std::string FileAllocationInformationStr = "FileAllocationInformation";
    const static std::string FileEndOfFileInformationStr = "FileEndOfFileInformation";
    const static std::string FileAlternateNameInformationStr = "FileAlternateNameInformation";
    const static std::string FileStreamInformationStr = "FileStreamInformation";
    const static std::string FilePipeInformationStr = "FilePipeInformation";
    const static std::string FilePipeLocalInformationStr = "FilePipeLocalInformation";
    const static std::string FilePipeRemoteInformationStr = "FilePipeRemoteInformation";
    const static std::string FileMailslotQueryInformationStr = "FileMailslotQueryInformation";
    const static std::string FileMailslotSetInformationStr = "FileMailslotSetInformation";
    const static std::string FileCompressionInformationStr = "FileCompressionInformation";
    const static std::string FileObjectIdInformationStr = "FileObjectIdInformation";
    const static std::string FileCompletionInformationStr = "FileCompletionInformation";
    const static std::string FileMoveClusterInformationStr = "FileMoveClusterInformation";
    const static std::string FileQuotaInformationStr = "FileQuotaInformation";
    const static std::string FileReparsePointInformationStr = "FileReparsePointInformation";
    const static std::string FileNetworkOpenInformationStr = "FileNetworkOpenInformation";
    const static std::string FileAttributeTagInformationStr = "FileAttributeTagInformation";
    const static std::string FileTrackingInformationStr = "FileTrackingInformation";
    const static std::string FileIdBothDirectoryInformationStr = "FileIdBothDirectoryInformation";
    const static std::string FileIdFullDirectoryInformationStr = "FileIdFullDirectoryInformation";
    const static std::string FileValidDataLengthInformationStr = "FileValidDataLengthInformation";
    const static std::string FileShortNameInformationStr = "FileShortNameInformation";
    const static std::string FileIoCompletionNotificationInformationStr =
        "FileIoCompletionNotificationInformation";
    const static std::string FileIoStatusBlockRangeInformationStr =
        "FileIoStatusBlockRangeInformation";
    const static std::string FileIoPriorityHintInformationStr = "FileIoPriorityHintInformation";
    const static std::string FileSfioReserveInformationStr = "FileSfioReserveInformation";
    const static std::string FileSfioVolumeInformationStr = "FileSfioVolumeInformation";
    const static std::string FileHardLinkInformationStr = "FileHardLinkInformation";
    const static std::string FileProcessIdsUsingFileInformationStr =
        "FileProcessIdsUsingFileInformation";
    const static std::string FileNormalizedNameInformationStr = "FileNormalizedNameInformation";
    const static std::string FileNetworkPhysicalNameInformationStr =
        "FileNetworkPhysicalNameInformation";
    const static std::string FileIdGlobalTxDirectoryInformationStr =
        "FileIdGlobalTxDirectoryInformation";
    const static std::string FileIsRemoteDeviceInformationStr = "FileIsRemoteDeviceInformation";
    const static std::string FileAttributeCacheInformationStr = "FileAttributeCacheInformation";
    const static std::string FileNumaNodeInformationStr = "FileNumaNodeInformation";
    const static std::string FileStandardLinkInformationStr = "FileStandardLinkInformation";
    const static std::string FileRemoteProtocolInformationStr = "FileRemoteProtocolInformation";
    const static std::string UnknownStr = "Unknown";

    switch (infoClass) {
    case FILE_INFORMATION_CLASS::FileDirectoryInformation:
        return FileDirectoryInformationStr;
    case FILE_INFORMATION_CLASS::FileFullDirectoryInformation:
        return FileFullDirectoryInformationStr;
    case FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
        return FileBothDirectoryInformationStr;
    case FILE_INFORMATION_CLASS::FileBasicInformation:
        return FileBasicInformationStr;
    case FILE_INFORMATION_CLASS::FileStandardInformation:
        return FileStandardInformationStr;
    case FILE_INFORMATION_CLASS::FileInternalInformation:
        return FileInternalInformationStr;
    case FILE_INFORMATION_CLASS::FileEaInformation:
        return FileEaInformationStr;
    case FILE_INFORMATION_CLASS::FileAccessInformation:
        return FileAccessInformationStr;
    case FILE_INFORMATION_CLASS::FileNameInformation:
        return FileNameInformationStr;
    case FILE_INFORMATION_CLASS::FileRenameInformation:
        return FileRenameInformationStr;
    case FILE_INFORMATION_CLASS::FileLinkInformation:
        return FileLinkInformationStr;
    case FILE_INFORMATION_CLASS::FileNamesInformation:
        return FileNamesInformationStr;
    case FILE_INFORMATION_CLASS::FileDispositionInformation:
        return FileDispositionInformationStr;
    case FILE_INFORMATION_CLASS::FilePositionInformation:
        return FilePositionInformationStr;
    case FILE_INFORMATION_CLASS::FileFullEaInformation:
        return FileFullEaInformationStr;
    case FILE_INFORMATION_CLASS::FileModeInformation:
        return FileModeInformationStr;
    case FILE_INFORMATION_CLASS::FileAlignmentInformation:
        return FileAlignmentInformationStr;
    case FILE_INFORMATION_CLASS::FileAllInformation:
        return FileAllInformationStr;
    case FILE_INFORMATION_CLASS::FileAllocationInformation:
        return FileAllocationInformationStr;
    case FILE_INFORMATION_CLASS::FileEndOfFileInformation:
        return FileEndOfFileInformationStr;
    case FILE_INFORMATION_CLASS::FileAlternateNameInformation:
        return FileAlternateNameInformationStr;
    case FILE_INFORMATION_CLASS::FileStreamInformation:
        return FileStreamInformationStr;
    case FILE_INFORMATION_CLASS::FilePipeInformation:
        return FilePipeInformationStr;
    case FILE_INFORMATION_CLASS::FilePipeLocalInformation:
        return FilePipeLocalInformationStr;
    case FILE_INFORMATION_CLASS::FilePipeRemoteInformation:
        return FilePipeRemoteInformationStr;
    case FILE_INFORMATION_CLASS::FileMailslotQueryInformation:
        return FileMailslotQueryInformationStr;
    case FILE_INFORMATION_CLASS::FileMailslotSetInformation:
        return FileMailslotSetInformationStr;
    case FILE_INFORMATION_CLASS::FileCompressionInformation:
        return FileCompressionInformationStr;
    case FILE_INFORMATION_CLASS::FileObjectIdInformation:
        return FileObjectIdInformationStr;
    case FILE_INFORMATION_CLASS::FileCompletionInformation:
        return FileCompletionInformationStr;
    case FILE_INFORMATION_CLASS::FileMoveClusterInformation:
        return FileMoveClusterInformationStr;
    case FILE_INFORMATION_CLASS::FileQuotaInformation:
        return FileQuotaInformationStr;
    case FILE_INFORMATION_CLASS::FileReparsePointInformation:
        return FileReparsePointInformationStr;
    case FILE_INFORMATION_CLASS::FileNetworkOpenInformation:
        return FileNetworkOpenInformationStr;
    case FILE_INFORMATION_CLASS::FileAttributeTagInformation:
        return FileAttributeTagInformationStr;
    case FILE_INFORMATION_CLASS::FileTrackingInformation:
        return FileTrackingInformationStr;
    case FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
        return FileIdBothDirectoryInformationStr;
    case FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation:
        return FileIdFullDirectoryInformationStr;
    case FILE_INFORMATION_CLASS::FileValidDataLengthInformation:
        return FileValidDataLengthInformationStr;
    case FILE_INFORMATION_CLASS::FileShortNameInformation:
        return FileShortNameInformationStr;
    case FILE_INFORMATION_CLASS::FileIoCompletionNotificationInformation:
        return FileIoCompletionNotificationInformationStr;
    case FILE_INFORMATION_CLASS::FileIoStatusBlockRangeInformation:
        return FileIoStatusBlockRangeInformationStr;
    case FILE_INFORMATION_CLASS::FileIoPriorityHintInformation:
        return FileIoPriorityHintInformationStr;
    case FILE_INFORMATION_CLASS::FileSfioReserveInformation:
        return FileSfioReserveInformationStr;
    case FILE_INFORMATION_CLASS::FileSfioVolumeInformation:
        return FileSfioVolumeInformationStr;
    case FILE_INFORMATION_CLASS::FileHardLinkInformation:
        return FileHardLinkInformationStr;
    case FILE_INFORMATION_CLASS::FileProcessIdsUsingFileInformation:
        return FileProcessIdsUsingFileInformationStr;
    case FILE_INFORMATION_CLASS::FileNormalizedNameInformation:
        return FileNormalizedNameInformationStr;
    case FILE_INFORMATION_CLASS::FileNetworkPhysicalNameInformation:
        return FileNetworkPhysicalNameInformationStr;
    case FILE_INFORMATION_CLASS::FileIdGlobalTxDirectoryInformation:
        return FileIdGlobalTxDirectoryInformationStr;
    case FILE_INFORMATION_CLASS::FileIsRemoteDeviceInformation:
        return FileIsRemoteDeviceInformationStr;
    case FILE_INFORMATION_CLASS::FileAttributeCacheInformation:
        return FileAttributeCacheInformationStr;
    case FILE_INFORMATION_CLASS::FileNumaNodeInformation:
        return FileNumaNodeInformationStr;
    case FILE_INFORMATION_CLASS::FileStandardLinkInformation:
        return FileStandardLinkInformationStr;
    case FILE_INFORMATION_CLASS::FileRemoteProtocolInformation:
        return FileRemoteProtocolInformationStr;
    }

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, FILE_INFORMATION_CLASS infoClass) {
    os << to_string(infoClass);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
