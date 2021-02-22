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

/*
 * Forward declarations for the PE namespace
 */

namespace introvirt {
namespace windows {

/**
 * @brief Classes related to parsing the PE file format in memory
 */
namespace pe {

class CV_INFO;
class DOS_HEADER;
class IMAGE_DEBUG_DIRECTORY;
class IMAGE_EXPORT_DIRECTORY;
class IMAGE_FILE_HEADER;
class IMAGE_IMPORT_DESCRIPTOR;
class IMAGE_OPTIONAL_HEADER;
class IMAGE_RELOCATION_SECTION;
class IMAGE_RESOURCE_DATA_ENTRY;
class IMAGE_RESOURCE_DIRECTORY_ENTRY;
class IMAGE_RESOURCE_DIRECTORY;
class IMAGE_SECTION_HEADER;
class IMAGE_SECTION_HEADERList;
class IMAGE_EXCEPTION_SECTION;
class IMPORT_NAME_TABLE;
class PE;
class RUNTIME_FUNCTION;
class StringFileInfo;
class StringTable;
class UnwindCode;
class UnwindInfo;
class Var;
class VarFileInfo;
class VS_FIXEDFILEINFO;
class VS_VERSIONINFO;

} // namespace pe
} // namespace windows
} // namespace introvirt
