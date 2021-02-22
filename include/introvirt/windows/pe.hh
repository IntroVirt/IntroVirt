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

#include <introvirt/windows/pe/PE.hh>
#include <introvirt/windows/pe/const/FileFlags.hh>
#include <introvirt/windows/pe/const/FileOS.hh>
#include <introvirt/windows/pe/const/FileSubtype.hh>
#include <introvirt/windows/pe/const/FileType.hh>
#include <introvirt/windows/pe/const/ImageDirectoryType.hh>
#include <introvirt/windows/pe/const/ImageFileCharacteristics.hh>
#include <introvirt/windows/pe/const/MachineType.hh>
#include <introvirt/windows/pe/const/ResourceDirType.hh>
#include <introvirt/windows/pe/const/UNWIND_OP.hh>
#include <introvirt/windows/pe/exception/PeException.hh>
#include <introvirt/windows/pe/types/DOS_HEADER.hh>
#include <introvirt/windows/pe/types/IMAGE_DEBUG_DIRECTORY.hh>
#include <introvirt/windows/pe/types/IMAGE_EXCEPTION_SECTION.hh>
#include <introvirt/windows/pe/types/IMAGE_EXPORT_DIRECTORY.hh>
#include <introvirt/windows/pe/types/IMAGE_FILE_HEADER.hh>
#include <introvirt/windows/pe/types/IMAGE_OPTIONAL_HEADER.hh>
#include <introvirt/windows/pe/types/IMAGE_RELOCATION_SECTION.hh>
#include <introvirt/windows/pe/types/IMAGE_RESOURCE_DATA_ENTRY.hh>
#include <introvirt/windows/pe/types/IMAGE_RESOURCE_DIRECTORY.hh>
#include <introvirt/windows/pe/types/IMAGE_RESOURCE_DIRECTORY_ENTRY.hh>
#include <introvirt/windows/pe/types/IMAGE_SECTION_HEADER.hh>
#include <introvirt/windows/pe/types/IMPORT_NAME_TABLE.hh>
#include <introvirt/windows/pe/types/RUNTIME_FUNCTION.hh>
#include <introvirt/windows/pe/types/StringFileInfo.hh>
#include <introvirt/windows/pe/types/StringTable.hh>
#include <introvirt/windows/pe/types/UnwindCode.hh>
#include <introvirt/windows/pe/types/UnwindInfo.hh>
#include <introvirt/windows/pe/types/VS_FIXEDFILEINFO.hh>
#include <introvirt/windows/pe/types/VS_VERSIONINFO.hh>
#include <introvirt/windows/pe/types/VarFileInfo.hh>