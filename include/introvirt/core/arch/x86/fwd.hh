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

namespace introvirt {

/**
 * @brief Classes for the x86 architecture
 */
namespace x86 {

class Cr0;
class Cr4;
class Efer;
class Flags;
class Idt;
class IdtEntry;
class PageDirectory;
class Registers;
class Segment;
class Segment;
class SegmentDescriptorTable;
class SegmentSelector;
class Tss;

} // namespace x86
} // namespace introvirt
