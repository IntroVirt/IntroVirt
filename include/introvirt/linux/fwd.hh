/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

namespace introvirt {

// NOTE: the namespace is `linux_guest`, not `linux`, because GCC/Clang in
// GNU mode predefine the object-like macro `linux` (== 1) on Linux targets,
// which would mangle `namespace linux`. Keeping it explicit avoids needing a
// fragile `#undef linux` in every translation unit. Mirrors `windows::`.
namespace linux_guest {

class LinuxGuest;
class LinuxKernel;
class LinuxProfile;

} // namespace linux_guest
} // namespace introvirt
