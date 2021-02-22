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

#include <introvirt/windows/fwd.hh>

#include <introvirt/util/compiler.hh>
#include <memory>

namespace introvirt {
namespace windows {

class SystemCallCreator {
  public:
    /**
     * Instantiates a new SyscallHandler that the caller must delete.
     *
     * @param event The incoming system call event
     *
     * @returns An instantiated SyscallHandler that must be deleted.
     */
    static std::unique_ptr<WindowsSystemCall> make_unique(WindowsEvent& event) HOT;

  private:
    // No instantiating.
    SystemCallCreator() = delete;
};

} /* namespace windows */
} /* namespace introvirt */
