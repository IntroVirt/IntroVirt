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

#include <introvirt/windows/kernel/WindowsSystemCall.hh>
#include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Base type for NT system calls
 *
 */
class NtSystemCall : public WindowsSystemCall {
  public:
    /**
     * @brief Get the result code
     *
     * NT system calls return an NTSTATUS code on completion
     *
     * @return NTSTATUS
     */
    virtual NTSTATUS result() const = 0;

    /**
     * @brief Set the result code
     *
     * This can be used to maniuplate the value received by the guest userland software.
     *
     * @param code The code to set
     * @throw introvirt::InvalidMethodException if the kernel has not yet returned with a result to
     * overwrite
     */
    virtual void result(NTSTATUS_CODE code) = 0;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
