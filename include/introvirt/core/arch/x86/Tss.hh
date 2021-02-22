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

#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace x86 {
/**
 * @brief x86 Task State Segment
 */
class Tss final {
  public:
    /**
     * @brief Get the E/RSP0 (kernel stack) value from the TSS
     *
     * Returns either ESP0 (32-bit) or RSP0 (64-bit) from the
     * Task State Segment.
     *
     * @return the esp0 or rsp0 task state segment value
     */
    GuestVirtualAddress sp0() const;

    /**
     * @brief Construct a new Tss object
     *
     * @param vcpu The Vcpu to read the task register from
     */
    Tss(const Vcpu& vcpu);

    /**
     * @brief Destroy the instance
     */
    ~Tss();

  private:
    const Vcpu& vcpu_;
};

} // namespace x86
} // namespace introvirt