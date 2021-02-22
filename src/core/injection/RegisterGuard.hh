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

#include <introvirt/fwd.hh>
#include <memory>

namespace introvirt {
namespace inject {

/**
 * @brief Save VCPU state and restore it once off-scope
 *
 */
class RegisterGuard final {
  public:
    /**
     * @brief Do not reset registers after going off scope
     */
    void release();

    RegisterGuard(Vcpu& vcpu);
    ~RegisterGuard();

  private:
    Vcpu& vcpu_;
    std::unique_ptr<Vcpu> original_;
};

} // namespace inject
} // namespace introvirt