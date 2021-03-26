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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/libraries/secur32/types/SecBufferDesc.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace secur32 {

namespace structs {

template <typename PtrType>
struct _SecBufferDesc {
    uint32_t ulVersion;
    uint32_t cBuffers;
    guest_member_ptr<void, PtrType> pBuffers;
};

} // namespace structs

template <typename PtrType>
class SecBufferDescImpl final : public SecBufferDesc {
  public:
    uint32_t ulVersion() const override { return ptr_->ulVersion; }
    void ulVersion(uint32_t ulVersion) override { ptr_->ulVersion = ulVersion; }

    uint32_t cBuffers() const override { return ptr_->cBuffers; }
    void cBuffers(uint32_t cBuffers) override { ptr_->cBuffers = cBuffers; }

    guest_ptr<void> pBuffers() const override { return ptr_->pBuffers.get(ptr_); }
    void pBuffers(const guest_ptr<void>& ptr) override { ptr_->pBuffers.set(ptr); }

    SecBufferDescImpl(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_SecBufferDesc<PtrType>> ptr_;
};

} // namespace secur32
} // namespace windows
} // namespace introvirt
