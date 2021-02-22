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

#include <introvirt/core/fwd.hh>
#include <introvirt/windows/common/WinError.hh>
#include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * Windows Thread Environment Block (TEB)
 */
class TEB {
  public:
    virtual const NT_TIB& NtTib() const = 0;
    virtual const CLIENT_ID& ClientId() const = 0;

    virtual NTSTATUS LastStatusValue() const = 0;
    virtual void LastStatusValue(NTSTATUS value) = 0;

    virtual WinError LastErrorValue() const = 0;
    virtual void LastErrorValue(WinError LastErrorValue) = 0;

    virtual GuestVirtualAddress address() const = 0;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
