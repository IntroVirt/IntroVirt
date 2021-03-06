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
#include <introvirt/windows/fwd.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Class for the Windows NT OBJECT_HEADER_QUOTA_INFO structure
 */
class OBJECT_HEADER_QUOTA_INFO {
  public:
    virtual ~OBJECT_HEADER_QUOTA_INFO() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt