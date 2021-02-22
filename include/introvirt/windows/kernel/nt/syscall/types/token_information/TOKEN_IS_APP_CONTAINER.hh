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

#include "TOKEN_INFORMATION.hh"

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Contains a DWORD value that is nonzero if the token is an app container token.
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
 *
 */
class TOKEN_IS_APP_CONTAINER : public TOKEN_INFORMATION {
  public:
    virtual uint32_t TokenIsAppContainer() const = 0;
    virtual void TokenIsAppContainer(uint32_t value) = 0;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
