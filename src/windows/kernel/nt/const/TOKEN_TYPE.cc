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

#include <introvirt/windows/kernel/nt/const/TOKEN_TYPE.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(TOKEN_TYPE type) {
    static const std::string TokenPrimaryStr("TokenPrimary");
    static const std::string TokenImpersonationStr("TokenImpersonation");
    static const std::string TokenUnknownStr("TokenUnknown");

    switch (type) {
    case TOKEN_TYPE::TokenPrimary:
        return TokenPrimaryStr;
    case TOKEN_TYPE::TokenImpersonation:
        return TokenImpersonationStr;
    default:
        return TokenUnknownStr;
    }
}

} // namespace nt
} // namespace windows
} // namespace introvirt
