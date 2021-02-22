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

#include <introvirt/windows/libraries/WindowsFunctionCall.hh>
#include <introvirt/windows/libraries/ncrypt/types/types.hh>

#include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>

namespace introvirt {
namespace windows {
namespace ncrypt {

/**
 * @brief Handler for ncrypt!Ssl3GenerateKeyMaterial
 *
 * This call doesn't have much documentation.
 * The information we have was taken from Cukoo:
 * https://github.com/cuckoosandbox/monitor/blob/master/sigs/crypto.rst
 */
class Ssl3GenerateKeyMaterial : public WindowsFunctionCall {
  public:
    /* Input arguments */

    GuestVirtualAddress pbSecret() const;
    void pbSecret(const GuestVirtualAddress& gva);

    uint32_t dwSecretLength() const;
    void dwSecretLength(uint32_t dwSecretLength);

    GuestVirtualAddress pbSeed() const;
    void pbSeed(const GuestVirtualAddress& gva);

    uint32_t dwSeedLength() const;
    void dwSeedLength(uint32_t dwSeedLength);

    /* Helpers */

    nt::NTSTATUS result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    Ssl3GenerateKeyMaterial(Event& event);
    ~Ssl3GenerateKeyMaterial() override;

    static constexpr int ArgumentCount = 7;
    inline static const std::string LibraryName = "ncrypt";
    inline static const std::string FunctionName = "Ssl3GenerateKeyMaterial";

  private:
    GuestVirtualAddress pbSecret_;
    uint64_t dwSecretLength_;
    GuestVirtualAddress pbSeed_;
    uint64_t dwSeedLength_;
};

} // namespace ncrypt
} // namespace windows
} // namespace introvirt