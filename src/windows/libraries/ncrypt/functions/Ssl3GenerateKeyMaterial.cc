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
#include <introvirt/windows/libraries/ncrypt/functions/Ssl3GenerateKeyMaterial.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ncrypt {

GuestVirtualAddress Ssl3GenerateKeyMaterial::pbSecret() const { return pbSecret_; }
void Ssl3GenerateKeyMaterial::pbSecret(const GuestVirtualAddress& gva) {
    set_address_argument(0, gva);
    pbSecret_ = gva;
}

uint32_t Ssl3GenerateKeyMaterial::dwSecretLength() const { return dwSecretLength_; }
void Ssl3GenerateKeyMaterial::dwSecretLength(uint32_t dwSecretLength) {
    set_argument(1, dwSecretLength);
    dwSecretLength_ = dwSecretLength;
}

GuestVirtualAddress Ssl3GenerateKeyMaterial::pbSeed() const { return pbSeed_; }
void Ssl3GenerateKeyMaterial::pbSeed(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    pbSeed_ = gva;
}

uint32_t Ssl3GenerateKeyMaterial::dwSeedLength() const { return dwSeedLength_; }
void Ssl3GenerateKeyMaterial::dwSeedLength(uint32_t dwSeedLength) {
    set_argument(3, dwSeedLength);
    dwSeedLength_ = dwSeedLength;
}

nt::NTSTATUS Ssl3GenerateKeyMaterial::result() const { return nt::NTSTATUS(raw_return_value()); }

const std::string& Ssl3GenerateKeyMaterial::function_name() const { return FunctionName; }
const std::string& Ssl3GenerateKeyMaterial::library_name() const { return LibraryName; }
void Ssl3GenerateKeyMaterial::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

Ssl3GenerateKeyMaterial::Ssl3GenerateKeyMaterial(Event& event)
    : WindowsFunctionCall(event, ArgumentCount) {

    pbSecret_ = get_address_argument(1);
    dwSecretLength_ = get_argument(2);
    pbSeed_ = get_address_argument(3);
    dwSeedLength_ = get_argument(4);
}

Ssl3GenerateKeyMaterial::~Ssl3GenerateKeyMaterial() = default;

} // namespace ncrypt
} // namespace windows
} // namespace introvirt