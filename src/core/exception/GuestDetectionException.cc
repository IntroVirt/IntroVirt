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
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>

#include <string>

namespace introvirt {

GuestDetectionException::GuestDetectionException(const Vcpu& vcpu, const std::string& message)
    : TraceableException("Domain " + vcpu.domain().name() + " Vcpu " + std::to_string(vcpu.id()) +
                         " failed guest detection: " + message) {}

GuestDetectionException::GuestDetectionException(const Domain& domain, const std::string& message)
    : TraceableException("Domain " + domain.name() + " failed guest detection: " + message) {}

} // namespace introvirt
