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

#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/core/fwd.hh>

#include <string>

namespace introvirt {

/**
 * @brief Thrown when to detect the guest operating system
 *
 * This may indicate that the guest has not booted yet, or is unsupported.
 */
class GuestDetectionException : public TraceableException {
  public:
    /**
     * @brief Construct a new GuestDetectionException instance
     * @param vcpu The vcpu related to the error message
     */
    GuestDetectionException(const Vcpu& vcpu, const std::string& message);

    /**
     * @brief Construct a new GuestDetectionException instance
     * @param domain The domain related to the error message
     */
    GuestDetectionException(const Domain& domain, const std::string& message);
};

} // namespace introvirt
