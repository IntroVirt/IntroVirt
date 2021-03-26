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
#include <introvirt/core/exception/TraceableException.hh>

#include <boost/stacktrace.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

using namespace std;

namespace introvirt {

static constexpr int IV_STACK_TRACE_DEPTH = 30;

class TraceableException::IMPL {
  public:
    boost::stacktrace::stacktrace trace_;
    void* stack_[IV_STACK_TRACE_DEPTH]{};
    size_t stack_size_;
    mutable std::vector<std::string> stack_symbols_;
    int err_;
};

int TraceableException::error_code() const { return pImpl_->err_; }

TraceableException::TraceableException(const std::string& msg)
    : runtime_error(msg), pImpl_(std::make_unique<IMPL>()) {}

TraceableException::TraceableException(const std::string& msg, int err)
    : TraceableException(msg + ": " + strerror(err)) {
    pImpl_->err_ = err;
}

TraceableException::TraceableException(TraceableException&& src) noexcept = default;
TraceableException& TraceableException::operator=(TraceableException&& src) noexcept = default;
TraceableException::~TraceableException() = default;

std::ostream& operator<<(std::ostream& os, const TraceableException& error) {
    os << error.what() << '\n';
    os << error.pImpl_->trace_;
    return os;
}

} // namespace introvirt
