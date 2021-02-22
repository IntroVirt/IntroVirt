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

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>
#include <execinfo.h>
#include <iostream>
#include <vector>

using namespace std;

namespace introvirt {

static constexpr int IV_STACK_TRACE_DEPTH = 30;

class TraceableException::IMPL {
  public:
    void* stack_[IV_STACK_TRACE_DEPTH]{};
    size_t stack_size_;
    mutable std::vector<std::string> stack_symbols_;
    int err_;
};

static void getSymbols(void* const stack[], size_t stack_size, std::vector<std::string>& output);
static std::string demangle(const std::string& trace);

int TraceableException::error_code() const { return pImpl_->err_; }

TraceableException::TraceableException(const std::string& msg)
    : runtime_error(msg), pImpl_(std::make_unique<IMPL>()) {

    // get void*'s for all entries on the stack
    pImpl_->stack_size_ = backtrace(pImpl_->stack_, IV_STACK_TRACE_DEPTH);
    pImpl_->err_ = 0;
}

TraceableException::TraceableException(const std::string& msg, int err)
    : TraceableException(msg + ": " + strerror(err)) {
    pImpl_->err_ = err;
}

TraceableException::TraceableException(TraceableException&& src) noexcept = default;
TraceableException& TraceableException::operator=(TraceableException&& src) noexcept = default;
TraceableException::~TraceableException() = default;

std::ostream& operator<<(std::ostream& os, const TraceableException& error) {
    os << error.what() << '\n';

    if (error.pImpl_->stack_symbols_.empty()) {
        getSymbols(error.pImpl_->stack_, error.pImpl_->stack_size_, error.pImpl_->stack_symbols_);
    }

    // Start at 1 to skip the call to TraceableException()
    for (size_t i = 1; i < error.pImpl_->stack_size_; ++i) {
        os << "\t" << demangle(error.pImpl_->stack_symbols_[i]) << '\n';
    }
    return os;
}

static void getSymbols(void* const stack[], size_t stack_size, std::vector<std::string>& output) {
    char** strings = backtrace_symbols(stack, stack_size);
    for (size_t i = 0; i < stack_size; ++i) {
        output.emplace_back(strings[i]);
    }
    free(strings);
}

static std::string demangle(const std::string& trace) {
    std::string::size_type begin, end;
    std::string result;

    // find the beginning and the end of the useful part of the trace
    begin = trace.find_first_of('(') + 1;
    end = trace.find_last_of('+');

    // if they were found, we'll go ahead and demangle
    if (begin != std::string::npos && end != std::string::npos) {
        std::string tmp(trace.substr(begin, end - begin));

        int demangleStatus;

        char* demangledName = nullptr;
        if (((demangledName = abi::__cxa_demangle(tmp.c_str(), nullptr, nullptr,
                                                  &demangleStatus)) != nullptr) &&
            demangleStatus == 0) {
            result = trace.substr(0, begin);
            result += demangledName;
            result += trace.substr(end); // the demangled name is now in our result string
        }
        if (demangledName != nullptr) {
            free(demangledName);
        }
    } else {
        result = std::string(trace);
    }
    return result;
}

} // namespace introvirt
