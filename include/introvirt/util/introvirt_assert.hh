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

#include "compiler.hh"

#include <boost/stacktrace.hpp>
#include <log4cxx/logger.h>

#include <cassert>
#include <cstdlib>
#include <iostream>

namespace introvirt {

#ifdef NDEBUG
#define introvirt_assert(condition, msg) /* */
#else
#define introvirt_assert(condition, msg)                                                           \
    if (unlikely(!(condition))) {                                                                  \
        static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.assert"));          \
        LOG4CXX_FATAL(logger, "Assertion '" << #condition << "' failed : " << msg << '\n'          \
                                            << __FILE__ << ":" << __LINE__ << " "                  \
                                            << __PRETTY_FUNCTION__ << '\n'                         \
                                            << boost::stacktrace::stacktrace());                   \
        exit(255);                                                                                 \
    }
#endif

} // namespace introvirt