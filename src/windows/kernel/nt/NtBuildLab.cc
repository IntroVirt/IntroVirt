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

#include <introvirt/windows/kernel/nt/NtBuildLab.hh>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <log4cxx/logger.h>
#include <vector>

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.NtBuildLab"));

using namespace boost;

namespace introvirt {
namespace windows {
namespace nt {

class NtBuildLab::IMPL {
  public:
    std::string original_;
    std::string build_type;
    std::string build_label;

    uint32_t major_build = 0;
    uint32_t minor_build = 0;

    uint32_t build_date = 0;
    uint16_t build_year = 0;
    uint16_t build_month = 0;
    uint16_t build_day = 0;
};

NtBuildLab::NtBuildLab(const std::string& str) : pImpl(std::make_unique<IMPL>()) {
    pImpl->original_ = str;

    // Do some parsing
    std::vector<std::string> toks;
    boost::split(toks, str, boost::is_any_of("."));
    std::string build_date;

    try {
        if (toks.size() == 5) {
            // New version
            pImpl->major_build = lexical_cast<uint32_t>(toks[0]);
            pImpl->minor_build = lexical_cast<uint32_t>(toks[1]);
            pImpl->build_type = toks[2];
            pImpl->build_label = toks[3];
            build_date = toks[4];
        } else if (toks.size() == 3) {
            // Old version
            pImpl->major_build = lexical_cast<uint32_t>(toks[0]);
            pImpl->minor_build = 0;
            pImpl->build_label = toks[1];
            build_date = toks[2];
        } else {
            pImpl->major_build = 0;
            pImpl->minor_build = 0;
            pImpl->build_year = 0;
            pImpl->build_month = 0;
            pImpl->build_day = 0;
        }

        if (!build_date.empty()) {
            pImpl->build_date = lexical_cast<uint32_t>(build_date.substr(0, 6));
            pImpl->build_year = lexical_cast<uint16_t>(build_date.substr(0, 2));
            pImpl->build_month = lexical_cast<uint16_t>(build_date.substr(2, 2));
            pImpl->build_day = lexical_cast<uint16_t>(build_date.substr(4, 2));
        }
    } catch (bad_lexical_cast& ex) {
        LOG4CXX_WARN(logger, ex.what());
    }
}

NtBuildLab::~NtBuildLab() = default;

uint32_t NtBuildLab::MajorBuildNumber() const { return pImpl->major_build; }
uint32_t NtBuildLab::MinorBuildNumber() const { return pImpl->minor_build; }
uint32_t NtBuildLab::BuildYear() const { return pImpl->build_year; }
uint32_t NtBuildLab::BuildMonth() const { return pImpl->build_month; }
uint32_t NtBuildLab::BuildDay() const { return pImpl->build_day; }
uint32_t NtBuildLab::BuildDate() const { return pImpl->build_date; }
std::string NtBuildLab::BuildType() const { return pImpl->build_type; }
std::string NtBuildLab::BuildLabel() const { return pImpl->build_label; }
std::string NtBuildLab::string() const { return pImpl->original_; }

std::ostream& operator<<(std::ostream& os, const NtBuildLab& label) {
    os << label.string();
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
