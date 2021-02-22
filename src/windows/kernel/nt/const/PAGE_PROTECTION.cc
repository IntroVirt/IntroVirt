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

#include <introvirt/windows/kernel/nt/const/PAGE_PROTECTION.hh>

#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

static const uint32_t PROTECT_FLAGS[] = {
    PAGE_PROTECTION::PAGE_NOACCESS,
    PAGE_PROTECTION::PAGE_READONLY,
    PAGE_PROTECTION::PAGE_EXECUTE,
    PAGE_PROTECTION::PAGE_EXECUTE_READ,
    PAGE_PROTECTION::PAGE_READWRITE,
    PAGE_PROTECTION::PAGE_WRITECOPY,
    PAGE_PROTECTION::PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY,
    PAGE_PROTECTION::PAGE_NOACCESS,
    PAGE_PROTECTION::PAGE_NOCACHE | PAGE_PROTECTION::PAGE_READONLY,
    PAGE_PROTECTION::PAGE_NOCACHE | PAGE_PROTECTION::PAGE_EXECUTE,
    PAGE_PROTECTION::PAGE_NOCACHE | PAGE_PROTECTION::PAGE_EXECUTE_READ,
    PAGE_PROTECTION::PAGE_NOCACHE | PAGE_PROTECTION::PAGE_READWRITE,
    PAGE_PROTECTION::PAGE_NOCACHE | PAGE_PROTECTION::PAGE_WRITECOPY,
    PAGE_PROTECTION::PAGE_NOCACHE | PAGE_PROTECTION::PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION::PAGE_NOCACHE | PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY,
    PAGE_PROTECTION::PAGE_NOACCESS,
    PAGE_PROTECTION::PAGE_GUARD | PAGE_PROTECTION::PAGE_READONLY,
    PAGE_PROTECTION::PAGE_GUARD | PAGE_PROTECTION::PAGE_EXECUTE,
    PAGE_PROTECTION::PAGE_GUARD | PAGE_PROTECTION::PAGE_EXECUTE_READ,
    PAGE_PROTECTION::PAGE_GUARD | PAGE_PROTECTION::PAGE_READWRITE,
    PAGE_PROTECTION::PAGE_GUARD | PAGE_PROTECTION::PAGE_WRITECOPY,
    PAGE_PROTECTION::PAGE_GUARD | PAGE_PROTECTION::PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION::PAGE_GUARD | PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY,
    PAGE_PROTECTION::PAGE_NOACCESS,
    PAGE_PROTECTION::PAGE_WRITECOMBINE | PAGE_PROTECTION::PAGE_READONLY,
    PAGE_PROTECTION::PAGE_WRITECOMBINE | PAGE_PROTECTION::PAGE_EXECUTE,
    PAGE_PROTECTION::PAGE_WRITECOMBINE | PAGE_PROTECTION::PAGE_EXECUTE_READ,
    PAGE_PROTECTION::PAGE_WRITECOMBINE | PAGE_PROTECTION::PAGE_READWRITE,
    PAGE_PROTECTION::PAGE_WRITECOMBINE | PAGE_PROTECTION::PAGE_WRITECOPY,
    PAGE_PROTECTION::PAGE_WRITECOMBINE | PAGE_PROTECTION::PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION::PAGE_WRITECOMBINE | PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY,
};

PAGE_PROTECTION PAGE_PROTECTION::fromVadProtection(uint32_t protection_) {
    return PAGE_PROTECTION(PROTECT_FLAGS[protection_]);
}

bool PAGE_PROTECTION::isExecutable() const {
    return (protection_ & (PAGE_PROTECTION::PAGE_EXECUTE | PAGE_PROTECTION::PAGE_EXECUTE_READ |
                           PAGE_PROTECTION::PAGE_EXECUTE_READWRITE |
                           PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY)) != 0u;
}

bool PAGE_PROTECTION::isWritable() const {
    return (protection_ &
            (PAGE_PROTECTION::PAGE_EXECUTE_READWRITE | PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY |
             PAGE_PROTECTION::PAGE_READWRITE | PAGE_PROTECTION::PAGE_WRITECOPY)) != 0u;
}

bool PAGE_PROTECTION::isRWX() const {
    return (protection_ & PAGE_PROTECTION::PAGE_EXECUTE_READWRITE) != 0u;
}

bool PAGE_PROTECTION::isReadable() const {
    return (protection_ &
            (PAGE_PROTECTION::PAGE_EXECUTE_READ | PAGE_PROTECTION::PAGE_EXECUTE_READWRITE |
             PAGE_PROTECTION::PAGE_READONLY | PAGE_PROTECTION::PAGE_READWRITE)) != 0u;
}

bool PAGE_PROTECTION::isCopyOnWrite() const {
    return (protection_ &
            (PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY | PAGE_PROTECTION::PAGE_WRITECOPY)) != 0u;
}

void PAGE_PROTECTION::clearExecutable() {
    if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE) != 0u) {
        protection_ ^= PAGE_PROTECTION::PAGE_EXECUTE;
    } else if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE_READ) != 0u) {
        protection_ ^= (PAGE_PROTECTION::PAGE_READONLY | PAGE_PROTECTION::PAGE_EXECUTE_READ);
    } else if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE_READWRITE) != 0u) {
        protection_ ^= (PAGE_PROTECTION::PAGE_READWRITE | PAGE_PROTECTION::PAGE_EXECUTE_READWRITE);
    } else if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY) != 0u) {
        protection_ ^= (PAGE_PROTECTION::PAGE_WRITECOPY | PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY);
    }
}

void PAGE_PROTECTION::clearWritable() {
    if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE_READWRITE) != 0u) {
        protection_ ^=
            (PAGE_PROTECTION::PAGE_EXECUTE_READ | PAGE_PROTECTION::PAGE_EXECUTE_READWRITE);
    } else if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY) != 0u) {
        protection_ ^=
            (PAGE_PROTECTION::PAGE_EXECUTE_READ | PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY);
    } else if ((protection_ & PAGE_PROTECTION::PAGE_READWRITE) != 0u) {
        protection_ ^= (PAGE_PROTECTION::PAGE_READONLY | PAGE_PROTECTION::PAGE_READWRITE);
    } else if ((protection_ & PAGE_PROTECTION::PAGE_WRITECOPY) != 0u) {
        protection_ ^= (PAGE_PROTECTION::PAGE_READONLY | PAGE_PROTECTION::PAGE_WRITECOPY);
    }
}

void PAGE_PROTECTION::changeToCopyOnWrite() {
    if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE_READWRITE) != 0u) {
        protection_ ^=
            (PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY | PAGE_PROTECTION::PAGE_EXECUTE_READWRITE);
    } else if ((protection_ & PAGE_PROTECTION::PAGE_READWRITE) != 0u) {
        protection_ ^= (PAGE_PROTECTION::PAGE_WRITECOPY | PAGE_PROTECTION::PAGE_READWRITE);
    }
}

uint32_t PAGE_PROTECTION::value() const { return protection_; }

PAGE_PROTECTION::operator uint32_t() const { return protection_; }

std::string PAGE_PROTECTION::string() const {
    std::stringstream ss;

    if ((protection_ & PAGE_PROTECTION::PAGE_NOACCESS) != 0u) {
        ss << "PAGE_NOACCESS ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_READONLY) != 0u) {
        ss << "PAGE_READONLY ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_READWRITE) != 0u) {
        ss << "PAGE_READWRITE ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_WRITECOPY) != 0u) {
        ss << "PAGE_WRITECOPY ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE) != 0u) {
        ss << "PAGE_EXECUTE ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE_READ) != 0u) {
        ss << "PAGE_EXECUTE_READ ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE_READWRITE) != 0u) {
        ss << "PAGE_EXECUTE_READWRITE ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_EXECUTE_WRITECOPY) != 0u) {
        ss << "PAGE_EXECUTE_WRITECOPY ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_GUARD) != 0u) {
        ss << "PAGE_GUARD ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_NOCACHE) != 0u) {
        ss << "PAGE_NOCACHE ";
    }
    if ((protection_ & PAGE_PROTECTION::PAGE_WRITECOMBINE) != 0u) {
        ss << "PAGE_WRITECOMBINE ";
    }

    return ss.str();
}

PAGE_PROTECTION::PAGE_PROTECTION(uint32_t protection) : protection_(protection) {}
PAGE_PROTECTION::PAGE_PROTECTION(PageProtectionFlag flag) : protection_(flag) {}
PAGE_PROTECTION::PAGE_PROTECTION(const PAGE_PROTECTION&) = default;
PAGE_PROTECTION& PAGE_PROTECTION::operator=(const PAGE_PROTECTION& other) = default;
bool PAGE_PROTECTION::operator==(const PAGE_PROTECTION& other) const {
    return protection_ == other.protection_;
}
PAGE_PROTECTION::~PAGE_PROTECTION() = default;

std::string to_string(PAGE_PROTECTION prot) { return prot.string(); }

std::ostream& operator<<(std::ostream& os, PAGE_PROTECTION prot) {
    os << prot.string();
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
