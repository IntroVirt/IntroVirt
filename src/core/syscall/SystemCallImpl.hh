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

#include <introvirt/core/syscall/SystemCall.hh>

#include <unordered_map>

namespace introvirt {

template <typename _BaseClass = SystemCall>
class SystemCallImpl : public _BaseClass {
  public:
    // Default to having the call indicate it will return
    bool will_return() const override { return true; }

    void data(const std::string& key, const std::shared_ptr<void>& value) final {
        data_[key] = value;
    }

    void data(const std::string& key, std::shared_ptr<void>&& value) final {
        data_[key] = std::move(value);
    }

    std::shared_ptr<void> data(const std::string& key) final {
        const auto* const_this = const_cast<const SystemCallImpl*>(this);
        return std::const_pointer_cast<void>(const_this->data(key));
    }

    std::shared_ptr<const void> data(const std::string& key) const final {
        auto iter = data_.find(key);
        if (iter != data_.end())
            return iter->second;

        return std::shared_ptr<const void>();
    }

  private:
    std::unordered_map<std::string, std::shared_ptr<void>> data_;
};

} // namespace introvirt