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
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/condrv/types/ConsoleCallServerGenericRequest.hh>

#include "windows/kernel/condrv/structs/structs.hh"

namespace introvirt {
namespace windows {
namespace condrv {

class ConsoleCallServerGenericRequest::IMPL {
  public:
    IMPL(const guest_ptr<void>& pRequestHeader, const guest_ptr<void>& pRequestData,
         uint32_t requestDataLen)
        : pRequestHeader_(pRequestHeader), pRequestData_(pRequestData, requestDataLen) {}

  private:
    using ConsoleCallServerGenericRequestHeader = structs::ConsoleCallServerGenericRequestHeader;

  public:
    guest_ptr<ConsoleCallServerGenericRequestHeader> pRequestHeader_;
    guest_ptr<uint8_t[]> pRequestData_;
};

ConsoleCallServerGenericRequestCode ConsoleCallServerGenericRequest::RequestCode() const {
    const ConsoleCallServerGenericRequestCode result =
        static_cast<ConsoleCallServerGenericRequestCode>(pImpl->pRequestHeader_->requestCode);

    // Make sure it's a legitimate value, else return the Unknown code
    switch (result) {
    case ConsoleCallServerGenericRequestCode::GetConsoleCP:
    case ConsoleCallServerGenericRequestCode::GetConsoleMode:
    case ConsoleCallServerGenericRequestCode::SetConsoleMode:
    case ConsoleCallServerGenericRequestCode::ReadConsole:
    case ConsoleCallServerGenericRequestCode::WriteConsole:
    case ConsoleCallServerGenericRequestCode::SetTEBLangID:
    case ConsoleCallServerGenericRequestCode::FillConsoleOutput:
    case ConsoleCallServerGenericRequestCode::GetConsoleScreenBufferInfoEx:
    case ConsoleCallServerGenericRequestCode::GetConsoleTitle:
    case ConsoleCallServerGenericRequestCode::SetConsoleTitle:
    case ConsoleCallServerGenericRequestCode::SetConsoleCursorPosition:
    case ConsoleCallServerGenericRequestCode::SetConsoleTextAttribute:
    case ConsoleCallServerGenericRequestCode::GetConsoleWindow:
    case ConsoleCallServerGenericRequestCode::Unknown:
        return result;
    }

    return ConsoleCallServerGenericRequestCode::Unknown;
}

uint32_t ConsoleCallServerGenericRequest::Data1() const { return pImpl->pRequestHeader_->data1; }
uint32_t ConsoleCallServerGenericRequest::Data2() const { return pImpl->pRequestHeader_->data2; }

guest_ptr<void> ConsoleCallServerGenericRequest::header_address() const {
    return pImpl->pRequestHeader_;
}
guest_ptr<void> ConsoleCallServerGenericRequest::data_address() const {
    return pImpl->pRequestData_;
}

guest_ptr<uint8_t[]> ConsoleCallServerGenericRequest::RequestData() { return pImpl->pRequestData_; }

ConsoleCallServerGenericRequest::ConsoleCallServerGenericRequest(
    const WindowsGuest& guest, const guest_ptr<void>& pRequestHeader,
    const guest_ptr<void>& pRequestData, uint32_t requestDataLen)
    : pImpl(std::make_unique<IMPL>(pRequestHeader, pRequestData, requestDataLen)) {}

ConsoleCallServerGenericRequest::~ConsoleCallServerGenericRequest() = default;

} /* namespace condrv */
} /* namespace windows */
} /* namespace introvirt */
