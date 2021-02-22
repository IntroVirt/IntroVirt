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
#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/kernel/condrv/const/ConsoleCallServerGenericRequestCode.hh>
#include <introvirt/windows/kernel/condrv/types/ConsoleCallServerGenericRequest.hh>
#include <introvirt/windows/kernel/condrv/types/ConsoleCallServerGenericWriteRequest.hh>

#include "windows/kernel/condrv/structs/structs.hh"

namespace introvirt {
namespace windows {
namespace condrv {

class ConsoleCallServerGenericWriteRequest::IMPL {
  public:
    virtual uint32_t getDataSize() const = 0;
    virtual GuestVirtualAddress getDataPtr() const = 0;
    virtual bool isUnicode() const = 0;
    virtual const std::string& getData() const = 0;

  public:
    virtual ~IMPL() = default;
};

template <typename PtrType>
class ConsoleCallServerGenericWriteRequest::IMPL_SPEC final
    : public ConsoleCallServerGenericWriteRequest::IMPL {
  public:
    IMPL_SPEC(ConsoleCallServerGenericRequest& request) : request(request) {

        // Sanity checks
        if (unlikely(request.RequestCode() != ConsoleCallServerGenericRequestCode::WriteConsole)) {
            throw InvalidMethodException();
        }

        if (unlikely(request.RequestData().length() <
                     sizeof(ConsoleCallServerGenericWriteConsoleData))) {
            throw BufferTooSmallException(sizeof(ConsoleCallServerGenericWriteConsoleData),
                                          request.RequestData().length());
        }

        // Cast the header to our type
        header = reinterpret_cast<ConsoleCallServerGenericWriteConsoleData*>(
            request.RequestData().get());

        // Get the string data
        guest_ptr<uint8_t[]> buffer(getDataPtr(), getDataSize());

        if (isUnicode()) {
            // Parse it with WSTR
            data = WStr(std::move(buffer)).utf8();
        } else {
            // Just copy it directly
            data = std::string(reinterpret_cast<const char*>(buffer.get()), buffer.length());
        }
    }

  public:
    uint32_t getDataSize() const override { return header->dataSize; }

    GuestVirtualAddress getDataPtr() const override {
        return request.header_address().create(header->dataPtr);
    }

    bool isUnicode() const override {
        // TODO (pape): Not sure how to detect UNICODE vs ASCII, this doesn't seem to work.
        //              So far everything has been UTF16 anyway, so returning true for now.
        // return (request.getData2() == 1);
        return true;
    }

    const std::string& getData() const override { return data; }

  private:
    using ConsoleCallServerGenericWriteConsoleData =
        structs::ConsoleCallServerGenericWriteConsoleData<PtrType>;
    const ConsoleCallServerGenericRequest& request;
    const ConsoleCallServerGenericWriteConsoleData* header;

    std::string data;
};

const std::string& ConsoleCallServerGenericWriteRequest::Data() const { return pImpl->getData(); }

ConsoleCallServerGenericWriteRequest::ConsoleCallServerGenericWriteRequest(
    const WindowsGuest& guest, ConsoleCallServerGenericRequest& request) {
    if (guest.x64()) {
        pImpl = std::make_unique<IMPL_SPEC<uint64_t>>(request);
    } else {
        pImpl = std::make_unique<IMPL_SPEC<uint32_t>>(request);
    }
}

ConsoleCallServerGenericWriteRequest::~ConsoleCallServerGenericWriteRequest() = default;

} /* namespace condrv */
} /* namespace windows */
} /* namespace introvirt */
