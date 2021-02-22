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
#include <introvirt/windows/libraries/WindowsFunctionCall.hh>
#include <introvirt/windows/libraries/ws2_32/types/SOCKET.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/**
 * @brief Handler for ws2_32!TransmitFile
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-transmitfile
 */
class TransmitFile : public WindowsFunctionCall {
  public:
    /* Input arguments */
    SOCKET hSocket() const;
    void hSocket(SOCKET hSocket);

    uint64_t hFile() const;
    void hFile(uint64_t hFile);

    uint32_t nNumberOfBytesToWrite() const;
    void nNumberOfBytesToWrite(uint32_t nNumberOfBytesToWrite);

    uint32_t nNumberOfBytesPerSend() const;
    void nNumberOfBytesPerSend(uint32_t nNumberOfBytesPerSend);

    GuestVirtualAddress lpOverlapped() const;
    void lpOverlapped(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpTransmitBuffers() const;
    void lpTransmitBuffers(const GuestVirtualAddress& gva);

    uint32_t dwReserved() const;
    void dwReserved(uint32_t dwReserved);

    /* Helpers */

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    TransmitFile(Event& event);
    ~TransmitFile() override;

    static constexpr int ArgumentCount = 7;
    inline static const std::string LibraryName = "ws2_32";
    inline static const std::string FunctionName = "TransmitFile";

  private:
    SOCKET hSocket_;
    uint64_t hFile_;
    uint32_t nNumberOfBytesToWrite_;
    uint32_t nNumberOfBytesPerSend_;
    GuestVirtualAddress lpOverlapped_;
    GuestVirtualAddress lpTransmitBuffers_;
    uint32_t dwReserved_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt