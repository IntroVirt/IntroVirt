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
#include <introvirt/windows/libraries/ws2_32/types/SOCKADDR.hh>
#include <introvirt/windows/libraries/ws2_32/types/SOCKET.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/**
 * @brief Handler for ws2_32!WSARecvFrom
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecvfrom
 */
class WSARecvFrom : public WindowsFunctionCall {
  public:
    /* Input arguments */
    SOCKET s() const;
    void s(SOCKET s);

    GuestVirtualAddress lpBuffers() const;
    void lpBuffers(const GuestVirtualAddress& gva);

    uint32_t dwBufferCount() const;
    void dwBufferCount(uint32_t dwBufferCount);

    GuestVirtualAddress lpNumberOfBytesRecvd() const;
    void lpNumberOfBytesRecvd(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpFlags() const;
    void lpFlags(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpFrom() const;
    void lpFrom(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpFromLen() const;
    void lpFromLen(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpOverlapped() const;
    void lpOverlapped(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpCompletionRoutine() const;
    void lpCompletionRoutine(const GuestVirtualAddress& gva);

    /* Helpers */
    uint32_t NumberOfBytesRecvd() const;
    void NumberOfBytesRecvd(uint32_t NumberOfBytesRecvd);

    uint32_t Flags() const;
    void Flags(uint32_t Flags);

    const SOCKADDR* From() const;
    SOCKADDR* From();

    int32_t FromLen() const;
    void FromLen(int32_t FromLen);

    int32_t result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    WSARecvFrom(Event& event);
    ~WSARecvFrom() override;

    static constexpr int ArgumentCount = 9;
    inline static const std::string LibraryName = "ws2_32";
    inline static const std::string FunctionName = "WSARecvFrom";

  private:
    SOCKET s_;
    GuestVirtualAddress lpBuffers_;
    uint32_t dwBufferCount_;
    GuestVirtualAddress lpNumberOfBytesRecvd_;
    GuestVirtualAddress lpFlags_;
    GuestVirtualAddress lpFrom_;
    GuestVirtualAddress lpFromLen_;
    GuestVirtualAddress lpOverlapped_;
    GuestVirtualAddress lpCompletionRoutine_;

    mutable std::unique_ptr<SOCKADDR> from_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt