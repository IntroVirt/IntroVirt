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
 * @brief Handler for ws2_32!ConnectEx
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex
 */
class ConnectEx : public WindowsFunctionCall {
  public:
    /* Input arguments */
    SOCKET s() const;
    void s(SOCKET s);

    GuestVirtualAddress pName() const;
    void pName(const GuestVirtualAddress& gva);

    int32_t namelen() const;
    void namelen(int32_t namelen);

    GuestVirtualAddress lpSendBuffer() const;
    void lpSendBuffer(const GuestVirtualAddress& gva);

    uint32_t dwSendDataLength() const;
    void dwSendDataLength(uint32_t namelen);

    GuestVirtualAddress lpdwBytesSent() const;
    void lpdwBytesSent(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpOverlapped() const;
    void lpOverlapped(const GuestVirtualAddress& gva);

    /* Helpers */
    const SOCKADDR* name() const;
    SOCKADDR* name();

    uint32_t dwBytesSent() const;
    void dwBytesSent(uint32_t dwBytesSent);

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    ConnectEx(Event& event);
    ~ConnectEx() override;

    static constexpr int ArgumentCount = 7;
    inline static const std::string LibraryName = "ws2_32";
    inline static const std::string FunctionName = "ConnectEx";

  private:
    SOCKET s_;
    GuestVirtualAddress pName_;
    int32_t namelen_;
    GuestVirtualAddress lpSendBuffer_;
    uint32_t dwSendDataLength_;
    GuestVirtualAddress lpdwBytesSent_;
    GuestVirtualAddress lpOverlapped_;

    mutable std::unique_ptr<SOCKADDR> name_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt