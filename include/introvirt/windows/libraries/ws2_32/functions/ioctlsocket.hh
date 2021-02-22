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
 * @brief Handler for ws2_32!ioctlsocket
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket
 */
class ioctlsocket : public WindowsFunctionCall {
  public:
    /* Input arguments */
    SOCKET s() const;
    void s(SOCKET s);

    int32_t cmd() const;
    void cmd(int32_t level);

    GuestVirtualAddress pArg() const;
    void pArg(const GuestVirtualAddress& gva);

    /* Helpers */
    uint32_t arg() const;
    void arg(uint32_t arg);

    int32_t result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    ioctlsocket(Event& event);
    ~ioctlsocket() override;

    static constexpr int ArgumentCount = 3;
    inline static const std::string LibraryName = "ws2_32";
    inline static const std::string FunctionName = "ioctlsocket";

  private:
    SOCKET s_;
    int32_t cmd_;
    GuestVirtualAddress pArg_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt