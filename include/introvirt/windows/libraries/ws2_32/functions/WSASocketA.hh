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
 * @brief Handler for ws2_32!WSASocketA
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
 */
class WSASocketA : public WindowsFunctionCall {
  public:
    /* Input arguments */
    int32_t af() const;
    void af(int32_t af);

    int32_t type() const;
    void type(int32_t type);

    int32_t protocol() const;
    void protocol(int32_t protocol);

    GuestVirtualAddress lpProtocolInfo() const;
    void lpProtocolInfo(const GuestVirtualAddress& gva);

    // TODO: This is supposed to be a GROUP type, have to figure out what that is
    int32_t g() const;
    void g(int32_t g);

    int32_t dwFlags() const;
    void dwFlags(int32_t dwFlags);

    /* Helpers */
    SOCKET result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    WSASocketA(Event& event);
    ~WSASocketA() override;

    static constexpr int ArgumentCount = 6;
    inline static const std::string LibraryName = "ws2_32";
    inline static const std::string FunctionName = "WSASocketA";

  private:
    int32_t af_;
    int32_t type_;
    int32_t protocol_;
    GuestVirtualAddress lpProtocolInfo_;
    int32_t g_;
    int32_t dwFlags_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt