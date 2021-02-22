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

#include <introvirt/windows/kernel/condrv/const/ConsoleCallServerGenericRequestCode.hh>

namespace introvirt {
namespace windows {
namespace condrv {

const static std::string GetConsoleCPStr("GetConsoleCP");
const static std::string GetConsoleModeStr("GetConsoleMode");
const static std::string SetConsoleModeStr("SetConsoleMode");
const static std::string ReadConsoleStr("ReadConsole");
const static std::string WriteConsoleStr("WriteConsole");
const static std::string SetTEBLangIDStr("SetTEBLangID");
const static std::string FillConsoleOutputStr("FillConsoleOutput");
const static std::string GetConsoleScreenBufferInfoExStr("GetConsoleScreenBufferInfoEx");
const static std::string GetConsoleTitleStr("GetConsoleTitle");
const static std::string SetConsoleTitleStr("SetConsoleTitle");
const static std::string SetConsoleCursorPositionStr("SetConsoleCursorPosition");
const static std::string SetConsoleTextAttributeStr("SetConsoleTextAttribute");
const static std::string GetConsoleWindowStr("GetConsoleWindow");
const static std::string UnknownStr("Unknown");

const std::string& to_string(ConsoleCallServerGenericRequestCode code) {
    switch (code) {
    case ConsoleCallServerGenericRequestCode::GetConsoleCP:
        return GetConsoleCPStr;
    case ConsoleCallServerGenericRequestCode::GetConsoleMode:
        return GetConsoleModeStr;
    case ConsoleCallServerGenericRequestCode::SetConsoleMode:
        return SetConsoleModeStr;
    case ConsoleCallServerGenericRequestCode::ReadConsole:
        return ReadConsoleStr;
    case ConsoleCallServerGenericRequestCode::WriteConsole:
        return WriteConsoleStr;
    case ConsoleCallServerGenericRequestCode::SetTEBLangID:
        return SetTEBLangIDStr;
    case ConsoleCallServerGenericRequestCode::FillConsoleOutput:
        return FillConsoleOutputStr;
    case ConsoleCallServerGenericRequestCode::GetConsoleScreenBufferInfoEx:
        return GetConsoleScreenBufferInfoExStr;
    case ConsoleCallServerGenericRequestCode::GetConsoleTitle:
        return GetConsoleTitleStr;
    case ConsoleCallServerGenericRequestCode::SetConsoleTitle:
        return SetConsoleTitleStr;
    case ConsoleCallServerGenericRequestCode::SetConsoleCursorPosition:
        return SetConsoleCursorPositionStr;
    case ConsoleCallServerGenericRequestCode::SetConsoleTextAttribute:
        return SetConsoleTextAttributeStr;
    case ConsoleCallServerGenericRequestCode::GetConsoleWindow:
        return GetConsoleWindowStr;
    case ConsoleCallServerGenericRequestCode::Unknown:
        return UnknownStr;
    }

    return UnknownStr;
}

} /* namespace condrv */
} /* namespace windows */
} /* namespace introvirt */
