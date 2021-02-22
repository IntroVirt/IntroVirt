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

#include <cstdint>

namespace introvirt {
namespace windows {

class LanguageId {
  public:
    static const uint16_t Afrikaans = 0x436;
    static const uint16_t Albanian = 0x041c;
    static const uint16_t Arabic_Saudi_Arabia = 0x401;
    static const uint16_t Arabic_Iraq = 0x801;
    static const uint16_t Arabic_Egypt = 0x0c01;
    static const uint16_t Arabic_Libya = 0x1001;
    static const uint16_t Arabic_Algeria = 0x1401;
    static const uint16_t Arabic_Morocco = 0x1801;
    static const uint16_t Arabic_Tunisia = 0x1c01;
    static const uint16_t Arabic_Oman = 0x2001;
    static const uint16_t Arabic_Yemen = 0x2401;
    static const uint16_t Arabic_Syria = 0x2801;
    static const uint16_t Arabic_Jordan = 0x2c01;
    static const uint16_t Arabic_Lebanon = 0x3001;
    static const uint16_t Arabic_Kuwait = 0x3401;
    static const uint16_t Arabic_UAE = 0x3801;
    static const uint16_t Arabic_Bahrain = 0x3c01;
    static const uint16_t Arabic_Qatar = 0x4001;
    static const uint16_t Armenian = 0x042b;
    static const uint16_t Azeri_Latin = 0x042c;
    static const uint16_t Azeri_Cyrillic = 0x082c;
    static const uint16_t Basque = 0x042d;
    static const uint16_t Belarusian = 0x423;
    static const uint16_t Bulgarian = 0x402;
    static const uint16_t Catalan = 0x403;
    static const uint16_t Chinese_Taiwan = 0x404;
    static const uint16_t Chinese_PRC = 0x804;
    static const uint16_t Chinese_Hong_Kong = 0x0c04;
    static const uint16_t Chinese_Singapore = 0x1004;
    static const uint16_t Chinese_Macau = 0x1404;
    static const uint16_t Croatian = 0x041a;
    static const uint16_t Czech = 0x405;
    static const uint16_t Danish = 0x406;
    static const uint16_t Dutch_Standard = 0x413;
    static const uint16_t Dutch_Belgian = 0x813;
    static const uint16_t English_United_States = 0x409;
    static const uint16_t English_United_Kingdom = 0x809;
    static const uint16_t English_Australian = 0x0c09;
    static const uint16_t English_Canadian = 0x1009;
    static const uint16_t English_New_Zealand = 0x1409;
    static const uint16_t English_Irish = 0x1809;
    static const uint16_t English_South_Africa = 0x1c09;
    static const uint16_t English_Jamaica = 0x2009;
    static const uint16_t English_Caribbean = 0x2409;
    static const uint16_t English_Belize = 0x2809;
    static const uint16_t English_Trinidad = 0x2c09;
    static const uint16_t English_Zimbabwe = 0x3009;
    static const uint16_t English_Philippines = 0x3409;
    static const uint16_t Estonian = 0x425;
    static const uint16_t Faeroese = 0x438;
    static const uint16_t Farsi = 0x429;
    static const uint16_t Finnish = 0x040b;
    static const uint16_t French_Standard = 0x040c;
    static const uint16_t French_Belgian = 0x080c;
    static const uint16_t French_Canadian = 0x0c0c;
    static const uint16_t French_Swiss = 0x100c;
    static const uint16_t French_Luxembourg = 0x140c;
    static const uint16_t French_Monaco = 0x180c;
    static const uint16_t Georgian = 0x437;
    static const uint16_t German_Standard = 0x407;
    static const uint16_t German_Swiss = 0x807;
    static const uint16_t German_Austrian = 0x0c07;
    static const uint16_t German_Luxembourg = 0x1007;
    static const uint16_t German_Liechtenstein = 0x1407;
    static const uint16_t Greek = 0x408;
    static const uint16_t Hebrew = 0x040d;
    static const uint16_t Hindi = 0x439;
    static const uint16_t Hungarian = 0x040e;
    static const uint16_t Icelandic = 0x040f;
    static const uint16_t Indonesian = 0x421;
    static const uint16_t Italian_Standard = 0x410;
    static const uint16_t Italian_Swiss = 0x810;
    static const uint16_t Japanese = 0x411;
    static const uint16_t Kazakh = 0x043f;
    static const uint16_t Konkani = 0x457;
    static const uint16_t Korean = 0x412;
    static const uint16_t Latvian = 0x426;
    static const uint16_t Lithuanian = 0x427;
    static const uint16_t FYRO_Macedonian = 0x042f;
    static const uint16_t Malay_Malaysia = 0x043e;
    static const uint16_t Malay_Brunei_Darussalam = 0x083e;
    static const uint16_t Marathi = 0x044e;
    static const uint16_t Norwegian_Bokmal = 0x414;
    static const uint16_t Norwegian_Nynorsk = 0x814;
    static const uint16_t Polish = 0x415;
    static const uint16_t Portuguese_Brazilian = 0x416;
    static const uint16_t Portuguese_Standard = 0x816;
    static const uint16_t Romanian = 0x418;
    static const uint16_t Russian = 0x419;
    static const uint16_t Sanskrit = 0x044f;
    static const uint16_t Serbian_Latin = 0x081a;
    static const uint16_t Serbian_Cyrillic = 0x0c1a;
    static const uint16_t Slovak = 0x041b;
    static const uint16_t Slovenian = 0x424;
    static const uint16_t Spanish_Traditional_Sort = 0x040a;
    static const uint16_t Spanish_Mexican = 0x080a;
    static const uint16_t Spanish_Modern_Sort = 0x0c0a;
    static const uint16_t Spanish_Guatemala = 0x100a;
    static const uint16_t Spanish_Costa_Rica = 0x140a;
    static const uint16_t Spanish_Panama = 0x180a;
    static const uint16_t Spanish_Dominican_Republic = 0x1c0a;
    static const uint16_t Spanish_Venezuela = 0x200a;
    static const uint16_t Spanish_Colombia = 0x240a;
    static const uint16_t Spanish_Peru = 0x280a;
    static const uint16_t Spanish_Argentina = 0x2c0a;
    static const uint16_t Spanish_Ecuador = 0x300a;
    static const uint16_t Spanish_Chile = 0x340a;
    static const uint16_t Spanish_Uruguay = 0x380a;
    static const uint16_t Spanish_Paraguay = 0x3c0a;
    static const uint16_t Spanish_Bolivia = 0x400a;
    static const uint16_t Spanish_El_Salvador = 0x440a;
    static const uint16_t Spanish_Honduras = 0x480a;
    static const uint16_t Spanish_Nicaragua = 0x4c0a;
    static const uint16_t Spanish_Puerto_Rico = 0x500a;
    static const uint16_t Swahili = 0x441;
    static const uint16_t Swedish = 0x041d;
    static const uint16_t Swedish_Finland = 0x081d;
    static const uint16_t Tamil = 0x449;
    static const uint16_t Tatar = 0x444;
    static const uint16_t Thai = 0x041e;
    static const uint16_t Turkish = 0x041f;
    static const uint16_t Ukrainian = 0x422;
    static const uint16_t Urdu = 0x420;
    static const uint16_t Uzbek_Latin = 0x443;
    static const uint16_t Uzbek_Cyrillic = 0x843;
    static const uint16_t Vietnamese = 0x042a;
};

} // namespace windows
} // namespace introvirt
