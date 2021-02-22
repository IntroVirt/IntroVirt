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

#include <introvirt/windows/libraries/advapi32/functions/CryptAcquireContextA.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptAcquireContextW.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptCreateHash.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptDecrypt.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptEncrypt.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptExportKey.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptGenKey.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptGenRandom.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptGetKeyParam.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptHashData.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptSetKeyParam.hh>
#include <introvirt/windows/libraries/advapi32/types/types.hh>
