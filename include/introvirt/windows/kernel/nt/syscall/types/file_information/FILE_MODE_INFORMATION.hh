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

#include "FILE_INFORMATION.hh"

#include <introvirt/windows/kernel/nt/const/FileCreateOptions.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace nt {

/* FileCreateOptions has the same values, plus more */
/* Below are the actual valid options, though */
/*
enum FILE_MODE_FLAGS {
    FILE_WRITE_THROUGH = 0x00000002,
    FILE_SEQUENTIAL_ONLY = 0x00000004,
    FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008,
    FILE_SYNCHRONOUS_IO_ALERT = 0x00000010,
    FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020,
    FILE_DELETE_ON_CLOSE = 0x00001000
};
*/

class FILE_MODE_INFORMATION : public FILE_INFORMATION {
  public:
    virtual uint32_t Mode() const = 0;
    virtual void Mode(uint32_t value) = 0;

    /**
     * @brief Check if the FILE_WRITE_THROUGH flag is set
     *
     * @return true if FILE_WRITE_THROUGH is set
     * @return false if FILE_WRITE_THROUGH is not set
     */
    bool WriteThrough() const;

    /**
     * @brief Check if the FILE_SEQUENTIAL_ONLY flag is set
     *
     * @return true if FILE_SEQUENTIAL_ONLY is set
     * @return false if FILE_SEQUENTIAL_ONLY is not set
     */
    bool SequentialOnly() const;

    /**
     * @brief Check if the FILE_NO_INTERMEDIATE_BUFFERING flag is set
     *
     * @return true if FILE_NO_INTERMEDIATE_BUFFERING is set
     * @return false if FILE_NO_INTERMEDIATE_BUFFERING is not set
     */
    bool NoIntermediateBuffering() const;

    /**
     * @brief Check if the FILE_SYNCHRONOUS_IO_ALERT flag is set
     *
     * @return true if FILE_SYNCHRONOUS_IO_ALERT is set
     * @return false if FILE_SYNCHRONOUS_IO_ALERT is not set
     */
    bool SynchronousIoAlert() const;

    /**
     * @brief Check if the FILE_SYNCHRONOUS_IO_NONALERT flag is set
     *
     * @return true if FILE_SYNCHRONOUS_IO_NONALERT is set
     * @return false if FILE_SYNCHRONOUS_IO_NONALERT is not set
     */
    bool SynchronousIoNonAlert() const;

    /**
     * @brief Check if the FILE_DELETE_ON_CLOSE flag is set
     *
     * @return true if FILE_DELETE_ON_CLOSE is set
     * @return false if FILE_DELETE_ON_CLOSE is not set
     */
    bool DeleteOnClose() const;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
