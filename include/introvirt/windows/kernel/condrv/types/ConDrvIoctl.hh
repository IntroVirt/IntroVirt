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

#include "../const/ConsoleRequestIoctl.hh"

#include <introvirt/windows/fwd.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace condrv {

/**
 * @brief A wrapper class for an ioctl to \Device\ConDrv\CurrentOut
 */
class ConDrvIoctl final {
  public:
    /**
     * @returns The code associated with this ioctl call
     */
    ConsoleRequestIoctl IoctlCode() const;

    /**
     * @returns The request data for a ConsoleCallServerGeneric IOCTL
     * @throws introvirt::traceable_error If the IOCTL is not ConsoleCallServerGeneric
     */
    ConsoleCallServerGenericRequest& GenericRequest() const;

    ConDrvIoctl(const WindowsGuest& guest, const nt::NtDeviceIoControlFile& ioctl);
    ~ConDrvIoctl();

  private:
    class IMPL;
    template <typename PtrType>
    class IMPL_SPEC;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace condrv */
} /* namespace windows */
} /* namespace introvirt */
