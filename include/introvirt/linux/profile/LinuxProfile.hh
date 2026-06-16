/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace introvirt {
namespace linux_guest {

/**
 * @brief Linux kernel symbol + struct-layout provider.
 *
 * The Windows guest model resolves symbols and struct member offsets from
 * the PDB embedded in the kernel PE image. Linux has no in-image debug
 * info, so the Linux model instead loads an offline-generated profile (the
 * "SecTepe Linux ISF", produced by tools/linux/generate_isf.py from a
 * Volatility3 ISF).
 *
 * Symbol addresses in the profile are the *link-time* addresses; the live
 * KASLR slide is applied by ``LinuxKernel``, not here.
 */
class LinuxProfile {
  public:
    /**
     * @brief Link-time address of a kernel symbol (e.g. "init_task").
     * @return the address, or std::nullopt if the profile lacks it.
     */
    virtual std::optional<uint64_t> symbol(const std::string& name) const = 0;

    /**
     * @brief Byte offset of a struct member (e.g. "task_struct", "comm").
     * @return the offset, or std::nullopt if the type/member is absent.
     */
    virtual std::optional<int64_t> member_offset(const std::string& type,
                                                 const std::string& member) const = 0;

    /**
     * @brief Size in bytes of a struct, if recorded.
     */
    virtual std::optional<uint64_t> type_size(const std::string& type) const = 0;

    /**
     * @brief Target architecture string, e.g. "x86_64".
     */
    virtual const std::string& arch() const = 0;

    virtual ~LinuxProfile() = default;

    /**
     * @brief Load a SecTepe Linux ISF profile from a JSON file on the host.
     * @throws GuestDetectionException if the file is missing/unparseable.
     */
    static std::unique_ptr<LinuxProfile> load(const std::string& path);

    /**
     * @brief Locate + load a profile for a kernel release string.
     *
     * Searches the IntroVirt profile directory (e.g.
     * ~/.introvirt/profiles/linux-<release>-<arch>.json), mirroring the
     * Windows ``NtKernel::profile_path()`` convention.
     *
     * @return the profile, or nullptr if none is installed for that kernel.
     */
    static std::unique_ptr<LinuxProfile> load_for_release(const std::string& release,
                                                          const std::string& arch);
};

} // namespace linux_guest
} // namespace introvirt
