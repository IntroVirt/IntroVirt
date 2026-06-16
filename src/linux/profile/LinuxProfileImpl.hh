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

#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/linux/profile/LinuxProfile.hh>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace introvirt {
namespace linux_guest {

/**
 * @brief Thrown when a Linux profile cannot be loaded or is malformed.
 *
 * Context-free (no Vcpu/Domain), unlike GuestDetectionException — the
 * profile is loaded from the host filesystem before any guest is attached.
 */
class LinuxProfileException : public TraceableException {
  public:
    explicit LinuxProfileException(const std::string& msg) : TraceableException(msg) {}
};

/**
 * @brief Concrete LinuxProfile backed by a parsed `sectepe-linux-isf/1` JSON.
 *
 * The maps are populated once at construction from the JSON text; lookups
 * are then O(1). See tools/linux/generate_isf.py for the emitter and
 * include/introvirt/linux/profile/LinuxProfile.hh for the interface.
 */
class LinuxProfileImpl final : public LinuxProfile {
  public:
    std::optional<uint64_t> symbol(const std::string& name) const override;
    std::optional<int64_t> member_offset(const std::string& type,
                                         const std::string& member) const override;
    std::optional<uint64_t> type_size(const std::string& type) const override;
    const std::string& arch() const override;

    /**
     * @brief Parse a `sectepe-linux-isf/1` profile from its JSON text.
     * @throws LinuxProfileException on parse error or unexpected format.
     */
    explicit LinuxProfileImpl(const std::string& json_text);

  private:
    std::string arch_;
    std::unordered_map<std::string, uint64_t> symbols_;
    std::unordered_map<std::string, std::unordered_map<std::string, int64_t>> types_;
    std::unordered_map<std::string, uint64_t> sizes_;
};

} // namespace linux_guest
} // namespace introvirt
