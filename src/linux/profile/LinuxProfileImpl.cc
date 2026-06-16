/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxProfileImpl.hh"

#include <introvirt/util/json/json.hh>

#include <sstream>

namespace introvirt {
namespace linux_guest {

// Must match tools/linux/generate_isf.py PROFILE_FORMAT.
static constexpr const char* kExpectedFormat = "sectepe-linux-isf/1";

LinuxProfileImpl::LinuxProfileImpl(const std::string& json_text) {
    Json::CharReaderBuilder builder;
    Json::Value root;
    Json::String errs;
    std::istringstream ss(json_text);
    if (!Json::parseFromStream(builder, ss, &root, &errs))
        throw LinuxProfileException("LinuxProfile: JSON parse error: " + errs);

    const std::string format = root.get("format", "").asString();
    if (format != kExpectedFormat)
        throw LinuxProfileException("LinuxProfile: unexpected format '" + format +
                                    "' (expected " + kExpectedFormat + ")");

    arch_ = root["metadata"].get("arch", "x86_64").asString();

    const Json::Value& symbols = root["symbols"];
    for (const auto& name : symbols.getMemberNames())
        symbols_[name] = symbols[name].asUInt64();

    const Json::Value& types = root["types"];
    for (const auto& type : types.getMemberNames()) {
        const Json::Value& members = types[type];
        auto& member_map = types_[type];
        for (const auto& member : members.getMemberNames())
            member_map[member] = members[member].asInt64();
    }

    const Json::Value& sizes = root["sizes"];
    for (const auto& type : sizes.getMemberNames())
        sizes_[type] = sizes[type].asUInt64();

    if (symbols_.empty())
        throw LinuxProfileException("LinuxProfile: no symbols in profile");
}

std::optional<uint64_t> LinuxProfileImpl::symbol(const std::string& name) const {
    auto it = symbols_.find(name);
    if (it == symbols_.end())
        return std::nullopt;
    return it->second;
}

std::optional<int64_t> LinuxProfileImpl::member_offset(const std::string& type,
                                                       const std::string& member) const {
    auto type_it = types_.find(type);
    if (type_it == types_.end())
        return std::nullopt;
    auto member_it = type_it->second.find(member);
    if (member_it == type_it->second.end())
        return std::nullopt;
    return member_it->second;
}

std::optional<uint64_t> LinuxProfileImpl::type_size(const std::string& type) const {
    auto it = sizes_.find(type);
    if (it == sizes_.end())
        return std::nullopt;
    return it->second;
}

const std::string& LinuxProfileImpl::arch() const { return arch_; }

} // namespace linux_guest
} // namespace introvirt
