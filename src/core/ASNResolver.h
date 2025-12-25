//*****************************************************************************
// FILE:            ASNResolver.h
//
// DESCRIPTION:     ASN (Autonomous System Number) resolver
//                  Queries ASN information for IP addresses
//
// LICENSE:         GPLv2
//*****************************************************************************

#pragma once

#include "Types.h"
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>

namespace mtr {

//=============================================================================
// ASN Resolver
//=============================================================================

/// Resolves IP addresses to ASN information
///
/// Uses multiple methods:
/// 1. Local cache (for performance)
/// 2. Team Cymru DNS lookup (whois.cymru.com)
/// 3. Fallback to hardcoded well-known ASNs
class ASNResolver {
public:
    ASNResolver();
    ~ASNResolver() = default;

    /// Resolve ASN for an IP address (non-blocking)
    /// Returns cached result immediately if available
    [[nodiscard]] std::optional<ASNInfo> resolve(const NetworkAddress& address);

    /// Resolve ASN for IPv4 address
    [[nodiscard]] std::optional<ASNInfo> resolveIPv4(const IPv4Address& address);

    /// Clear cache
    void clearCache();

    /// Get cache statistics
    [[nodiscard]] size_t getCacheSize() const;

private:
    struct IPv6KeyHash {
        size_t operator()(const std::array<uint8_t, 16>& value) const noexcept {
            size_t hash = 0;
            for (auto byte : value) {
                hash = (hash * 131) + byte;
            }
            return hash;
        }
    };

    mutable std::mutex cacheMutex_;
    std::unordered_map<uint32_t, ASNInfo> cacheIPv4_;  ///< IPv4 cache
    std::unordered_map<std::array<uint8_t, 16>, ASNInfo, IPv6KeyHash> cacheIPv6_; ///< IPv6 cache

    /// Try to resolve using well-known ASN database (hardcoded)
    [[nodiscard]] std::optional<ASNInfo> resolveWellKnown(const IPv4Address& address);

    /// Try to resolve using DNS (Team Cymru)
    [[nodiscard]] std::optional<ASNInfo> resolveDNS(const IPv4Address& address);

    /// Try to resolve using DNS (Team Cymru) for IPv6
    [[nodiscard]] std::optional<ASNInfo> resolveDNS(const IPv6Address& address);

    /// Resolve ASN organization name (Team Cymru)
    [[nodiscard]] std::string resolveASNName(uint32_t asn);
};

} // namespace mtr
