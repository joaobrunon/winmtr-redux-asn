//*****************************************************************************
// FILE:            Types.h
//
// DESCRIPTION:     Core types for MTR engine (C++20, cross-platform)
//
// LICENSE:         GPLv2
//*****************************************************************************

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include <variant>
#include <array>
#include <cstdint>
#include <cmath>
#include <algorithm>

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

namespace mtr {

//=============================================================================
// Type Aliases
//=============================================================================
using Milliseconds = std::chrono::milliseconds;
using TimePoint = std::chrono::steady_clock::time_point;
using HostName = std::string;

//=============================================================================
// Network Address Types
//=============================================================================

/// IPv4 address (4 bytes)
struct IPv4Address {
    std::array<uint8_t, 4> bytes{};

    IPv4Address() = default;
    explicit IPv4Address(uint32_t addr);
    IPv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

    [[nodiscard]] std::string toString() const;
    [[nodiscard]] uint32_t toUint32() const noexcept;

    auto operator<=>(const IPv4Address&) const = default;
};

/// IPv6 address (16 bytes)
struct IPv6Address {
    std::array<uint8_t, 16> bytes{};

    IPv6Address() = default;
    explicit IPv6Address(const std::array<uint8_t, 16>& addr);

    [[nodiscard]] std::string toString() const;

    auto operator<=>(const IPv6Address&) const = default;
};

/// Network address that can be IPv4 or IPv6
using NetworkAddress = std::variant<IPv4Address, IPv6Address>;

//=============================================================================
// Hop Statistics
//=============================================================================

/// ASN (Autonomous System Number) information
struct ASNInfo {
    uint32_t number{0};                     ///< ASN number (e.g., 15169)
    std::string organization;               ///< Organization name (e.g., "Google LLC")
    std::string country;                    ///< Country code (e.g., "US")
    std::string prefix;                     ///< BGP prefix (e.g., "8.8.8.0/24")
    std::string registry;                   ///< RIR (e.g., "arin")
    std::string allocated;                  ///< Allocation date (e.g., "2005-01-01")

    [[nodiscard]] bool isValid() const noexcept {
        return number != 0;
    }

    [[nodiscard]] std::string toString() const {
        if (!isValid()) return "Unknown";
        if (organization.empty()) {
            return "AS" + std::to_string(number);
        }
        return "AS" + std::to_string(number) + " " + organization;
    }
};

/// Statistics for a single hop in the route
struct HopStatistics {
    NetworkAddress address;                 ///< IP address of this hop
    std::optional<HostName> hostname;       ///< DNS hostname (if resolved)
    std::optional<ASNInfo> asn;             ///< ASN information (if resolved)

    uint32_t packetsSent{0};                ///< Total packets sent
    uint32_t packetsReceived{0};            ///< Total packets received

    Milliseconds lastRTT{0};                ///< Round-trip time of last packet
    Milliseconds bestRTT{Milliseconds::max()}; ///< Best (minimum) RTT
    Milliseconds worstRTT{0};               ///< Worst (maximum) RTT
    Milliseconds totalRTT{0};               ///< Sum of all RTTs (for average)
    double rttMeanMs{0.0};                  ///< Running mean RTT (ms)
    double rttM2{0.0};                      ///< Running variance accumulator
    double rttLogSum{0.0};                  ///< Sum of log RTTs (ms)
    uint32_t rttLogSamples{0};              ///< Samples used for geo mean
    double prevRTTMs{0.0};                  ///< Previous RTT (ms)
    bool hasPrevRTT{false};                 ///< Has previous RTT?
    double jitterCurrentMs{0.0};            ///< Current jitter (ms)
    double jitterMeanMs{0.0};               ///< Mean jitter (ms)
    double jitterMaxMs{0.0};                ///< Worst jitter (ms)
    uint32_t jitterSamples{0};              ///< Number of jitter samples

    /// Calculate packet loss percentage (0.0 - 100.0)
    [[nodiscard]] double packetLossPercent() const noexcept {
        if (packetsSent == 0) return 0.0;
        return 100.0 * (1.0 - static_cast<double>(packetsReceived) / packetsSent);
    }

    /// Calculate average RTT
    [[nodiscard]] Milliseconds averageRTT() const noexcept {
        if (packetsReceived == 0) return Milliseconds{0};
        return totalRTT / packetsReceived;
    }

    /// Calculate standard deviation (ms)
    [[nodiscard]] double stdDevMs() const noexcept {
        if (packetsReceived < 2) return 0.0;
        return std::sqrt(rttM2 / static_cast<double>(packetsReceived - 1));
    }

    /// Calculate geometric mean RTT (ms)
    [[nodiscard]] double geoMeanMs() const noexcept {
        if (rttLogSamples == 0) return 0.0;
        return std::exp(rttLogSum / static_cast<double>(rttLogSamples));
    }

    /// Get current jitter (ms)
    [[nodiscard]] double currentJitterMs() const noexcept {
        return jitterCurrentMs;
    }

    /// Get average jitter (ms)
    [[nodiscard]] double averageJitterMs() const noexcept {
        if (jitterSamples == 0) return 0.0;
        return jitterMeanMs;
    }

    /// Get worst jitter (ms)
    [[nodiscard]] double worstJitterMs() const noexcept {
        return jitterMaxMs;
    }

    /// Get interarrival jitter (ms) - approximated as average jitter
    [[nodiscard]] double interarrivalJitterMs() const noexcept {
        return averageJitterMs();
    }

    /// Update statistics with new RTT measurement
    void updateRTT(Milliseconds rtt) noexcept {
        const double rttMs = static_cast<double>(rtt.count());
        ++packetsReceived;
        lastRTT = rtt;
        totalRTT += rtt;
        bestRTT = std::min(bestRTT, rtt);
        worstRTT = std::max(worstRTT, rtt);

        const double delta = rttMs - rttMeanMs;
        rttMeanMs += delta / static_cast<double>(packetsReceived);
        const double delta2 = rttMs - rttMeanMs;
        rttM2 += delta * delta2;
        if (rttMs > 0.0) {
            rttLogSum += std::log(rttMs);
            ++rttLogSamples;
        }

        if (hasPrevRTT) {
            const double jitter = std::fabs(rttMs - prevRTTMs);
            jitterCurrentMs = jitter;
            ++jitterSamples;
            const double jitterDelta = jitter - jitterMeanMs;
            jitterMeanMs += jitterDelta / static_cast<double>(jitterSamples);
            jitterMaxMs = std::max(jitterMaxMs, jitter);
        }
        prevRTTMs = rttMs;
        hasPrevRTT = true;
    }
};

//=============================================================================
// Trace Configuration
//=============================================================================

/// Configuration for MTR trace
struct TraceConfig {
    NetworkAddress destination;             ///< Target to trace
    uint16_t firstHop{1};                   ///< Starting TTL
    uint16_t maxHops{30};                   ///< Maximum TTL
    uint16_t pingSize{64};                  ///< ICMP payload size (bytes)
    Milliseconds pingInterval{1000};        ///< Interval between pings
    Milliseconds timeout{5000};             ///< ICMP timeout
    bool resolveDNS{true};                  ///< Resolve hostnames?
    bool resolveASN{true};                  ///< Resolve ASN information?
    int tos{-1};                            ///< TOS/Traffic Class (-1 = default)
    int bitPattern{-1};                     ///< Payload pattern (-1 = default)
};

//=============================================================================
// Trace Result
//=============================================================================

/// Complete trace route result
struct TraceResult {
    TraceConfig config;                     ///< Configuration used
    std::vector<HopStatistics> hops;        ///< Statistics for each hop
    TimePoint startTime;                    ///< When trace started
    bool isRunning{false};                  ///< Is trace currently active?

    /// Get maximum number of hops discovered
    [[nodiscard]] size_t hopCount() const noexcept {
        return hops.size();
    }

    /// Get hop statistics by index (0-based)
    [[nodiscard]] const HopStatistics* getHop(size_t index) const noexcept {
        return (index < hops.size()) ? &hops[index] : nullptr;
    }
};

//=============================================================================
// Error Types
//=============================================================================

/// ICMP error codes
enum class ICMPError {
    Success,
    Timeout,
    HostUnreachable,
    NetworkUnreachable,
    ProtocolUnreachable,
    PortUnreachable,
    FragmentationNeeded,
    TTLExpired,
    ParameterProblem,
    Unknown
};

/// Convert ICMP error to string
[[nodiscard]] const char* toString(ICMPError error) noexcept;

} // namespace mtr
