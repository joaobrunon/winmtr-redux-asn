//*****************************************************************************
// FILE:            ICMPSocket.h
//
// DESCRIPTION:     Platform-agnostic ICMP socket interface
//                  Implementations: PosixICMP (Linux), WindowsICMP (Windows)
//
// LICENSE:         GPLv2
//*****************************************************************************

#pragma once

#include "Types.h"
#include <memory>
#include <variant>
#include <string>

// Simple expected-like wrapper for C++20 compatibility
// (Expected is C++23)
template<typename T, typename E>
using Expected = std::variant<T, E>;

template<typename T, typename E>
bool hasValue(const Expected<T, E>& exp) {
    return std::holds_alternative<T>(exp);
}

template<typename T, typename E>
const T& getValue(const Expected<T, E>& exp) {
    return std::get<T>(exp);
}

template<typename T, typename E>
const E& getError(const Expected<T, E>& exp) {
    return std::get<E>(exp);
}

namespace mtr {

//=============================================================================
// ICMP Echo Reply
//=============================================================================

/// Result of an ICMP echo request
struct EchoReply {
    NetworkAddress source;          ///< Source address of reply
    Milliseconds roundTripTime;     ///< Round-trip time
    uint8_t ttl;                    ///< TTL of reply packet
    ICMPError status;               ///< Status of the reply

    [[nodiscard]] bool isSuccess() const noexcept {
        return status == ICMPError::Success;
    }
};

//=============================================================================
// ICMP Socket Interface (Abstract)
//=============================================================================

/// Platform-independent ICMP socket interface
///
/// This is implemented by:
/// - PosixICMP (Linux/Unix - raw sockets)
/// - WindowsICMP (Windows - IcmpCreateFile API)
class ICMPSocket {
public:
    virtual ~ICMPSocket() = default;

    /// Send ICMP echo request
    ///
    /// @param destination Target address
    /// @param ttl Time-to-live value
    /// @param payloadSize Size of ICMP payload
    /// @param timeout Maximum wait time for reply
    /// @return Echo reply or error
    [[nodiscard]] virtual Expected<EchoReply, std::string>
    sendEcho(
        const NetworkAddress& destination,
        uint8_t ttl,
        uint16_t payloadSize,
        Milliseconds timeout,
        const TraceConfig& config
    ) = 0;

    /// Check if this socket supports IPv6
    [[nodiscard]] virtual bool supportsIPv6() const noexcept = 0;

    /// Get last platform-specific error message
    [[nodiscard]] virtual std::string getLastError() const = 0;
};

//=============================================================================
// Factory Function
//=============================================================================

/// Create platform-appropriate ICMP socket
///
/// Returns:
/// - PosixICMP on Linux/Unix
/// - WindowsICMP on Windows
[[nodiscard]] std::unique_ptr<ICMPSocket> createICMPSocket();

} // namespace mtr
