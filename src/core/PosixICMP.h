//*****************************************************************************
// FILE:            PosixICMP.h
//
// DESCRIPTION:     POSIX/Linux implementation of ICMP socket using raw sockets
//
// LICENSE:         GPLv2
//*****************************************************************************

#pragma once

#include "ICMPSocket.h"

#ifndef _WIN32  // Only compile on POSIX systems

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

namespace mtr {

//=============================================================================
// POSIX ICMP Implementation
//=============================================================================

class PosixICMP : public ICMPSocket {
public:
    PosixICMP();
    ~PosixICMP() override;

    // Disable copy, allow move
    PosixICMP(const PosixICMP&) = delete;
    PosixICMP& operator=(const PosixICMP&) = delete;
    PosixICMP(PosixICMP&&) noexcept;
    PosixICMP& operator=(PosixICMP&&) noexcept;

    [[nodiscard]] Expected<EchoReply, std::string>
    sendEcho(
        const NetworkAddress& destination,
        uint8_t ttl,
        uint16_t payloadSize,
        Milliseconds timeout
    ) override;

    [[nodiscard]] bool supportsIPv6() const noexcept override;
    [[nodiscard]] std::string getLastError() const override;

private:
    int socketIPv4_{-1};     ///< IPv4 raw socket file descriptor
    int socketIPv6_{-1};     ///< IPv6 raw socket file descriptor
    uint16_t sequenceNumber_{0}; ///< ICMP sequence number
    std::string lastError_;   ///< Last error message

    /// Send IPv4 echo request
    [[nodiscard]] Expected<EchoReply, std::string>
    sendEchoIPv4(const IPv4Address& dest, uint8_t ttl, uint16_t size, Milliseconds timeout);

    /// Send IPv6 echo request
    [[nodiscard]] Expected<EchoReply, std::string>
    sendEchoIPv6(const IPv6Address& dest, uint8_t ttl, uint16_t size, Milliseconds timeout);

    /// Calculate ICMP checksum
    [[nodiscard]] static uint16_t calculateChecksum(const void* data, size_t length) noexcept;

    /// Set socket timeout
    bool setSocketTimeout(int sock, Milliseconds timeout);

    /// Set socket TTL
    bool setSocketTTL(int sock, uint8_t ttl, bool isIPv6);

    /// Convert system error to string
    [[nodiscard]] std::string systemError() const;
};

} // namespace mtr

#endif // !_WIN32
