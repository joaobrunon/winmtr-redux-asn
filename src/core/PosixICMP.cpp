//*****************************************************************************
// FILE:            PosixICMP.cpp
//
// DESCRIPTION:     POSIX/Linux ICMP implementation using raw sockets
//
// LICENSE:         GPLv2
//*****************************************************************************

#ifndef _WIN32

#include "PosixICMP.h"
#include <algorithm>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <sys/select.h>
#include <arpa/inet.h>
#include <random>

namespace mtr {

//=============================================================================
// ICMP Header Structures
//=============================================================================

struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

//=============================================================================
// Constructor / Destructor
//=============================================================================

PosixICMP::PosixICMP() {
    // Create IPv4 raw socket
    socketIPv4_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketIPv4_ < 0) {
        lastError_ = "Failed to create IPv4 socket: " + systemError();
        lastError_ += " (Note: Raw sockets require root/administrator privileges)";
    }

    // Create IPv6 raw socket
    socketIPv6_ = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (socketIPv6_ < 0) {
        // IPv6 failure is not critical
        lastError_ = "IPv6 not available: " + systemError();
    }
}

PosixICMP::~PosixICMP() {
    if (socketIPv4_ >= 0) {
        close(socketIPv4_);
    }
    if (socketIPv6_ >= 0) {
        close(socketIPv6_);
    }
}

PosixICMP::PosixICMP(PosixICMP&& other) noexcept
    : socketIPv4_(other.socketIPv4_)
    , socketIPv6_(other.socketIPv6_)
    , sequenceNumber_(other.sequenceNumber_)
    , lastError_(std::move(other.lastError_))
{
    other.socketIPv4_ = -1;
    other.socketIPv6_ = -1;
}

PosixICMP& PosixICMP::operator=(PosixICMP&& other) noexcept {
    if (this != &other) {
        if (socketIPv4_ >= 0) close(socketIPv4_);
        if (socketIPv6_ >= 0) close(socketIPv6_);

        socketIPv4_ = other.socketIPv4_;
        socketIPv6_ = other.socketIPv6_;
        sequenceNumber_ = other.sequenceNumber_;
        lastError_ = std::move(other.lastError_);

        other.socketIPv4_ = -1;
        other.socketIPv6_ = -1;
    }
    return *this;
}

//=============================================================================
// Public Methods
//=============================================================================

Expected<EchoReply, std::string>
PosixICMP::sendEcho(
    const NetworkAddress& destination,
    uint8_t ttl,
    uint16_t payloadSize,
    Milliseconds timeout,
    const TraceConfig& config)
{
    return std::visit([&](const auto& addr) -> Expected<EchoReply, std::string> {
        using T = std::decay_t<decltype(addr)>;
        if constexpr (std::is_same_v<T, IPv4Address>) {
            return sendEchoIPv4(addr, ttl, payloadSize, timeout, config);
        } else {
            return sendEchoIPv6(addr, ttl, payloadSize, timeout, config);
        }
    }, destination);
}

bool PosixICMP::supportsIPv6() const noexcept {
    return socketIPv6_ >= 0;
}

std::string PosixICMP::getLastError() const {
    return lastError_;
}

//=============================================================================
// IPv4 Implementation
//=============================================================================

Expected<EchoReply, std::string>
PosixICMP::sendEchoIPv4(
    const IPv4Address& dest,
    uint8_t ttl,
    uint16_t size,
    Milliseconds timeout,
    const TraceConfig& config)
{
    if (socketIPv4_ < 0) {
        return std::string("IPv4 socket not available");
    }

    if (config.tos >= 0) {
        const int tos = config.tos;
        setsockopt(socketIPv4_, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    }

    // Set TTL
    if (!setSocketTTL(socketIPv4_, ttl, false)) {
        return std::string("Failed to set TTL: " + systemError());
    }

    // Set timeout
    if (!setSocketTimeout(socketIPv4_, timeout)) {
        return std::string("Failed to set timeout: " + systemError());
    }

    // Build ICMP packet
    std::vector<uint8_t> packet(sizeof(ICMPHeader) + size);
    auto* header = reinterpret_cast<ICMPHeader*>(packet.data());

    header->type = ICMP_ECHO;
    header->code = 0;
    header->checksum = 0;
    header->id = htons(getpid() & 0xFFFF);
    header->sequence = htons(++sequenceNumber_);

    // Fill payload with pattern
    if (config.bitPattern >= 0) {
        uint8_t pattern = static_cast<uint8_t>(config.bitPattern & 0xFF);
        if (config.bitPattern > 255) {
            static thread_local std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<int> dist(0, 255);
            pattern = static_cast<uint8_t>(dist(rng));
        }
        std::fill(packet.begin() + sizeof(ICMPHeader), packet.end(), pattern);
    } else {
        for (size_t i = 0; i < size; ++i) {
            packet[sizeof(ICMPHeader) + i] = static_cast<uint8_t>(i);
        }
    }

    // Calculate checksum
    header->checksum = calculateChecksum(packet.data(), packet.size());

    // Prepare destination address
    sockaddr_in destAddr{};
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = htonl(dest.toUint32());

    // Send packet
    auto startTime = std::chrono::steady_clock::now();

    ssize_t sent = sendto(
        socketIPv4_,
        packet.data(),
        packet.size(),
        0,
        reinterpret_cast<const sockaddr*>(&destAddr),
        sizeof(destAddr)
    );

    if (sent < 0) {
        return std::string("Send failed: " + systemError());
    }

    // Wait for reply
    std::vector<uint8_t> replyBuf(1500);  // MTU size
    sockaddr_in fromAddr{};
    socklen_t fromLen = sizeof(fromAddr);

    ssize_t received = recvfrom(
        socketIPv4_,
        replyBuf.data(),
        replyBuf.size(),
        0,
        reinterpret_cast<sockaddr*>(&fromAddr),
        &fromLen
    );

    auto endTime = std::chrono::steady_clock::now();
    auto rtt = std::chrono::duration_cast<Milliseconds>(endTime - startTime);

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            EchoReply reply{};
            reply.status = ICMPError::Timeout;
            return reply;
        }
        return std::string("Receive failed: " + systemError());
    }

    // Parse reply
    if (received < static_cast<ssize_t>(sizeof(iphdr) + sizeof(ICMPHeader))) {
        return std::string("Reply too short");
    }

    auto* ipHdr = reinterpret_cast<const iphdr*>(replyBuf.data());
    size_t ipHdrLen = ipHdr->ihl * 4;
    auto* icmpHdr = reinterpret_cast<const ICMPHeader*>(replyBuf.data() + ipHdrLen);

    // Build reply
    EchoReply reply{};
    reply.source = IPv4Address(ntohl(fromAddr.sin_addr.s_addr));
    reply.roundTripTime = rtt;
    reply.ttl = ipHdr->ttl;

    // Determine status based on ICMP type
    if (icmpHdr->type == ICMP_ECHOREPLY) {
        reply.status = ICMPError::Success;
    } else if (icmpHdr->type == ICMP_TIME_EXCEEDED) {
        reply.status = ICMPError::TTLExpired;
    } else if (icmpHdr->type == ICMP_DEST_UNREACH) {
        reply.status = ICMPError::HostUnreachable;
    } else {
        reply.status = ICMPError::Unknown;
    }

    return reply;
}

//=============================================================================
// IPv6 Implementation
//=============================================================================

Expected<EchoReply, std::string>
PosixICMP::sendEchoIPv6(
    const IPv6Address& dest,
    uint8_t ttl,
    uint16_t size,
    Milliseconds timeout,
    const TraceConfig& config)
{
    if (socketIPv6_ < 0) {
        return std::string("IPv6 socket not available");
    }

    (void)dest;
    (void)ttl;
    (void)size;
    (void)timeout;
    (void)config;

    // Similar to IPv4 but using ICMPv6
    // For brevity, returning not implemented error
    // Full implementation would be similar to IPv4
    return std::string("IPv6 not yet implemented");
}

//=============================================================================
// Helper Methods
//=============================================================================

uint16_t PosixICMP::calculateChecksum(const void* data, size_t length) noexcept {
    const auto* buf = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;

    for (size_t i = 0; i < length / 2; ++i) {
        sum += buf[i];
    }

    // Add odd byte if present
    if (length % 2) {
        sum += static_cast<const uint8_t*>(data)[length - 1];
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

bool PosixICMP::setSocketTimeout(int sock, Milliseconds timeout) {
    timeval tv{};
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;

    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}

bool PosixICMP::setSocketTTL(int sock, uint8_t ttl, bool isIPv6) {
    if (isIPv6) {
        int ttlInt = ttl;
        return setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttlInt, sizeof(ttlInt)) == 0;
    } else {
        int ttlInt = ttl;
        return setsockopt(sock, IPPROTO_IP, IP_TTL, &ttlInt, sizeof(ttlInt)) == 0;
    }
}

std::string PosixICMP::systemError() const {
    return std::string(strerror(errno));
}

} // namespace mtr

#endif // !_WIN32
