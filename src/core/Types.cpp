//*****************************************************************************
// FILE:            Types.cpp
//
// DESCRIPTION:     Implementation of core types
//
// LICENSE:         GPLv2
//*****************************************************************************

#include "Types.h"
#include <sstream>
#include <iomanip>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace mtr {

//=============================================================================
// IPv4Address Implementation
//=============================================================================

IPv4Address::IPv4Address(uint32_t addr) {
    bytes[0] = (addr >> 24) & 0xFF;
    bytes[1] = (addr >> 16) & 0xFF;
    bytes[2] = (addr >> 8) & 0xFF;
    bytes[3] = addr & 0xFF;
}

IPv4Address::IPv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
    : bytes{a, b, c, d} {}

std::string IPv4Address::toString() const {
    std::ostringstream oss;
    oss << static_cast<int>(bytes[0]) << '.'
        << static_cast<int>(bytes[1]) << '.'
        << static_cast<int>(bytes[2]) << '.'
        << static_cast<int>(bytes[3]);
    return oss.str();
}

uint32_t IPv4Address::toUint32() const noexcept {
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) |
           static_cast<uint32_t>(bytes[3]);
}

//=============================================================================
// IPv6Address Implementation
//=============================================================================

IPv6Address::IPv6Address(const std::array<uint8_t, 16>& addr)
    : bytes(addr) {}

std::string IPv6Address::toString() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) oss << ':';
        uint16_t word = (static_cast<uint16_t>(bytes[i]) << 8) | bytes[i + 1];
        oss << word;
    }

    // TODO: Implement zero compression (::) for compact notation
    return oss.str();
}

//=============================================================================
// Error Conversion
//=============================================================================

const char* toString(ICMPError error) noexcept {
    switch (error) {
        case ICMPError::Success:              return "Success";
        case ICMPError::Timeout:              return "Request timed out";
        case ICMPError::HostUnreachable:      return "Host unreachable";
        case ICMPError::NetworkUnreachable:   return "Network unreachable";
        case ICMPError::ProtocolUnreachable:  return "Protocol unreachable";
        case ICMPError::PortUnreachable:      return "Port unreachable";
        case ICMPError::FragmentationNeeded:  return "Fragmentation needed";
        case ICMPError::TTLExpired:           return "TTL expired in transit";
        case ICMPError::ParameterProblem:     return "Parameter problem";
        case ICMPError::Unknown:
        default:                              return "Unknown error";
    }
}

} // namespace mtr
