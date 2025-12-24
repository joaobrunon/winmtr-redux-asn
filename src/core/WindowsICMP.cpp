//*****************************************************************************
// FILE:            WindowsICMP.cpp
//
// DESCRIPTION:     Windows ICMP implementation using IcmpCreateFile API
//
// LICENSE:         GPLv2
//*****************************************************************************

#ifdef _WIN32

#include "WindowsICMP.h"
#include <cstring>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace mtr {

//=============================================================================
// Constructor / Destructor
//=============================================================================

WindowsICMP::WindowsICMP() {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        lastError_ = "Failed to initialize Winsock";
        return;
    }

    // Load Iphlpapi.dll
    dllHandle_ = LoadLibraryA("Iphlpapi.dll");
    if (!dllHandle_) {
        lastError_ = "Failed to load Iphlpapi.dll";
        WSACleanup();
        return;
    }

    // Get IPv4 function pointers
    icmpCreateFile_ = reinterpret_cast<IcmpCreateFileFunc>(
        GetProcAddress(dllHandle_, "IcmpCreateFile")
    );
    icmpCloseHandle_ = reinterpret_cast<IcmpCloseHandleFunc>(
        GetProcAddress(dllHandle_, "IcmpCloseHandle")
    );
    icmpSendEcho2_ = reinterpret_cast<IcmpSendEcho2Func>(
        GetProcAddress(dllHandle_, "IcmpSendEcho2")
    );

    if (!icmpCreateFile_ || !icmpCloseHandle_ || !icmpSendEcho2_) {
        lastError_ = "Failed to get IPv4 ICMP functions";
        FreeLibrary(dllHandle_);
        dllHandle_ = nullptr;
        WSACleanup();
        return;
    }

    // Get IPv6 function pointers (optional)
    icmp6CreateFile_ = reinterpret_cast<Icmp6CreateFileFunc>(
        GetProcAddress(dllHandle_, "Icmp6CreateFile")
    );
    icmp6SendEcho2_ = reinterpret_cast<Icmp6SendEcho2Func>(
        GetProcAddress(dllHandle_, "Icmp6SendEcho2")
    );

    hasIPv6_ = (icmp6CreateFile_ != nullptr && icmp6SendEcho2_ != nullptr);

    // Create ICMP handles
    handleIPv4_ = icmpCreateFile_();
    if (handleIPv4_ == INVALID_HANDLE_VALUE) {
        lastError_ = "Failed to create IPv4 ICMP handle: " +
                     windowsErrorMessage(GetLastError());
        FreeLibrary(dllHandle_);
        dllHandle_ = nullptr;
        WSACleanup();
        return;
    }

    if (hasIPv6_) {
        handleIPv6_ = icmp6CreateFile_();
        if (handleIPv6_ == INVALID_HANDLE_VALUE) {
            // IPv6 failure is not critical
            hasIPv6_ = false;
        }
    }
}

WindowsICMP::~WindowsICMP() {
    if (handleIPv4_ != INVALID_HANDLE_VALUE && icmpCloseHandle_) {
        icmpCloseHandle_(handleIPv4_);
    }
    if (handleIPv6_ != INVALID_HANDLE_VALUE && icmpCloseHandle_) {
        icmpCloseHandle_(handleIPv6_);
    }
    if (dllHandle_) {
        FreeLibrary(dllHandle_);
    }
    WSACleanup();
}

WindowsICMP::WindowsICMP(WindowsICMP&& other) noexcept
    : handleIPv4_(other.handleIPv4_)
    , handleIPv6_(other.handleIPv6_)
    , dllHandle_(other.dllHandle_)
    , hasIPv6_(other.hasIPv6_)
    , lastError_(std::move(other.lastError_))
    , icmpCreateFile_(other.icmpCreateFile_)
    , icmpCloseHandle_(other.icmpCloseHandle_)
    , icmpSendEcho2_(other.icmpSendEcho2_)
    , icmp6CreateFile_(other.icmp6CreateFile_)
    , icmp6SendEcho2_(other.icmp6SendEcho2_)
{
    other.handleIPv4_ = INVALID_HANDLE_VALUE;
    other.handleIPv6_ = INVALID_HANDLE_VALUE;
    other.dllHandle_ = nullptr;
    other.hasIPv6_ = false;
}

WindowsICMP& WindowsICMP::operator=(WindowsICMP&& other) noexcept {
    if (this != &other) {
        if (handleIPv4_ != INVALID_HANDLE_VALUE && icmpCloseHandle_) {
            icmpCloseHandle_(handleIPv4_);
        }
        if (handleIPv6_ != INVALID_HANDLE_VALUE && icmpCloseHandle_) {
            icmpCloseHandle_(handleIPv6_);
        }
        if (dllHandle_) {
            FreeLibrary(dllHandle_);
        }

        handleIPv4_ = other.handleIPv4_;
        handleIPv6_ = other.handleIPv6_;
        dllHandle_ = other.dllHandle_;
        hasIPv6_ = other.hasIPv6_;
        lastError_ = std::move(other.lastError_);
        icmpCreateFile_ = other.icmpCreateFile_;
        icmpCloseHandle_ = other.icmpCloseHandle_;
        icmpSendEcho2_ = other.icmpSendEcho2_;
        icmp6CreateFile_ = other.icmp6CreateFile_;
        icmp6SendEcho2_ = other.icmp6SendEcho2_;

        other.handleIPv4_ = INVALID_HANDLE_VALUE;
        other.handleIPv6_ = INVALID_HANDLE_VALUE;
        other.dllHandle_ = nullptr;
        other.hasIPv6_ = false;
    }
    return *this;
}

//=============================================================================
// Public Methods
//=============================================================================

Expected<EchoReply, std::string>
WindowsICMP::sendEcho(
    const NetworkAddress& destination,
    uint8_t ttl,
    uint16_t payloadSize,
    Milliseconds timeout)
{
    return std::visit([&](const auto& addr) -> Expected<EchoReply, std::string> {
        using T = std::decay_t<decltype(addr)>;
        if constexpr (std::is_same_v<T, IPv4Address>) {
            return sendEchoIPv4(addr, ttl, payloadSize, timeout);
        } else {
            return sendEchoIPv6(addr, ttl, payloadSize, timeout);
        }
    }, destination);
}

bool WindowsICMP::supportsIPv6() const noexcept {
    return hasIPv6_;
}

std::string WindowsICMP::getLastError() const {
    return lastError_;
}

//=============================================================================
// IPv4 Implementation
//=============================================================================

Expected<EchoReply, std::string>
WindowsICMP::sendEchoIPv4(
    const IPv4Address& dest,
    uint8_t ttl,
    uint16_t size,
    Milliseconds timeout)
{
    if (handleIPv4_ == INVALID_HANDLE_VALUE) {
        return std::string("IPv4 handle not available");
    }

    // Prepare request data
    std::vector<uint8_t> sendData(size);
    for (size_t i = 0; i < size; ++i) {
        sendData[i] = static_cast<uint8_t>(i);
    }

    // Prepare IP options
    IP_OPTION_INFORMATION ipOptions{};
    ipOptions.Ttl = ttl;
    ipOptions.Flags = IP_FLAG_DF;  // Don't fragment

    // Prepare reply buffer
    const size_t replySize = sizeof(ICMP_ECHO_REPLY) + size + 8;
    std::vector<uint8_t> replyBuffer(replySize);

    // Send echo request
    const DWORD result = icmpSendEcho2_(
        handleIPv4_,
        nullptr,  // Event
        nullptr,  // APC routine
        nullptr,  // APC context
        htonl(dest.toUint32()),
        sendData.data(),
        static_cast<WORD>(sendData.size()),
        &ipOptions,
        replyBuffer.data(),
        static_cast<DWORD>(replyBuffer.size()),
        static_cast<DWORD>(timeout.count())
    );

    if (result == 0) {
        const DWORD error = GetLastError();
        lastError_ = windowsErrorMessage(error);

        EchoReply reply{};
        reply.status = windowsErrorToICMPError(error);
        return reply;
    }

    // Parse reply
    const auto* echoReply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer.data());

    EchoReply reply{};
    reply.source = IPv4Address(ntohl(echoReply->Address));
    reply.roundTripTime = Milliseconds(echoReply->RoundTripTime);
    reply.ttl = echoReply->Options.Ttl;
    reply.status = windowsErrorToICMPError(echoReply->Status);

    return reply;
}

//=============================================================================
// IPv6 Implementation
//=============================================================================

Expected<EchoReply, std::string>
WindowsICMP::sendEchoIPv6(
    const IPv6Address& dest,
    uint8_t ttl,
    uint16_t size,
    Milliseconds timeout)
{
    if (!hasIPv6_ || handleIPv6_ == INVALID_HANDLE_VALUE) {
        return std::string("IPv6 not supported");
    }

    // Prepare request data
    std::vector<uint8_t> sendData(size);
    for (size_t i = 0; i < size; ++i) {
        sendData[i] = static_cast<uint8_t>(i);
    }

    // Prepare IP options
    IP_OPTION_INFORMATION ipOptions{};
    ipOptions.Ttl = ttl;

    // Prepare source and destination addresses
    sockaddr_in6 sourceAddr{};
    sourceAddr.sin6_family = AF_INET6;
    sourceAddr.sin6_addr = in6addr_any;

    sockaddr_in6 destAddr{};
    destAddr.sin6_family = AF_INET6;
    std::memcpy(&destAddr.sin6_addr, dest.bytes.data(), 16);

    // Prepare reply buffer
    const size_t replySize = sizeof(ICMPV6_ECHO_REPLY) + size + 8;
    std::vector<uint8_t> replyBuffer(replySize);

    // Send echo request
    const DWORD result = icmp6SendEcho2_(
        handleIPv6_,
        nullptr,  // Event
        nullptr,  // APC routine
        nullptr,  // APC context
        &sourceAddr,
        &destAddr,
        sendData.data(),
        static_cast<WORD>(sendData.size()),
        &ipOptions,
        replyBuffer.data(),
        static_cast<DWORD>(replyBuffer.size()),
        static_cast<DWORD>(timeout.count())
    );

    if (result == 0) {
        const DWORD error = GetLastError();
        lastError_ = windowsErrorMessage(error);

        EchoReply reply{};
        reply.status = windowsErrorToICMPError(error);
        return reply;
    }

    // Parse reply
    const auto* echoReply = reinterpret_cast<const ICMPV6_ECHO_REPLY*>(replyBuffer.data());

    std::array<uint8_t, 16> addr6;
    std::memcpy(addr6.data(), &echoReply->Address.sin6_addr, 16);

    EchoReply reply{};
    reply.source = IPv6Address(addr6);
    reply.roundTripTime = Milliseconds(echoReply->RoundTripTime);
    reply.ttl = 64;  // IPv6 doesn't return TTL in reply
    reply.status = windowsErrorToICMPError(echoReply->Status);

    return reply;
}

//=============================================================================
// Helper Methods
//=============================================================================

ICMPError WindowsICMP::windowsErrorToICMPError(DWORD error) noexcept {
    switch (error) {
        case IP_SUCCESS:              return ICMPError::Success;
        case IP_REQ_TIMED_OUT:        return ICMPError::Timeout;
        case IP_DEST_HOST_UNREACHABLE: return ICMPError::HostUnreachable;
        case IP_DEST_NET_UNREACHABLE: return ICMPError::NetworkUnreachable;
        case IP_DEST_PROT_UNREACHABLE: return ICMPError::ProtocolUnreachable;
        case IP_DEST_PORT_UNREACHABLE: return ICMPError::PortUnreachable;
        case IP_PACKET_TOO_BIG:       return ICMPError::FragmentationNeeded;
        case IP_TTL_EXPIRED_TRANSIT:  return ICMPError::TTLExpired;
        case IP_PARAM_PROBLEM:        return ICMPError::ParameterProblem;
        default:                      return ICMPError::Unknown;
    }
}

std::string WindowsICMP::windowsErrorMessage(DWORD error) {
    char* msgBuf = nullptr;
    const DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&msgBuf),
        0,
        nullptr
    );

    std::string message;
    if (size > 0 && msgBuf) {
        message = msgBuf;
        LocalFree(msgBuf);
        // Remove trailing newline
        while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
            message.pop_back();
        }
    } else {
        message = "Error code: " + std::to_string(error);
    }

    return message;
}

} // namespace mtr

#endif // _WIN32
