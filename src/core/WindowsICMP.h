//*****************************************************************************
// FILE:            WindowsICMP.h
//
// DESCRIPTION:     Windows implementation of ICMP socket using Iphlpapi.dll
//
// LICENSE:         GPLv2
//*****************************************************************************

#pragma once

#include "ICMPSocket.h"

#ifdef _WIN32  // Only compile on Windows

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

namespace mtr {

//=============================================================================
// Windows ICMP Implementation
//=============================================================================

class WindowsICMP : public ICMPSocket {
public:
    WindowsICMP();
    ~WindowsICMP() override;

    // Disable copy, allow move
    WindowsICMP(const WindowsICMP&) = delete;
    WindowsICMP& operator=(const WindowsICMP&) = delete;
    WindowsICMP(WindowsICMP&&) noexcept;
    WindowsICMP& operator=(WindowsICMP&&) noexcept;

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
    HANDLE handleIPv4_{INVALID_HANDLE_VALUE};  ///< IPv4 ICMP handle
    HANDLE handleIPv6_{INVALID_HANDLE_VALUE};  ///< IPv6 ICMP handle
    HMODULE dllHandle_{nullptr};               ///< Iphlpapi.dll handle
    bool hasIPv6_{false};                      ///< IPv6 support flag
    std::string lastError_;                    ///< Last error message

    // Function pointers for dynamic loading
    using IcmpCreateFileFunc = HANDLE (WINAPI*)();
    using IcmpCloseHandleFunc = BOOL (WINAPI*)(HANDLE);
    using IcmpSendEcho2Func = DWORD (WINAPI*)(
        HANDLE, HANDLE, FARPROC, PVOID, IPAddr, LPVOID,
        WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD
    );
    using Icmp6CreateFileFunc = HANDLE (WINAPI*)();
    using Icmp6SendEcho2Func = DWORD (WINAPI*)(
        HANDLE, HANDLE, FARPROC, PVOID, sockaddr_in6*, sockaddr_in6*,
        LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD
    );

    IcmpCreateFileFunc icmpCreateFile_{nullptr};
    IcmpCloseHandleFunc icmpCloseHandle_{nullptr};
    IcmpSendEcho2Func icmpSendEcho2_{nullptr};
    Icmp6CreateFileFunc icmp6CreateFile_{nullptr};
    Icmp6SendEcho2Func icmp6SendEcho2_{nullptr};

    /// Send IPv4 echo request
    [[nodiscard]] Expected<EchoReply, std::string>
    sendEchoIPv4(const IPv4Address& dest, uint8_t ttl, uint16_t size, Milliseconds timeout);

    /// Send IPv6 echo request
    [[nodiscard]] Expected<EchoReply, std::string>
    sendEchoIPv6(const IPv6Address& dest, uint8_t ttl, uint16_t size, Milliseconds timeout);

    /// Convert Windows error to ICMP error
    [[nodiscard]] static ICMPError windowsErrorToICMPError(DWORD error) noexcept;

    /// Get Windows error message
    [[nodiscard]] static std::string windowsErrorMessage(DWORD error);
};

} // namespace mtr

#endif // _WIN32
