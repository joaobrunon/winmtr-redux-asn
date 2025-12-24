//*****************************************************************************
// FILE:            ICMPSocket.cpp
//
// DESCRIPTION:     ICMP socket factory implementation
//
// LICENSE:         GPLv2
//*****************************************************************************

#include "ICMPSocket.h"

#ifdef _WIN32
#include "WindowsICMP.h"
#else
#include "PosixICMP.h"
#endif

namespace mtr {

std::unique_ptr<ICMPSocket> createICMPSocket() {
#ifdef _WIN32
    return std::make_unique<WindowsICMP>();
#else
    return std::make_unique<PosixICMP>();
#endif
}

} // namespace mtr
