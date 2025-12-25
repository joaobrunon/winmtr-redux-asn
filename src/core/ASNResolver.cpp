//*****************************************************************************
// FILE:            ASNResolver.cpp
//
// DESCRIPTION:     ASN resolver implementation with well-known ASN database
//
// LICENSE:         GPLv2
//*****************************************************************************

#include "ASNResolver.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <windns.h>
#else
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#endif

namespace mtr {

namespace {

bool asnDebugEnabled() {
    static const bool enabled = []() {
        const char* value = std::getenv("MTR_ASN_DEBUG");
        return value && value[0] != '\0';
    }();
    return enabled;
}

bool isPrivateIPv4(uint32_t addr) {
    const uint8_t a = (addr >> 24) & 0xFF;
    const uint8_t b = (addr >> 16) & 0xFF;
    if (a == 10) {
        return true;
    }
    if (a == 172 && b >= 16 && b <= 31) {
        return true;
    }
    if (a == 192 && b == 168) {
        return true;
    }
    if (a == 100 && b >= 64 && b <= 127) {
        return true;
    }
    if (a == 127) {
        return true;
    }
    if (a == 169 && b == 254) {
        return true;
    }
    if (a == 0) {
        return true;
    }
    if (a >= 224) {
        return true;
    }
    return false;
}

bool isPrivateIPv6(const IPv6Address& address) {
    const auto& b = address.bytes;
    const bool allZero = std::all_of(b.begin(), b.end(), [](uint8_t v) { return v == 0; });
    if (allZero) {
        return true;
    }
    if (b[0] == 0 && b[15] == 1 && std::all_of(b.begin() + 1, b.begin() + 15, [](uint8_t v) { return v == 0; })) {
        return true;
    }
    if ((b[0] & 0xFE) == 0xFC) {
        return true;
    }
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) {
        return true;
    }
    if ((b[0] & 0xF0) == 0xF0) {
        return true;
    }
    return false;
}

std::string trim(const std::string& value) {
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(start, end - start);
}

std::vector<std::string> splitCymruFields(const std::string& txt) {
    std::vector<std::string> parts;
    std::stringstream stream(txt);
    std::string token;
    while (std::getline(stream, token, '|')) {
        parts.push_back(trim(token));
    }
    return parts;
}

std::optional<ASNInfo> parseCymruResponse(const std::string& txt) {
    const auto parts = splitCymruFields(txt);

    if (parts.size() < 5 || parts[0] == "NA" || parts[0] == "0") {
        return std::nullopt;
    }

    ASNInfo info{};
    try {
        info.number = static_cast<uint32_t>(std::stoul(parts[0]));
    } catch (...) {
        return std::nullopt;
    }

    if (parts.size() >= 7) {
        info.prefix = parts[2];
        info.country = parts[3];
        info.registry = parts[4];
        info.allocated = parts[5];
        info.organization = parts[6];
    } else if (parts.size() >= 5) {
        info.prefix = parts[1];
        info.country = parts[2];
        info.registry = parts[3];
        info.allocated = parts[4];
    }
    return info.isValid() ? std::optional<ASNInfo>(info) : std::nullopt;
}

std::optional<std::string> parseCymruAsnNameResponse(const std::string& txt, uint32_t asn) {
    const auto parts = splitCymruFields(txt);
    if (parts.size() < 5) {
        return std::nullopt;
    }
    std::string asnField = parts[0];
    if (asnField.rfind("AS", 0) == 0) {
        asnField = asnField.substr(2);
    }
    try {
        const auto parsed = static_cast<uint32_t>(std::stoul(asnField));
        if (parsed != asn) {
            return std::nullopt;
        }
    } catch (...) {
        return std::nullopt;
    }
    if (parts[4].empty()) {
        return std::nullopt;
    }
    return parts[4];
}

std::string reverseIPv4(const IPv4Address& address) {
    const auto& b = address.bytes;
    return std::to_string(b[3]) + "." + std::to_string(b[2]) + "." +
           std::to_string(b[1]) + "." + std::to_string(b[0]);
}

std::string reverseIPv6(const IPv6Address& address) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(32 * 2);
    for (int i = 15; i >= 0; --i) {
        const uint8_t byte = address.bytes[static_cast<size_t>(i)];
        const char low = hex[byte & 0x0F];
        const char high = hex[(byte >> 4) & 0x0F];
        out.push_back(low);
        out.push_back('.');
        out.push_back(high);
        if (i > 0) {
            out.push_back('.');
        }
    }
    return out;
}

} // namespace

//=============================================================================
// Well-Known ASN Database (Hardcoded for offline operation)
//=============================================================================

struct ASNRange {
    uint32_t start;
    uint32_t end;
    uint32_t asn;
    const char* org;
    const char* country;
};

// Major public DNS, CDN, and cloud providers
static const ASNRange WELL_KNOWN_ASNS[] = {
    // Google Public DNS
    {0x08080808, 0x08080808, 15169, "Google LLC", "US"},           // 8.8.8.8
    {0x08080404, 0x08080404, 15169, "Google LLC", "US"},           // 8.8.4.4

    // Cloudflare DNS
    {0x01010101, 0x01010101, 13335, "Cloudflare Inc", "US"},       // 1.1.1.1
    {0x01000001, 0x01000001, 13335, "Cloudflare Inc", "US"},       // 1.0.0.1

    // Quad9 DNS
    {0x09090909, 0x09090909, 19281, "Quad9", "CH"},                // 9.9.9.9

    // OpenDNS
    {0xD043DEDE, 0xD043DEDE, 36692, "OpenDNS LLC", "US"},          // 208.67.222.222
    {0xD043DCDC, 0xD043DCDC, 36692, "OpenDNS LLC", "US"},          // 208.67.220.220

    // Google ranges (approximate)
    {0x08000000, 0x08FFFFFF, 15169, "Google LLC", "US"},           // 8.0.0.0/8
    {0x22000000, 0x22FFFFFF, 15169, "Google LLC", "US"},           // 34.0.0.0/8
    {0x23000000, 0x23FFFFFF, 15169, "Google LLC", "US"},           // 35.0.0.0/8

    // Amazon AWS
    {0x36000000, 0x36FFFFFF, 16509, "Amazon.com Inc", "US"},       // 54.0.0.0/8
    {0x34000000, 0x34FFFFFF, 16509, "Amazon.com Inc", "US"},       // 52.0.0.0/8

    // Cloudflare ranges
    {0x68000000, 0x68FFFFFF, 13335, "Cloudflare Inc", "US"},       // 104.0.0.0/8

    // Akamai
    {0x17000000, 0x17FFFFFF, 20940, "Akamai Technologies", "US"},  // 23.0.0.0/8

    // Level3
    {0x04000000, 0x04FFFFFF, 3356, "Level 3 (Lumen)", "US"},       // 4.0.0.0/8

    // Hurricane Electric
    {0x48000000, 0x48FFFFFF, 6939, "Hurricane Electric", "US"},    // 72.0.0.0/8

    // Comcast
    {0x44000000, 0x44FFFFFF, 7922, "Comcast Cable", "US"},         // 68.0.0.0/8

    // AT&T
    {0x0C000000, 0x0CFFFFFF, 7018, "AT&T Services", "US"},         // 12.0.0.0/8

    // Verizon
    {0x4B000000, 0x4BFFFFFF, 701, "Verizon Business", "US"},       // 75.0.0.0/8
};

constexpr size_t WELL_KNOWN_COUNT = sizeof(WELL_KNOWN_ASNS) / sizeof(WELL_KNOWN_ASNS[0]);

//=============================================================================
// Constructor
//=============================================================================

ASNResolver::ASNResolver() {
    // Pre-populate cache with well-known DNS servers
    cacheIPv4_[0x08080808] = {15169, "Google LLC", "US"};          // 8.8.8.8
    cacheIPv4_[0x08080404] = {15169, "Google LLC", "US"};          // 8.8.4.4
    cacheIPv4_[0x01010101] = {13335, "Cloudflare Inc", "US"};      // 1.1.1.1
    cacheIPv4_[0x01000001] = {13335, "Cloudflare Inc", "US"};      // 1.0.0.1
}

//=============================================================================
// Public Methods
//=============================================================================

std::optional<ASNInfo> ASNResolver::resolve(const NetworkAddress& address) {
    return std::visit([this](const auto& addr) -> std::optional<ASNInfo> {
        using T = std::decay_t<decltype(addr)>;
        if constexpr (std::is_same_v<T, IPv4Address>) {
            return resolveIPv4(addr);
        } else if constexpr (std::is_same_v<T, IPv6Address>) {
            if (isPrivateIPv6(addr)) {
                if (asnDebugEnabled()) {
                    std::cerr << "[ASN] Skip private address: " << addr.toString() << "\n";
                }
                return std::nullopt;
            }
            {
                std::lock_guard<std::mutex> lock(cacheMutex_);
                auto it = cacheIPv6_.find(addr.bytes);
                if (it != cacheIPv6_.end()) {
                    return it->second;
                }
            }

            auto result = resolveDNS(addr);
            if (result && result->organization.empty() && result->number != 0) {
                const std::string org = resolveASNName(result->number);
                if (!org.empty()) {
                    result->organization = org;
                }
            }

            if (result) {
                std::lock_guard<std::mutex> lock(cacheMutex_);
                cacheIPv6_[addr.bytes] = *result;
            }
            return result;
        } else {
            return std::nullopt;
        }
    }, address);
}

std::optional<ASNInfo> ASNResolver::resolveIPv4(const IPv4Address& address) {
    const uint32_t addrInt = address.toUint32();

    if (isPrivateIPv4(addrInt)) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] Skip private address: " << address.toString() << "\n";
        }
        return std::nullopt;
    }

    // Check cache first
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = cacheIPv4_.find(addrInt);
        if (it != cacheIPv4_.end()) {
            return it->second;
        }
    }

    // Try DNS (Team Cymru)
    auto result = resolveDNS(address);

    // Fallback to well-known database
    if (!result) {
        result = resolveWellKnown(address);
    }

    if (result && result->organization.empty() && result->number != 0) {
        const std::string org = resolveASNName(result->number);
        if (!org.empty()) {
            result->organization = org;
        }
    }

    // Cache the result (even if null, to avoid repeated lookups)
    if (result) {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        cacheIPv4_[addrInt] = *result;
    }

    return result;
}

void ASNResolver::clearCache() {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cacheIPv4_.clear();
    cacheIPv6_.clear();
}

size_t ASNResolver::getCacheSize() const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    return cacheIPv4_.size() + cacheIPv6_.size();
}

//=============================================================================
// Private Methods
//=============================================================================

std::optional<ASNInfo> ASNResolver::resolveWellKnown(const IPv4Address& address) {
    const uint32_t addrInt = address.toUint32();

    // Binary search in sorted ranges (for efficiency)
    for (size_t i = 0; i < WELL_KNOWN_COUNT; ++i) {
        const auto& range = WELL_KNOWN_ASNS[i];
        if (addrInt >= range.start && addrInt <= range.end) {
            ASNInfo info;
            info.number = range.asn;
            info.organization = range.org;
            info.country = range.country;
            return info;
        }
    }

    return std::nullopt;
}

std::optional<ASNInfo> ASNResolver::resolveDNS(const IPv4Address& address) {
    // Team Cymru DNS lookup:
    // Format: reverse-ip.origin.asn.cymru.com
    // Example: 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com
    // Returns: "ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
    const std::string query = reverseIPv4(address) + ".origin.asn.cymru.com";

#ifdef _WIN32
    PDNS_RECORDA record = nullptr;
    const DNS_STATUS status = DnsQuery_A(
        query.c_str(),
        DNS_TYPE_TEXT,
        DNS_QUERY_STANDARD,
        nullptr,
        &record,
        nullptr
    );

    if (status != ERROR_SUCCESS || !record) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS query failed: " << query << " status=" << status << "\n";
        }
        return std::nullopt;
    }

    std::optional<ASNInfo> result;
    for (auto* current = record; current; current = current->pNext) {
        if (current->wType != DNS_TYPE_TEXT) {
            continue;
        }

        const DNS_TXT_DATAA& txt = current->Data.TXT;
        if (txt.dwStringCount == 0 || !txt.pStringArray) {
            continue;
        }

        std::string joined;
        for (DWORD i = 0; i < txt.dwStringCount; ++i) {
            if (txt.pStringArray[i]) {
                joined += txt.pStringArray[i];
            }
        }

        result = parseCymruResponse(joined);
        if (result) {
            break;
        }
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS TXT invalid: " << query << " response=\"" << joined << "\"\n";
        }
    }

    DnsRecordListFree(record, DnsFreeRecordList);
    if (!result && asnDebugEnabled()) {
        std::cerr << "[ASN] DNS TXT no valid record: " << query << "\n";
    }
    return result;
#else
    unsigned char answer[NS_PACKETSZ];
    const int len = res_query(query.c_str(), ns_c_in, ns_t_txt, answer, sizeof(answer));
    if (len < 0) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS query failed: " << query << " h_errno=" << h_errno
                      << " (" << hstrerror(h_errno) << ")\n";
        }
        return std::nullopt;
    }

    ns_msg handle;
    if (ns_initparse(answer, len, &handle) < 0) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS parse failed: " << query << " h_errno=" << h_errno
                      << " (" << hstrerror(h_errno) << ")\n";
        }
        return std::nullopt;
    }

    const int count = ns_msg_count(handle, ns_s_an);
    if (count == 0 && asnDebugEnabled()) {
        std::cerr << "[ASN] DNS TXT empty answer: " << query << "\n";
    }
    for (int i = 0; i < count; ++i) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0) {
            continue;
        }
        if (ns_rr_type(rr) != ns_t_txt) {
            continue;
        }

        const unsigned char* rdata = ns_rr_rdata(rr);
        const int rdlen = ns_rr_rdlen(rr);
        if (rdlen < 1) {
            continue;
        }

        std::string joined;
        int offset = 0;
        while (offset < rdlen) {
            const int seglen = rdata[offset];
            if (seglen <= 0 || offset + 1 + seglen > rdlen) {
                break;
            }
            joined.append(reinterpret_cast<const char*>(rdata + offset + 1), seglen);
            offset += seglen + 1;
        }

        auto result = parseCymruResponse(joined);
        if (result) {
            return result;
        }
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS TXT invalid: " << query << " response=\"" << joined << "\"\n";
        }
    }

    if (asnDebugEnabled()) {
        std::cerr << "[ASN] DNS TXT no valid record: " << query << "\n";
    }
    return std::nullopt;
#endif
}

std::optional<ASNInfo> ASNResolver::resolveDNS(const IPv6Address& address) {
    const std::string query = reverseIPv6(address) + ".origin6.asn.cymru.com";

#ifdef _WIN32
    PDNS_RECORDA record = nullptr;
    const DNS_STATUS status = DnsQuery_A(
        query.c_str(),
        DNS_TYPE_TEXT,
        DNS_QUERY_STANDARD,
        nullptr,
        &record,
        nullptr
    );

    if (status != ERROR_SUCCESS || !record) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS query failed: " << query << " status=" << status << "\n";
        }
        return std::nullopt;
    }

    std::optional<ASNInfo> result;
    for (auto* current = record; current; current = current->pNext) {
        if (current->wType != DNS_TYPE_TEXT) {
            continue;
        }

        const DNS_TXT_DATAA& txt = current->Data.TXT;
        if (txt.dwStringCount == 0 || !txt.pStringArray) {
            continue;
        }

        std::string joined;
        for (DWORD i = 0; i < txt.dwStringCount; ++i) {
            if (txt.pStringArray[i]) {
                joined += txt.pStringArray[i];
            }
        }

        result = parseCymruResponse(joined);
        if (result) {
            break;
        }
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS TXT invalid: " << query << " response=\"" << joined << "\"\n";
        }
    }

    DnsRecordListFree(record, DnsFreeRecordList);
    if (!result && asnDebugEnabled()) {
        std::cerr << "[ASN] DNS TXT no valid record: " << query << "\n";
    }
    return result;
#else
    unsigned char answer[NS_PACKETSZ];
    const int len = res_query(query.c_str(), ns_c_in, ns_t_txt, answer, sizeof(answer));
    if (len < 0) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS query failed: " << query << " h_errno=" << h_errno
                      << " (" << hstrerror(h_errno) << ")\n";
        }
        return std::nullopt;
    }

    ns_msg handle;
    if (ns_initparse(answer, len, &handle) < 0) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS parse failed: " << query << " h_errno=" << h_errno
                      << " (" << hstrerror(h_errno) << ")\n";
        }
        return std::nullopt;
    }

    const int count = ns_msg_count(handle, ns_s_an);
    if (count == 0 && asnDebugEnabled()) {
        std::cerr << "[ASN] DNS TXT empty answer: " << query << "\n";
    }
    for (int i = 0; i < count; ++i) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0) {
            continue;
        }
        if (ns_rr_type(rr) != ns_t_txt) {
            continue;
        }

        const unsigned char* rdata = ns_rr_rdata(rr);
        const int rdlen = ns_rr_rdlen(rr);
        if (rdlen < 1) {
            continue;
        }

        std::string joined;
        int offset = 0;
        while (offset < rdlen) {
            const int seglen = rdata[offset];
            if (seglen <= 0 || offset + 1 + seglen > rdlen) {
                break;
            }
            joined.append(reinterpret_cast<const char*>(rdata + offset + 1), seglen);
            offset += seglen + 1;
        }

        auto result = parseCymruResponse(joined);
        if (result) {
            return result;
        }
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] DNS TXT invalid: " << query << " response=\"" << joined << "\"\n";
        }
    }

    if (asnDebugEnabled()) {
        std::cerr << "[ASN] DNS TXT no valid record: " << query << "\n";
    }
    return std::nullopt;
#endif
}

std::string ASNResolver::resolveASNName(uint32_t asn) {
    const std::string query = "AS" + std::to_string(asn) + ".asn.cymru.com";
#ifdef _WIN32
    PDNS_RECORDA record = nullptr;
    const DNS_STATUS status = DnsQuery_A(
        query.c_str(),
        DNS_TYPE_TEXT,
        DNS_QUERY_STANDARD,
        nullptr,
        &record,
        nullptr
    );

    if (status != ERROR_SUCCESS || !record) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] ASN name query failed: " << query << " status=" << status << "\n";
        }
        return {};
    }

    std::string org;
    for (auto* current = record; current; current = current->pNext) {
        if (current->wType != DNS_TYPE_TEXT) {
            continue;
        }

        const DNS_TXT_DATAA& txt = current->Data.TXT;
        if (txt.dwStringCount == 0 || !txt.pStringArray) {
            continue;
        }

        std::string joined;
        for (DWORD i = 0; i < txt.dwStringCount; ++i) {
            if (txt.pStringArray[i]) {
                joined += txt.pStringArray[i];
            }
        }

        auto parsed = parseCymruAsnNameResponse(joined, asn);
        if (parsed) {
            org = *parsed;
            break;
        }
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] ASN name TXT invalid: " << query << " response=\"" << joined << "\"\n";
        }
    }

    DnsRecordListFree(record, DnsFreeRecordList);
    if (org.empty() && asnDebugEnabled()) {
        std::cerr << "[ASN] ASN name TXT no valid record: " << query << "\n";
    }
    return org;
#else
    unsigned char answer[NS_PACKETSZ];
    const int len = res_query(query.c_str(), ns_c_in, ns_t_txt, answer, sizeof(answer));
    if (len < 0) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] ASN name query failed: " << query << " h_errno=" << h_errno
                      << " (" << hstrerror(h_errno) << ")\n";
        }
        return {};
    }

    ns_msg handle;
    if (ns_initparse(answer, len, &handle) < 0) {
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] ASN name parse failed: " << query << " h_errno=" << h_errno
                      << " (" << hstrerror(h_errno) << ")\n";
        }
        return {};
    }

    const int count = ns_msg_count(handle, ns_s_an);
    if (count == 0 && asnDebugEnabled()) {
        std::cerr << "[ASN] ASN name TXT empty answer: " << query << "\n";
    }
    for (int i = 0; i < count; ++i) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0) {
            continue;
        }
        if (ns_rr_type(rr) != ns_t_txt) {
            continue;
        }

        const unsigned char* rdata = ns_rr_rdata(rr);
        const int rdlen = ns_rr_rdlen(rr);
        if (rdlen < 1) {
            continue;
        }

        std::string joined;
        int offset = 0;
        while (offset < rdlen) {
            const int seglen = rdata[offset];
            if (seglen <= 0 || offset + 1 + seglen > rdlen) {
                break;
            }
            joined.append(reinterpret_cast<const char*>(rdata + offset + 1), seglen);
            offset += seglen + 1;
        }

        auto parsed = parseCymruAsnNameResponse(joined, asn);
        if (parsed) {
            return *parsed;
        }
        if (asnDebugEnabled()) {
            std::cerr << "[ASN] ASN name TXT invalid: " << query << " response=\"" << joined << "\"\n";
        }
    }

    if (asnDebugEnabled()) {
        std::cerr << "[ASN] ASN name TXT no valid record: " << query << "\n";
    }
    return {};
#endif
}

} // namespace mtr
