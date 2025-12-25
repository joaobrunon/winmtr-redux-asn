//*****************************************************************************
// FILE:            mtr_cli.cpp
//
// DESCRIPTION:     Minimal CLI frontend for the MTR core library
//
// LICENSE:         GPLv2
//*****************************************************************************

#include "ASNResolver.h"
#include "MTREngine.h"
#include "Types.h"

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <csignal>
#include <cmath>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <ctime>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <random>

#if defined(__linux__)
#include <linux/errqueue.h>
#include <termios.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <conio.h>
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#endif

namespace {

struct Options {
    std::string host;
    std::vector<std::string> hostList;
    int count = 10;
    int firstTtl = 1;
    int maxHops = 30;
    int intervalMs = 1000;
    int timeoutMs = 5000;
    int graceTimeMs = 5000;
    int payloadSize = 64;
    int bitPattern = -1;
    int tos = -1;
    int port = -1;
    int localPort = -1;
    int mark = -1;
    int maxUnknown = 5;
    bool resolveDNS = true;
    bool resolveASN = true;
    bool showIps = false;
    bool reportMode = false;
    bool reportWide = false;
    bool splitMode = false;
    bool rawMode = false;
    bool csvMode = false;
    bool jsonMode = false;
    bool xmlMode = false;
    bool cursesMode = false;
    bool gtkMode = false;
    bool ipv4Only = false;
    bool ipv6Only = false;
    int ipinfoMode = 0;
    std::string order = "LRS N BAWV";
    std::string interfaceName;
    std::string bindAddress;
    std::string mode = "icmp";
};

std::atomic<bool> g_interrupted{false};
std::atomic<bool> g_asnEnabled{true};
std::atomic<int> g_ipinfoMode{0};
std::atomic<bool> g_inputStop{false};

void handleSignal(int) {
    g_interrupted.store(true);
}

void printUsage(const char* argv0) {
    std::cout
        << "Usage:\n"
        << " " << argv0 << " [options] hostname\n\n"
        << " -F, --filename FILE        read hostname(s) from a file\n"
        << " -4                         use IPv4 only\n"
        << " -6                         use IPv6 only\n"
        << " -u, --udp                  use UDP instead of ICMP echo\n"
        << " -T, --tcp                  use TCP instead of ICMP echo\n"
        << " -S, --sctp                 use SCTP instead of ICMP echo\n"
        << " -I, --interface NAME       use named network interface\n"
        << " -a, --address ADDRESS      bind the outgoing socket to ADDRESS\n"
        << " -f, --first-ttl NUMBER     set what TTL to start\n"
        << " -m, --max-ttl NUMBER       maximum number of hops\n"
        << " -U, --max-unknown NUMBER   maximum unknown host\n"
        << " -P, --port PORT            target port number for TCP, SCTP, or UDP\n"
        << " -L, --localport LOCALPORT  source port number for UDP\n"
        << " -s, --psize PACKETSIZE     set the packet size used for probing\n"
        << " -B, --bitpattern NUMBER    set bit pattern to use in payload\n"
        << " -i, --interval SECONDS     ICMP echo request interval\n"
        << " -G, --gracetime SECONDS    number of seconds to wait for responses\n"
        << " -Q, --tos NUMBER           type of service field in IP header\n"
        << " -e, --mpls                 display information from ICMP extensions\n"
        << " -Z, --timeout SECONDS      seconds to keep probe sockets open\n"
        << " -M, --mark MARK            mark each sent packet\n"
        << " -r, --report               output using report mode\n"
        << " -w, --report-wide          output wide report\n"
        << " -c, --report-cycles COUNT  set the number of pings sent\n"
        << " -j, --json                 output json\n"
        << " -x, --xml                  output xml\n"
        << " -C, --csv                  output comma separated values\n"
        << " -l, --raw                  output raw format\n"
        << " -p, --split                split output\n"
        << " -t, --curses               use curses terminal interface\n"
        << "     --displaymode MODE     select initial display mode\n"
        << " -g, --gtk                  use GTK+ xwindow interface\n"
        << " -n, --no-dns               do not resolve host names\n"
        << " -b, --show-ips             show IP numbers and host names\n"
        << " -o, --order FIELDS         select output fields\n"
        << " -y, --ipinfo NUMBER        select IP information in output\n"
        << " -z, --aslookup             display AS number\n"
        << " -h, --help                 display this help and exit\n"
        << " -v, --version              output version information and exit\n";
}

bool parseInt(const std::string& value, int& out) {
    if (value.empty()) {
        return false;
    }
    char* end = nullptr;
    long parsed = std::strtol(value.c_str(), &end, 10);
    if (!end || *end != '\0') {
        return false;
    }
    out = static_cast<int>(parsed);
    return true;
}

bool parseDouble(const std::string& value, double& out) {
    if (value.empty()) {
        return false;
    }
    char* end = nullptr;
    double parsed = std::strtod(value.c_str(), &end);
    if (!end || *end != '\0') {
        return false;
    }
    out = parsed;
    return true;
}

bool readOptionValue(const std::vector<std::string>& args, size_t& i, std::string& out) {
    const std::string& arg = args[i];
    const auto eq = arg.find('=');
    if (eq != std::string::npos) {
        out = arg.substr(eq + 1);
        return true;
    }
    if (i + 1 >= args.size()) {
        return false;
    }
    out = args[++i];
    return true;
}

std::vector<std::string> tokenizeOptions(const std::string& input) {
    std::vector<std::string> tokens;
    std::string current;
    bool inSingle = false;
    bool inDouble = false;
    bool escape = false;

    for (char ch : input) {
        if (escape) {
            current.push_back(ch);
            escape = false;
            continue;
        }
        if (ch == '\\') {
            escape = true;
            continue;
        }
        if (inSingle) {
            if (ch == '\'') {
                inSingle = false;
            } else {
                current.push_back(ch);
            }
            continue;
        }
        if (inDouble) {
            if (ch == '"') {
                inDouble = false;
            } else {
                current.push_back(ch);
            }
            continue;
        }
        if (ch == '\'') {
            inSingle = true;
            continue;
        }
        if (ch == '"') {
            inDouble = true;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
            continue;
        }
        current.push_back(ch);
    }

    if (!current.empty()) {
        tokens.push_back(current);
    }
    return tokens;
}

std::string trimString(const std::string& value) {
    size_t start = 0;
    while (start < value.size() &&
           std::isspace(static_cast<unsigned char>(value[start])) != 0) {
        ++start;
    }
    size_t end = value.size();
    while (end > start &&
           std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return value.substr(start, end - start);
}

bool loadHostsFromFile(const std::string& path, std::vector<std::string>& hosts) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    std::string line;
    while (std::getline(file, line)) {
        const std::string trimmed = trimString(line);
        if (!trimmed.empty() && trimmed[0] != '#') {
            hosts.push_back(trimmed);
        }
    }
    return true;
}

std::optional<mtr::NetworkAddress> parseLiteralAddress(const std::string& host) {
    in_addr ipv4{};
    if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
        mtr::IPv4Address addr{};
        std::memcpy(addr.bytes.data(), &ipv4.s_addr, addr.bytes.size());
        return mtr::NetworkAddress{addr};
    }

    in6_addr ipv6{};
    if (inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
        mtr::IPv6Address addr{};
        std::memcpy(addr.bytes.data(), &ipv6.s6_addr, addr.bytes.size());
        return mtr::NetworkAddress{addr};
    }

    return std::nullopt;
}

#if defined(_WIN32)
std::optional<sockaddr_in> parseBindIPv4(const std::string& address, int port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(std::max(0, port)));
    if (address.empty()) {
        addr.sin_addr.s_addr = INADDR_ANY;
        return addr;
    }
    in_addr ipv4{};
    if (inet_pton(AF_INET, address.c_str(), &ipv4) != 1) {
        return std::nullopt;
    }
    addr.sin_addr = ipv4;
    return addr;
}
#endif

std::optional<mtr::NetworkAddress> resolveHost(const std::string& host, int family) {
    if (auto literal = parseLiteralAddress(host)) {
        if (family == AF_UNSPEC) {
            return literal;
        }
        if (family == AF_INET && std::holds_alternative<mtr::IPv4Address>(*literal)) {
            return literal;
        }
        if (family == AF_INET6 && std::holds_alternative<mtr::IPv6Address>(*literal)) {
            return literal;
        }
        return std::nullopt;
    }

    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
        return std::nullopt;
    }

    std::optional<mtr::NetworkAddress> out;
    for (auto* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        if (ptr->ai_family == AF_INET) {
            auto* addr = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
            mtr::IPv4Address ipv4{};
            std::memcpy(ipv4.bytes.data(), &addr->sin_addr.s_addr, ipv4.bytes.size());
            out = mtr::NetworkAddress{ipv4};
            break;
        }
        if (ptr->ai_family == AF_INET6) {
            auto* addr = reinterpret_cast<sockaddr_in6*>(ptr->ai_addr);
            mtr::IPv6Address ipv6{};
            std::memcpy(ipv6.bytes.data(), &addr->sin6_addr.s6_addr, ipv6.bytes.size());
            out = mtr::NetworkAddress{ipv6};
            break;
        }
    }

    freeaddrinfo(result);
    return out;
}

std::string addressToString(const mtr::NetworkAddress& addr) {
    return std::visit([](const auto& a) { return a.toString(); }, addr);
}

bool addressEqualsIPv4(const mtr::NetworkAddress& addr, const mtr::IPv4Address& ipv4) {
    if (!std::holds_alternative<mtr::IPv4Address>(addr)) {
        return false;
    }
    return std::get<mtr::IPv4Address>(addr) == ipv4;
}

std::optional<mtr::IPv4Address> getIPv4Address(const mtr::NetworkAddress& addr) {
    if (!std::holds_alternative<mtr::IPv4Address>(addr)) {
        return std::nullopt;
    }
    return std::get<mtr::IPv4Address>(addr);
}

std::optional<mtr::IPv6Address> getIPv6Address(const mtr::NetworkAddress& addr) {
    if (!std::holds_alternative<mtr::IPv6Address>(addr)) {
        return std::nullopt;
    }
    return std::get<mtr::IPv6Address>(addr);
}

bool isInteractiveInput() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

void inputThreadFunc() {
#ifdef _WIN32
    while (!g_inputStop.load()) {
        const int ch = _getch();
        if (ch == EOF) {
            continue;
        }
        if (ch == 'z' || ch == 'Z') {
            g_asnEnabled.store(!g_asnEnabled.load());
        } else if (ch == 'y' || ch == 'Y') {
            const int next = (g_ipinfoMode.load() + 1) % 5;
            g_ipinfoMode.store(next);
        }
    }
#else
    termios original{};
    if (tcgetattr(STDIN_FILENO, &original) == 0) {
        termios raw = original;
        raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        while (!g_inputStop.load()) {
            char ch = 0;
            if (read(STDIN_FILENO, &ch, 1) <= 0) {
                continue;
            }
            if (ch == 'z' || ch == 'Z') {
                g_asnEnabled.store(!g_asnEnabled.load());
            } else if (ch == 'y' || ch == 'Y') {
                const int next = (g_ipinfoMode.load() + 1) % 5;
                g_ipinfoMode.store(next);
            }
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &original);
    }
#endif
}

constexpr auto kAsnRetryInterval = std::chrono::seconds(5);

std::optional<mtr::ASNInfo> resolveAsnWithRetry(
    mtr::ASNResolver& resolver,
    std::unordered_map<uint32_t, mtr::ASNInfo>& cache,
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point>& lastAttempt,
    std::unordered_map<std::string, mtr::ASNInfo>& cacheV6,
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>& lastAttemptV6,
    const mtr::NetworkAddress& address) {
    const auto ipv4 = getIPv4Address(address);
    if (!ipv4) {
        const auto ipv6 = getIPv6Address(address);
        if (!ipv6) {
            return std::nullopt;
        }
        const std::string key = ipv6->toString();
        if (key.empty()) {
            return std::nullopt;
        }

        auto cached6 = cacheV6.find(key);
        if (cached6 != cacheV6.end()) {
            return cached6->second;
        }

        const auto now6 = std::chrono::steady_clock::now();
        auto last6 = lastAttemptV6.find(key);
        if (last6 != lastAttemptV6.end() && now6 - last6->second < kAsnRetryInterval) {
            return std::nullopt;
        }

        lastAttemptV6[key] = now6;
        auto result6 = resolver.resolve(address);
        if (result6) {
            cacheV6[key] = *result6;
        }
        return result6;
    }

    const uint32_t key = ipv4->toUint32();
    if (key == 0) {
        return std::nullopt;
    }

    auto cached = cache.find(key);
    if (cached != cache.end()) {
        return cached->second;
    }

    const auto now = std::chrono::steady_clock::now();
    auto last = lastAttempt.find(key);
    if (last != lastAttempt.end() && now - last->second < kAsnRetryInterval) {
        return std::nullopt;
    }

    lastAttempt[key] = now;
    auto result = resolver.resolve(address);
    if (result) {
        cache[key] = *result;
    }
    return result;
}

std::string ipinfoLabel(int mode, bool asnEnabled) {
    if (!asnEnabled) {
        return "ASN";
    }
    switch (mode) {
        case 0:
            return "ASN";
        case 1:
            return "Prefix";
        case 2:
            return "CC";
        case 3:
            return "RIR";
        case 4:
            return "Data";
        default:
            return "ASN";
    }
}

std::string ipinfoValue(const mtr::HopStatistics& hop, int mode, bool asnEnabled) {
    if (!asnEnabled) {
        return "-";
    }
    if (!hop.asn || !hop.asn->isValid()) {
        return (mode == 0) ? "AS???" : "???";
    }
    const auto& asn = *hop.asn;
    switch (mode) {
        case 0: {
            const std::string num = "AS" + std::to_string(asn.number);
            if (asn.organization.empty()) {
                return num;
            }
            return num + " " + asn.organization;
        }
        case 1:
            return asn.prefix.empty() ? "???" : asn.prefix;
        case 2:
            return asn.country.empty() ? "???" : asn.country;
        case 3:
            return asn.registry.empty() ? "???" : asn.registry;
        case 4:
            return asn.allocated.empty() ? "???" : asn.allocated;
        default:
            return "???";
    }
}

std::string fitColumn(const std::string& value, size_t width);

std::string formatRttValue(double value) {
    if (value <= 0.0) {
        return "?";
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << value;
    return oss.str();
}

std::string formatLossPercent(double loss) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << loss << "%";
    return oss.str();
}

std::string formatCount(uint32_t value) {
    return std::to_string(value);
}

std::string escapeJson(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                out += ch;
        }
    }
    return out;
}

std::string escapeXml(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        switch (ch) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:
                out += ch;
        }
    }
    return out;
}

std::string resolveHostname(const mtr::NetworkAddress& addr,
                            std::unordered_map<std::string, std::string>& cache) {
    const std::string key = addressToString(addr);
    auto it = cache.find(key);
    if (it != cache.end()) {
        return it->second;
    }

    char host[NI_MAXHOST]{};
    int result = EAI_FAIL;
    if (const auto* ipv4 = std::get_if<mtr::IPv4Address>(&addr)) {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        std::memcpy(&sa.sin_addr.s_addr, ipv4->bytes.data(), ipv4->bytes.size());
        result = getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), host, sizeof(host), nullptr, 0, 0);
    } else if (const auto* ipv6 = std::get_if<mtr::IPv6Address>(&addr)) {
        sockaddr_in6 sa6{};
        sa6.sin6_family = AF_INET6;
        std::memcpy(&sa6.sin6_addr.s6_addr, ipv6->bytes.data(), ipv6->bytes.size());
        result = getnameinfo(reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6), host, sizeof(host), nullptr, 0, 0);
    }

    std::string resolved;
    if (result == 0) {
        resolved = host;
    }
    cache[key] = resolved;
    return resolved;
}

bool isValidOrderField(char code) {
    switch (code) {
        case 'L': case 'D': case 'R': case 'S':
        case 'N': case 'B': case 'A': case 'W':
        case 'V': case 'G': case 'J': case 'M':
        case 'X': case 'I':
            return true;
        default:
            return false;
    }
}

std::vector<char> parseOrderFields(const std::string& order) {
    std::vector<char> fields;
    for (char ch : order) {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            continue;
        }
        char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        if (isValidOrderField(upper)) {
            fields.push_back(upper);
        }
    }
    if (fields.empty()) {
        fields = {'L', 'R', 'S', 'N', 'B', 'A', 'W', 'V'};
    }
    return fields;
}

std::string formatOrderValue(char code, const mtr::HopStatistics& hop) {
    const uint32_t sent = hop.packetsSent;
    const uint32_t received = hop.packetsReceived;
    const uint32_t dropped = (sent >= received) ? (sent - received) : 0;
    const double loss = hop.packetLossPercent();

    switch (code) {
        case 'L':
            return formatLossPercent(loss);
        case 'D':
            return formatCount(dropped);
        case 'R':
            return formatCount(received);
        case 'S':
            return formatCount(sent);
        case 'N':
            return (received > 0) ? formatRttValue(static_cast<double>(hop.lastRTT.count())) : "?";
        case 'B':
            return (received > 0) ? formatRttValue(static_cast<double>(hop.bestRTT.count())) : "?";
        case 'A':
            return (received > 0) ? formatRttValue(static_cast<double>(hop.averageRTT().count())) : "?";
        case 'W':
            return (received > 0) ? formatRttValue(static_cast<double>(hop.worstRTT.count())) : "?";
        case 'V':
            return (received > 1) ? formatRttValue(hop.stdDevMs()) : "?";
        case 'G':
            return (received > 0) ? formatRttValue(hop.geoMeanMs()) : "?";
        case 'J':
            return (received > 1) ? formatRttValue(hop.currentJitterMs()) : "?";
        case 'M':
            return (received > 1) ? formatRttValue(hop.averageJitterMs()) : "?";
        case 'X':
            return (received > 1) ? formatRttValue(hop.worstJitterMs()) : "?";
        case 'I':
            return (received > 1) ? formatRttValue(hop.interarrivalJitterMs()) : "?";
        default:
            return "?";
    }
}

std::string orderLabel(char code) {
    switch (code) {
        case 'L': return "Loss%";
        case 'D': return "Drop";
        case 'R': return "Rcv";
        case 'S': return "Snt";
        case 'N': return "Last";
        case 'B': return "Best";
        case 'A': return "Avg";
        case 'W': return "Wrst";
        case 'V': return "StDev";
        case 'G': return "Gmean";
        case 'J': return "Jttr";
        case 'M': return "Javg";
        case 'X': return "Jmax";
        case 'I': return "Jint";
        default: return "?";
    }
}

std::string hopHostLabel(
    size_t hopIndex,
    const mtr::HopStatistics& hop,
    bool resolveDNS,
    bool showIps,
    std::unordered_map<std::string, std::string>& dnsCache) {
    const std::string addr = (hop.packetsReceived > 0) ? addressToString(hop.address) : "???";
    if (!resolveDNS || addr == "???" || !showIps) {
        std::string name = addr;
        if (resolveDNS && addr != "???") {
            const std::string resolved = resolveHostname(hop.address, dnsCache);
            if (!resolved.empty() && !showIps) {
                name = resolved;
            }
        }
        return std::to_string(hopIndex + 1) + ". " + name;
    }

    const std::string resolved = resolveDNS ? resolveHostname(hop.address, dnsCache) : "";
    if (resolved.empty() || resolved == addr) {
        return std::to_string(hopIndex + 1) + ". " + addr;
    }
    return std::to_string(hopIndex + 1) + ". " + resolved + " (" + addr + ")";
}

void printReport(
    const mtr::TraceResult& result,
    const Options& options,
    const std::vector<char>& fields,
    int ipinfoMode,
    bool asnEnabled) {
    std::unordered_map<std::string, std::string> dnsCache;
    std::vector<std::string> hostLabels;
    std::vector<std::vector<std::string>> values;

    const size_t startIndex = (options.firstTtl > 0) ? static_cast<size_t>(options.firstTtl - 1) : 0;
    for (size_t i = startIndex; i < result.hops.size(); ++i) {
        const auto& hop = result.hops[i];
        hostLabels.push_back(hopHostLabel(i, hop, options.resolveDNS, options.showIps, dnsCache));

        std::vector<std::string> row;
        row.reserve(fields.size());
        for (char field : fields) {
            row.push_back(formatOrderValue(field, hop));
        }
        if (options.resolveASN && asnEnabled) {
            row.push_back(ipinfoValue(hop, ipinfoMode, asnEnabled));
        }
        values.push_back(std::move(row));
    }

    size_t hostWidth = 4;
    for (const auto& label : hostLabels) {
        hostWidth = std::max(hostWidth, label.size());
    }
    if (!options.reportWide) {
        hostWidth = std::min<size_t>(hostWidth, 40);
    }

    std::vector<size_t> widths(fields.size());
    for (size_t i = 0; i < fields.size(); ++i) {
        widths[i] = orderLabel(fields[i]).size();
    }
    size_t ipinfoWidth = 0;
    if (options.resolveASN && asnEnabled) {
        ipinfoWidth = ipinfoLabel(ipinfoMode, asnEnabled).size();
    }

    for (const auto& row : values) {
        for (size_t i = 0; i < fields.size(); ++i) {
            widths[i] = std::max(widths[i], row[i].size());
        }
        if (options.resolveASN && asnEnabled && !row.empty()) {
            ipinfoWidth = std::max(ipinfoWidth, row.back().size());
        }
    }

    std::cout << "HOST: " << options.host << "\n";
    std::cout << std::left << std::setw(static_cast<int>(hostWidth)) << "Host" << " ";
    for (size_t i = 0; i < fields.size(); ++i) {
        std::cout << std::right << std::setw(static_cast<int>(widths[i])) << orderLabel(fields[i]) << " ";
    }
    if (options.resolveASN && asnEnabled) {
        std::cout << std::right << std::setw(static_cast<int>(ipinfoWidth)) << ipinfoLabel(ipinfoMode, asnEnabled) << " ";
    }
    std::cout << "\n";

    for (size_t rowIndex = 0; rowIndex < values.size(); ++rowIndex) {
        const std::string host = options.reportWide ? hostLabels[rowIndex] : fitColumn(hostLabels[rowIndex], hostWidth);
        std::cout << std::left << std::setw(static_cast<int>(hostWidth)) << host << " ";
        for (size_t i = 0; i < fields.size(); ++i) {
            std::cout << std::right << std::setw(static_cast<int>(widths[i])) << values[rowIndex][i] << " ";
        }
        if (options.resolveASN && asnEnabled) {
            std::cout << std::right << std::setw(static_cast<int>(ipinfoWidth)) << values[rowIndex].back() << " ";
        }
        std::cout << "\n";
    }
}

long long unixTimestamp() {
    return static_cast<long long>(std::time(nullptr));
}

void printJsonReport(
    const mtr::TraceResult& result,
    const Options& options,
    const std::vector<char>& fields,
    int ipinfoMode,
    bool asnEnabled) {
    std::unordered_map<std::string, std::string> dnsCache;

    std::cout << "{\n";
    std::cout << "  \"host\": \"" << escapeJson(options.host) << "\",\n";
    std::cout << "  \"timestamp\": " << unixTimestamp() << ",\n";
    std::cout << "  \"fields\": [";
    for (size_t i = 0; i < fields.size(); ++i) {
        std::cout << "\"" << fields[i] << "\"";
        if (i + 1 < fields.size()) {
            std::cout << ", ";
        }
    }
    std::cout << "],\n";
    std::cout << "  \"hops\": [\n";

    const size_t startIndex = (options.firstTtl > 0) ? static_cast<size_t>(options.firstTtl - 1) : 0;
    bool firstHop = true;
    for (size_t i = startIndex; i < result.hops.size(); ++i) {
        const auto& hop = result.hops[i];
        if (!firstHop) {
            std::cout << ",\n";
        }
        firstHop = false;
        const std::string hostLabel = hopHostLabel(i, hop, options.resolveDNS, options.showIps, dnsCache);
        const std::string addr = (hop.packetsReceived > 0) ? addressToString(hop.address) : "";

        std::cout << "    {\n";
        std::cout << "      \"count\": " << (i + 1) << ",\n";
        std::cout << "      \"host\": \"" << escapeJson(hostLabel) << "\",\n";
        std::cout << "      \"ip\": \"" << escapeJson(addr) << "\",\n";
        std::cout << "      \"values\": [";
        for (size_t f = 0; f < fields.size(); ++f) {
            std::cout << "\"" << formatOrderValue(fields[f], hop) << "\"";
            if (f + 1 < fields.size()) {
                std::cout << ", ";
            }
        }
        std::cout << "]";
        if (options.resolveASN && asnEnabled) {
            std::cout << ",\n      \"ipinfo\": \"" << escapeJson(ipinfoValue(hop, ipinfoMode, asnEnabled)) << "\"\n";
            std::cout << "    }";
        } else {
            std::cout << "\n    }";
        }
    }
    std::cout << "\n  ]\n";
    std::cout << "}\n";
}

void printXmlReport(
    const mtr::TraceResult& result,
    const Options& options,
    const std::vector<char>& fields,
    int ipinfoMode,
    bool asnEnabled) {
    std::unordered_map<std::string, std::string> dnsCache;

    std::cout << "<mtr host=\"" << escapeXml(options.host) << "\" timestamp=\"" << unixTimestamp() << "\">\n";
    std::cout << "  <fields>";
    for (char field : fields) {
        std::cout << field;
    }
    std::cout << "</fields>\n";

    const size_t startIndex = (options.firstTtl > 0) ? static_cast<size_t>(options.firstTtl - 1) : 0;
    for (size_t i = startIndex; i < result.hops.size(); ++i) {
        const auto& hop = result.hops[i];
        const std::string hostLabel = hopHostLabel(i, hop, options.resolveDNS, options.showIps, dnsCache);
        const std::string addr = (hop.packetsReceived > 0) ? addressToString(hop.address) : "";
        std::cout << "  <hop count=\"" << (i + 1) << "\" host=\"" << escapeXml(hostLabel)
                  << "\" ip=\"" << escapeXml(addr) << "\">\n";
        std::cout << "    <values>";
        for (char field : fields) {
            std::cout << "<value code=\"" << field << "\">" << formatOrderValue(field, hop) << "</value>";
        }
        std::cout << "</values>\n";
        if (options.resolveASN && asnEnabled) {
            std::cout << "    <ipinfo>" << escapeXml(ipinfoValue(hop, ipinfoMode, asnEnabled)) << "</ipinfo>\n";
        }
        std::cout << "  </hop>\n";
    }
    std::cout << "</mtr>\n";
}

void printCsvReport(
    const mtr::TraceResult& result,
    const Options& options) {
    std::unordered_map<std::string, std::string> dnsCache;
    const long long timestamp = unixTimestamp();
    const size_t startIndex = (options.firstTtl > 0) ? static_cast<size_t>(options.firstTtl - 1) : 0;

    for (size_t i = startIndex; i < result.hops.size(); ++i) {
        const auto& hop = result.hops[i];
        const std::string hostLabel = hopHostLabel(i, hop, options.resolveDNS, options.showIps, dnsCache);
        const double avg = (hop.packetsReceived > 0)
            ? static_cast<double>(hop.averageRTT().count())
            : 0.0;
    std::cout << "MTR.0.95;" << timestamp << ";OK;" << options.host << ";"
                  << (i + 1) << ";" << hostLabel << ";" << static_cast<long long>(avg) << "\n";
    }
}

void printRawReport(
    const mtr::TraceResult& result,
    const Options& options) {
    const size_t startIndex = (options.firstTtl > 0) ? static_cast<size_t>(options.firstTtl - 1) : 0;
    for (size_t i = startIndex; i < result.hops.size(); ++i) {
        const auto& hop = result.hops[i];
        const std::string addr = (hop.packetsReceived > 0) ? addressToString(hop.address) : "???";
        std::cout << "h " << i << " " << addr << "\n";
        if (hop.packetsReceived > 0) {
            std::cout << "p " << i << " " << hop.lastRTT.count() << "\n";
        }
    }
}

void printSplitReport(
    const mtr::TraceResult& result,
    const Options& options,
    int ipinfoMode,
    bool asnEnabled) {
    std::unordered_map<std::string, std::string> dnsCache;
    const size_t startIndex = (options.firstTtl > 0) ? static_cast<size_t>(options.firstTtl - 1) : 0;

    for (size_t i = startIndex; i < result.hops.size(); ++i) {
        const auto& hop = result.hops[i];
        const std::string hostLabel = hopHostLabel(i, hop, options.resolveDNS, options.showIps, dnsCache);
        std::cout
            << (i + 1) << " "
            << hostLabel << " "
            << formatLossPercent(hop.packetLossPercent()) << " "
            << hop.packetsSent << " "
            << hop.packetsReceived << " "
            << formatRttValue(static_cast<double>(hop.lastRTT.count())) << " "
            << formatRttValue(static_cast<double>(hop.averageRTT().count())) << " "
            << formatRttValue(static_cast<double>(hop.bestRTT.count())) << " "
            << formatRttValue(static_cast<double>(hop.worstRTT.count()));
        if (options.resolveASN && asnEnabled) {
            std::cout << " " << ipinfoValue(hop, ipinfoMode, asnEnabled);
        }
        std::cout << "\n";
    }
}

void printHeader(int round, int ipinfoMode, bool asnEnabled) {
    std::cout << "\nRound " << round << "\n";
    std::cout << "Hop  Loss%   Snt   Rcv  Last  Avg   Best  Wrst  Address            "
              << ipinfoLabel(ipinfoMode, asnEnabled) << "\n";
    std::cout << "---- ----- ----- ----- ----- ----- ----- ----- ------------------ ------------------------\n";
}

std::string fitColumn(const std::string& value, size_t width) {
    if (value.size() <= width) {
        return value;
    }
    if (width <= 3) {
        return value.substr(0, width);
    }
    return value.substr(0, width - 3) + "...";
}

std::string formatMilliseconds(const std::string& value) {
    if (value == "-") {
        return value;
    }
    return value + "ms";
}

void printHopLine(size_t index, const mtr::HopStatistics& hop, int ipinfoMode, bool asnEnabled) {
    const double loss = hop.packetLossPercent();
    const bool hasReply = hop.packetsReceived > 0;

    std::string last = hasReply ? std::to_string(hop.lastRTT.count()) : "-";
    std::string avg = hasReply ? std::to_string(hop.averageRTT().count()) : "-";
    std::string best = hasReply ? std::to_string(hop.bestRTT.count()) : "-";
    std::string worst = hasReply ? std::to_string(hop.worstRTT.count()) : "-";
    std::string addr = hasReply ? addressToString(hop.address) : "*";
    std::string asn = ipinfoValue(hop, ipinfoMode, asnEnabled);

    addr = fitColumn(addr, 18);
    asn = fitColumn(asn, 24);
    last = formatMilliseconds(last);
    avg = formatMilliseconds(avg);
    best = formatMilliseconds(best);
    worst = formatMilliseconds(worst);

    const double lossRounded = std::round(loss * 10.0) / 10.0;

    std::cout
        << std::setw(3) << (index + 1) << "  "
        << std::setw(5) << std::fixed << std::setprecision(1) << lossRounded << " "
        << std::setw(5) << hop.packetsSent << " "
        << std::setw(5) << hop.packetsReceived << " "
        << std::setw(5) << last << " "
        << std::setw(5) << avg << " "
        << std::setw(5) << best << " "
        << std::setw(5) << worst << " "
        << std::left << std::setw(18) << addr << " "
        << std::left << std::setw(24) << asn
        << std::right
        << "\n";
}

#if defined(__linux__)
bool runUdpTrace(const Options& options, const mtr::IPv4Address& destIPv4) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create UDP socket: " << std::strerror(errno) << "\n";
        return false;
    }

    int on = 1;
    if (setsockopt(sock, SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0) {
        std::cerr << "Failed to enable IP_RECVERR: " << std::strerror(errno) << "\n";
        close(sock);
        return false;
    }
    if (options.tos >= 0) {
        int tos = options.tos;
        setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    }

    sockaddr_in destAddr{};
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = htonl(destIPv4.toUint32());

    constexpr uint16_t basePort = 33434;
    std::vector<mtr::HopStatistics> hops(static_cast<size_t>(options.maxHops));
    mtr::ASNResolver asnResolver;
    std::unordered_map<uint32_t, mtr::ASNInfo> asnCache;
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> asnLastAttempt;
    std::unordered_map<std::string, mtr::ASNInfo> asnCacheV6;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> asnLastAttemptV6;
    int finalHop = -1;

    for (int round = 1; round <= options.count; ++round) {
        if (g_interrupted.load()) {
            break;
        }

        printHeader(round, g_ipinfoMode.load(), g_asnEnabled.load());
        const int hopLimit = (finalHop > 0) ? finalHop : options.maxHops;

        for (int ttl = options.firstTtl; ttl <= hopLimit; ++ttl) {
            if (g_interrupted.load()) {
                break;
            }

            auto& hop = hops[static_cast<size_t>(ttl - 1)];
            ++hop.packetsSent;

            int ttlVal = ttl;
            if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttlVal, sizeof(ttlVal)) != 0) {
                std::cerr << "Failed to set TTL: " << std::strerror(errno) << "\n";
                close(sock);
                return false;
            }

            destAddr.sin_port = htons(static_cast<uint16_t>(basePort + ttl));
            std::vector<uint8_t> payload(static_cast<size_t>(options.payloadSize), 0x42);
            if (options.bitPattern >= 0) {
                uint8_t pattern = static_cast<uint8_t>(options.bitPattern & 0xFF);
                if (options.bitPattern > 255) {
                    static thread_local std::mt19937 rng(std::random_device{}());
                    std::uniform_int_distribution<int> dist(0, 255);
                    pattern = static_cast<uint8_t>(dist(rng));
                }
                std::fill(payload.begin(), payload.end(), pattern);
            }

            auto start = std::chrono::steady_clock::now();
            ssize_t sent = sendto(
                sock,
                payload.data(),
                payload.size(),
                0,
                reinterpret_cast<sockaddr*>(&destAddr),
                sizeof(destAddr));

            if (sent < 0) {
                printHopLine(static_cast<size_t>(ttl - 1), hop, g_ipinfoMode.load(), g_asnEnabled.load());
                continue;
            }

            pollfd pfd{};
            pfd.fd = sock;
            pfd.events = POLLERR;
            int pollResult = poll(&pfd, 1, options.timeoutMs);

            if (pollResult <= 0 || !(pfd.revents & POLLERR)) {
                printHopLine(static_cast<size_t>(ttl - 1), hop, g_ipinfoMode.load(), g_asnEnabled.load());
                continue;
            }

            char controlBuf[128];
            char dataBuf[512];
            sockaddr_in fromAddr{};
            iovec iov{};
            iov.iov_base = dataBuf;
            iov.iov_len = sizeof(dataBuf);

            msghdr msg{};
            msg.msg_name = &fromAddr;
            msg.msg_namelen = sizeof(fromAddr);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = controlBuf;
            msg.msg_controllen = sizeof(controlBuf);

            ssize_t recvLen = recvmsg(sock, &msg, MSG_ERRQUEUE);
            if (recvLen < 0) {
                printHopLine(static_cast<size_t>(ttl - 1), hop, g_ipinfoMode.load(), g_asnEnabled.load());
                continue;
            }

            const sock_extended_err* serr = nullptr;
            for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
                    serr = reinterpret_cast<const sock_extended_err*>(CMSG_DATA(cmsg));
                    break;
                }
            }

            auto end = std::chrono::steady_clock::now();
            auto rtt = std::chrono::duration_cast<mtr::Milliseconds>(end - start);

            if (!serr || serr->ee_origin != SO_EE_ORIGIN_ICMP) {
                printHopLine(static_cast<size_t>(ttl - 1), hop, g_ipinfoMode.load(), g_asnEnabled.load());
                continue;
            }

            mtr::IPv4Address replyAddr(ntohl(fromAddr.sin_addr.s_addr));
            if (!addressEqualsIPv4(hop.address, replyAddr)) {
                hop.address = replyAddr;
                hop.hostname.reset();
                hop.asn.reset();
            }

            if (serr->ee_type == ICMP_TIME_EXCEEDED) {
                hop.updateRTT(rtt);
            } else if (serr->ee_type == ICMP_DEST_UNREACH && serr->ee_code == ICMP_PORT_UNREACH) {
                hop.updateRTT(rtt);
                if (finalHop <= 0) {
                    finalHop = ttl;
                }
            }

            if (options.resolveASN && g_asnEnabled.load() && !hop.asn) {
                auto asnInfo = resolveAsnWithRetry(
                    asnResolver,
                    asnCache,
                    asnLastAttempt,
                    asnCacheV6,
                    asnLastAttemptV6,
                    hop.address);
                if (asnInfo) {
                    hop.asn = *asnInfo;
                }
            }

            printHopLine(static_cast<size_t>(ttl - 1), hop, g_ipinfoMode.load(), g_asnEnabled.load());
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        if (g_interrupted.load()) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(options.intervalMs));
    }

    close(sock);
    return true;
}
#endif

#if defined(_WIN32)
bool parseIcmpTimeExceeded(
    const std::vector<uint8_t>& buffer,
    uint16_t expectedPort) {
    if (buffer.size() < 28) {
        return false;
    }
    const uint8_t* data = buffer.data();
    const uint8_t ipHeaderLen = static_cast<uint8_t>((data[0] & 0x0F) * 4);
    if (buffer.size() < ipHeaderLen + 8) {
        return false;
    }
    const uint8_t icmpType = data[ipHeaderLen];
    if (icmpType != 11 && icmpType != 3) {
        return false;
    }
    const uint8_t* innerIp = data + ipHeaderLen + 8;
    if (innerIp + 20 > data + buffer.size()) {
        return false;
    }
    const uint8_t innerHeaderLen = static_cast<uint8_t>((innerIp[0] & 0x0F) * 4);
    if (innerIp + innerHeaderLen + 8 > data + buffer.size()) {
        return false;
    }
    if (innerIp[9] != IPPROTO_TCP) {
        return false;
    }
    const uint8_t* tcpHeader = innerIp + innerHeaderLen;
    uint16_t destPortNet = 0;
    std::memcpy(&destPortNet, tcpHeader + 2, sizeof(destPortNet));
    const uint16_t destPort = ntohs(destPortNet);
    if (destPort != expectedPort) {
        return false;
    }
    return true;
}

bool runTcpTraceWindows(
    const Options& options,
    const mtr::IPv4Address& destIPv4,
    bool reportMode,
    std::optional<mtr::TraceResult>& outResult) {
    SOCKET icmpSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmpSock == INVALID_SOCKET) {
        std::cerr << "Failed to create ICMP socket: " << WSAGetLastError() << "\n";
        return false;
    }

    sockaddr_in destAddr{};
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = htonl(destIPv4.toUint32());

    const uint16_t destPort = static_cast<uint16_t>((options.port > 0) ? options.port : 80);
    destAddr.sin_port = htons(destPort);

    std::optional<sockaddr_in> localBind;
    if (!options.bindAddress.empty() || options.localPort >= 0) {
        localBind = parseBindIPv4(options.bindAddress, options.localPort);
        if (!localBind) {
            std::cerr << "Invalid bind address: " << options.bindAddress << "\n";
            closesocket(icmpSock);
            return false;
        }
    }

    std::vector<mtr::HopStatistics> hops(static_cast<size_t>(options.maxHops));
    mtr::ASNResolver asnResolver;
    std::unordered_map<uint32_t, mtr::ASNInfo> asnCache;
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> asnLastAttempt;
    std::unordered_map<std::string, mtr::ASNInfo> asnCacheV6;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> asnLastAttemptV6;
    int finalHop = -1;

    for (int round = 1; round <= options.count; ++round) {
        if (g_interrupted.load()) {
            break;
        }

        if (!reportMode) {
            printHeader(round, g_ipinfoMode.load(), g_asnEnabled.load());
        }
        const int hopLimit = (finalHop > 0) ? finalHop : options.maxHops;

        for (int ttl = options.firstTtl; ttl <= hopLimit; ++ttl) {
            if (g_interrupted.load()) {
                break;
            }

            auto& hop = hops[static_cast<size_t>(ttl - 1)];
            ++hop.packetsSent;

            SOCKET tcpSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (tcpSock == INVALID_SOCKET) {
                if (!reportMode) {
                    printHopLine(static_cast<size_t>(ttl - 1), hop, g_ipinfoMode.load(), g_asnEnabled.load());
                }
                continue;
            }

            if (options.tos >= 0) {
                int tos = options.tos;
                setsockopt(tcpSock, IPPROTO_IP, IP_TOS, reinterpret_cast<const char*>(&tos), sizeof(tos));
            }

            if (localBind) {
                if (bind(tcpSock, reinterpret_cast<sockaddr*>(&(*localBind)), sizeof(sockaddr_in)) != 0) {
                    closesocket(tcpSock);
                    if (!reportMode) {
                        printHopLine(static_cast<size_t>(ttl - 1), hop, g_ipinfoMode.load(), g_asnEnabled.load());
                    }
                    continue;
                }
            }

            int ttlVal = ttl;
            setsockopt(tcpSock, IPPROTO_IP, IP_TTL, reinterpret_cast<const char*>(&ttlVal), sizeof(ttlVal));

            u_long nonBlocking = 1;
            ioctlsocket(tcpSock, FIONBIO, &nonBlocking);

            const auto start = std::chrono::steady_clock::now();
            connect(tcpSock, reinterpret_cast<sockaddr*>(&destAddr), sizeof(destAddr));

            bool gotReply = false;
            mtr::NetworkAddress replyAddr{};
            mtr::Milliseconds rtt{0};

            while (true) {
                const auto now = std::chrono::steady_clock::now();
                const auto elapsed = std::chrono::duration_cast<mtr::Milliseconds>(now - start);
                if (elapsed.count() >= options.timeoutMs) {
                    break;
                }
                const int remainingMs = options.timeoutMs - static_cast<int>(elapsed.count());
                timeval tv{};
                tv.tv_sec = remainingMs / 1000;
                tv.tv_usec = (remainingMs % 1000) * 1000;

                fd_set readfds;
                fd_set writefds;
                FD_ZERO(&readfds);
                FD_ZERO(&writefds);
                FD_SET(icmpSock, &readfds);
                FD_SET(tcpSock, &writefds);

                const int ready = select(0, &readfds, &writefds, nullptr, &tv);
                if (ready <= 0) {
                    break;
                }

                if (FD_ISSET(icmpSock, &readfds)) {
                    std::vector<uint8_t> buffer(512);
                    sockaddr_in fromAddr{};
                    int fromLen = sizeof(fromAddr);
                    const int recvLen = recvfrom(
                        icmpSock,
                        reinterpret_cast<char*>(buffer.data()),
                        static_cast<int>(buffer.size()),
                        0,
                        reinterpret_cast<sockaddr*>(&fromAddr),
                        &fromLen);
                    if (recvLen > 0) {
                        buffer.resize(static_cast<size_t>(recvLen));
                        if (parseIcmpTimeExceeded(buffer, destPort)) {
                            const auto end = std::chrono::steady_clock::now();
                            rtt = std::chrono::duration_cast<mtr::Milliseconds>(end - start);
                            replyAddr = mtr::IPv4Address(ntohl(fromAddr.sin_addr.s_addr));
                            gotReply = true;
                            break;
                        }
                    }
                }

                if (FD_ISSET(tcpSock, &writefds)) {
                    int soError = 0;
                    int len = sizeof(soError);
                    getsockopt(tcpSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &len);
                    const auto end = std::chrono::steady_clock::now();
                    rtt = std::chrono::duration_cast<mtr::Milliseconds>(end - start);
                    if (soError == 0 || soError == WSAECONNREFUSED) {
                        replyAddr = destIPv4;
                        gotReply = true;
                        if (finalHop <= 0) {
                            finalHop = ttl;
                        }
                    }
                    break;
                }
            }

            closesocket(tcpSock);

            if (gotReply) {
                if (hop.address != replyAddr) {
                    hop.address = replyAddr;
                    hop.hostname.reset();
                    hop.asn.reset();
                }
                hop.updateRTT(rtt);
                if (options.resolveASN && g_asnEnabled.load() && !hop.asn) {
                    auto asnInfo = resolveAsnWithRetry(
                        asnResolver,
                        asnCache,
                        asnLastAttempt,
                        asnCacheV6,
                        asnLastAttemptV6,
                        hop.address);
                    if (asnInfo) {
                        hop.asn = *asnInfo;
                    }
                }
            }

            if (!reportMode) {
                printHopLine(static_cast<size_t>(ttl - 1), hop, g_ipinfoMode.load(), g_asnEnabled.load());
            }
        }

        if (g_interrupted.load()) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(options.intervalMs));
    }

    closesocket(icmpSock);

    if (reportMode) {
        mtr::TraceResult result{};
        result.config.maxHops = static_cast<uint16_t>(options.maxHops);
        result.config.firstHop = static_cast<uint16_t>(options.firstTtl);
        result.config.resolveDNS = options.resolveDNS;
        result.config.resolveASN = options.resolveASN;
        result.config.pingInterval = mtr::Milliseconds(options.intervalMs);
        result.config.timeout = mtr::Milliseconds(options.timeoutMs);
        result.hops = std::move(hops);
        outResult = std::move(result);
    }

    return true;
}
#endif

} // namespace

int main(int argc, char** argv) {
#ifndef _WIN32
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);
#endif

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "Failed to initialize Winsock.\n";
        return 1;
    }
#endif

    Options options{};
    std::vector<std::string> args;
    if (const char* envOptions = std::getenv("MTR_OPTIONS")) {
        auto tokens = tokenizeOptions(envOptions);
        args.insert(args.end(), tokens.begin(), tokens.end());
    }
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            std::cout << "mtr 0.95 (winmtr-redux)\n";
            return 0;
        }
        if (arg == "-4") {
            options.ipv4Only = true;
            continue;
        }
        if (arg == "-6") {
            options.ipv6Only = true;
            continue;
        }
        if (arg == "-u" || arg == "--udp") {
            options.mode = "udp";
            continue;
        }
        if (arg == "-T" || arg == "--tcp") {
            options.mode = "tcp";
            continue;
        }
        if (arg == "-S" || arg == "--sctp") {
            options.mode = "sctp";
            continue;
        }
        if (arg == "-r" || arg == "--report") {
            options.reportMode = true;
            continue;
        }
        if (arg == "-w" || arg == "--report-wide") {
            options.reportMode = true;
            options.reportWide = true;
            continue;
        }
        if (arg == "-n" || arg == "--no-dns") {
            options.resolveDNS = false;
            continue;
        }
        if (arg == "-b" || arg == "--show-ips") {
            options.showIps = true;
            continue;
        }
        if (arg == "-j" || arg == "--json") {
            options.jsonMode = true;
            continue;
        }
        if (arg == "-x" || arg == "--xml") {
            options.xmlMode = true;
            continue;
        }
        if (arg == "-C" || arg == "--csv") {
            options.csvMode = true;
            continue;
        }
        if (arg == "-l" || arg == "--raw") {
            options.rawMode = true;
            continue;
        }
        if (arg == "-p" || arg == "--split") {
            options.splitMode = true;
            continue;
        }
        if (arg == "-t" || arg == "--curses") {
            options.cursesMode = true;
            continue;
        }
        if (arg == "-g" || arg == "--gtk") {
            options.gtkMode = true;
            continue;
        }
        if (arg == "-z" || arg == "--aslookup") {
            options.ipinfoMode = 0;
            options.resolveASN = true;
            continue;
        }
        if (arg == "--no-asn") {
            options.resolveASN = false;
            continue;
        }
        if (arg == "-y" || arg == "--ipinfo") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed) || parsed < 0 || parsed > 4) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.ipinfoMode = parsed;
            options.resolveASN = true;
            continue;
        }
        if (arg == "-F" || arg == "--filename") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            if (!loadHostsFromFile(value, options.hostList)) {
                std::cerr << "Failed to read host file: " << value << "\n";
                return 1;
            }
            continue;
        }
        if (arg == "-I" || arg == "--interface") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.interfaceName = value;
            continue;
        }
        if (arg == "-a" || arg == "--address") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.bindAddress = value;
            continue;
        }
        if (arg == "-f" || arg == "--first-ttl") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.firstTtl = parsed;
            continue;
        }
        if (arg == "-m" || arg == "--max-ttl" || arg == "--max-hops") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.maxHops = parsed;
            continue;
        }
        if (arg == "-U" || arg == "--max-unknown") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.maxUnknown = parsed;
            continue;
        }
        if (arg == "-P" || arg == "--port") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed) || parsed < 0 || parsed > 65535) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.port = parsed;
            continue;
        }
        if (arg == "-L" || arg == "--localport") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed) || parsed < 0 || parsed > 65535) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.localPort = parsed;
            continue;
        }
        if (arg == "-s" || arg == "--psize" || arg == "--size") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.payloadSize = parsed;
            continue;
        }
        if (arg == "-B" || arg == "--bitpattern") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed) || parsed < 0) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.bitPattern = parsed;
            continue;
        }
        if (arg == "-i" || arg == "--interval") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            double parsed = 0.0;
            if (!parseDouble(value, parsed) || parsed <= 0.0) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.intervalMs = static_cast<int>(std::round(parsed * 1000.0));
            continue;
        }
        if (arg == "-G" || arg == "--gracetime") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            double parsed = 0.0;
            if (!parseDouble(value, parsed) || parsed < 0.0) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.graceTimeMs = static_cast<int>(std::round(parsed * 1000.0));
            continue;
        }
        if (arg == "-Q" || arg == "--tos") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed) || parsed < 0 || parsed > 255) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.tos = parsed;
            continue;
        }
        if (arg == "-e" || arg == "--mpls") {
            std::cerr << "Option not supported yet: " << arg << "\n";
            return 1;
        }
        if (arg == "-Z" || arg == "--timeout") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            double parsed = 0.0;
            if (!parseDouble(value, parsed) || parsed <= 0.0) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.timeoutMs = static_cast<int>(std::round(parsed * 1000.0));
            continue;
        }
        if (arg == "-M" || arg == "--mark") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.mark = parsed;
            continue;
        }
        if (arg == "-o" || arg == "--order") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.order = value;
            continue;
        }
        if (arg == "-c" || arg == "--report-cycles" || arg == "--count") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.count = parsed;
            continue;
        }
        if (arg == "--mode") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            options.mode = value;
            continue;
        }
        if (arg == "--displaymode") {
            std::string value;
            if (!readOptionValue(args, i, value)) {
                std::cerr << "Invalid option: " << arg << "\n";
                return 1;
            }
            continue;
        }

        if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        }

        if (options.host.empty()) {
            options.host = arg;
        } else {
            options.hostList.push_back(arg);
        }
    }

    if (options.ipv4Only && options.ipv6Only) {
        std::cerr << "Invalid options: -4 and -6 are mutually exclusive.\n";
        return 1;
    }

    if (!options.host.empty()) {
        options.hostList.insert(options.hostList.begin(), options.host);
    }
    if (options.hostList.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    if (options.jsonMode || options.xmlMode || options.csvMode ||
        options.rawMode || options.splitMode) {
        options.reportMode = true;
    }

    if (options.payloadSize < 0) {
        std::cerr << "Random packet size is not supported yet.\n";
        return 1;
    }
    if (options.count <= 0 || options.firstTtl <= 0 ||
        options.maxHops <= 0 || options.maxHops > 255 ||
        options.firstTtl > options.maxHops ||
        options.intervalMs <= 0 || options.timeoutMs <= 0 || options.payloadSize == 0) {
        std::cerr << "Invalid parameters.\n";
        return 1;
    }

    if (options.cursesMode || options.gtkMode) {
        std::cerr << "Requested UI mode not supported yet.\n";
        return 1;
    }

    std::vector<std::string> warnings;
    if (options.mode == "sctp") {
        warnings.emplace_back("SCTP probing not supported yet; using ICMP.");
        options.mode = "icmp";
    }
#if !defined(_WIN32)
    if (options.mode == "tcp") {
        warnings.emplace_back("TCP probing not supported yet; using ICMP.");
        options.mode = "icmp";
    }
#endif
    if (options.mode != "tcp" && options.port >= 0) {
        warnings.emplace_back("Port option is only supported for TCP on Windows; ignoring.");
    }
#if defined(_WIN32)
    if (options.mode != "tcp" && (!options.bindAddress.empty() || options.localPort >= 0)) {
        warnings.emplace_back("Bind/localport options are only supported for TCP on Windows; ignoring.");
    }
#else
    if (!options.bindAddress.empty() || options.localPort >= 0) {
        warnings.emplace_back("Bind/localport options are only supported for TCP on Windows; ignoring.");
    }
#endif
    if (options.mode == "tcp" && options.bitPattern >= 0) {
        warnings.emplace_back("Bitpattern is not supported for TCP; ignoring.");
    }
    if (!options.interfaceName.empty() || options.mark >= 0) {
        warnings.emplace_back("Interface/mark options are not supported yet; ignoring.");
    }
    if (options.maxUnknown != 5) {
        warnings.emplace_back("max-unknown is not supported yet; ignoring.");
    }

    for (const auto& warning : warnings) {
        std::cerr << "Warning: " << warning << "\n";
    }

    const int family = options.ipv4Only ? AF_INET : (options.ipv6Only ? AF_INET6 : AF_UNSPEC);
    const auto orderFields = parseOrderFields(options.order);

    bool hadError = false;
    for (size_t hostIndex = 0; hostIndex < options.hostList.size(); ++hostIndex) {
        options.host = options.hostList[hostIndex];
        auto destination = resolveHost(options.host, family);
        if (!destination) {
            std::cerr << "Failed to resolve host: " << options.host << "\n";
            hadError = true;
            continue;
        }

        if (options.mode == "udp") {
#if defined(__linux__)
            if (options.reportMode) {
                std::cerr << "Report mode for UDP is not supported yet.\n";
                return 1;
            }
            g_asnEnabled.store(options.resolveASN);
            g_ipinfoMode.store(options.ipinfoMode);
            g_inputStop.store(false);
            std::thread inputThread;
            if (isInteractiveInput()) {
                inputThread = std::thread(inputThreadFunc);
            }
            if (!std::holds_alternative<mtr::IPv4Address>(*destination)) {
                std::cerr << "UDP mode supports IPv4 only for now.\n";
                g_inputStop.store(true);
                if (inputThread.joinable()) {
                    inputThread.join();
                }
                return 1;
            }
            const auto& destIPv4 = std::get<mtr::IPv4Address>(*destination);
            if (!runUdpTrace(options, destIPv4)) {
                g_inputStop.store(true);
                if (inputThread.joinable()) {
                    inputThread.join();
                }
                return 1;
            }
            g_inputStop.store(true);
            if (inputThread.joinable()) {
                inputThread.join();
            }
#else
            std::cerr << "UDP mode supported only on Linux.\n";
            return 1;
#endif
        } else if (options.mode == "tcp") {
#if defined(_WIN32)
            if (!std::holds_alternative<mtr::IPv4Address>(*destination)) {
                std::cerr << "TCP mode supports IPv4 only for now.\n";
                return 1;
            }
            g_asnEnabled.store(options.resolveASN);
            g_ipinfoMode.store(options.ipinfoMode);
            g_inputStop.store(false);
            std::thread inputThread;
            if (!options.reportMode && isInteractiveInput()) {
                inputThread = std::thread(inputThreadFunc);
            }
            std::optional<mtr::TraceResult> tcpResult;
            const auto& destIPv4 = std::get<mtr::IPv4Address>(*destination);
            if (!runTcpTraceWindows(options, destIPv4, options.reportMode, tcpResult)) {
                g_inputStop.store(true);
                if (inputThread.joinable()) {
                    inputThread.join();
                }
                return 1;
            }
            g_inputStop.store(true);
            if (inputThread.joinable()) {
                inputThread.join();
            }
            if (options.reportMode && tcpResult) {
                if (options.jsonMode) {
                    printJsonReport(*tcpResult, options, orderFields, g_ipinfoMode.load(), g_asnEnabled.load());
                } else if (options.xmlMode) {
                    printXmlReport(*tcpResult, options, orderFields, g_ipinfoMode.load(), g_asnEnabled.load());
                } else if (options.csvMode) {
                    printCsvReport(*tcpResult, options);
                } else if (options.rawMode) {
                    printRawReport(*tcpResult, options);
                } else if (options.splitMode) {
                    printSplitReport(*tcpResult, options, g_ipinfoMode.load(), g_asnEnabled.load());
                } else {
                    printReport(*tcpResult, options, orderFields, g_ipinfoMode.load(), g_asnEnabled.load());
                }
            }
#else
            std::cerr << "TCP mode supported only on Windows.\n";
            return 1;
#endif
        } else {
            mtr::TraceConfig config{};
            config.destination = *destination;
            config.firstHop = static_cast<uint16_t>(options.firstTtl);
            config.maxHops = static_cast<uint16_t>(options.maxHops);
            config.pingSize = static_cast<uint16_t>(options.payloadSize);
            config.pingInterval = mtr::Milliseconds(options.intervalMs);
            config.timeout = mtr::Milliseconds(options.timeoutMs);
            config.resolveDNS = options.resolveDNS;
            config.resolveASN = options.resolveASN;
            config.tos = options.tos;
            config.bitPattern = options.bitPattern;

            std::atomic<int> rounds{0};
            std::mutex doneMutex;
            std::condition_variable doneCv;
            bool done = false;
            std::optional<mtr::TraceResult> finalResult;
            mtr::ASNResolver asnResolver;
            std::unordered_map<uint32_t, mtr::ASNInfo> asnCache;
            std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> asnLastAttempt;
            std::unordered_map<std::string, mtr::ASNInfo> asnCacheV6;
            std::unordered_map<std::string, std::chrono::steady_clock::time_point> asnLastAttemptV6;

            g_asnEnabled.store(options.resolveASN);
            g_ipinfoMode.store(options.ipinfoMode);
            g_inputStop.store(false);
            std::thread inputThread;
            if (!options.reportMode && isInteractiveInput()) {
                inputThread = std::thread(inputThreadFunc);
            }

            mtr::MTREngine engine([&](const mtr::TraceResult& result) {
                if (g_interrupted.load()) {
                    std::lock_guard<std::mutex> lock(doneMutex);
                    done = true;
                    doneCv.notify_one();
                    return;
                }

                const int current = ++rounds;
                if (!options.reportMode) {
                    printHeader(current, g_ipinfoMode.load(), g_asnEnabled.load());
                }
                for (size_t i = 0; i < result.hops.size(); ++i) {
                    auto displayHop = result.hops[i];
                    if (displayHop.asn) {
                        if (const auto ipv4 = getIPv4Address(displayHop.address)) {
                            asnCache[ipv4->toUint32()] = *displayHop.asn;
                        } else if (const auto ipv6 = getIPv6Address(displayHop.address)) {
                            asnCacheV6[ipv6->toString()] = *displayHop.asn;
                        }
                    } else if (options.resolveASN && g_asnEnabled.load()) {
                        auto asnInfo = resolveAsnWithRetry(
                            asnResolver,
                            asnCache,
                            asnLastAttempt,
                            asnCacheV6,
                            asnLastAttemptV6,
                            displayHop.address);
                        if (asnInfo) {
                            displayHop.asn = *asnInfo;
                        }
                    }
                    if (!options.reportMode) {
                        printHopLine(i, displayHop, g_ipinfoMode.load(), g_asnEnabled.load());
                    }
                }

                if (options.reportMode) {
                    finalResult = result;
                }

                if (current >= options.count) {
                    std::lock_guard<std::mutex> lock(doneMutex);
                    done = true;
                    doneCv.notify_one();
                }
            });

            if (!engine.start(config)) {
                std::cerr << "Failed to start traceroute.\n";
                return 1;
            }

            {
                std::unique_lock<std::mutex> lock(doneMutex);
                doneCv.wait(lock, [&] { return done || g_interrupted.load(); });
            }

            engine.stop();
            g_inputStop.store(true);
            if (inputThread.joinable()) {
                inputThread.join();
            }

            if (options.reportMode && finalResult) {
                if (options.jsonMode) {
                    printJsonReport(*finalResult, options, orderFields, g_ipinfoMode.load(), g_asnEnabled.load());
                } else if (options.xmlMode) {
                    printXmlReport(*finalResult, options, orderFields, g_ipinfoMode.load(), g_asnEnabled.load());
                } else if (options.csvMode) {
                    printCsvReport(*finalResult, options);
                } else if (options.rawMode) {
                    printRawReport(*finalResult, options);
                } else if (options.splitMode) {
                    printSplitReport(*finalResult, options, g_ipinfoMode.load(), g_asnEnabled.load());
                } else {
                    printReport(*finalResult, options, orderFields, g_ipinfoMode.load(), g_asnEnabled.load());
                }
            }
        }

        if (hostIndex + 1 < options.hostList.size()) {
            std::cout << "\n";
        }
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return hadError ? 1 : 0;
}
