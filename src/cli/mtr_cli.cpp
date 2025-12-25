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
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cmath>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

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
    int count = 5;
    int maxHops = 30;
    int intervalMs = 1000;
    int timeoutMs = 5000;
    int payloadSize = 64;
    bool resolveDNS = true;
    bool resolveASN = true;
    int ipinfoMode = 0;
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
        << "Uso: " << argv0 << " <host> [opcoes]\n"
        << "Opcoes:\n"
        << "  --count N        Numero de rodadas (padrao: 5)\n"
        << "  --max-hops N     Maximo de hops (padrao: 30)\n"
        << "  --interval MS   Intervalo entre rodadas (padrao: 1000)\n"
        << "  --timeout MS    Timeout por echo (padrao: 5000)\n"
        << "  --size BYTES    Tamanho do payload ICMP (padrao: 64)\n"
        << "  --mode MODE     Modo de trace: icmp ou udp (padrao: icmp)\n"
        << "  --udp           Atalho para --mode udp\n"
        << "  --no-dns        Nao resolver DNS\n"
        << "  --no-asn        Nao resolver ASN\n"
        << "  -z, --aslookup  Mostrar ASN (equivalente a --ipinfo 0)\n"
        << "  -y, --ipinfo N  Mostrar IP info (0=ASN,1=Prefix,2=CC,3=RIR,4=Data)\n"
        << "  -h, --help      Mostrar esta ajuda\n";
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

bool readOptionValue(int argc, char** argv, int& i, std::string& out) {
    const std::string arg = argv[i];
    const auto eq = arg.find('=');
    if (eq != std::string::npos) {
        out = arg.substr(eq + 1);
        return true;
    }
    if (i + 1 >= argc) {
        return false;
    }
    out = argv[++i];
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

std::optional<mtr::NetworkAddress> resolveHost(const std::string& host) {
    if (auto literal = parseLiteralAddress(host)) {
        return literal;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
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

void printHeader(int round, int ipinfoMode, bool asnEnabled) {
    std::cout << "\nRodada " << round << "\n";
    std::cout << "Hop  Loss%   Snt   Rcv  Last  Avg   Best  Wrst  Endereco           "
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
        std::cerr << "Falha ao criar socket UDP: " << std::strerror(errno) << "\n";
        return false;
    }

    int on = 1;
    if (setsockopt(sock, SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0) {
        std::cerr << "Falha ao habilitar IP_RECVERR: " << std::strerror(errno) << "\n";
        close(sock);
        return false;
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

        for (int ttl = 1; ttl <= hopLimit; ++ttl) {
            if (g_interrupted.load()) {
                break;
            }

            auto& hop = hops[static_cast<size_t>(ttl - 1)];
            ++hop.packetsSent;

            int ttlVal = ttl;
            if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttlVal, sizeof(ttlVal)) != 0) {
                std::cerr << "Falha ao definir TTL: " << std::strerror(errno) << "\n";
                close(sock);
                return false;
            }

            destAddr.sin_port = htons(static_cast<uint16_t>(basePort + ttl));
            std::vector<uint8_t> payload(static_cast<size_t>(options.payloadSize), 0x42);

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

} // namespace

int main(int argc, char** argv) {
#ifndef _WIN32
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);
#endif

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "Falha ao inicializar Winsock.\n";
        return 1;
    }
#endif

    Options options{};
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
        if (arg == "--no-dns") {
            options.resolveDNS = false;
            continue;
        }
        if (arg == "--no-asn") {
            options.resolveASN = false;
            continue;
        }
        if (arg == "-z" || arg == "--aslookup") {
            options.ipinfoMode = 0;
            options.resolveASN = true;
            continue;
        }
        if (arg == "--udp") {
            options.mode = "udp";
            continue;
        }
        if (arg == "-y" || arg == "--ipinfo") {
            std::string value;
            if (!readOptionValue(argc, argv, i, value)) {
                std::cerr << "Opcao invalida: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (!parseInt(value, parsed) || parsed < 0 || parsed > 4) {
                std::cerr << "Opcao invalida: " << arg << "\n";
                return 1;
            }
            options.ipinfoMode = parsed;
            options.resolveASN = true;
            continue;
        }
        if (arg.rfind("--", 0) == 0) {
            std::string value;
            if (!readOptionValue(argc, argv, i, value)) {
                std::cerr << "Opcao invalida: " << arg << "\n";
                return 1;
            }
            int parsed = 0;
            if (arg.rfind("--count", 0) == 0 && parseInt(value, parsed)) {
                options.count = parsed;
            } else if (arg.rfind("--max-hops", 0) == 0 && parseInt(value, parsed)) {
                options.maxHops = parsed;
            } else if (arg.rfind("--interval", 0) == 0 && parseInt(value, parsed)) {
                options.intervalMs = parsed;
            } else if (arg.rfind("--timeout", 0) == 0 && parseInt(value, parsed)) {
                options.timeoutMs = parsed;
            } else if (arg.rfind("--size", 0) == 0 && parseInt(value, parsed)) {
                options.payloadSize = parsed;
            } else if (arg.rfind("--mode", 0) == 0) {
                options.mode = value;
            } else {
                std::cerr << "Opcao invalida: " << arg << "\n";
                return 1;
            }
            continue;
        }
        if (options.host.empty()) {
            options.host = arg;
            continue;
        }
        std::cerr << "Argumento desconhecido: " << arg << "\n";
        return 1;
    }

    if (options.host.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    if (options.count <= 0 || options.maxHops <= 0 || options.maxHops > 255 ||
        options.intervalMs <= 0 || options.timeoutMs <= 0 || options.payloadSize <= 0) {
        std::cerr << "Parametros invalidos.\n";
        return 1;
    }

    auto destination = resolveHost(options.host);
    if (!destination) {
        std::cerr << "Falha ao resolver host: " << options.host << "\n";
        return 1;
    }

    if (options.mode == "udp") {
#if defined(__linux__)
        g_asnEnabled.store(options.resolveASN);
        g_ipinfoMode.store(options.ipinfoMode);
        g_inputStop.store(false);
        std::thread inputThread;
        if (isInteractiveInput()) {
            inputThread = std::thread(inputThreadFunc);
        }
        if (!std::holds_alternative<mtr::IPv4Address>(*destination)) {
            std::cerr << "Modo UDP suporta apenas IPv4 no momento.\n";
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
        std::cerr << "Modo UDP suportado apenas em Linux.\n";
        return 1;
#endif
    } else {
        mtr::TraceConfig config{};
        config.destination = *destination;
        config.maxHops = static_cast<uint16_t>(options.maxHops);
        config.pingSize = static_cast<uint16_t>(options.payloadSize);
        config.pingInterval = mtr::Milliseconds(options.intervalMs);
        config.timeout = mtr::Milliseconds(options.timeoutMs);
        config.resolveDNS = options.resolveDNS;
        config.resolveASN = options.resolveASN;

        std::atomic<int> rounds{0};
        std::mutex doneMutex;
        std::condition_variable doneCv;
        bool done = false;
        mtr::ASNResolver asnResolver;
        std::unordered_map<uint32_t, mtr::ASNInfo> asnCache;
        std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> asnLastAttempt;
        std::unordered_map<std::string, mtr::ASNInfo> asnCacheV6;
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> asnLastAttemptV6;

        g_asnEnabled.store(options.resolveASN);
        g_ipinfoMode.store(options.ipinfoMode);
        g_inputStop.store(false);
        std::thread inputThread;
        if (isInteractiveInput()) {
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
            printHeader(current, g_ipinfoMode.load(), g_asnEnabled.load());
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
                printHopLine(i, displayHop, g_ipinfoMode.load(), g_asnEnabled.load());
            }
            if (current >= options.count) {
                std::lock_guard<std::mutex> lock(doneMutex);
                done = true;
                doneCv.notify_one();
            }
        });

        if (!engine.start(config)) {
            std::cerr << "Falha ao iniciar o traceroute.\n";
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
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
