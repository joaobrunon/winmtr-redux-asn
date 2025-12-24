//*****************************************************************************
// FILE:            test_mtr.cpp
//
// DESCRIPTION:     Test program for WinMTR Redux core library
//                  Performs a simple trace to demonstrate functionality
//
// USAGE:           sudo ./test_mtr <host>
//                  Example: sudo ./test_mtr 8.8.8.8
//
// LICENSE:         GPLv2
//*****************************************************************************

#include "Types.h"
#include "MTREngine.h"
#include <iostream>
#include <iomanip>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

using namespace mtr;
using namespace std::chrono_literals;

std::atomic<bool> g_running{true};

void signalHandler(int signal) {
    if (signal == SIGINT) {
        std::cout << "\n\nStopping trace...\n";
        g_running = false;
    }
}

void printHeader() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                   WinMTR Redux 2.0 - Test Program                    ║\n";
    std::cout << "║                   Modern C++20 MTR Implementation                     ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════╝\n\n";
}

void printTraceResults(const TraceResult& result) {
    std::cout << "\033[2J\033[H";  // Clear screen
    printHeader();

    std::cout << "Destination: ";
    std::visit([](const auto& addr) {
        std::cout << addr.toString();
    }, result.config.destination);
    std::cout << "\n";
    std::cout << "Hops discovered: " << result.hopCount() << "\n";
    std::cout << "Status: " << (result.isRunning ? "Running" : "Stopped") << "\n\n";

    // Table header
    std::cout << std::left
              << std::setw(4) << "Hop"
              << std::setw(20) << "Address"
              << std::setw(8) << "Loss%"
              << std::setw(8) << "Sent"
              << std::setw(8) << "Recv"
              << std::setw(10) << "Best"
              << std::setw(10) << "Avg"
              << std::setw(10) << "Worst"
              << std::setw(10) << "Last"
              << "\n";

    std::cout << std::string(90, '─') << "\n";

    // Table rows
    for (size_t i = 0; i < result.hops.size(); ++i) {
        const auto& hop = result.hops[i];

        if (hop.packetsSent == 0) continue;  // Skip empty hops

        std::string addrStr;
        std::visit([&addrStr](const auto& addr) {
            addrStr = addr.toString();
        }, hop.address);

        if (addrStr.empty() || addrStr == "0.0.0.0") {
            addrStr = "???";
        }

        std::cout << std::left
                  << std::setw(4) << (i + 1)
                  << std::setw(20) << addrStr
                  << std::setw(8) << std::fixed << std::setprecision(1) << hop.packetLossPercent()
                  << std::setw(8) << hop.packetsSent
                  << std::setw(8) << hop.packetsReceived
                  << std::setw(10) << (hop.bestRTT.count() < 999999 ? std::to_string(hop.bestRTT.count()) + "ms" : "-")
                  << std::setw(10) << (hop.packetsReceived > 0 ? std::to_string(hop.averageRTT().count()) + "ms" : "-")
                  << std::setw(10) << std::to_string(hop.worstRTT.count()) + "ms"
                  << std::setw(10) << std::to_string(hop.lastRTT.count()) + "ms"
                  << "\n";
    }

    std::cout << "\nPress Ctrl+C to stop...\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0] << " <host>\n";
        std::cerr << "Example: sudo " << argv[0] << " 8.8.8.8\n";
        std::cerr << "\nNote: Root privileges required for raw ICMP sockets\n";
        return 1;
    }

    printHeader();

    // Parse destination
    const char* destStr = argv[1];
    std::cout << "Resolving destination: " << destStr << "...\n";

    // Simple IPv4 parser (for demonstration)
    IPv4Address destination;
    unsigned int a, b, c, d;
    if (sscanf(destStr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        destination = IPv4Address(a, b, c, d);
        std::cout << "Destination: " << destination.toString() << "\n\n";
    } else {
        std::cerr << "Error: Invalid IPv4 address format\n";
        std::cerr << "Please use format: xxx.xxx.xxx.xxx\n";
        return 1;
    }

    // Setup signal handler
    signal(SIGINT, signalHandler);

    // Create trace configuration
    TraceConfig config;
    config.destination = destination;
    config.maxHops = 30;
    config.pingSize = 64;
    config.pingInterval = 1000ms;
    config.timeout = 5000ms;
    config.resolveDNS = false;  // DNS not implemented yet

    // Create MTR engine with callback
    bool firstUpdate = true;
    MTREngine engine([&firstUpdate](const TraceResult& result) {
        if (!firstUpdate) {
            printTraceResults(result);
        }
        firstUpdate = false;
    });

    std::cout << "Starting trace...\n";
    std::cout << "Configuration:\n";
    std::cout << "  Max hops: " << config.maxHops << "\n";
    std::cout << "  Ping size: " << config.pingSize << " bytes\n";
    std::cout << "  Interval: " << config.pingInterval.count() << " ms\n";
    std::cout << "  Timeout: " << config.timeout.count() << " ms\n\n";

    // Start trace
    if (!engine.start(config)) {
        std::cerr << "Error: Failed to start trace\n";
        std::cerr << "Make sure you have root privileges (use sudo)\n";
        return 1;
    }

    std::cout << "Trace started! Waiting for results...\n\n";

    // Main loop
    while (g_running && engine.isRunning()) {
        std::this_thread::sleep_for(500ms);

        // Get and display results
        auto result = engine.getResults();
        if (result.hops.size() > 0) {
            printTraceResults(result);
        }
    }

    // Stop and show final results
    engine.stop();
    auto finalResult = engine.getResults();
    printTraceResults(finalResult);

    std::cout << "\nTrace completed.\n";
    std::cout << "Total hops discovered: " << finalResult.hopCount() << "\n\n";

    return 0;
}
