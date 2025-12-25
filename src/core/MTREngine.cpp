//*****************************************************************************
// FILE:            MTREngine.cpp
//
// DESCRIPTION:     MTR Engine implementation (C++20, modern threading)
//
// LICENSE:         GPLv2
//*****************************************************************************

#include "MTREngine.h"
#include <algorithm>
#include <thread>
#include <chrono>

namespace mtr {

//=============================================================================
// Constructor / Destructor
//=============================================================================

MTREngine::MTREngine(UpdateCallback callback)
    : icmpSocket_(createICMPSocket())
    , callback_(std::move(callback))
{
}

MTREngine::~MTREngine() {
    stop();  // Ensure worker thread is stopped
}

MTREngine::MTREngine(MTREngine&& other) noexcept
    : icmpSocket_(std::move(other.icmpSocket_))
    , workerThread_(std::move(other.workerThread_))
    , callback_(std::move(other.callback_))
    , traceResult_(std::move(other.traceResult_))
{
    running_.store(other.running_.load());
    stopRequested_.store(other.stopRequested_.load());
}

MTREngine& MTREngine::operator=(MTREngine&& other) noexcept {
    if (this != &other) {
        stop();  // Stop our current trace

        icmpSocket_ = std::move(other.icmpSocket_);
        workerThread_ = std::move(other.workerThread_);
        callback_ = std::move(other.callback_);
        traceResult_ = std::move(other.traceResult_);
        running_.store(other.running_.load());
        stopRequested_.store(other.stopRequested_.load());
    }
    return *this;
}

//=============================================================================
// Trace Control
//=============================================================================

bool MTREngine::start(const TraceConfig& config) {
    // Don't start if already running
    if (running_.load(std::memory_order_acquire)) {
        return false;
    }

    // Validate configuration
    if (config.maxHops == 0 || config.maxHops > 255 || config.firstHop == 0 ||
        config.firstHop > config.maxHops) {
        return false;
    }

    // Reset state
    {
        std::lock_guard<std::mutex> lock(resultMutex_);
        traceResult_ = TraceResult{};
        traceResult_.config = config;
        traceResult_.startTime = std::chrono::steady_clock::now();
        traceResult_.isRunning = true;
    }

    // Start worker thread
    stopRequested_.store(false, std::memory_order_release);
    running_.store(true, std::memory_order_release);

    workerThread_ = std::make_unique<std::thread>(
        &MTREngine::workerThreadFunc,
        this,
        config
    );

    return true;
}

void MTREngine::stop() {
    // Request stop
    stopRequested_.store(true, std::memory_order_release);

    // Wait for worker thread
    if (workerThread_ && workerThread_->joinable()) {
        workerThread_->join();
        workerThread_.reset();
    }

    // Update state
    running_.store(false, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(resultMutex_);
        traceResult_.isRunning = false;
    }
}

TraceResult MTREngine::getResults() const {
    std::lock_guard<std::mutex> lock(resultMutex_);
    return traceResult_;
}

void MTREngine::reset() {
    std::lock_guard<std::mutex> lock(resultMutex_);
    for (auto& hop : traceResult_.hops) {
        hop = HopStatistics{};
    }
}

//=============================================================================
// Configuration
//=============================================================================

void MTREngine::setCallback(UpdateCallback callback) {
    callback_ = std::move(callback);
}

//=============================================================================
// Worker Thread
//=============================================================================

void MTREngine::workerThreadFunc(TraceConfig config) {
    using namespace std::chrono_literals;

    bool destinationReached = false;

    while (!stopRequested_.load(std::memory_order_acquire)) {
        // Ping each hop up to max or destination
        for (uint8_t ttl = static_cast<uint8_t>(config.firstHop);
             ttl <= config.maxHops;
             ++ttl) {
            if (stopRequested_.load(std::memory_order_acquire)) {
                break;
            }

            // Check if we've already reached destination
            if (destinationReached && ttl > traceResult_.hops.size()) {
                break;
            }

            pingHop(ttl, config);

            // Check if this hop is the destination
            {
                std::lock_guard<std::mutex> lock(resultMutex_);
                if (ttl <= traceResult_.hops.size()) {
                    const auto& hop = traceResult_.hops[ttl - 1];
                    if (hop.address == config.destination) {
                        destinationReached = true;
                    }
                }
            }

            // Small delay between hops (reduces network load)
            std::this_thread::sleep_for(30ms);
        }

        // Notify UI of update
        notifyUpdate();

        // Wait for interval before next round
        std::this_thread::sleep_for(config.pingInterval);
    }

    running_.store(false, std::memory_order_release);
}

void MTREngine::pingHop(uint8_t ttl, const TraceConfig& config) {
    if (!icmpSocket_) {
        return;
    }

    // Ensure hop entry exists
    ensureHopExists(ttl - 1);

    // Send ICMP echo with specified TTL
    auto result = icmpSocket_->sendEcho(
        config.destination,
        ttl,
        config.pingSize,
        config.timeout
    );

    std::optional<NetworkAddress> asnAddress;
    bool shouldResolveAsn = false;

    {
        std::lock_guard<std::mutex> lock(resultMutex_);

        auto& hop = traceResult_.hops[ttl - 1];
        ++hop.packetsSent;

        if (hasValue(result)) {
            const EchoReply& reply = getValue(result);

            if (hop.address != reply.source) {
                hop.address = reply.source;
                hop.hostname.reset();
                hop.asn.reset();
            }

            // Update statistics if successful or TTL expired (expected for intermediate hops)
            if (reply.status == ICMPError::Success || reply.status == ICMPError::TTLExpired) {
                hop.updateRTT(reply.roundTripTime);

                if (config.resolveASN && !hop.asn) {
                    asnAddress = hop.address;
                    shouldResolveAsn = true;
                }

                // TODO: DNS resolution (if config.resolveDNS)
                // For now, just use IP address
            }
        }
    }

    if (shouldResolveAsn && asnAddress) {
        auto asnInfo = asnResolver_.resolve(*asnAddress);
        if (asnInfo) {
            std::lock_guard<std::mutex> lock(resultMutex_);
            auto& hop = traceResult_.hops[ttl - 1];
            if (hop.address == *asnAddress && !hop.asn) {
                hop.asn = *asnInfo;
            }
        }
    }
    // On error/timeout, packet is counted as sent but not received
}

void MTREngine::notifyUpdate() {
    if (callback_) {
        try {
            callback_(getResults());
        } catch (...) {
            // Ignore callback exceptions
        }
    }
}

void MTREngine::ensureHopExists(size_t index) {
    std::lock_guard<std::mutex> lock(resultMutex_);

    if (index >= traceResult_.hops.size()) {
        traceResult_.hops.resize(index + 1);
    }
}

} // namespace mtr
