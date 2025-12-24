//*****************************************************************************
// FILE:            MTREngine.h
//
// DESCRIPTION:     Main MTR trace engine (C++20, thread-safe)
//
// LICENSE:         GPLv2
//*****************************************************************************

#pragma once

#include "Types.h"
#include "ICMPSocket.h"
#include "ASNResolver.h"
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <memory>

namespace mtr {

//=============================================================================
// MTR Engine (Thread-Safe)
//=============================================================================

/// Main MTR trace engine
///
/// Features:
/// - Thread-safe operation
/// - Real-time statistics updates
/// - Callback-based notifications
/// - RAII resource management
/// - Modern C++20 with smart pointers
class MTREngine {
public:
    /// Callback function type for trace updates
    /// Called from worker thread - must be thread-safe!
    using UpdateCallback = std::function<void(const TraceResult&)>;

    explicit MTREngine(UpdateCallback callback = nullptr);
    ~MTREngine();

    // Disable copy, allow move
    MTREngine(const MTREngine&) = delete;
    MTREngine& operator=(const MTREngine&) = delete;
    MTREngine(MTREngine&&) noexcept;
    MTREngine& operator=(MTREngine&&) noexcept;

    //=========================================================================
    // Trace Control
    //=========================================================================

    /// Start tracing to destination
    /// @param config Trace configuration
    /// @return true if started successfully
    [[nodiscard]] bool start(const TraceConfig& config);

    /// Stop current trace
    void stop();

    /// Check if trace is currently running
    [[nodiscard]] bool isRunning() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

    /// Get current trace results (thread-safe)
    [[nodiscard]] TraceResult getResults() const;

    /// Reset statistics (clears all hop data)
    void reset();

    //=========================================================================
    // Configuration
    //=========================================================================

    /// Set update callback
    void setCallback(UpdateCallback callback);

    /// Get ICMP socket (for diagnostics)
    [[nodiscard]] const ICMPSocket* getSocket() const noexcept {
        return icmpSocket_.get();
    }

private:
    std::unique_ptr<ICMPSocket> icmpSocket_;  ///< Platform-specific ICMP
    ASNResolver asnResolver_;                ///< ASN resolver/cache
    std::unique_ptr<std::thread> workerThread_; ///< Trace worker thread
    UpdateCallback callback_;                  ///< Update notification callback

    mutable std::mutex resultMutex_;           ///< Protects traceResult_
    TraceResult traceResult_;                  ///< Current trace result
    std::atomic<bool> running_{false};         ///< Is trace running?
    std::atomic<bool> stopRequested_{false};   ///< Stop requested flag

    /// Worker thread function
    void workerThreadFunc(TraceConfig config);

    /// Send ping to specific TTL and update statistics
    void pingHop(uint8_t ttl, const TraceConfig& config);

    /// Notify callback of update (if set)
    void notifyUpdate();

    /// Ensure hops vector has enough entries
    void ensureHopExists(size_t index);
};

} // namespace mtr
