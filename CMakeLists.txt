cmake_minimum_required(VERSION 3.20)

# WinMTR Redux - Cross-Platform Build System
project(WinMTR VERSION 2.0.0 LANGUAGES CXX)

# ============================================================================
# Build Options
# ============================================================================
option(BUILD_CORE_LIB "Build cross-platform core library" ON)
option(BUILD_CLI "Build command-line tool (cross-platform)" ON)
option(BUILD_WITH_MFC "Build with MFC (Windows legacy UI)" OFF)
option(BUILD_WITH_WXWIDGETS "Build with wxWidgets (modern cross-platform UI)" OFF)
option(BUILD_TESTS "Build unit tests" OFF)

# ============================================================================
# C++ Standard and Compiler Settings
# ============================================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Platform-specific definitions
if(WIN32)
    add_compile_definitions(
        WINVER=0x0A00          # Windows 10
        _WIN32_WINNT=0x0A00    # Windows 10
        NTDDI_VERSION=0x0A000000
        _CRT_SECURE_NO_WARNINGS
    )
endif()

# ============================================================================
# Output Directories
# ============================================================================
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ============================================================================
# Core Library (Cross-Platform C++20)
# ============================================================================
if(BUILD_CORE_LIB)
    set(CORE_SOURCES
        src/core/Types.h
        src/core/Types.cpp
        src/core/ASNResolver.h
        src/core/ASNResolver.cpp
        src/core/ICMPSocket.h
        src/core/ICMPSocket.cpp
        src/core/MTREngine.h
        src/core/MTREngine.cpp
    )

    # Platform-specific ICMP implementation
    if(WIN32)
        list(APPEND CORE_SOURCES
            src/core/WindowsICMP.h
            src/core/WindowsICMP.cpp
        )
    else()
        list(APPEND CORE_SOURCES
            src/core/PosixICMP.h
            src/core/PosixICMP.cpp
        )
    endif()

    # Create core library
    add_library(mtr_core STATIC ${CORE_SOURCES})

    target_include_directories(mtr_core PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/core>
        $<INSTALL_INTERFACE:include>
    )

    # Platform-specific libraries
    if(WIN32)
        target_link_libraries(mtr_core PUBLIC
            ws2_32      # Winsock 2
            iphlpapi    # ICMP APIs
        )
    else()
        # Linux/Unix - needs pthread for threads
        target_link_libraries(mtr_core PUBLIC
            pthread
        )
    endif()

    # Compiler warnings and optimizations
    if(MSVC)
        target_compile_options(mtr_core PRIVATE
            /W4                 # Warning level 4
            /permissive-        # Standards conformance
            /Zc:__cplusplus     # Correct __cplusplus macro
            /utf-8              # UTF-8 source and execution charset
            $<$<CONFIG:Release>:/O2>  # Optimize for speed
            $<$<CONFIG:Release>:/GL>  # Whole program optimization
        )
    else()
        target_compile_options(mtr_core PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            $<$<CONFIG:Release>:-O3>
        )
    endif()

    set_target_properties(mtr_core PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        POSITION_INDEPENDENT_CODE ON
    )
endif()

# ============================================================================
# CLI Tool (Cross-Platform)
# ============================================================================
if(BUILD_CLI AND BUILD_CORE_LIB)
    add_executable(mtr_cli
        src/cli/mtr_cli.cpp
    )

    target_link_libraries(mtr_cli PRIVATE mtr_core)

    if(MSVC)
        target_compile_options(mtr_cli PRIVATE /W4 /permissive-)
    else()
        target_compile_options(mtr_cli PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

# ============================================================================
# MFC Build (Windows Legacy UI)
# ============================================================================
if(BUILD_WITH_MFC AND WIN32)
    set(CMAKE_MFC_FLAG 1)  # Use MFC in a Shared DLL

    add_executable(WinMTR_MFC WIN32
        src/mfc/WinMTRMain.cpp
        src/mfc/WinMTRMain.h
        src/mfc/WinMTRDialog.cpp
        src/mfc/WinMTRDialog.h
        src/mfc/WinMTRNet.cpp
        src/mfc/WinMTRNet.h
        src/mfc/WinMTRGlobal.cpp
        src/mfc/WinMTRGlobal.h
        src/mfc/WinMTRStatusBar.cpp
        src/mfc/WinMTRStatusBar.h
        src/mfc/WinMTROptions.cpp
        src/mfc/WinMTROptions.h
        src/mfc/WinMTRProperties.cpp
        src/mfc/WinMTRProperties.h
        src/mfc/WinMTRLicense.cpp
        src/mfc/WinMTRLicense.h
        src/mfc/WinMTRHelp.cpp
        src/mfc/WinMTRHelp.h
        src/mfc/resource.h
        src/mfc/WinMTR.rc
    )

    target_compile_definitions(WinMTR_MFC PRIVATE
        WIN32
        _WINDOWS
        _AFXDLL  # Use MFC as DLL
        $<$<CONFIG:Debug>:_DEBUG>
        $<$<CONFIG:Release>:NDEBUG>
    )

    target_link_libraries(WinMTR_MFC PRIVATE
        ws2_32
        iphlpapi
    )

    # Can optionally use new core
    if(BUILD_CORE_LIB)
        target_link_libraries(WinMTR_MFC PRIVATE mtr_core)
        target_compile_definitions(WinMTR_MFC PRIVATE USE_NEW_CORE)
    endif()

    set_target_properties(WinMTR_MFC PROPERTIES
        OUTPUT_NAME "WinMTR"
        VS_DPI_AWARE "PerMonitor"
    )
endif()

# ============================================================================
# wxWidgets Build (Cross-Platform Modern UI)
# ============================================================================
if(BUILD_WITH_WXWIDGETS)
    find_package(wxWidgets REQUIRED COMPONENTS core base net)
    include(${wxWidgets_USE_FILE})

    # wxWidgets UI will be added in Phase 3
    message(STATUS "wxWidgets UI will be added in Phase 3")
endif()

# ============================================================================
# Testing (Phase 5)
# ============================================================================
if(BUILD_TESTS AND BUILD_CORE_LIB)
    enable_testing()
    message(STATUS "Tests will be added in Phase 5")
endif()

# ============================================================================
# Installation
# ============================================================================
if(BUILD_CORE_LIB)
    install(TARGETS mtr_core
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
    )
    install(DIRECTORY src/core/
        DESTINATION include/mtr
        FILES_MATCHING PATTERN "*.h"
    )
endif()

if(BUILD_WITH_MFC AND TARGET WinMTR_MFC)
    install(TARGETS WinMTR_MFC
        RUNTIME DESTINATION bin
    )
endif()

# ============================================================================
# Build Summary
# ============================================================================
message(STATUS "")
message(STATUS "============================================")
message(STATUS "WinMTR Redux - Configuration Summary")
message(STATUS "============================================")
message(STATUS "Version:        ${PROJECT_VERSION}")
message(STATUS "Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard:   C++${CMAKE_CXX_STANDARD}")
message(STATUS "Platform:       ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "")
message(STATUS "Build Options:")
message(STATUS "  Core Library:  ${BUILD_CORE_LIB}")
message(STATUS "  CLI Tool:      ${BUILD_CLI}")
message(STATUS "  MFC UI:        ${BUILD_WITH_MFC}")
message(STATUS "  wxWidgets UI:  ${BUILD_WITH_WXWIDGETS}")
message(STATUS "  Unit Tests:    ${BUILD_TESTS}")
if(BUILD_CORE_LIB)
    if(WIN32)
        message(STATUS "  ICMP Backend:  WindowsICMP (Iphlpapi.dll)")
    else()
        message(STATUS "  ICMP Backend:  PosixICMP (raw sockets)")
    endif()
endif()
message(STATUS "============================================")
message(STATUS "")
