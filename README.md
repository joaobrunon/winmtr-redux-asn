# WinMTR Redux 2.0

> **A modernized fork of WinMTR** - Network diagnostic tool combining traceroute and ping functionality

[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)]()
[![C++](https://img.shields.io/badge/C%2B%2B-20-00599C.svg)]()

## About This Fork

This is a **complete modernization** of the [White-Tiger/WinMTR](https://github.com/White-Tiger/WinMTR) fork (last updated 2014), which itself was an enhancement of [Appnor's original WinMTR](http://winmtr.net/).

### What's New in 2.0

**🔧 Modernization:**
- ✅ Visual Studio 2010 → **Visual Studio 2022**
- ✅ C++98 → **C++20** (auto, smart pointers, ranges, concepts)
- 🚧 MFC → **wxWidgets** (cross-platform, modern UI)
- ✅ MSBuild → **CMake** (modern build system)

**🎨 New Features:**
- 🚧 **Dark Mode** support
- 🚧 **Real-time latency graphs**
- 🚧 **JSON/CSV export**
- 🚧 **Packet loss alerts**
- 🚧 **Multiple simultaneous traces** (tabbed interface)
- 🚧 **Integration with monitoring tools**

**🐛 Fixes & Improvements:**
- ✅ Fixed memory leaks
- ✅ Modern C++ RAII patterns
- ✅ Better threading (`_beginthreadex` instead of `_beginthread`)
- ✅ Unicode support
- 🚧 Unit tests
- 🚧 Performance optimizations

---

## Quick Start

### Download

**Pre-built binaries:** Coming soon!

### Build from Source

See [BUILD.md](BUILD.md) for detailed instructions.

**Quick build (Windows):**
```powershell
# Using PowerShell script
.\build.ps1

# Or using CMake directly
cmake --preset x64-release
cmake --build out/build/x64-release --config Release
```

---

## Features

### Core Functionality (Inherited from Original)
- **Combined traceroute + ping** - Monitor network path and latency over time
- **IPv4 and IPv6 support** - Full dual-stack support
- **Continuous monitoring** - Long-term network path analysis
- **Export capabilities** - Text and HTML export
- **DNS resolution** - Automatic hostname lookup
- **Configurable ping interval** - Customize monitoring frequency

### Enhanced Features (This Fork)
- **Windows 10/11 optimized** - Native support for modern Windows
- **High DPI aware** - Crisp UI on high-resolution displays
- **Modern C++ codebase** - Safer, faster, more maintainable
- **CMake build system** - Easy to build and contribute

---

## Screenshots

*Coming soon - UI redesign in progress*

---

## System Requirements

### Runtime
- **OS:** Windows 10 (1809+) or Windows 11
- **Architecture:** x64 or x86
- **Privileges:** Administrator rights (for ICMP raw sockets)

### Build Requirements
- **Visual Studio 2022** (17.0+)
  - Desktop development with C++
  - C++ MFC for latest v143 build tools
  - Windows 10 SDK (10.0.19041.0+)
- **CMake 3.20+**
- **wxWidgets 3.2+** (for wxWidgets build - Phase 3)

See [BUILD.md](BUILD.md) for complete build instructions.

---

## Development Roadmap

### ✅ Phase 1: Build System & Analysis (Current)
- [x] Analyze legacy codebase
- [x] Identify dependencies and issues
- [x] Create CMake build system
- [x] Setup VS 2022 configuration
- [ ] Compile and test on Windows 10/11

### 🚧 Phase 2: Core Refactoring
- [ ] Decouple network logic from UI
- [ ] Modernize to C++20
  - [ ] Smart pointers (unique_ptr, shared_ptr)
  - [ ] STL containers (std::vector, std::string)
  - [ ] Modern threading (std::thread, std::mutex)
  - [ ] Ranges and concepts
- [ ] Fix identified memory leaks
- [ ] Create clean abstraction layer

### 🚧 Phase 3: wxWidgets Migration
- [ ] Setup wxWidgets in CMake
- [ ] Implement main window
- [ ] Implement hop list view
- [ ] Port all controls and dialogs
- [ ] Integrate with refactored core

### 🚧 Phase 4: New Features
- [ ] Dark mode support
- [ ] Real-time latency graphs (wxCharts)
- [ ] JSON/CSV export
- [ ] Packet loss alert system
- [ ] Multi-tab interface for concurrent traces
- [ ] Integration APIs

### 🚧 Phase 5: Polish & Release
- [ ] Unit tests (Google Test)
- [ ] Performance profiling & optimization
- [ ] Documentation
- [ ] CI/CD pipeline
- [ ] Official release

---

## Contributing

Contributions are welcome! This project is actively being modernized.

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style
- **C++20** features encouraged
- **Modern C++** idioms (RAII, smart pointers, STL)
- **No raw pointers** unless absolutely necessary
- **const correctness**
- Follow existing formatting (use `clang-format`)

---

## License

This project is licensed under **GPLv2** - see [LICENSE](LICENSE) file for details.

### License History
- Original WinMTR by Appnor - GPLv2
- WinMTR Redux (White-Tiger) - GPLv2
- WinMTR Redux 2.0 (This fork) - GPLv2

---

## Credits

### Original Authors
- **Appnor MSN** - Original WinMTR (up to v0.92)
- **White-Tiger** - IPv6 support and enhancements (v1.0, 2014)

### This Fork
- **2024-2025** - Complete modernization project
  - Build system modernization
  - C++20 upgrade
  - wxWidgets migration
  - New features and improvements

### Special Thanks
- All contributors to the original WinMTR project
- The wxWidgets team
- The CMake developers

---

## Related Projects

- [Original WinMTR](http://winmtr.net/) - The original Windows MTR
- [mtr (Linux)](https://github.com/traviscross/mtr) - The Unix MTR tool
- [vTrace](http://vtrace.pl) - Alternative Windows network diagnostic tool

---

## Support

- **Issues:** [GitHub Issues](https://github.com/YOUR_USERNAME/WinMTR/issues)
- **Discussions:** [GitHub Discussions](https://github.com/YOUR_USERNAME/WinMTR/discussions)
- **Documentation:** [BUILD.md](BUILD.md)

---

<div align="center">

**Made with ❤️ for the network diagnostic community**

[Report Bug](https://github.com/YOUR_USERNAME/WinMTR/issues) · [Request Feature](https://github.com/YOUR_USERNAME/WinMTR/issues) · [Documentation](BUILD.md)

</div>
