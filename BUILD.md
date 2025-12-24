# WinMTR Redux - Build Instructions

## Prerequisites

### For MFC Build (Phase 1 - Current)
- **Visual Studio 2022** (17.0 or later)
  - Workload: "Desktop development with C++"
  - Individual components:
    - C++ MFC for latest v143 build tools (x86 & x64)
    - C++ CMake tools for Windows
    - Windows 10 SDK (10.0.19041.0 or later)

### For wxWidgets Build (Phase 3 - Future)
- **wxWidgets 3.2+**
- All MFC prerequisites above

### Build Tools
- **CMake 3.20+**
- **Git** (for version control)

---

## Quick Start (Visual Studio 2022)

### Method 1: Using VS 2022 CMake Integration (Recommended)

1. **Open the project:**
   ```
   File → Open → Folder → Select WinMTR directory
   ```

2. **Configure CMake:**
   - VS 2022 will automatically detect `CMakeLists.txt`
   - Wait for CMake configuration to complete
   - Check the Output window for any errors

3. **Select build configuration:**
   - Use the toolbar dropdown to select: `x64-Debug` or `x64-Release`

4. **Build:**
   - `Build → Build All` or press `Ctrl+Shift+B`
   - Output: `out/build/x64-Debug/bin/WinMTR.exe`

5. **Run:**
   - `Debug → Start Debugging` or press `F5`

### Method 2: Using Command Line

1. **Open Developer Command Prompt for VS 2022**

2. **Navigate to project directory:**
   ```cmd
   cd C:\path\to\winmtr
   ```

3. **Configure with CMake:**
   ```cmd
   cmake -B build -G "Visual Studio 17 2022" -A x64
   ```

4. **Build:**
   ```cmd
   cmake --build build --config Release
   ```

5. **Run:**
   ```cmd
   .\build\bin\Release\WinMTR.exe
   ```

---

## Build Options

Configure these options when running CMake:

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
  -DBUILD_WITH_MFC=ON ^
  -DBUILD_WITH_WXWIDGETS=OFF ^
  -DBUILD_TESTS=OFF ^
  -DENABLE_IPV6=ON
```

### Available Options:

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_WITH_MFC` | `ON` | Build with MFC (legacy UI - Phase 1) |
| `BUILD_WITH_WXWIDGETS` | `OFF` | Build with wxWidgets (modern UI - Phase 3) |
| `BUILD_TESTS` | `OFF` | Build unit tests (Phase 5) |
| `ENABLE_IPV6` | `ON` | Enable IPv6 support |

---

## Build Configurations

### Debug
- Full debug symbols
- No optimizations
- Runtime checks enabled
- Output: `build/bin/Debug/WinMTR.exe`

### Release
- Optimized for speed (`/O2`)
- Whole program optimization (`/GL`, `/LTCG`)
- No debug info
- Output: `build/bin/Release/WinMTR.exe`

---

## Troubleshooting

### "MFC not found"
Install MFC components in Visual Studio Installer:
1. Open Visual Studio Installer
2. Modify Visual Studio 2022
3. Individual Components → Search "MFC"
4. Check: "C++ MFC for latest v143 build tools (x86 & x64)"
5. Install

### "Windows SDK not found"
Install Windows 10/11 SDK:
1. Visual Studio Installer → Modify
2. Individual Components → SDKs
3. Install "Windows 10 SDK (10.0.19041.0)" or later

### "CMake configuration failed"
1. Ensure CMake 3.20+ is installed: `cmake --version`
2. Check CMake output in VS Output window
3. Verify all prerequisites are installed
4. Try deleting `build/` or `out/` directory and reconfigure

### Build errors with MFC
Ensure you have:
- Latest Visual Studio 2022 updates
- MFC libraries for x64 architecture
- Correct Windows SDK version

---

## Project Structure

```
winmtr/
├── CMakeLists.txt          # Main build configuration
├── BUILD.md               # This file
├── README.md              # Project documentation
├── src/                   # Source code
│   ├── WinMTR*.cpp/h     # Application files
│   ├── WinMTR.rc         # Resources
│   └── WinMTR.ico        # Icon
├── build/                 # Build output (git-ignored)
└── out/                   # VS CMake output (git-ignored)
```

---

## Development Phases

### ✅ Phase 1: MFC Build System (Current)
- [x] CMake build system
- [ ] Compile with VS 2022
- [ ] Test on Windows 10/11

### ⏳ Phase 2: Core Refactoring
- [ ] Separate network logic from UI
- [ ] Modernize to C++20
- [ ] Fix memory leaks

### ⏳ Phase 3: wxWidgets Migration
- [ ] Setup wxWidgets in CMake
- [ ] Implement new UI
- [ ] Port all features

### ⏳ Phase 4: New Features
- [ ] Dark mode
- [ ] Latency graphs
- [ ] JSON/CSV export
- [ ] Alerts system
- [ ] Multiple traces

### ⏳ Phase 5: Polish
- [ ] Unit tests
- [ ] Performance optimization
- [ ] Documentation

---

## Contributing

This is a modernization effort for the WinMTR project. We're migrating from:
- Visual Studio 2010 → Visual Studio 2022
- C++98 → C++20
- MFC → wxWidgets

See `README.md` for more information.
