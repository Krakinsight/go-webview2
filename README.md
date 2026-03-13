[![Go](https://github.com/Krakinsight/go-webview2/actions/workflows/go.yml/badge.svg)](https://github.com/Krakinsight/go-webview2/actions/workflows/go.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/Krakinsight/go-webview2)](https://goreportcard.com/report/github.com/Krakinsight/go-webview2) [![Go Reference](https://pkg.go.dev/badge/github.com/Krakinsight/go-webview2.svg)](https://pkg.go.dev/github.com/Krakinsight/go-webview2)

# go-webview2
This package provides an interface for using the Microsoft Edge WebView2 component with Go. It is based on [webview/webview](https://github.com/webview/webview) and provides a compatible API.

Please note that this package only supports Windows, since it provides functionality specific to WebView2. If you wish to use this library for Windows, but use webview/webview for all other operating systems, you could use the [go-webview-selector](https://github.com/Krakinsight/go-webview-selector) package instead. However, you will not be able to use WebView2-specific functionality.

If you wish to build desktop applications in Go using web technologies, please consider [Wails](https://wails.io/). It uses go-webview2 internally on Windows.


If you are using Windows 10+, the WebView2 runtime should already be installed. If not, download it from:

[WebView2 runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/)

## Requirements

- **Go 1.21 or later** - This library uses [`runtime.Pinner`](https://pkg.go.dev/runtime#Pinner) to ensure safe interaction with native Windows COM code
- **Windows 10+** with WebView2 runtime installed

## Basic Usage

```go
package main

import (
    "github.com/Krakinsight/go-webview2"
)

func main() {
    w := webview2.NewWithOptions(webview2.WebViewOptions{
        Debug:     true,
        AutoFocus: true,
        WindowOptions: webview2.WindowOptions{
            Title:  "My App",
            Width:  800,
            Height: 600,
            Center: true,
        },
    })
    
    if w == nil {
        panic("Failed to load webview")
    }
    defer w.Destroy()
    
    w.Navigate("https://example.com")
    w.Run()
}
```

## Features

### Window Positioning

The `Location` struct allows precise window positioning:

```go
// Position from top-left corner
Location: &webview2.Location{X: 100, Y: 100}

// Position from bottom-right corner using negative coordinates
Location: &webview2.Location{X: -500, Y: -1}
```

**Note**: Negative coordinates use Windows work area (excludes taskbar), ensuring windows never overlap the taskbar.

### Custom User-Agent

```go
webview2.NewWithOptions(webview2.WebViewOptions{
    UserAgent: "MyApp/1.0 (CustomBrowser)",
})
```

### Access to WebView2 Settings

```go
w := webview2.NewWithOptions(...)
settings := w.GetSettings()

// Configure zoom controls
settings.PutIsZoomControlEnabled(false)

// Disable browser accelerator keys
settings.PutAreBrowserAcceleratorKeysEnabled(false)
```

### Accelerator Keys

```go
w.SetAcceleratorKeyCallback(func(virtualKey uint) bool {
    switch virtualKey {
    case 0x74: // VK_F5
        fmt.Println("Blocked F5 refresh")
        return true // Block the key
    case 0x7B: // VK_F12  
        fmt.Println("Blocked DevTools")
        return true
    default:
        return false // Allow other keys
    }
})
```

Common virtual key codes:
- `0x74` - F5 (Refresh)
- `0x7B` - F12 (DevTools)
- `0x41-0x5A` - Letters A-Z
- `0x30-0x39` - Numbers 0-9

See [Virtual-Key Codes](https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes) for complete reference.

### Window Styles

- `WindowStyleDefault` - Standard resizable window
- `WindowStyleFixed` - Non-resizable window
- `WindowStyleBorderless` - No borders/title bar (custom UI)
- `WindowStyleToolWindow` - Tool window (not in taskbar)

### DPI Awareness

Control how your application handles high-DPI displays to ensure crisp rendering across different display configurations:

```go
w := webview2.NewWithOptions(webview2.WebViewOptions{
    WindowOptions: webview2.WindowOptions{
        Title:                "My DPI-Aware App",
        Width:                800,
        Height:               600,
        DpiAwarenessContext:  webview2.DpiAwarenessContextPerMonitorAwareV2,
    },
})
```

#### Available DPI Awareness Modes:

- `DpiAwarenessContextDefault` - System default (no explicit setting)
- `DpiAwarenessContextUnaware` - Windows handles scaling (may appear blurry)
- `DpiAwarenessContextSystemAware` - Scales to primary monitor DPI
- `DpiAwarenessContextPerMonitorAware` - Adapts to each monitor
- `DpiAwarenessContextPerMonitorAwareV2` - **Recommended** for Windows 10 1703+
- `DpiAwarenessContextUnawareGdiScaled` - Improved unaware mode (Windows 10 1809+)

**Recommendation**: Use `DpiAwarenessContextPerMonitorAwareV2` for modern applications to ensure crisp rendering across all displays. This setting is particularly important for applications that will be used on high-DPI monitors or multi-monitor setups with different DPI settings.

**Note**: The DPI awareness setting affects the entire process and should be set early during window creation. On older Windows versions where the API is unavailable, the setting is silently ignored for backward compatibility.

## Demos

### Available Demos

**Basic centered window:**
```
go run ./cmd/demo-basic
```

**Positioned window with custom style:**
```
go run ./cmd/demo-positioned
```

**Borderless window:**
```
go run ./cmd/demo-borderless
```

**Tool window (top-right):**
```
go run ./cmd/demo-toolwindow
```

**Bottom-right positioned:**
```
go run ./cmd/demo-bottomright
```

**DPI awareness demonstration:**
```
go run ./cmd/demo-dpi-aware
```

**Accelerator keys (F5/F12 blocking):**
```
go run ./cmd/demo-accelerator-keys
```

This will use go-winloader to load an embedded copy of WebView2Loader.dll. If you want, you can also provide a newer version of WebView2Loader.dll in the DLL search path and it should be picked up instead. It can be acquired from the WebView2 SDK (which is permissively licensed.)
