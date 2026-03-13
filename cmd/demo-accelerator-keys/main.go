package main

import (
	"fmt"
	"log"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "Accelerator Keys Demo",
			Width:  800,
			Height: 600,
			Center: true,
		},
	})

	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()

	// Set up accelerator key handler
	w.SetAcceleratorKeyCallback(func(vk uint) bool {
		keyName := getKeyName(vk)

		switch vk {
		case 0x1B: // VK_ESCAPE
			fmt.Printf("[HANDLED] ESC (0x%02X) - Closing window\n", vk)
			w.Destroy()
			return true

		case 0x74: // VK_F5
			fmt.Printf("[BLOCKED] F5 (0x%02X) - Refresh\n", vk)
			return true

		case 0x7B: // VK_F12
			fmt.Printf("[BLOCKED] F12 (0x%02X) - DevTools\n", vk)
			return true

		case 0x77: // VK_F8
			fmt.Printf("[ALLOWED] F8 (0x%02X) - Custom action triggered\n", vk)
			// Could trigger custom functionality here
			return false

		default:
			fmt.Printf("[PASSTHROUGH] %s (0x%02X)\n", keyName, vk)
			return false
		}
	})

	// Navigate to test page
	w.SetHtml(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Accelerator Keys Test</title>
			<style>
				body {
					font-family: Arial, sans-serif;
					max-width: 800px;
					margin: 50px auto;
					padding: 20px;
				}
				.key-test {
					background: #f0f0f0;
					padding: 20px;
					margin: 10px 0;
					border-radius: 5px;
				}
				.blocked { background: #ffcccc; }
				.allowed { background: #ccffcc; }
				code {
					background: #e0e0e0;
					padding: 2px 6px;
					border-radius: 3px;
				}
			</style>
		</head>
		<body>
			<h1>Accelerator Keys Demo</h1>
			<p>Try pressing the following keys and watch the console output:</p>
			
			<div class="key-test blocked">
				<h3>🚫 Blocked Keys</h3>
				<ul>
					<li><code>F5</code> - Refresh (blocked)</li>
					<li><code>F12</code> - DevTools (blocked)</li>
				</ul>
			</div>
			
			<div class="key-test allowed">
				<h3>✅ Allowed Keys</h3>
				<ul>
					<li><code>ESC</code> - Closes the window (custom handler)</li>
					<li><code>F8</code> - Custom action (logged but not blocked)</li>
					<li>All other keys - Pass through normally</li>
				</ul>
			</div>
			
			<div class="key-test">
				<h3>📝 Test Input</h3>
				<input type="text" placeholder="Type here to test keyboard..." 
					   style="width: 100%; padding: 10px; font-size: 16px;">
			</div>
			
			<div class="key-test">
				<h3>ℹ️ Instructions</h3>
				<ol>
					<li>Press <code>F5</code> - The page should NOT refresh</li>
					<li>Press <code>F12</code> - DevTools should NOT open</li>
					<li>Press <code>F8</code> - Check console for custom message</li>
					<li>Press <code>ESC</code> - Window will close</li>
					<li>Type normally in the input field - All keys work</li>
				</ol>
			</div>
		</body>
		</html>
	`)

	w.Run()
}

// getKeyName returns a human-readable name for common virtual keys
func getKeyName(vk uint) string {
	keyNames := map[uint]string{
		0x08: "Backspace", 0x09: "Tab", 0x0D: "Enter",
		0x10: "Shift", 0x11: "Ctrl", 0x12: "Alt",
		0x1B: "Escape", 0x20: "Space",
		0x70: "F1", 0x71: "F2", 0x72: "F3", 0x73: "F4",
		0x74: "F5", 0x75: "F6", 0x76: "F7", 0x77: "F8",
		0x78: "F9", 0x79: "F10", 0x7A: "F11", 0x7B: "F12",
	}

	if name, ok := keyNames[vk]; ok {
		return name
	}

	// Letters A-Z
	if vk >= 0x41 && vk <= 0x5A {
		return string(rune(vk))
	}

	// Numbers 0-9
	if vk >= 0x30 && vk <= 0x39 {
		return string(rune(vk))
	}

	return fmt.Sprintf("Unknown Key")
}
