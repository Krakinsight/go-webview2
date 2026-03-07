package main

import (
	"log"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	// Demo 4: Tool window
	// This demonstrates a tool window style - a small window with smaller title bar
	// that is not shown in the taskbar, typically used for auxiliary tools
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:    "Tool Window Demo",
			Width:    400,
			Height:   300,
			Location: &webview2.Location{X: -420, Y: 20}, // 420px from right (20px margin), 20px from top
			Style:    webview2.WindowStyleToolWindow,     // Tool window (not in taskbar)
		},
	})

	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()
	
	w.Navigate("https://en.m.wikipedia.org/wiki/Main_Page")
	w.Run()
}
