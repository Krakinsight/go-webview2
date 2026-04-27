package main

import (
	"log"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	// Demo 2: Positioned window with custom style and User-Agent
	// This demonstrates precise window positioning from the top-left corner
	// with a fixed (non-resizable) style and custom User-Agent
	w,_ := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		UserAgent: "CustomApp/1.0 (Demo-Positioned)",
		WindowOptions: webview2.WindowOptions{
			Title:    "Positioned Window Demo",
			Width:    1024,
			Height:   768,
			Location: &webview2.Location{X: 100, Y: 100}, // 100px from left, 100px from top
			Style:    webview2.WindowStyleFixed,          // Non-resizable window
		},
	})

	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()
	
	w.Navigate("https://en.m.wikipedia.org/wiki/Main_Page")
	w.Run()
}
