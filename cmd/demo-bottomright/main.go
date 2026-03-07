package main

import (
	"log"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	// Demo 5: Bottom-right positioned window
	// This demonstrates negative coordinates for positioning from screen edges
	// X: -500 means 500px from the right edge of the work area
	// Y: -1 means 1px from the bottom edge of the work area (excludes taskbar)
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:    "Bottom-Right Window Demo",
			Width:    480,
			Height:   360,
			Location: &webview2.Location{X: -1, Y: -1}, // 500px from right, 1px from bottom (taskbar-safe)
		},
	})

	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()

	w.Navigate("https://en.m.wikipedia.org/wiki/Main_Page")
	w.Run()
}
