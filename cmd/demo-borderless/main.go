package main

import (
	"log"

	"github.com/jchv/go-webview2"
)

func main() {
	// Demo 3: Borderless window
	// This demonstrates a window without title bar or borders, useful for creating
	// custom UI with your own controls
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:    "Borderless Window Demo",
			Width:    800,
			Height:   600,
			Location: &webview2.Location{X: 200, Y: 200}, // Positioned at 200,200
			Style:    webview2.WindowStyleBorderless,     // No borders or title bar
		},
	})

	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()
	
	w.Navigate("https://en.m.wikipedia.org/wiki/Main_Page")
	w.Run()
}
