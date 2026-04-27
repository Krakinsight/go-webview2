package main

import (
	"log"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	// Demo 1: Basic centered window
	// This demonstrates the simplest window configuration with centered positioning
	w, _ := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "Basic Centered Window Demo",
			Width:  800,
			Height: 600,
			IconId: 2,    // icon resource id
			Center: true, // Center the window on screen
		},
	})

	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()

	w.SetSize(800, 600, webview2.HintFixed)
	w.Navigate("https://en.m.wikipedia.org/wiki/Main_Page")
	w.Run()
}
