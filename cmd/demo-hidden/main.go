package main

import (
	"log"
	"time"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	// Demo 1: Basic centered window
	// This demonstrates the simplest window configuration with centered positioning
	w, _ := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug: true,
		WindowOptions: webview2.WindowOptions{
			Title:               "Basic Centered Window Demo",
			Width:               800,
			Height:              600,
			IconId:              2,    // icon resource id
			Center:              true, // Center the window on screen
			Style:               webview2.WindowStyleBorderless,
			DpiAwarenessContext: webview2.DpiAwarenessContextPerMonitorAwareV2,
			Hidden:              true, // Pre-warmed window starts hidden
		},
		WebAuthn: webview2.WebAuthnOptions{
			Enabled: webview2.IsWebAuthnDLLAvailable(),
			OnWindowsHelloFallback: func(op webview2.WebAuthnOperation, err error) bool {
				return false
			},
		},
	})
	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()

	w.Navigate("https://en.m.wikipedia.org/wiki/Main_Page")
	w.Hide()
	// after 3sec, show the window (simulate pre-warming)

	go func() {
		time.Sleep(3 * time.Second)
		w.ShowUrl("https://immortal-pc.info")
	}()
	w.Run()
}
