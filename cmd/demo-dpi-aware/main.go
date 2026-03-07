package main

import (
	"log"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:               "DPI Aware WebView2 Demo",
			Width:               800,
			Height:              600,
			Center:              true,
			DpiAwarenessContext: webview2.DpiAwarenessContextPerMonitorAwareV2,
		},
	})

	if w == nil {
		log.Fatal("Failed to load webview")
	}
	defer w.Destroy()

	// Simple HTML to demonstrate DPI awareness
	// On high-DPI displays, this should render crisp and clear
	html := `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
			display: flex;
			flex-direction: column;
			align-items: center;
			justify-content: center;
			min-height: 100vh;
			margin: 0;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			color: white;
		}
		.container {
			text-align: center;
			background: rgba(255, 255, 255, 0.1);
			padding: 40px;
			border-radius: 20px;
			backdrop-filter: blur(10px);
			box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
		}
		h1 {
			font-size: 2.5em;
			margin: 0 0 20px 0;
			font-weight: 300;
		}
		.dpi-info {
			margin-top: 30px;
			font-size: 1.1em;
			line-height: 1.6;
		}
		.metric {
			margin: 10px 0;
			padding: 10px;
			background: rgba(255, 255, 255, 0.1);
			border-radius: 5px;
		}
		.label {
			font-weight: bold;
			color: #ffd700;
		}
		.test-text {
			margin-top: 20px;
			font-size: 0.9em;
			font-style: italic;
			opacity: 0.8;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>🖥️ DPI Awareness Demo</h1>
		<p>This window is using <strong>Per-Monitor DPI Awareness V2</strong></p>
		<div class="dpi-info">
			<div class="metric">
				<span class="label">Device Pixel Ratio:</span> 
				<span id="dpr"></span>
			</div>
			<div class="metric">
				<span class="label">Screen Resolution:</span> 
				<span id="resolution"></span>
			</div>
			<div class="metric">
				<span class="label">Window Size:</span> 
				<span id="windowSize"></span>
			</div>
		</div>
		<p class="test-text">
			Move this window between monitors with different DPI settings to test per-monitor DPI awareness.
			Text and graphics should remain crisp on all displays.
		</p>
	</div>
	<script>
		function updateInfo() {
			document.getElementById('dpr').textContent = window.devicePixelRatio.toFixed(2);
			document.getElementById('resolution').textContent = 
				screen.width + ' × ' + screen.height + ' pixels';
			document.getElementById('windowSize').textContent = 
				window.innerWidth + ' × ' + window.innerHeight + ' pixels';
		}
		
		updateInfo();
		
		// Update info when window is resized or moved
		window.addEventListener('resize', updateInfo);
		
		// Check for DPI changes periodically (when moved between monitors)
		setInterval(updateInfo, 1000);
	</script>
</body>
</html>`

	w.SetHtml(html)
	w.Run()
}
