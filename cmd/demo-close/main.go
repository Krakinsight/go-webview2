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
			Title:  "Window Close Demo",
			Width:  600,
			Height: 400,
			Center: true,
		},
	})

	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()

	// Bind close function
	w.Bind("close2", func() {
		log.Printf("Closing !")
		w.Destroy()
	})

	w.SetHtml(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Close Demo</title>
			<style>
				body {
					font-family: Arial, sans-serif;
					max-width: 500px;
					margin: 50px auto;
					padding: 20px;
					background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
					min-height: 100vh;
					display: flex;
					align-items: center;
					justify-content: center;
				}
				.container {
					background: white;
					padding: 40px;
					border-radius: 15px;
					box-shadow: 0 20px 60px rgba(0,0,0,0.3);
				}
				h1 {
					color: #333;
					margin-bottom: 20px;
				}
				p {
					color: #666;
					margin-bottom: 25px;
					line-height: 1.6;
				}
				button {
					padding: 15px 30px;
					font-size: 16px;
					margin: 10px 5px;
					cursor: pointer;
					border: none;
					border-radius: 8px;
					font-weight: 600;
					transition: all 0.3s ease;
					display: inline-block;
				}
				button:hover {
					transform: translateY(-2px);
					box-shadow: 0 5px 15px rgba(0,0,0,0.2);
				}
				.close-btn {
					background: #dc3545;
					color: white;
				}
				.close-btn:hover {
					background: #c82333;
				}
				.confirm-btn {
					background: #ffc107;
					color: black;
				}
				.confirm-btn:hover {
					background: #e0a800;
				}
				.info {
					background: #e7f3ff;
					border-left: 4px solid #2196F3;
					padding: 15px;
					margin-top: 20px;
					border-radius: 5px;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<h1>🪟 Window Close Demo</h1>
				<p>This demonstrates the built-in <code>close()</code> function that's automatically available in JavaScript.</p>
				
				<button class="close-btn" onclick="window.close()">
					🚪 Close window.Close()
				</button>

				<button class="close-btn" onclick="window.close2()">
					🚪 Close window.close2()// Binding
				</button>

				<button class="confirm-btn" onclick="if(confirm('Are you sure you want to close?')) close()">
					⚠️ Close with Confirmation
				</button>
				
				<div class="info">
					<strong>ℹ️ Info:</strong> The <code>close()</code> function is automatically bound by go-webview2 and calls <code>w.Destroy()</code> when invoked from JavaScript.
				</div>
			</div>
		</body>
		</html>
	`)

	w.Run()
}
