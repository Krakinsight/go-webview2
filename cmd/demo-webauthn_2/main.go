package main

import (
	"errors"
	"log"
	"syscall"
	"time"
	"unsafe"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "WebAuthn Bridge Demo",
			Width:  900,
			Height: 700,
			Center: true,
		},
	})

	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()

	// Enable WebAuthn bridge
	bridge := w.EnableWebAuthnBridge()
	bridge.SetTimeout(60 * time.Second)

	// Step 1: Optional gate — returning true cancels the operation.
	// Returning false (or nil callback) proceeds to Windows Hello.
	bridge.OnUserApproval = func(op webview2.WebAuthnOperation) bool {
		log.Printf("WebAuthn gate: Type=%s, RPID=%s", op.Type, op.RPID)

		result := messageBox(
			0,
			"WebAuthn operation requested\n\n"+
				"Type: "+op.Type+"\n"+
				"RP: "+op.RPName+" ("+op.RPID+")\n\n"+
				"Click Cancel to abort.",
			"WebAuthn",
			0x00000001|0x00000020, // MB_OKCANCEL | MB_ICONQUESTION
		)

		cancelled := result != 1 // IDOK=1 → not cancelled; anything else → cancelled
		if cancelled {
			log.Println("Operation cancelled by user")
		}
		return cancelled // true = abort
	}

	// Step 3: Called when Windows Hello fails.
	// If no credential exists yet (NTE_NO_KEY), silently fall back to internal ECDSA.
	// For any other failure, ask the user.
	bridge.OnWindowsHelloFallback = func(op webview2.WebAuthnOperation, whErr error) bool {
		if errors.Is(whErr, webview2.ErrWindowsHelloNoCredential) {
			log.Println("No Windows Hello credential found, using internal ECDSA fallback")
			return true
		}

		log.Printf("Windows Hello failed (%v), offering ECDSA fallback", whErr)
		result := messageBox(
			0,
			"Windows Hello failed:\n"+whErr.Error()+"\n\nUse software ECDSA fallback instead?",
			"Windows Hello Failed",
			0x00000001|0x00000030, // MB_OKCANCEL | MB_ICONWARNING
		)
		use := result == 1
		if use {
			log.Println("Using internal ECDSA fallback")
		}
		return use
	}

	// Log Windows Hello availability
	if webview2.IsWebAuthnDLLAvailable() {
		version, _ := webview2.GetWebAuthnAPIVersion()
		log.Printf("Windows Hello is available (WebAuthn API version: %d)", version)
		bridge.OnUserApproval = nil // Use automatic Windows Hello fallback without custom approval dialog
	} else {
		log.Printf("Windows Hello (webauthn.dll) not available")
	}

	w.Navigate("https://webauthn.io/")
	w.Run()
}

// messageBox wraps Windows MessageBox API for approval dialogs
func messageBox(hwnd uintptr, text, caption string, flags uint32) int {
	user32 := syscall.MustLoadDLL("user32.dll")
	messageBoxW := user32.MustFindProc("MessageBoxW")

	textUTF16, _ := syscall.UTF16PtrFromString(text)
	captionUTF16, _ := syscall.UTF16PtrFromString(caption)

	ret, _, _ := messageBoxW.Call(
		hwnd,
		uintptr(unsafe.Pointer(textUTF16)),
		uintptr(unsafe.Pointer(captionUTF16)),
		uintptr(flags),
	)

	return int(ret)
}
