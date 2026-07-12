//go:build wasm

package base64

import "testing"

func TestBase64_WASM(t *testing.T) {
	RunBase64Tests(t)
}
