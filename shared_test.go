package base64

import (
	"bytes"
	"strings"
	"testing"
)

// RunBase64Tests is the single source of truth for both environments.
// Entry points: backStlib_test.go (!wasm) and frontWasm_test.go (wasm).
func RunBase64Tests(t *testing.T) {
	t.Run("URLVectors", test_URLVectors)
	t.Run("URLSafeAlphabet", test_URLSafeAlphabet)
	t.Run("RoundTrip", test_RoundTrip)
	t.Run("DecodeErrors", test_DecodeErrors)
	t.Run("DecodeVectors", test_DecodeVectors)
}

// rfc4648Vectors are the RFC 4648 §10 test vectors, unpadded (RawURLEncoding).
// Known-answer vectors, not just round-trips: a round-trip passes even when
// encode and decode are wrong in the same way.
var rfc4648Vectors = []struct {
	decoded string
	encoded string
}{
	{"", ""},
	{"f", "Zg"},
	{"fo", "Zm8"},
	{"foo", "Zm9v"},
	{"foob", "Zm9vYg"},
	{"fooba", "Zm9vYmE"},
	{"foobar", "Zm9vYmFy"},
}

func test_URLVectors(t *testing.T) {
	for _, v := range rfc4648Vectors {
		got := URLEncode([]byte(v.decoded))
		if got != v.encoded {
			t.Errorf("URLEncode(%q) = %q, want %q", v.decoded, got, v.encoded)
		}
	}
}

func test_DecodeVectors(t *testing.T) {
	for _, v := range rfc4648Vectors {
		got, err := URLDecode(v.encoded)
		if err != nil {
			t.Errorf("URLDecode(%q) failed: %v", v.encoded, err)
			continue
		}
		if string(got) != v.decoded {
			t.Errorf("URLDecode(%q) = %q, want %q", v.encoded, got, v.decoded)
		}
	}
}

func test_URLSafeAlphabet(t *testing.T) {
	// 0xfb,0xff exercises indexes 62 and 63, the two symbols that differ from
	// the standard alphabet. If '+' or '/' ever show up, the output would break
	// URLs and JWT segments.
	got := URLEncode([]byte{0xfb, 0xff})
	if got != "-_8" {
		t.Errorf("URLEncode([0xfb 0xff]) = %q, want %q", got, "-_8")
	}

	for _, bad := range []string{"+", "/", "="} {
		if strings.Contains(got, bad) {
			t.Errorf("output %q contains %q, which is not URL-safe", got, bad)
		}
	}
}

func test_RoundTrip(t *testing.T) {
	for n := 0; n <= 64; n++ {
		src := make([]byte, n)
		for i := range src {
			// Spread across the full byte range so every 6-bit index is hit.
			src[i] = byte(i*7 + n*3)
		}

		got, err := URLDecode(URLEncode(src))
		if err != nil {
			t.Fatalf("round trip of %d bytes failed: %v", n, err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("round trip of %d bytes: got %v, want %v", n, got, src)
		}
	}
}

func test_DecodeErrors(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"padded", "Zg=="},
		{"standard alphabet", "+/8"},
		{"non-alphabet byte", "Zg!"},
		{"trailing group of one", "Zm9vYmFyZ"},
		{"whitespace", "Zm 9v"},
	}

	for _, c := range cases {
		got, err := URLDecode(c.input)
		if err != ErrInvalid {
			t.Errorf("URLDecode(%q) [%s] error = %v, want ErrInvalid", c.input, c.name, err)
		}
		if got != nil {
			t.Errorf("URLDecode(%q) [%s] returned %v, want nil on error", c.input, c.name, got)
		}
	}
}
