// Package base64 implements the base64 codec (RFC 4648) without the Go
// standard library.
//
// It exists because `encoding/base64` costs a measured 18,740 bytes in a TinyGo
// wasm binary — real weight on the edge (Cloudflare Workers, goflare) for a
// transformation that is a lookup table and some bit shifting. The stdlib is
// TinyGo-compatible; this package is about size, not compatibility.
package base64

// invalidError is the package's only error. It is a bare type rather than
// fmt.Err/errors.New on purpose: this package must import NOTHING.
//
// Measured under TinyGo (wasm target), pulling in tinywasm/fmt just to build one
// error value costs ~74 KB — four times more than the whole encoding/base64 this
// package exists to avoid. A zero-import package is what makes it pay off.
type invalidError struct{}

func (invalidError) Error() string { return "base64 invalid" }

// ErrInvalid is returned for any input that is not well-formed base64.
var ErrInvalid error = invalidError{}

// urlAlphabet is the URL- and filename-safe alphabet (RFC 4648 §5). It differs
// from the standard one only in the last two symbols: '-' and '_' replace '+'
// and '/', which are unsafe in URLs and in JWT segments.
const urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// invalidByte marks a byte that is not part of the alphabet.
const invalidByte = 0xFF

// urlDecodeTable maps an ASCII byte to its 6-bit value, or invalidByte.
// An array, not a map: no hashing, no allocation, and it keeps the package free
// of map types.
var urlDecodeTable = newDecodeTable(urlAlphabet)

func newDecodeTable(alphabet string) [256]byte {
	var t [256]byte
	for i := range t {
		t[i] = invalidByte
	}
	for i := 0; i < len(alphabet); i++ {
		t[alphabet[i]] = byte(i)
	}
	return t
}

// URLEncode encodes src as base64url (RFC 4648 §5) WITHOUT padding.
//
// Unpadded is what JWT uses (equivalent to the stdlib's RawURLEncoding). The
// output never contains '+', '/' or '='.
func URLEncode(src []byte) string {
	if len(src) == 0 {
		return ""
	}

	// 3 input bytes (24 bits) map to 4 output chars (4 x 6 bits). A trailing
	// group of 1 byte yields 2 chars, of 2 bytes yields 3 chars.
	n := len(src) / 3 * 4
	switch len(src) % 3 {
	case 1:
		n += 2
	case 2:
		n += 3
	}

	dst := make([]byte, 0, n)
	i := 0
	for ; i+2 < len(src); i += 3 {
		v := uint(src[i])<<16 | uint(src[i+1])<<8 | uint(src[i+2])
		dst = append(dst,
			urlAlphabet[v>>18&0x3F],
			urlAlphabet[v>>12&0x3F],
			urlAlphabet[v>>6&0x3F],
			urlAlphabet[v&0x3F],
		)
	}

	switch len(src) - i {
	case 1:
		v := uint(src[i]) << 16
		dst = append(dst, urlAlphabet[v>>18&0x3F], urlAlphabet[v>>12&0x3F])
	case 2:
		v := uint(src[i])<<16 | uint(src[i+1])<<8
		dst = append(dst, urlAlphabet[v>>18&0x3F], urlAlphabet[v>>12&0x3F], urlAlphabet[v>>6&0x3F])
	}

	return string(dst)
}

// URLDecode decodes an unpadded base64url string.
//
// Every byte outside the alphabet is rejected, including '=', '+', '/' and
// whitespace: this decodes tokens, so leniency would mean accepting a signature
// segment the signer never produced.
func URLDecode(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}

	// A trailing group of exactly 1 char cannot encode any byte: valid unpadded
	// lengths are 4k, 4k+2 and 4k+3.
	if len(s)%4 == 1 {
		return nil, ErrInvalid
	}

	n := len(s) / 4 * 3
	switch len(s) % 4 {
	case 2:
		n++
	case 3:
		n += 2
	}

	dst := make([]byte, 0, n)
	var buf uint
	var bits uint

	for i := 0; i < len(s); i++ {
		c := urlDecodeTable[s[i]]
		if c == invalidByte {
			return nil, ErrInvalid
		}

		buf = buf<<6 | uint(c)
		bits += 6

		if bits >= 8 {
			bits -= 8
			dst = append(dst, byte(buf>>bits))
		}
	}

	return dst, nil
}
