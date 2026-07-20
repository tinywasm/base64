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

// standardAlphabet is the RFC 4648 §4 alphabet used by JSON/HTTP payloads —
// data URIs, MCP content blocks, anything a browser decodes with atob() or a
// client SDK decodes as plain base64. '+' and '/' are fine there; only URLs
// and JWT segments need the URL-safe variant above.
const standardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// urlDecodeTable and standardDecodeTable map an ASCII byte to its 6-bit
// value, or invalidByte. Arrays, not maps: no hashing, no allocation, and it
// keeps the package free of map types.
var urlDecodeTable = newDecodeTable(urlAlphabet)
var standardDecodeTable = newDecodeTable(standardAlphabet)

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
// whitespace, and so is any non-canonical encoding (RFC 4648 §3.5: the unused
// trailing bits of the final group must be zero). This decodes tokens, so
// leniency would mean accepting a signature segment the signer never produced.
// It is equivalent to the stdlib's RawURLEncoding.Strict() — deliberately
// stricter than the stdlib default, which accepts non-canonical input.
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

	// RFC 4648 §3.5: the leftover bits of a final partial group MUST be zero.
	// Otherwise several encodings decode to the same bytes ("Zg" and "Zh" both
	// yield "f"), and a decoder this strict about the alphabet would still be
	// accepting strings no encoder produces.
	if bits > 0 && buf&(1<<bits-1) != 0 {
		return nil, ErrInvalid
	}

	return dst, nil
}

// Encode encodes src as standard base64 (RFC 4648 §4) WITH padding —
// equivalent to the stdlib's StdEncoding. This is what data URIs, MCP image
// content, and most JSON/HTTP payloads expect; use URLEncode instead for
// tokens embedded in a URL or a JWT segment.
func Encode(src []byte) string {
	if len(src) == 0 {
		return ""
	}

	n := (len(src) + 2) / 3 * 4
	dst := make([]byte, 0, n)
	i := 0
	for ; i+2 < len(src); i += 3 {
		v := uint(src[i])<<16 | uint(src[i+1])<<8 | uint(src[i+2])
		dst = append(dst,
			standardAlphabet[v>>18&0x3F],
			standardAlphabet[v>>12&0x3F],
			standardAlphabet[v>>6&0x3F],
			standardAlphabet[v&0x3F],
		)
	}

	switch len(src) - i {
	case 1:
		v := uint(src[i]) << 16
		dst = append(dst, standardAlphabet[v>>18&0x3F], standardAlphabet[v>>12&0x3F], '=', '=')
	case 2:
		v := uint(src[i])<<16 | uint(src[i+1])<<8
		dst = append(dst, standardAlphabet[v>>18&0x3F], standardAlphabet[v>>12&0x3F], standardAlphabet[v>>6&0x3F], '=')
	}

	return string(dst)
}

// Decode decodes a padded standard base64 string (RFC 4648 §4), equivalent
// to the stdlib's StdEncoding.Strict(). Padding is required and its length
// must match the trailing group size; any '=' outside the final group — or
// any byte outside the standard alphabet — is rejected via the same
// canonicality rule URLDecode applies.
func Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}
	if len(s)%4 != 0 {
		return nil, ErrInvalid
	}

	padding := 0
	if s[len(s)-1] == '=' {
		padding = 1
		if s[len(s)-2] == '=' {
			padding = 2
		}
	}
	core := s[:len(s)-padding]

	switch len(core) % 4 {
	case 0:
		if padding != 0 {
			return nil, ErrInvalid
		}
	case 2:
		if padding != 2 {
			return nil, ErrInvalid
		}
	case 3:
		if padding != 1 {
			return nil, ErrInvalid
		}
	default:
		return nil, ErrInvalid
	}

	dst := make([]byte, 0, len(s)/4*3-padding)
	var buf uint
	var bits uint

	for i := 0; i < len(core); i++ {
		c := standardDecodeTable[core[i]]
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

	if bits > 0 && buf&(1<<bits-1) != 0 {
		return nil, ErrInvalid
	}

	return dst, nil
}
