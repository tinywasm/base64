package base64

import (
	"bytes"
	"strings"
	"testing"
)

const bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func test_AlphabetValidation(t *testing.T) {
	// 63 caracteres
	if _, err := NewEncoding(bcryptAlphabet[:63], false); err != ErrAlphabetLength {
		t.Errorf("alfabeto 63 chars: error = %v, want ErrAlphabetLength", err)
	}
	// 65 caracteres
	if _, err := NewEncoding(bcryptAlphabet+"X", false); err != ErrAlphabetLength {
		t.Errorf("alfabeto 65 chars: error = %v, want ErrAlphabetLength", err)
	}
	// repetido: duplicar primer char
	dup := "A" + bcryptAlphabet[1:] // '.' reemplazado por 'A', ahora hay dos 'A'
	// bcryptAlphabet es "./ABC...": segundo char es '/', tercer char es 'A'. Si ponemos 'A' al inicio, duplicamos.
	// Mejor: tomar standardAlphabet y duplicar primer char al final.
	dup2 := standardAlphabet[:63] + "A"
	if _, err := NewEncoding(dup, false); err != ErrAlphabetDuplicate {
		// intenta con dup2 si dup no dispara por otro motivo
		if _, err2 := NewEncoding(dup2, false); err2 != ErrAlphabetDuplicate {
			t.Errorf("alfabeto duplicado: error = %v / %v, want ErrAlphabetDuplicate", err, err2)
		}
	}
	// duplicado explícito con estándar
	if _, err := NewEncoding(dup2, false); err != ErrAlphabetDuplicate {
		t.Errorf("alfabeto duplicado (std): error = %v, want ErrAlphabetDuplicate", err)
	}
	// no ASCII: byte >127
	badASCII := string(append([]byte(bcryptAlphabet[:63]), 0xFF))
	if _, err := NewEncoding(badASCII, false); err != ErrAlphabetNonASCII {
		t.Errorf("alfabeto non-ASCII: error = %v, want ErrAlphabetNonASCII", err)
	}
}

func test_BcryptRoundTrip(t *testing.T) {
	enc, err := NewEncoding(bcryptAlphabet, false)
	if err != nil {
		t.Fatalf("NewEncoding bcrypt: %v", err)
	}
	for n := 0; n <= 64; n++ {
		src := make([]byte, n)
		for i := range src {
			src[i] = byte(i*7 + n*3)
		}
		encoded := enc.Encode(src)
		// bcrypt alphabet no usa '=', verificar que nunca aparezca
		if strings.Contains(encoded, "=") {
			t.Fatalf("bcrypt encode de %d bytes contiene '=': %q", n, encoded)
		}
		got, err := enc.Decode(encoded)
		if err != nil {
			t.Fatalf("bcrypt round-trip %d bytes decode failed: %v", n, err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("bcrypt round-trip %d bytes: got %v, want %v", n, got, src)
		}
	}
}

func test_NoPadding(t *testing.T) {
	enc, err := NewEncoding(bcryptAlphabet, false)
	if err != nil {
		t.Fatalf("NewEncoding: %v", err)
	}
	// 1 byte -> 2 chars sin '='
	s1 := enc.Encode([]byte{0xFF})
	if strings.Contains(s1, "=") {
		t.Errorf("pad=false 1 byte: %q contiene '='", s1)
	}
	if len(s1) != 2 {
		t.Errorf("pad=false 1 byte: len = %d, want 2 (%q)", len(s1), s1)
	}
	// 2 bytes -> 3 chars sin '='
	s2 := enc.Encode([]byte{0xFF, 0xFE})
	if strings.Contains(s2, "=") {
		t.Errorf("pad=false 2 bytes: %q contiene '='", s2)
	}
	if len(s2) != 3 {
		t.Errorf("pad=false 2 bytes: len = %d, want 3 (%q)", len(s2), s2)
	}
}

func test_StdAlphabetWithPad(t *testing.T) {
	enc, err := NewEncoding(standardAlphabet, true)
	if err != nil {
		t.Fatalf("NewEncoding std pad: %v", err)
	}
	for n := 0; n <= 64; n++ {
		src := make([]byte, n)
		for i := range src {
			src[i] = byte(i*11 + n*5)
		}
		if got := enc.Encode(src); got != Encode(src) {
			t.Fatalf("std pad Encode mismatch n=%d: got %q, want %q", n, got, Encode(src))
		}
		// También verificar EncodedLen / DecodedLen coherencia
		if enc.EncodedLen(n) != len(Encode(src)) {
			t.Errorf("EncodedLen(%d) = %d, want %d", n, enc.EncodedLen(n), len(Encode(src)))
		}
	}
}

func test_InvalidCharacter(t *testing.T) {
	enc, err := NewEncoding(bcryptAlphabet, false)
	if err != nil {
		t.Fatalf("NewEncoding: %v", err)
	}
	// bcrypt alphabet no contiene '+', así que '+' debe fallar
	if _, err := enc.Decode("AB+C"); err != ErrInvalidCharacter {
		t.Errorf("carácter fuera alfabeto: error = %v, want ErrInvalidCharacter", err)
	}
	// '=' con pad=false debe ser ErrInvalidCharacter
	if _, err := enc.Decode("AB=="); err != ErrInvalidCharacter {
		t.Errorf("pad=false con '=': error = %v, want ErrInvalidCharacter", err)
	}
}

func test_InvalidLength(t *testing.T) {
	enc, err := NewEncoding(bcryptAlphabet, false)
	if err != nil {
		t.Fatalf("NewEncoding: %v", err)
	}
	// longitud 1 sin relleno es imposible
	if _, err := enc.Decode("A"); err != ErrInvalidLength {
		t.Errorf("longitud 1 sin relleno: error = %v, want ErrInvalidLength", err)
	}
	// 5 chars -> 5%4==1 también imposible
	if _, err := enc.Decode("ABCDE"); err != ErrInvalidLength {
		t.Errorf("longitud 5 sin relleno: error = %v, want ErrInvalidLength", err)
	}
	// con pad=true longitud no múltiplo de 4
	encPad, _ := NewEncoding(standardAlphabet, true)
	if _, err := encPad.Decode("ABC"); err != ErrInvalidLength {
		t.Errorf("pad=true len 3: error = %v, want ErrInvalidLength", err)
	}
}

func test_AlphabetEncodedDecodedLen(t *testing.T) {
	enc, _ := NewEncoding(bcryptAlphabet, false)
	encPad, _ := NewEncoding(standardAlphabet, true)
	for n := 0; n <= 64; n++ {
		src := make([]byte, n)
		for i := range src {
			src[i] = byte(i)
		}
		s := enc.Encode(src)
		if enc.EncodedLen(n) != len(s) {
			t.Errorf("EncodedLen raw n=%d: got %d, want %d", n, enc.EncodedLen(n), len(s))
		}
		if enc.DecodedLen(len(s)) != n {
			t.Errorf("DecodedLen raw n=%d len(s)=%d: got %d, want %d", n, len(s), enc.DecodedLen(len(s)), n)
		}
		s2 := encPad.Encode(src)
		if encPad.EncodedLen(n) != len(s2) {
			t.Errorf("EncodedLen pad n=%d: got %d, want %d", n, encPad.EncodedLen(n), len(s2))
		}
		// DecodedLen para pad es cota superior (n/4*3), no exacta con relleno.
		if got := encPad.DecodedLen(len(s2)); got < n || got != len(s2)/4*3 {
			t.Errorf("DecodedLen pad n=%d len(s2)=%d: got %d, want >=%d y ==%d", n, len(s2), got, n, len(s2)/4*3)
		}
		// Verificar que decodificar realmente devuelve n bytes.
		dec, err := encPad.Decode(s2)
		if err != nil {
			t.Fatalf("decode pad n=%d failed: %v", n, err)
		}
		if len(dec) != n {
			t.Errorf("decode pad n=%d: len=%d, want %d", n, len(dec), n)
		}
	}
}
