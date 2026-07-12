# base64
<img src="docs/img/badges.svg">

Códec base64 (RFC 4648) con **cero dependencias** — ni stdlib ni `tinywasm/*` —
pensado para binarios WASM del edge (Cloudflare Workers, `goflare`) compilados
con TinyGo.

## Por qué existe

`encoding/base64` **sí es compatible con TinyGo**. Este paquete no se justifica
por compatibilidad sino por **tamaño**: base64 es una tabla de lookup y unos
desplazamientos de bits, y la versión del stdlib arrastra bastante más de lo que
esa tarea necesita.

Medido con TinyGo 0.41.1 (`-target wasm`), el mismo programa mínimo que codifica
y decodifica una cadena:

| Implementación | Binario `.wasm` |
|---|---|
| `encoding/base64` | 154 115 bytes |
| `tinywasm/base64` | 122 967 bytes |
| **ahorro** | **31 148 bytes (20 %)** |

### La regla que hay detrás: cero imports o no compensa

La primera versión de este paquete importaba `tinywasm/fmt` solo para declarar su
error. El resultado fue **74 KB más grande que el stdlib**: la dependencia costaba
cuatro veces más que todo lo que el códec ahorraba.

Por eso el error se declara con un tipo propio y el paquete **no importa nada**:

```go
type invalidError struct{}

func (invalidError) Error() string { return "base64 invalid" }

var ErrInvalid error = invalidError{}
```

Un paquete de utilidad para el edge solo compensa si es de cero dependencias. Si
alguna vez hay que importar algo aquí, hay que volver a medir: puede dejar de
tener sentido.

## API

```go
// base64url (RFC 4648 §5), SIN padding — la codificación que usa JWT.
// Equivale a encoding/base64.RawURLEncoding.
func URLEncode(src []byte) string
func URLDecode(s string) ([]byte, error)

var ErrInvalid error
```

Sin constructor y sin estado: funciones directas a nivel de paquete, como el
resto del ecosistema.

## Uso

```go
package main

import (
	"fmt"

	"github.com/tinywasm/base64"
)

func main() {
	s := base64.URLEncode([]byte("hello"))
	fmt.Println(s) // aGVsbG8

	b, err := base64.URLDecode(s)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b)) // hello
}
```

## Garantías

- **Idéntico al stdlib**: verificado contra `encoding/base64.RawURLEncoding` en
  200/200 entradas aleatorias, en codificación y decodificación.
- **Vectores RFC 4648 §10**, no solo round-trips: un round-trip pasa igual aunque
  las dos direcciones estén mal del mismo modo.
- **URL-safe**: la salida nunca contiene `+`, `/` ni `=` (usa `-` y `_` para los
  índices 62 y 63).
- **Estricto al decodificar**: rechaza padding, alfabeto estándar, espacios y
  cualquier byte fuera del alfabeto. Decodifica *tokens*: ser permisivo
  significaría aceptar una firma que el emisor nunca generó.
- **Sin `map`**: la tabla de decodificación es un `[256]byte`.

## Tests

```bash
go install github.com/tinywasm/devflow/cmd/gotest@latest
gotest           # nativo + wasm (compilador de Go)
gotest -tinygo   # suite WASM compilada con TinyGo real
```

Patrón dual: la lógica vive en `RunBase64Tests` (`shared_test.go`) y los dos
puntos de entrada (`backStlib_test.go` con `!wasm`, `frontWasm_test.go` con
`wasm`) delegan en ella.
