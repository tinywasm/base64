---
message: "fix: reject non-canonical base64url — nonzero trailing bits (RFC 4648 §3.5)"
---

> Este plan se despacha vía el flujo CodeJob. Ver skill: agents-workflow.

# PLAN — `base64`: rechazar codificaciones no canónicas

> **Estado: ✅ COMPLETADO** — ejecutado localmente (no vía CodeJob) el 2026-07-14:
> comprobación de bits sobrantes en `URLDecode`, `test_DecodeCanonicality` registrado,
> README y doc de API actualizados (equivale a `RawURLEncoding.Strict()`).

Autocontenido, en español.

## Contexto (sin contexto previo)

`github.com/tinywasm/base64` es el codec base64url (RFC 4648 §5, sin padding) del
ecosistema. Es **deliberadamente un paquete con cero imports** — ni stdlib ni
`tinywasm/*` — porque su razón de existir es el tamaño del binario WASM/edge.

Su consumidor sensible es `github.com/tinywasm/jwt`: decodifica segmentos de tokens.
La auditoría de seguridad de esa librería (hallazgo **I-1** de
<https://github.com/tinywasm/jwt/blob/main/docs/SECURITY_AUDIT.md>) detectó el defecto
que este plan corrige.

## El problema: varias cadenas decodifican a los mismos bytes

En base64 sin padding, el último grupo parcial deja **bits sobrantes** (4 bits si
`len%4 == 2`, 2 bits si `len%4 == 3`). RFC 4648 §3.5 exige que esos bits sean **cero**;
si no se comprueba, cadenas distintas decodifican al mismo resultado:

```
URLDecode("Zg") → 0x66 ("f")   canónica  ('g' = 32, sobrante 0)
URLDecode("Zh") → 0x66 ("f")   NO canónica ('h' = 33, sobrante 1) — hoy se ACEPTA
```

`URLDecode` hoy descarta los bits sobrantes sin mirarlos. Consecuencia: **malleabilidad**
— un tercero puede reescribir un dato codificado en una variante distinta que decodifica
igual. En `jwt` no es explotable (la firma HMAC cubre el texto *codificado*, así que
cualquier variante rompe la autenticación), pero `DecodeUnverified` acepta grafías de
token que ningún firmante produjo, y cualquier consumidor futuro que use la cadena
codificada como clave/identidad heredaría el agujero. El propio doc del paquete promete
lo contrario: *"leniency would mean accepting a signature segment the signer never
produced"*.

## El cambio — `base64.go`, función `URLDecode`

El bucle de decodificación acumula en `buf` y lleva `bits` de resto. Al salir del bucle,
si quedan bits pendientes deben ser cero. Añade **después** del bucle, antes del
`return dst, nil`:

```go
	// RFC 4648 §3.5: the leftover bits of a final partial group MUST be zero.
	// Otherwise several encodings decode to the same bytes, and a decoder this
	// strict about the alphabet would still accept strings no encoder produces.
	if bits > 0 && buf&(1<<bits-1) != 0 {
		return nil, ErrInvalid
	}
```

Reglas obligatorias:

- **Cero imports se mantiene.** Nada de `fmt`/`errors` ni `tinywasm/fmt`: el error es el
  `ErrInvalid` que ya existe. No distingas la causa (canonicidad vs alfabeto): un solo
  error, como hasta ahora.
- **No toques `URLEncode`**: ya emite canónico siempre.
- **No añadas API** (ni `URLDecodeLenient` ni opciones). Estricto es el único modo.

## Tests — `shared_test.go`, patrón dual obligatorio

Añade `test_DecodeCanonicality` y regístralo en `RunBase64Tests` (los `TestXxx` sueltos
solo corren en uno de los dos entornos; las entradas son `backStlib_test.go` (!wasm) y
`frontWasm_test.go` (wasm) y **no se tocan**).

Pares canónica-aceptada / no-canónica-rechazada, escritos a mano:

```go
// len%4 == 2 → 4 bits sobrantes
{"Zg", ok},  // 'g'=32, sobrante 0000 — decodifica "f"
{"Zh", bad}, // 'h'=33, sobrante 0001
{"AQ", ok},  // 0x01
{"AR", bad}, // mismos bytes que "AQ" si no se comprueba
// len%4 == 3 → 2 bits sobrantes
{"AAA", ok},  // 0x00 0x00
{"AAB", bad}, // sobrante 01
{"Zm8", ok},  // "fo" (vector RFC)
{"Zm9", bad}, // sobrante no nulo
```

Para cada caso `bad`: `URLDecode` devuelve `(nil, ErrInvalid)` — exactamente `ErrInvalid`,
y el slice **nil**, igual que hace `test_DecodeErrors`. Para cada `ok`: decodifica sin
error. Verifica también que los 7 vectores RFC de `rfc4648Vectors` siguen pasando sin
cambios (son todos canónicos; si alguno falla, el parche está mal, no el vector).

## Efecto aguas abajo (informativo, no lo toques tú)

`tinywasm/jwt` se vuelve estricto en `DecodeUnverified` con tokens no canónicos. Ningún
token emitido por un firmante real se ve afectado (todos emiten canónico). No hay que
cambiar nada en `jwt`.

## Criterios de aceptación

1. `gotest` en verde (nativo + wasm) y `gotest -tinygo` en verde.
2. `test_DecodeCanonicality` registrado en `RunBase64Tests` y en verde.
3. El paquete sigue sin imports: `grep -n "import" base64.go` → vacío.
4. `grep -rn "func URLDecodeLenient\|Strict" base64.go` → vacío (no creció la API).
5. Nunca llames `gopush` ni `codejob`: herramientas locales, fuera del agente.

## Ciclo de vida de este archivo

No borres ni renombres este archivo: el flujo CodeJob lo gestiona.
