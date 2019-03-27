package topdown

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"github.com/lestrrat-go/jwx/buffer"
	"github.com/lestrrat-go/jwx/jws"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/open-policy-agent/opa/ast"
)

func TestParseTokenConstraints(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		var constraints tokenConstraints
		var err error
		c := ast.NewObject()
		constraints, err = parseTokenConstraints(c)
		if err != nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
		if constraints.alg != "" {
			t.Errorf("alg: %v", constraints.alg)
		}
		if constraints.key != nil {
			t.Errorf("key: %v", constraints.key)
		}
	})
	t.Run("Alg", func(t *testing.T) {
		var constraints tokenConstraints
		var err error
		c := ast.NewObject()
		c.Insert(ast.StringTerm("alg"), ast.StringTerm("RS256"))
		constraints, err = parseTokenConstraints(c)
		if err != nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
		if constraints.alg != "RS256" {
			t.Errorf("alg: %v", constraints.alg)
		}
	})
	t.Run("Cert", func(t *testing.T) {
		var constraints tokenConstraints
		var err error
		c := ast.NewObject()
		c.Insert(ast.StringTerm("cert"), ast.StringTerm(`-----BEGIN CERTIFICATE-----
MIIBcDCCARagAwIBAgIJAMZmuGSIfvgzMAoGCCqGSM49BAMCMBMxETAPBgNVBAMM
CHdoYXRldmVyMB4XDTE4MDgxMDE0Mjg1NFoXDTE4MDkwOTE0Mjg1NFowEzERMA8G
A1UEAwwId2hhdGV2ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATPwn3WCEXL
mjp/bFniDwuwsfu7bASlPae2PyWhqGeWwe23Xlyx+tSqxlkXYe4pZ23BkAAscpGj
yn5gXHExyDlKo1MwUTAdBgNVHQ4EFgQUElRjSoVgKjUqY5AXz2o74cLzzS8wHwYD
VR0jBBgwFoAUElRjSoVgKjUqY5AXz2o74cLzzS8wDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDAgNIADBFAiEA4yQ/88ZrUX68c6kOe9G11u8NUaUzd8pLOtkKhniN
OHoCIHmNX37JOqTcTzGn2u9+c8NlnvZ0uDvsd1BmKPaUmjmm
-----END CERTIFICATE-----`))
		constraints, err = parseTokenConstraints(c)
		if err != nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
		pubKey := constraints.key.(*ecdsa.PublicKey)
		if pubKey.Curve != elliptic.P256() {
			t.Errorf("curve: %v", pubKey.Curve)
		}
		if pubKey.X.Text(16) != "cfc27dd60845cb9a3a7f6c59e20f0bb0b1fbbb6c04a53da7b63f25a1a86796c1" {
			t.Errorf("x: %x", pubKey.X)
		}
		if pubKey.Y.Text(16) != "edb75e5cb1fad4aac6591761ee29676dc190002c7291a3ca7e605c7131c8394a" {
			t.Errorf("y: %x", pubKey.Y)
		}
	})
	t.Run("Unrecognized", func(t *testing.T) {
		var err error
		c := ast.NewObject()
		c.Insert(ast.StringTerm("hatever"), ast.StringTerm("junk"))
		_, err = parseTokenConstraints(c)
		if err == nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
	})
	t.Run("IllFormed", func(t *testing.T) {
		var err error
		c := ast.Array{ast.StringTerm("alg")}
		_, err = parseTokenConstraints(c)
		if err == nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
	})
}

func TestParseTokenHeader(t *testing.T) {
	t.Run("Errors", func(t *testing.T) {
		token := &JSONWebToken{
			header: "",
		}
		var err error
		if err = token.decodeHeader(); err == nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		token.header = "###"
		if err = token.decodeHeader(); err == nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		token.header = base64.RawURLEncoding.EncodeToString([]byte(`{`))
		if err = token.decodeHeader(); err == nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		token.header = base64.RawURLEncoding.EncodeToString([]byte(`{}`))
		if err = token.decodeHeader(); err != nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		var header tokenHeader
		header, err = parseTokenHeader(token)
		if err != nil {
			t.Fatalf("parseTokenHeader: %v", err)
		}
		if header.valid() {
			t.Fatalf("tokenHeader valid")
		}
	})
	t.Run("Alg", func(t *testing.T) {
		token := &JSONWebToken{
			header: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)),
		}
		var err error
		if err = token.decodeHeader(); err != nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		var header tokenHeader
		header, err = parseTokenHeader(token)
		if err != nil {
			t.Fatalf("parseTokenHeader: %v", err)
		}
		if !header.valid() {
			t.Fatalf("tokenHeader !valid")
		}
		if header.alg != "RS256" {
			t.Fatalf("alg: %s", header.alg)
		}
	})
}

func TestEncodeSignVerify(t *testing.T) {
	const (
		localClientKeyFile    = "testdata/client-key.pem"
		localPubClientKeyFile = "testdata/pub-client-key.pem"
	)

	// https://tools.ietf.org/html/rfc7515#appendix-A.1

	jwsPayload := []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
		32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
		48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
		109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
		111, 116, 34, 58, 116, 114, 117, 101, 125}
	encPayload := base64.RawURLEncoding.EncodeToString(jwsPayload)
	expectedEncPayload := "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	if encPayload != expectedEncPayload {
		t.Fatalf("Encoded Payload: %s does not match expected payload: %s", encPayload, expectedEncPayload)
	}

	t.Run("HS256Compact", func(t *testing.T) {
		// https://tools.ietf.org/html/rfc7515#appendix-A.1
		hdr := []byte{123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32,
			34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125}
		const jwksrc = `{
"kty":"oct",
"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
}`
		const expectedCompactSerialization = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

		standardHeaders := &jws.StandardHeaders{}
		err := standardHeaders.UnmarshalJSON(hdr)
		if err != nil {
			t.Fatal("Failed to parse header")
		}
		alg := standardHeaders.Algorithm()
		if err != nil {
			t.Fatal("Failed to parse header")
		}

		keys, err := jwk.ParseString(jwksrc)
		if err != nil {
			t.Fatal("Failed to parse JWK")
		}
		key, err := keys.Keys[0].Materialize()
		if err != nil {
			t.Fatal("Failed to create private key")
		}
		var jwsCompact []byte
		jwsCompact, err = jws.SignLiteral(jwsPayload, alg, key, hdr)
		if err != nil {
			t.Fatal("Failed to sign message")
		}

		if string(jwsCompact) != expectedCompactSerialization {
			t.Fatal("Signature does match expected")
		}
	})

	t.Run("RS256_SIGN_VERIFY_PEM_KEY_FILE", func(t *testing.T) {

		hdrRS256 := []byte{123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 50, 53, 54, 34, 125}
		encodedHeader := base64.RawURLEncoding.EncodeToString(hdrRS256)
		jwsSigningInput := encodedHeader + "." + encPayload
		hashed256 := sha256.Sum256([]byte(jwsSigningInput))
		key, err := ioutil.ReadFile(localClientKeyFile)
		if err != nil {
			t.Fatalf("Error (%s) reading key file (%s)", err, localClientKeyFile)
		}
		block, _ := pem.Decode(key)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			t.Fatalf("Error (%s) decoding key file (%s)", err, localClientKeyFile)
		}
		rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("Error (%s) parsing key file (%s)", err, localClientKeyFile)
		}
		rsaPublicKey := rsaPrivateKey.Public().(*rsa.PublicKey)

		rng := rand.Reader
		signature, err := rsa.SignPKCS1v15(rng, rsaPrivateKey, crypto.SHA256, hashed256[:])

		err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed256[:], signature)
		if err != nil {
			t.Fatalf("Error (%s) verifying signature (%s)", err, hex.EncodeToString(signature))
		}
	})
	t.Run("RS256Compact", func(t *testing.T) {
		// https://tools.ietf.org/html/rfc7515#appendix-A.2
		hdrRS256 := []byte{123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 50, 53, 54, 34, 125}
		const expectedSignature = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

		const jwksrc = `{
    "kty":"RSA",
    "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    "e":"AQAB",
    "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
    "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
    "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
    "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
    "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
    "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
  }`

		standardHeaders := &jws.StandardHeaders{}
		err := standardHeaders.UnmarshalJSON(hdrRS256)
		if err != nil {
			t.Fatal("Failed to parse header")
		}
		alg := standardHeaders.Algorithm()
		if err != nil {
			t.Fatal("Failed to parse header")
		}

		keys, _ := jwk.ParseString(jwksrc)
		key, err := keys.Keys[0].Materialize()
		if err != nil {
			t.Fatal("Failed to create private key")
		}

		rng := rand.Reader
		signingHdr, err := buffer.Buffer(hdrRS256).Base64Encode()
		signingPayload, err := buffer.Buffer(jwsPayload).Base64Encode()
		jwsSigningInput := bytes.Join(
			[][]byte{
				signingHdr,
				signingPayload,
			},
			[]byte{'.'},
		)
		// Sign with specific RSA API
		hashed256 := sha256.Sum256(jwsSigningInput)
		rsaSignature, err := rsa.SignPKCS1v15(rng, key.(*rsa.PrivateKey), crypto.SHA256, hashed256[:])
		rsaSignatureStr := base64.RawURLEncoding.EncodeToString(rsaSignature)
		if rsaSignatureStr != expectedSignature {
			t.Fatal("Failed to sign message")
		}

		// Sign with generic API
		var jwsCompact []byte
		jwsCompact, err = jws.Sign(jwsPayload, alg, key)
		if err != nil {
			t.Fatal("Failed to sign message")
		}
		jwsParts := bytes.Split(jwsCompact, []byte("."))
		jwsSignature := jwsParts[2]
		if string(jwsSignature) != rsaSignatureStr {
			t.Fatal("Failed to sign message")
		}
	})
	t.Run("ES256Compact", func(t *testing.T) {
		// ES256Compact tests that https://tools.ietf.org/html/rfc7515#appendix-A.3 works
		// const hdr = `{"alg":"ES256"}`
		hdrES256 := []byte{123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 50, 53, 54, 34, 125}
		const jwksrc = `{
    "kty":"EC",
    "crv":"P-256",
    "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
  }`

		standardHeaders := &jws.StandardHeaders{}
		err := standardHeaders.UnmarshalJSON(hdrES256)
		if err != nil {
			t.Fatal("Failed to parse header")
		}
		alg := standardHeaders.Algorithm()
		if err != nil {
			t.Fatal("Failed to parse header")
		}

		keys, err := jwk.ParseString(jwksrc)
		if err != nil {
			t.Fatal("Failed to parse JWK")
		}
		key, err := keys.Keys[0].Materialize()
		if err != nil {
			t.Fatal("Failed to create private key")
		}
		var jwsCompact []byte
		jwsCompact, err = jws.Sign(jwsPayload, alg, key)
		if err != nil {
			t.Fatal("Failed to sign message")
		}

		// Verify with standard ecdsa library
		_, _, jwsSignature, err := jws.SplitCompact(bytes.NewReader(jwsCompact))
		if err != nil {
			t.Fatal("Failed to split compact JWT")
		}
		decodedJwsSignature := make([]byte, base64.RawURLEncoding.DecodedLen(len(jwsSignature)))
		decodedLen, err := base64.RawURLEncoding.Decode(decodedJwsSignature, jwsSignature)
		if err != nil {
			t.Fatal("Failed to sign message")
		}
		r, s := &big.Int{}, &big.Int{}
		n := decodedLen / 2
		r.SetBytes(decodedJwsSignature[:n])
		s.SetBytes(decodedJwsSignature[n:])
		ecdsaPrivateKey := key.(*ecdsa.PrivateKey)
		signingHdr, err := buffer.Buffer(hdrES256).Base64Encode()
		if err != nil {
			t.Fatal("Failed to base64 encode headers")
		}
		signingPayload, err := buffer.Buffer(jwsPayload).Base64Encode()
		if err != nil {
			t.Fatal("Failed to base64 encode payload")
		}
		jwsSigningInput := bytes.Join(
			[][]byte{
				signingHdr,
				signingPayload,
			},
			[]byte{'.'},
		)
		hashed256 := sha256.Sum256(jwsSigningInput)
		verified := ecdsa.Verify(&ecdsaPrivateKey.PublicKey, hashed256[:], r, s)
		if !verified {
			t.Fatal("Failed to verify message")
		}

		// Verify with vendor library
		verifiedPayload, err := jws.Verify(jwsCompact, alg, &ecdsaPrivateKey.PublicKey)
		if err != nil || string(verifiedPayload) != string(jwsPayload) {
			t.Fatal("Failed to verify message")
		}
	})
	t.Run("ES512Compact", func(t *testing.T) {
		// ES256Compact tests that https://tools.ietf.org/html/rfc7515#appendix-A.3 works
		// const hdr = `{"alg":"ES512"}`
		hdr := []byte{123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 53, 49, 50, 34, 125}
		const jwksrc = `{
"kty":"EC",
"crv":"P-521",
"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"
}`

		// "Payload"
		jwsPayload = []byte{80, 97, 121, 108, 111, 97, 100}

		standardHeaders := &jws.StandardHeaders{}
		err := standardHeaders.UnmarshalJSON(hdr)
		if err != nil {
			t.Fatal("Failed to parse header")
		}
		alg := standardHeaders.Algorithm()
		if err != nil {
			t.Fatal("Failed to parse header")
		}

		keys, err := jwk.ParseString(jwksrc)
		if err != nil {
			t.Fatal("Failed to parse JWK")
		}
		key, err := keys.Keys[0].Materialize()
		if err != nil {
			t.Fatal("Failed to create private key")
		}
		var jwsCompact []byte
		jwsCompact, err = jws.Sign(jwsPayload, alg, key)
		if err != nil {
			t.Fatal("Failed to sign message")
		}

		// Verify with standard ecdsa library
		_, _, jwsSignature, err := jws.SplitCompact(bytes.NewReader(jwsCompact))
		if err != nil {
			t.Fatal("Failed to split compact JWT")
		}
		decodedJwsSignature := make([]byte, base64.RawURLEncoding.DecodedLen(len(jwsSignature)))
		decodedLen, err := base64.RawURLEncoding.Decode(decodedJwsSignature, jwsSignature)
		if err != nil {
			t.Fatal("Failed to sign message")
		}
		r, s := &big.Int{}, &big.Int{}
		n := decodedLen / 2
		r.SetBytes(decodedJwsSignature[:n])
		s.SetBytes(decodedJwsSignature[n:])
		ecdsaPrivateKey := key.(*ecdsa.PrivateKey)
		signingHdr, err := buffer.Buffer(hdr).Base64Encode()
		if err != nil {
			t.Fatal("Failed to base64 encode headers")
		}
		signingPayload, err := buffer.Buffer(jwsPayload).Base64Encode()
		if err != nil {
			t.Fatal("Failed to base64 encode payload")
		}
		jwsSigningInput := bytes.Join(
			[][]byte{
				signingHdr,
				signingPayload,
			},
			[]byte{'.'},
		)
		hashed512 := sha512.Sum512(jwsSigningInput)
		verified := ecdsa.Verify(&ecdsaPrivateKey.PublicKey, hashed512[:], r, s)
		if !verified {
			t.Fatal("Failed to verify message")
		}

		// Verify with vendor library
		verifiedPayload, err := jws.Verify(jwsCompact, alg, &ecdsaPrivateKey.PublicKey)
		if err != nil || string(verifiedPayload) != string(jwsPayload) {
			t.Fatal("Failed to verify message")
		}
	})
}
