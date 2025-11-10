package tests

import (
	"encoding/base64"
	"testing"

	"github.com/eclipse-xfsc/did-core/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

const didJson2 = `{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "@vocab": "https://www.iana.org/assignments/jose#"
    }
  ],
  "id": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Im8xbkRMYmFnVUpYZTZORjY1N04zck0ySjRTSE5uSXE5UVpCeGh5d3hhdWMiLCJ5IjoiMkt3ZzBJN203eHFKLVMzaDhDS1hQWjZjRENSSm1iU2JVWEJlSnZ5bjdhUSJ9",
  "verificationMethod": [
    {
      "id": "#0",
      "type": "JsonWebKey2020",
      "controller": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Im8xbkRMYmFnVUpYZTZORjY1N04zck0ySjRTSE5uSXE5UVpCeGh5d3hhdWMiLCJ5IjoiMkt3ZzBJN203eHFKLVMzaDhDS1hQWjZjRENSSm1iU2JVWEJlSnZ5bjdhUSJ9",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "o1nDLbagUJXe6NF657N3rM2J4SHNnIq9QZBxhywxauc",
        "y": "2Kwg0I7m7xqJ-S3h8CKXPZ6cDCRJmbSbUXBeJvyn7aQ"
      }
    }
  ]
}`

const didJSON = `{
	"@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  
  "verificationMethod": [
	"did:bla:bla",
    {
    "id": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
    "type": "JsonWebKey2020", 
    "controller": "did:example:123",
    "publicKeyJwk": {
      "crv": "Ed25519", 
      "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ", 
      "kty": "OKP", 
      "kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A" 
    }
  }, {
    "id": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4Afff",
    "type": "JsonWebKey2020", 
    "controller": "did:example:123",
    "publicKeyJwk": {
      "crv": "Ed25519", 
      "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ", 
      "kty": "OKP", 
      "kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A" 
    }
  }]
  }`

func TestDidDocumentParsing(t *testing.T) {
	didDoc, err := did.ParseDidDocument(didJSON)

	if err != nil || didDoc == nil {
		t.Error(err)
	}

	if didDoc.VerificationMethod[0].Reference == nil {
		t.Error()
	}

	if didDoc.VerificationMethod[1].Key.PublicKeyJwk == nil {
		t.Error()
	}
	noString := false
	didDoc.Context.Iterate(func(i int, s string, m map[string]interface{}, okS, okM bool) {

		if okM {
			noString = true
		}
	})

	if noString {
		t.Error()
	}
}

func TestDidDocumentParsing2(t *testing.T) {
	didDoc, err := did.ParseDidDocument(didJson2)

	if err != nil || didDoc == nil {
		t.Error(err)
	}

	if didDoc.VerificationMethod[0].Key == nil {
		t.Error()
	}

	if didDoc.VerificationMethod[0].Key.PublicKeyJwk == nil {
		t.Error()
	}

	noMix := false
	didDoc.Context.Iterate(func(i int, s string, m map[string]interface{}, okS, okM bool) {

		if okS {
			noMix = true
		}

		if okM {
			noMix = noMix && true
		}
	})

	if !noMix {
		t.Error()
	}
}

func TestGetKeys(t *testing.T) {
	didDoc, err := did.ParseDidDocument(didJSON)

	if err != nil {
		t.Error(err)
	}

	set := didDoc.GetPublicKeys()

	if set.Len() != 2 || set == nil {
		t.Error()
	}

}

func TestDidResolver(t *testing.T) {
	viper.SetDefault("DID_RESOLVER", "https://dev.uniresolver.io")
	didString := "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"

	d, err := did.Resolve(didString)

	if d == nil || err != nil {
		t.Error()
	}

	if d.Id != didString {
		t.Error()
	}

	if d.VerificationMethod != nil && len(d.VerificationMethod) == 0 {
		t.Error()
	}
}

var exampleJwk = `{
	"kty": "OKP",
	"crv": "Ed25519",
	"x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"
  }`

// Hilfsfunktion: encodiert JWK → did:jwk
func makeDidJwk(jwkJSON string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(jwkJSON))
	return "did:jwk:" + encoded
}

func TestResolveDidJwk(t *testing.T) {
	didJwk := makeDidJwk(exampleJwk)

	doc, err := did.Resolve(didJwk)
	require.NoError(t, err, "Resolver should not error on valid did:jwk")
	require.NotNil(t, doc, "DID Document should not be nil")

	// ID sollte korrekt gesetzt sein
	require.Equal(t, didJwk, doc.Id)

	// VerificationMethod sollte existieren
	require.Len(t, doc.VerificationMethod, 1)
	vm := doc.VerificationMethod[0]

	require.Equal(t, "JsonWebKey2020", vm.Key.Type)
	require.Equal(t, doc.Id, vm.Key.Controller)

	// publicKeyJwk sollte ein valides JSON sein
	// var parsed map[string]any
	// err = json.Unmarshal(vm.Key.PublicKeyJwk, &parsed)
	// require.NoError(t, err)
	// require.Equal(t, "OKP", parsed["kty"])
	// require.Equal(t, "Ed25519", parsed["crv"])
	// require.Equal(t, "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ", parsed["x"])
}
