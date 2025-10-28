package tests

import (
	"testing"

	"github.com/eclipse-xfsc/did-core/v2"
	"github.com/spf13/viper"
)

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
