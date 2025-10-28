package types

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/sirupsen/logrus"
)

type VerificationMethod struct {
	Context      []string `json:"@context,omitempty"`
	Id           string   `json:"id"`
	Controller   string   `json:"controller"`
	Type         string   `json:"type"`
	PublicKeyJwk jwk.Key  `json:"publicKeyJwk,omitempty"`
}

// VerificationRelationShipEntry unterstützt entweder ein String-Referenz oder ein eingebettetes Struct
type VerificationRelationShipEntry struct {
	Key       *VerificationMethod
	Reference *string
}

func (v *VerificationMethod) UnmarshalJSON(data []byte) error {
	// Hilfsstruktur: alle Felder außer JWK direkt übernehmen
	type Alias VerificationMethod
	aux := &struct {
		PublicKeyJwk json.RawMessage `json:"publicKeyJwk,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(v),
	}

	// Erst das Standard-Unmarshal
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// Wenn ein JWK-Block vorhanden ist, parse ihn über lestrrat-go
	if len(aux.PublicKeyJwk) > 0 {
		key, err := jwk.ParseKey(aux.PublicKeyJwk)
		if err != nil {
			return fmt.Errorf("failed to parse publicKeyJwk: %w", err)
		}
		v.PublicKeyJwk = key
	}

	return nil
}

func (v *VerificationRelationShipEntry) UnmarshalJSON(data []byte) error {

	var s VerificationMethod

	err := json.Unmarshal(data, &s)
	if err == nil && s.Id != "" {
		v.Key = &s
		return nil
	}

	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		v.Reference = &str
		return nil
	}

	return fmt.Errorf("verificationMethod entry is neither string nor struct: %s", string(data))
}

// Optional: für korrektes Serialisieren zurück ins JSON
func (v VerificationRelationShipEntry) MarshalJSON() ([]byte, error) {
	if v.Key != nil {
		return json.Marshal(v.Key)
	}
	if v.Reference != nil {
		return json.Marshal(v.Reference)
	}
	return []byte("null"), nil
}

type DidDocument struct {
	Context    []string `json:"@context,omitempty"`
	Id         string   `json:"id"`
	Controller string   `json:"controller,omitempty"`

	VerificationMethod   []VerificationRelationShipEntry `json:"verificationMethod,omitempty"`
	Authentication       []VerificationRelationShipEntry `json:"authentication,omitempty"`
	AssertionMethod      []VerificationRelationShipEntry `json:"assertionMethod,omitempty"`
	KeyAgreement         []VerificationRelationShipEntry `json:"keyAgreement,omitempty"`
	CapabilityInvocation []VerificationRelationShipEntry `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []VerificationRelationShipEntry `json:"capabilityDelegation,omitempty"`
}

// Liefert alle eingebetteten JWK Public Keys aus allen VerificationMethods
func (d *DidDocument) GetPublicKeys() jwk.Set {
	const METHOD_TYPE = "JsonWebKey2020"
	keys := jwk.NewSet()

	for _, entry := range d.VerificationMethod {
		if entry.Key != nil && entry.Key.Type == METHOD_TYPE {
			jwkJson, err := json.Marshal(entry.Key.PublicKeyJwk)
			if err != nil {
				logrus.Infof("%s has invalid JWK definition", entry.Key.Id)
				continue
			}

			key, err := jwk.ParseKey(jwkJson)
			if err != nil {
				logrus.Infof("%s is not valid JWK", entry.Key.Id)
				continue
			}

			_ = key.Set(jwk.KeyIDKey, entry.Key.Id)
			keys.AddKey(key)
		}
	}

	return keys
}
