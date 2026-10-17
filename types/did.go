package types

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/mr-tron/base58"
	"github.com/sirupsen/logrus"
)

type VerificationMethod struct {
	Context            []string `json:"@context,omitempty"`
	Id                 string   `json:"id"`
	Controller         string   `json:"controller"`
	Type               string   `json:"type"`
	PublicKeyJwk       jwk.Key  `json:"publicKeyJwk,omitempty"`
	PublicKeyBase58    string   `json:"publicKeyBase58,omitempty"`
	PublicKeyMultibase string   `json:"publicKeyMultibase,omitempty"`
}

type VerificationRelationShipEntry struct {
	Key       *VerificationMethod
	Reference *string
}

func (v *VerificationMethod) UnmarshalJSON(data []byte) error {
	type Alias VerificationMethod

	aux := &struct {
		PublicKeyJwk json.RawMessage `json:"publicKeyJwk,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(v),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	if len(aux.PublicKeyJwk) > 0 && string(aux.PublicKeyJwk) != "null" {
		key, err := jwk.ParseKey(aux.PublicKeyJwk)
		if err != nil {
			return fmt.Errorf("failed to parse publicKeyJwk: %w", err)
		}

		v.PublicKeyJwk = key
	}

	return nil
}

func (v *VerificationRelationShipEntry) UnmarshalJSON(data []byte) error {
	var method VerificationMethod

	if err := json.Unmarshal(data, &method); err == nil && method.Id != "" {
		v.Key = &method
		v.Reference = nil
		return nil
	}

	var reference string

	if err := json.Unmarshal(data, &reference); err == nil {
		v.Reference = &reference
		v.Key = nil
		return nil
	}

	return fmt.Errorf(
		"verificationMethod entry is neither string nor struct: %s",
		string(data),
	)
}

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
	Context    ContextValue `json:"@context,omitempty"`
	Id         string       `json:"id"`
	Controller any          `json:"controller,omitempty"`

	VerificationMethod   []VerificationRelationShipEntry `json:"verificationMethod,omitempty"`
	Authentication       []VerificationRelationShipEntry `json:"authentication,omitempty"`
	AssertionMethod      []VerificationRelationShipEntry `json:"assertionMethod,omitempty"`
	KeyAgreement         []VerificationRelationShipEntry `json:"keyAgreement,omitempty"`
	CapabilityInvocation []VerificationRelationShipEntry `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []VerificationRelationShipEntry `json:"capabilityDelegation,omitempty"`
}

func (d *DidDocument) GetPublicKeys() jwk.Set {
	const (
		JWKMethodType     = "JsonWebKey2020"
		Ed25519MethodType = "Ed25519VerificationKey2018"
	)

	keys := jwk.NewSet()

	for _, entry := range d.VerificationMethod {
		if entry.Key == nil {
			continue
		}

		method := entry.Key

		var key jwk.Key
		var err error

		switch method.Type {
		case JWKMethodType:
			if method.PublicKeyJwk == nil {
				logrus.Warnf(
					"%s has no publicKeyJwk",
					method.Id,
				)
				continue
			}

			jwkJSON, marshalErr := json.Marshal(method.PublicKeyJwk)
			if marshalErr != nil {
				logrus.Warnf(
					"%s has invalid JWK definition: %v",
					method.Id,
					marshalErr,
				)
				continue
			}

			key, err = jwk.ParseKey(jwkJSON)
			if err != nil {
				logrus.Warnf(
					"%s is not a valid JWK: %v",
					method.Id,
					err,
				)
				continue
			}

		case Ed25519MethodType:
			if method.PublicKeyBase58 == "" {
				logrus.Warnf(
					"%s has no publicKeyBase58",
					method.Id,
				)
				continue
			}

			publicKeyBytes, decodeErr := base58.Decode(method.PublicKeyBase58)
			if decodeErr != nil {
				logrus.Warnf(
					"%s has invalid Base58 public key: %v",
					method.Id,
					decodeErr,
				)
				continue
			}

			if len(publicKeyBytes) != ed25519.PublicKeySize {
				logrus.Warnf(
					"%s has invalid Ed25519 public key length: %d",
					method.Id,
					len(publicKeyBytes),
				)
				continue
			}

			key, err = jwk.FromRaw(ed25519.PublicKey(publicKeyBytes))
			if err != nil {
				logrus.Warnf(
					"%s could not be converted to JWK: %v",
					method.Id,
					err,
				)
				continue
			}

		default:
			logrus.Debugf(
				"unsupported verification method type: %s",
				method.Type,
			)
			continue
		}

		if key == nil {
			continue
		}

		if err := key.Set(jwk.KeyIDKey, method.Id); err != nil {
			logrus.Warnf(
				"could not set kid for %s: %v",
				method.Id,
				err,
			)
			continue
		}

		if err := keys.AddKey(key); err != nil {
			logrus.Warnf(
				"could not add key %s: %v",
				method.Id,
				err,
			)
		}
	}

	return keys
}

type ContextValue []interface{}

func (c *ContextValue) UnmarshalJSON(data []byte) error {
	var single string

	if err := json.Unmarshal(data, &single); err == nil {
		*c = ContextValue{single}
		return nil
	}

	var array []interface{}

	if err := json.Unmarshal(data, &array); err == nil {
		*c = ContextValue(array)
		return nil
	}

	return fmt.Errorf("invalid @context format: %s", string(data))
}

func (c ContextValue) MarshalJSON() ([]byte, error) {
	if len(c) == 1 {
		if value, ok := c[0].(string); ok {
			return json.Marshal(value)
		}
	}

	return json.Marshal([]interface{}(c))
}

func (c ContextValue) Iterate(
	fn func(
		i int,
		s string,
		m map[string]interface{},
		okString bool,
		okMap bool,
	),
) {
	for i, value := range c {
		switch v := value.(type) {
		case string:
			fn(i, v, nil, true, false)

		case map[string]interface{}:
			fn(i, "", v, false, true)

		default:
			fn(i, "", nil, false, false)
		}
	}
}
