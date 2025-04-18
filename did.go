package did

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/did-core/types"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var did_resolver string
var initialized bool

func Initialize() {
	if initialized {
		return
	}
	viper.AutomaticEnv()
	did_resolver = viper.GetString("DID_RESOLVER")
}

type didVerificationMethod struct {
	Id           string      `json:"id"`
	Controller   string      `json:"controller"`
	Type         string      `json:"type"`
	PublicKeyJwk interface{} `json:"publicKeyJwk,omitempty"`
}

type didDocument struct {
	Id                 string                  `json:"id"`
	Controller         string                  `json:"controller"`
	VerificationMethod []didVerificationMethod `json:"verificationMethod"`
}

type didResolution struct {
	Document interface{} `json:"didDocument"`
}

func ParseDidDocument(didJson string) (*types.DidDocument, error) {
	var didDoc didDocument
	err := json.Unmarshal([]byte(didJson), &didDoc)

	if err != nil {
		return nil, err
	}

	doc, err := didDoc.transformParsing()

	if err != nil {
		return nil, err
	}

	return doc, nil
}

func ToDidWeb(rawURL string, dockerAware bool) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("ungültige URL: %w", err)
	}

	host := parsedURL.Host
	if host == "" {
		// Fallback für reine Hoststrings wie "127.0.0.1:8080"
		host = rawURL
	}

	// Sonderbehandlung für docker-aware mode
	if dockerAware {
		if strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost") {
			// Versuche Port zu erhalten (falls vorhanden)
			parts := strings.Split(host, ":")
			if len(parts) == 2 {
				host = "host.docker.internal:" + parts[1]
			} else {
				host = "host.docker.internal"
			}
		}
	}

	// DID:web verlangt Encoding von ":" → "%3A"
	didSafeHost := strings.ReplaceAll(host, ":", "%3A")

	didWeb := fmt.Sprintf("did:web:%s", didSafeHost)
	return didWeb, nil
}

func (d *didDocument) transformParsing() (*types.DidDocument, error) {

	var newDoc types.DidDocument
	newDoc.Id = d.Id
	newDoc.Controller = d.Controller
	newDoc.VerificationMethod = make([]types.DidVerificationMethod, 0)
	for _, method := range d.VerificationMethod {
		json, err := json.Marshal(method.PublicKeyJwk)
		if err != nil {
			return nil, err
		}
		key, err := jwk.ParseKey(json)
		if err != nil {
			return nil, err
		}
		newMethod := types.DidVerificationMethod{
			Id:           method.Id,
			Type:         method.Type,
			Controller:   method.Controller,
			PublicKeyJwk: key,
		}
		newDoc.VerificationMethod = append(newDoc.VerificationMethod, newMethod)
	}
	return &newDoc, nil

}

func extractHttpBody(reader io.ReadCloser) string {
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		logrus.Fatal(err)
	}
	bodyString := string(bodyBytes)
	return bodyString
}

func Resolve(did string) (*types.DidDocument, error) {
	Initialize()
	if did == "" {
		return nil, errors.New("DID cannot be empty")
	}

	req, err := http.NewRequest("GET", did_resolver+"/1.0/identifiers/"+did, nil)
	if err != nil {
		return nil, err
	}

	request := req.WithContext(context.Background())

	resp, err := http.DefaultClient.Do(request)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // nolint:errcheck

	v := extractHttpBody(resp.Body)
	if err != nil {
		return nil, err
	}
	var didResolve didResolution
	err = json.Unmarshal([]byte(v), &didResolve)

	if err != nil {
		return nil, err
	}

	s, err := json.Marshal(didResolve.Document)

	if err != nil {
		return nil, err
	}

	d, err := ParseDidDocument(string(s))

	if err != nil {
		return nil, err
	}

	return d, nil

}
