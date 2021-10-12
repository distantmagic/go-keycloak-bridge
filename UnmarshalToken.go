package keycloak

import (
	"encoding/json"

	"golang.org/x/oauth2"
)

func UnmarshalToken(marshaledToken interface{}) (*oauth2.Token, error) {
	if marshaledToken == nil {
		return nil, nil
	}

	token := new(oauth2.Token)

	err := json.Unmarshal(marshaledToken.([]byte), token)

	if nil != err {
		return nil, err
	}

	return token, nil
}
