package keycloak

import (
	"encoding/json"

	"golang.org/x/oauth2"
)

func UnmarshalToken(marshaledToken []byte) (*oauth2.Token, error) {
	token := new(oauth2.Token)

	err := json.Unmarshal(marshaledToken, token)

	if nil != err {
		return nil, err
	}

	return token, nil
}
