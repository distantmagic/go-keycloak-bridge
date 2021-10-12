package keycloak

import (
	"github.com/golang-jwt/jwt"
)

func ValidateAccessToken(keystore *Keystore, token string) (*jwt.Token, error) {
	if "" == token {
		return nil, nil
	}

	accessToken, err := jwt.Parse(token, keystore.GetAccessTokenSigningKey)

	if nil != err {
		return nil, err
	}

	return accessToken, nil
}
