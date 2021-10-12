package keycloak

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// see: https://github.com/MicahParks/keyfunc/blob/846f636e1ec4589ebd0a506dbe1e3ba839b3cae7/rsa.go

type KeystoreKey struct {
	KeyId                           string   `json:"kid"`
	KeyType                         string   `json:"kty"`
	Algorithm                       string   `json:"alg"`
	Use                             string   `json:"use"`
	RSAModulus                      string   `json:"n"`
	RSAPublicExponent               string   `json:"e"`
	X509CertificateChain            []string `json:"x5c"`
	X509CertificateThumbprint       string   `json:"x5t"`
	X509CertificateSHA256Thumbprint string   `json:"x5t#S256"`
}

func (keystoreKey *KeystoreKey) GetRSAPublicKey() (*rsa.PublicKey, error) {
	exponent, err := decodeRSAExponent(keystoreKey.RSAPublicExponent)

	if nil != err {
		return nil, err
	}

	modulus, err := decodeRSAModulus(keystoreKey.RSAModulus)

	if nil != err {
		return nil, err
	}

	rsaPublicKey := &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}

	return rsaPublicKey, nil
}

func decodeRSAExponent(codedExponent string) (int, error) {
	// This is a really common one
	if "AQAB" == codedExponent {
		return 65537, nil
	}

	exponent, err := base64.RawURLEncoding.DecodeString(codedExponent)

	if nil != err {
		return 0, err
	}

	return int(big.NewInt(0).SetBytes(exponent).Uint64()), nil
}

func decodeRSAModulus(codedModulus string) (*big.Int, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(codedModulus)

	if nil != err {
		return nil, err
	}

	return big.NewInt(0).SetBytes(modulus), nil
}
