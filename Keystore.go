package keycloak

import (
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/golang-jwt/jwt"
)

type Keystore struct {
	Keys []KeystoreKey `json:"keys"`

	rsaPublicKeysCache map[string]*rsa.PublicKey
}

func (keystore *Keystore) FindSigningKeyById(kid string) (*KeystoreKey, error) {
	for _, keystoreKey := range keystore.Keys {
		if kid == keystoreKey.KeyId {
			if "sig" != keystoreKey.Use {
				return nil, fmt.Errorf("Found key with kid, but it is not a signing key: %s", kid)
			}

			return &keystoreKey, nil
		}
	}

	return nil, nil
}

// Parse takes the token string and a function for looking up the key. The latter is especially
// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
// head of the token to identify which key to use, but the parsed token (head and claims) is provided
// to the callback, providing flexibility.
func (keystore *Keystore) GetAccessTokenSigningKey(accessToken *jwt.Token) (interface{}, error) {
	_, ok := accessToken.Method.(*jwt.SigningMethodRSA)

	if !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", accessToken.Header["alg"])
	}

	kid, ok := accessToken.Header["kid"].(string)

	if !ok {
		return nil, fmt.Errorf("Token does not specify key id")
	}

	rsaPublicKey, err := keystore.cachedGetRSAPublicKey(kid)

	if nil != err {
		return nil, err
	}

	return rsaPublicKey, nil
}

func (keystore *Keystore) cachedGetRSAPublicKey(kid string) (*rsa.PublicKey, error) {
	if nil == keystore.rsaPublicKeysCache {
		keystore.rsaPublicKeysCache = make(map[string]*rsa.PublicKey)
	}

	cachedRSAPublicKey := keystore.rsaPublicKeysCache[kid]

	if nil != cachedRSAPublicKey {
		return cachedRSAPublicKey, nil
	}

	keystoreKey, err := keystore.FindSigningKeyById(kid)

	if nil != err {
		return nil, err
	}

	rsaPublicKey, err := keystoreKey.GetRSAPublicKey()

	if nil != err {
		return nil, err
	}

	keystore.rsaPublicKeysCache[kid] = rsaPublicKey

	// Sanity check.
	if len(keystore.rsaPublicKeysCache) > len(keystore.Keys) {
		log.Println("There are more cached keys than there are keys overall.")

		// Just clear the cache. Keys must have been regenerated a few times.
		for k := range keystore.rsaPublicKeysCache {
			delete(keystore.rsaPublicKeysCache, k)
		}
	}

	return rsaPublicKey, nil
}
