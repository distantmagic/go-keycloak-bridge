package keycloak

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

func PopulateKeystoreFromCertServer(
	state *KeystorePopulateState,
	keystore *Keystore,
	oauth2EndpointCerts string,
) error {
	if state.IsLoading {
		return nil
	}

	state.IsLoading = true

	defer func() {
		state.IsLoading = false
	}()

	keysRequest, err := http.NewRequest("GET", oauth2EndpointCerts, nil)

	if nil != err {
		return err
	}

	keysRequest.Header.Set("Accept", "application/json")

	client := &http.Client{}

	keysResponse, err := client.Do(keysRequest)

	if nil != err {
		return err
	}

	if nil != keysResponse.Body {
		defer keysResponse.Body.Close()
	}

	keysBytes, err := ioutil.ReadAll(keysResponse.Body)

	if nil != err {
		return err
	}

	err = json.Unmarshal(keysBytes, keystore)

	if nil != err {
		return err
	}

	return nil
}
