package keycloak

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

func CreateKeystoreRefreshCallback(
	logger *logrus.Logger,
	keystorePopulateState *KeystorePopulateState,
	keystore *Keystore,
	keycloakCertsURL string,
) func() {
	return func() {
		err := PopulateKeystoreFromCertServer(keystorePopulateState, keystore, keycloakCertsURL)

		if nil != err {
			logger.Error(fmt.Sprintf("Error while reloading Keycloak keys: %s", err.Error()))

			return
		}

		logger.Debug("Reloaded Keycloak certs from cert server")
	}
}
