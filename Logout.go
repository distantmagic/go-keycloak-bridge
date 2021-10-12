package keycloak

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

func Logout(
	token *oauth2.Token,
	oauth2ClientId string,
	oauth2ClientSecret string,
	oauth2EndpointLogout string,
) error {
	logoutRequestData := url.Values{}
	logoutRequestData.Set("client_id", oauth2ClientId)
	logoutRequestData.Set("client_secret", oauth2ClientSecret)
	logoutRequestData.Set("refresh_token", token.RefreshToken)

	logoutRequestEncodedData := logoutRequestData.Encode()

	logoutRequest, err := http.NewRequest(
		"POST",
		oauth2EndpointLogout,
		strings.NewReader(logoutRequestEncodedData),
	)

	if nil != err {
		return err
	}

	logoutRequest.Header.Add("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))
	logoutRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	logoutRequest.Header.Add("Content-Length", strconv.Itoa(len(logoutRequestEncodedData)))

	client := &http.Client{}
	logoutResponse, err := client.Do(logoutRequest)

	if nil != logoutResponse.Body {
		defer logoutResponse.Body.Close()
	}

	if nil != err {
		return err
	}

	_, err = ioutil.ReadAll(logoutResponse.Body)

	if nil != err {
		return err
	}

	return nil
}
