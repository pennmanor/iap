package iap

import (
	"cloud.google.com/go/compute/metadata"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	TokenURI = "https://www.googleapis.com/oauth2/v4/token"
)

func GetTokenFromGCE(target string) (string, error) {

	project, email, err := getGCEMetaData()
	if err != nil {
		return "", err
	}

	client := &http.Client{
		Transport: &oauth2.Transport{
			Source: google.ComputeTokenSource(""),
		},
	}

	iamClient, err := iam.New(client)

	iat := time.Now()
	exp := iat.Add(time.Hour)

	resourceName := fmt.Sprintf("projects/%+v/serviceAccounts/%v", project, email)
	jwtPayload := map[string]interface{}{
		"iss":             email,
		"aud":             TokenURI,
		"iat":             iat.Unix(),
		"exp":             exp.Unix(),
		"target_audience": target,
	}

	payloadBytes, err := json.Marshal(jwtPayload)
	if err != nil {
		log.Fatal(err)
	}

	signJwtReq := &iam.SignJwtRequest{Payload: string(payloadBytes)}

	resp, err := iamClient.Projects.ServiceAccounts.SignJwt(resourceName, signJwtReq).Do()
	if err != nil {
		log.Fatal(err)
	}

	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	v.Set("assertion", resp.SignedJwt)

	postResp, err := client.PostForm(TokenURI, v)

	if err != nil {
		log.Fatal(err)
	}
	defer postResp.Body.Close()

	body, err := ioutil.ReadAll(postResp.Body)

	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenRes); err != nil {
		log.Fatal("error unmarshalling")
		return "", errors.New("Error unmarshalling response")
	}

	return tokenRes.IDToken, nil

}

func getGCEMetaData() (project string, email string, e error) {
	c := metadata.NewClient(&http.Client{Transport: userAgentTransport{
		userAgent: "my-user-agent",
		base:      http.DefaultTransport,
	}})

	project, err := c.ProjectID()
	if err != nil {
		return "", "", err
	}

	email, err = c.Get("instance/service-accounts/default/email")
	if err != nil {
		return "", "", err
	}

	return project, email, nil
}

type userAgentTransport struct {
	userAgent string
	base      http.RoundTripper
}

func (t userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(req)
}
