package iap

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
	"google.golang.org/api/iam/v1"
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

func GetToken(target string, serviceAccountFile string) (token string, err error) {
	sa, err := ioutil.ReadFile(serviceAccountFile)
	if err != nil {
		return
	}
	conf, err := google.JWTConfigFromJSON(sa)
	if err != nil {
		return
	}
	rsaKey, _ := readRsaPrivateKey(conf.PrivateKey)
	iat := time.Now()
	exp := iat.Add(time.Minute)
	jwt := &jws.ClaimSet{
		Iss: conf.Email,
		Aud: TokenURI,
		Iat: iat.Unix(),
		Exp: exp.Unix(),
		PrivateClaims: map[string]interface{}{
			"target_audience": target,
		},
	}
	jwsHeader := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	}

	msg, err := jws.Encode(jwsHeader, jwt, rsaKey)
	if err != nil {
		return
	}

	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	v.Set("assertion", msg)

	ctx := context.Background()
	hc := oauth2.NewClient(ctx, nil)
	resp, err := hc.PostForm(TokenURI, v)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenRes); err != nil {
		return token, err
	}
	fmt.Printf("Expires in: %+v\n", tokenRes.ExpiresIn)

	token = tokenRes.IDToken
	return
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

func readRsaPrivateKey(bytes []byte) (key *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		err = errors.New("invalid private key data")
		return
	}

	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return
		}
	} else if block.Type == "PRIVATE KEY" {
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not RSA private key")
		}
	} else {
		return nil, fmt.Errorf("invalid private key type: %s", block.Type)
	}

	key.Precompute()

	if err := key.Validate(); err != nil {
		return nil, err
	}

	return
}

type userAgentTransport struct {
	userAgent string
	base      http.RoundTripper
}

func (t userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(req)
}
