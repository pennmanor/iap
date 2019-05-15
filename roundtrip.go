package iap

import (
	"fmt"
	"net/http"
	"time"
)

/* Round Tripper */
type RT struct {
	saFile    string //service account json file
	useGCE    bool
	target    string
	renewedAt time.Time
	token     string
	base      http.RoundTripper
	headers   http.Header
}

func NewRT(target string, serviceAccountFile string, base http.RoundTripper) *RT {
	r := &RT{saFile: serviceAccountFile, useGCE: false, target: target, base: base}
	return r
}

func NewRTGCE(target string, base http.RoundTripper) *RT {
	r := &RT{useGCE: true, target: target, base: base}
	return r
}

func (r *RT) Renew() error {

	if r.useGCE {
		token, err := GetTokenFromGCE(r.target)
		r.token = token
		if err == nil {
			r.renewedAt = time.Now()
		}
		return err
	}

	token, err := GetToken(r.target, r.saFile)
	r.token = token
	if err == nil {
		r.renewedAt = time.Now()
	}
	return err
}

func (r *RT) SetHeader(key string, value string) {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	r.headers.Set(key, value)
}

func (r *RT) RoundTrip(req *http.Request) (*http.Response, error) {

	if time.Since(r.renewedAt).Minutes() > 30 {
		r.Renew()
	}

	for k, h := range r.headers {
		for _, i := range h {
			req.Header.Set(k, i)
		}
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %+v", r.token))

	return r.base.RoundTrip(req)
}
