package fb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	libraryVersion = "0.1"
	userAgent      = "go-facebook-client/" + libraryVersion
)

var (
	graphAPIUrl     = "https://graph.facebook.com"
	graphAPIVersion = "3.2"

	accountKitAPIUrl  = "https://graph.accountkit.com"
	accountKitVersion = "1.3"
)

var (
	// ErrUnauthorized can be returned on any call on response status code 401.
	ErrUnauthorized = errors.New("go-facebook-client: unauthorized")
)

type errorResponse struct {
	Error Error `json:"error"`
}

type Error struct {
	Message string `json:"message,omitempty"`
}

type doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type DoerFunc func(req *http.Request) (resp *http.Response, err error)

type Client struct {
	doer       doer
	baseURL    *url.URL
	apiVersion string
	userAgent  string
	httpClient *http.Client

	logEnabled bool

	AccountKit *AccountKit
}

func NewClient() *Client {

	baseUrl := fmt.Sprintf("%s/", graphAPIUrl)

	baseURL, _ := url.Parse(baseUrl)
	client := &Client{
		doer:       http.DefaultClient,
		baseURL:    baseURL,
		apiVersion: graphAPIVersion,
		userAgent:  userAgent,
	}

	akUrl, _ := url.Parse(fmt.Sprintf("%s/v%s/", accountKitAPIUrl, accountKitVersion))
	client.AccountKit = &AccountKit{
		client: &Client{
			doer:       client.doer,
			baseURL:    akUrl,
			apiVersion: accountKitVersion,
			userAgent:  userAgent,
			logEnabled: client.logEnabled,
		}}

	return client
}

func (c *Client) request(method string, path string, data interface{}, v interface{}) error {

	urlStr := path

	rel, err := url.Parse(urlStr)
	if err != nil {
		return err
	}
	u := c.baseURL.ResolveReference(rel)
	var body io.Reader

	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)

	}

	if c.logEnabled {
		fmt.Printf("Request %s to %s with data: %s \n", method, u.String(), body)
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.doer.Do(req.WithContext(context.Background()))
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}

	// Return error from facebook API
	if resp.StatusCode != http.StatusOK {
		rb := new(errorResponse)

		err = json.NewDecoder(resp.Body).Decode(rb)

		if err != nil {
			return errors.New("general error")
		}

		return errors.New(rb.Error.Message)
	}

	// Decode to interface
	res := v
	err = json.NewDecoder(resp.Body).Decode(res)

	by, _ := json.Marshal(res)
	if c.logEnabled {
		fmt.Printf("Response %s from %s : %s \n", method, u.String(), string(by))
	}

	return err
}
