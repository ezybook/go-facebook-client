package fb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type AccountKit struct {
	client         *Client
	appId          string
	appSecret      string
	appAccessToken string
}

func (c *AccountKit) EnabledLog() {
	c.client.logEnabled = true
}

func (c *AccountKit) SetAPIVersion(version string) {
	c.client.apiVersion = version
}

func (c *AccountKit) GetAPIVersion() string {
	return c.client.apiVersion
}

func (c *AccountKit) SetFacebookAppId(appId string) {
	c.appId = appId
}

func (c *AccountKit) GetFacebookAppId() string {
	return c.appId
}

func (c *AccountKit) SetAppSecret(appSecret string) {
	c.appSecret = appSecret
}

func (c *AccountKit) GetAppSecret() string {
	return c.appSecret
}

func (c *AccountKit) GetAppAccessToken() string {
	return fmt.Sprintf("AA|%s|%s", c.appId, c.appSecret)
}

func generateAppSecretProof(data string, secret string) string {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	return sha
}

type AccessTokenResponse struct {
	Id          string `json:"id"`
	AccessToken string `json:"access_token"`
}

func (c *AccountKit) GetAccessToken(authorizationCode string) (AccessTokenResponse, error) {
	res := new(AccessTokenResponse)

	endpoint := fmt.Sprintf("access_token?grant_type=authorization_code&code=%s&access_token=%s", authorizationCode, c.GetAppAccessToken())

	err := c.client.request("GET", endpoint, nil, res)
	return *res, err
}

type UserResponse struct {
	Id    string `json:"id"`
	Phone Phone  `json:"phone"`
}

type AccessTokenValidationResponse struct {
	UserResponse
	Application Application `json:"application"`
}

type Phone struct {
	Number         string `json:"number"`
	CountryPrefix  string `json:"country_prefix"`
	NationalNumber string `json:"national_number"`
}

type Application struct {
	Id string `json:"id"`
}

func (c *AccountKit) ValidateAccessToken(accessToken string) (AccessTokenValidationResponse, error) {
	res := new(AccessTokenValidationResponse)

	appSecretProof := generateAppSecretProof(accessToken, c.appSecret)

	endpoint := fmt.Sprintf("me/?access_token=%s&appsecret_proof=%s", accessToken, appSecretProof)

	err := c.client.request("GET", endpoint, nil, res)
	return *res, err
}

type LogoutResponse struct {
	Success bool `json:"success"`
}

func (c *AccountKit) Logout(accessToken string) (LogoutResponse, error) {
	res := new(LogoutResponse)

	appSecretProof := generateAppSecretProof(accessToken, c.appSecret)

	endpoint := fmt.Sprintf("logout/?access_token=%s&appsecret_proof=%s", accessToken, appSecretProof)

	err := c.client.request("POST", endpoint, nil, res)
	return *res, err
}

func (c *AccountKit) LogoutAllSession(accountId string) (LogoutResponse, error) {
	res := new(LogoutResponse)

	endpoint := fmt.Sprintf("%s/invalidate_all_tokens/?access_token=%s", accountId, c.GetAppAccessToken())

	err := c.client.request("POST", endpoint, nil, res)
	return *res, err
}

func (c *AccountKit) RemoveAccount(accountId string) (LogoutResponse, error) {
	res := new(LogoutResponse)

	endpoint := fmt.Sprintf("%s?access_token=%s", accountId, c.GetAppAccessToken())

	err := c.client.request("DELETE", endpoint, nil, res)
	return *res, err
}

type UserDataResponse struct {
	Data   []UserResponse `json:"data"`
	Paging Paging         `json:"paging"`
}

type Paging struct {
	Cursors  Cursors `json:"cursors"`
	Previous string  `json:"previous"`
	Next     string  `json:"next"`
}

type Cursors struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

func (c *AccountKit) GetUserData(limit int) ([]UserDataResponse, error) {
	res := new([]UserDataResponse)

	endpoint := fmt.Sprintf("%s/accounts/?&access_token=%s&limit=%d", c.appId, c.GetAppAccessToken(), limit)

	err := c.client.request("GET", endpoint, nil, res)
	return *res, err
}
