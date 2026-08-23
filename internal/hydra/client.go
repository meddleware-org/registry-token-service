// Package hydra provides a minimal client for validating OAuth2 client credentials
// against Ory Hydra's token endpoint.
package hydra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client calls the Hydra public token endpoint to validate client credentials.
type Client struct {
	tokenURL   string
	httpClient *http.Client
}

// NewClient constructs a Client targeting the given Hydra public token URL
// (e.g. "http://hydra.auth.svc.cluster.local:4444/oauth2/token").
func NewClient(tokenURL string) *Client {
	return &Client{
		tokenURL:   tokenURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// tokenResponse is the subset of the OAuth2 token response we need.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ValidateClientCredentials performs a client_credentials grant against Hydra
// using the provided clientID and clientSecret. Returns true if Hydra issues a
// token (credentials valid), false if Hydra rejects them.
// Returns an error only for transport or server-side failures.
func (c *Client) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (bool, error) {
	body := url.Values{}
	body.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL,
		strings.NewReader(body.Encode()))
	if err != nil {
		return false, fmt.Errorf("build hydra request: %w", err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("hydra token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false, fmt.Errorf("read hydra response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hydra returned HTTP %d: %s", resp.StatusCode, raw)
	}

	var tok tokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return false, fmt.Errorf("decode hydra response: %w", err)
	}
	if tok.Error != "" {
		return false, nil
	}
	return tok.AccessToken != "", nil
}
