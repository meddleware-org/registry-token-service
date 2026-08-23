// Package keto provides a minimal client for the Ory Keto v0.14 REST read API.
package keto

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client queries the Keto read API for permission checks.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient constructs a Client targeting the given Keto read base URL
// (e.g. "http://keto.auth.svc.cluster.local:4466").
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// checkResponse is the Keto v0.13 GET /relation-tuples/check response body.
type checkResponse struct {
	Allowed bool `json:"allowed"`
}

// CheckPermission returns true if subjectID holds relation rel on object in namespace.
// namespace is the Keto namespace name (e.g. "Registry").
// relation is the relation name (e.g. "pushers", "pullers").
func (c *Client) CheckPermission(ctx context.Context, namespace, object, relation, subjectID string) (bool, error) {
	endpoint := c.baseURL + "/relation-tuples/check"

	q := url.Values{}
	q.Set("namespace", namespace)
	q.Set("object", object)
	q.Set("relation", relation)
	q.Set("subject_id", subjectID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return false, fmt.Errorf("build keto request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("keto check request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return false, fmt.Errorf("read keto response: %w", err)
	}

	// Keto returns 200 {allowed:true} or 403 {allowed:false}.
	if resp.StatusCode == http.StatusForbidden {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("keto returned HTTP %d: %s", resp.StatusCode, raw)
	}

	var result checkResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return false, fmt.Errorf("decode keto response: %w", err)
	}
	return result.Allowed, nil
}
