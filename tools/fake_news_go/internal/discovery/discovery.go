package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"

	internaltransport "github.com/jmpsec/osctrl/tools/fake_news_go/internal/transport"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ExpHours int    `json:"exp_hours"`
}

type loginResponse struct {
	Token string `json:"token"`
}

type Environment struct {
	UUID   string `json:"uuid"`
	Name   string `json:"name"`
	Secret string `json:"-"`
}

type dataResponse struct {
	Data string `json:"data"`
}

type Client struct {
	baseURL    string
	httpClient *internaltransport.Client
}

func NewClient(baseURL string, httpClient *internaltransport.Client) *Client {
	if httpClient == nil {
		httpClient = internaltransport.New(nil)
	}
	return &Client{
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		httpClient: httpClient,
	}
}

func (c *Client) Discover(ctx context.Context, username, password string) ([]Environment, error) {
	if c == nil {
		return nil, errors.New("discovery client is nil")
	}
	token, err := c.login(ctx, username, password)
	if err != nil {
		return nil, err
	}
	envs, err := c.listEnvironments(ctx, token)
	if err != nil {
		return nil, err
	}
	discovered := make([]Environment, 0, len(envs))
	for _, env := range envs {
		if strings.TrimSpace(env.UUID) == "" {
			continue
		}
		secret, err := c.getEnrollSecret(ctx, token, env.UUID)
		if err != nil {
			continue
		}
		env.Secret = secret
		discovered = append(discovered, env)
	}
	sort.Slice(discovered, func(i, j int) bool {
		return discovered[i].UUID < discovered[j].UUID
	})
	if len(discovered) == 0 {
		return nil, errors.New("no environments with enroll secrets were discoverable")
	}
	return discovered, nil
}

func (c *Client) login(ctx context.Context, username, password string) (string, error) {
	resp, err := c.httpClient.PostJSON(ctx, c.apiURL("api/v1/login"), LoginRequest{
		Username: username,
		Password: password,
		ExpHours: 24,
	}, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api login failed with status %d", resp.StatusCode)
	}
	var body loginResponse
	if err := internaltransport.DecodeJSON(resp.RawBody, &body); err != nil {
		return "", err
	}
	if strings.TrimSpace(body.Token) == "" {
		return "", errors.New("api login returned empty token")
	}
	return body.Token, nil
}

func (c *Client) listEnvironments(ctx context.Context, token string) ([]Environment, error) {
	resp, err := c.httpClient.GetJSON(ctx, c.apiURL("api/v1/environments"), bearerHeaders(token))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api environments failed with status %d", resp.StatusCode)
	}
	var envs []Environment
	if err := internaltransport.DecodeJSON(resp.RawBody, &envs); err != nil {
		return nil, err
	}
	return envs, nil
}

func (c *Client) getEnrollSecret(ctx context.Context, token, envUUID string) (string, error) {
	resp, err := c.httpClient.GetJSON(ctx, c.apiURL(path.Join("api/v1/environments", envUUID, "enroll/secret")), bearerHeaders(token))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api enroll secret failed for %s with status %d", envUUID, resp.StatusCode)
	}
	var body dataResponse
	if err := internaltransport.DecodeJSON(resp.RawBody, &body); err != nil {
		return "", err
	}
	if strings.TrimSpace(body.Data) == "" {
		return "", fmt.Errorf("api enroll secret empty for %s", envUUID)
	}
	return body.Data, nil
}

func (c *Client) apiURL(relativePath string) string {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return c.baseURL + "/" + strings.TrimLeft(relativePath, "/")
	}
	base.Path = path.Join(base.Path, relativePath)
	return base.String()
}

func bearerHeaders(token string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + token,
	}
}
