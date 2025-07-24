// Copyright ©, 2023-present, Lightspark Group, Inc. - All Rights Reserved
package sspapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/zstd"
)

// RequestError indicates that a request to the Lightspark API failed.
// It could be due to a service outage or a network error.
// The request should be retried if RequestError is returned with server errors (500-599).
type RequestError struct {
	Message    string
	StatusCode int
}

func (e RequestError) Error() string {
	return "lightspark request failed: " + strconv.Itoa(e.StatusCode) + ": " + e.Message
}

// GraphQLInternalError indicates there's a failure in the Lightspark API.
// It could be due to a bug on Ligthspark's side.
// The request can be retried, because the error might be transient.
type GraphQLInternalError struct {
	Message string
}

func (e GraphQLInternalError) Error() string {
	return "lightspark request failed: " + e.Message
}

// GraphQLError indicates the GraphQL request succeeded, but there's a user error.
// The request should not be retried, because the error is due to the user's input.
type GraphQLError struct {
	Message string
	Type    string
}

func (e GraphQLError) Error() string {
	return e.Type + ": " + e.Message
}

type Requester struct {
	BaseURL           string
	IdentityPublicKey string

	HTTPClient *http.Client
}

func NewRequester(identityPublicKey string) (*Requester, error) {
	return &Requester{IdentityPublicKey: identityPublicKey}, nil
}

func NewRequesterWithBaseURL(identityPublicKey string, baseURL string) (*Requester, error) {
	if len(baseURL) == 0 {
		return NewRequester(identityPublicKey)
	}
	if err := ValidateBaseURL(baseURL); err != nil {
		return nil, err
	}
	return &Requester{
		IdentityPublicKey: identityPublicKey,
		BaseURL:           baseURL,
	}, nil
}

func ValidateBaseURL(baseURL string) error {
	if len(baseURL) == 0 {
		return errors.New("base url is empty")
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base url: %q", baseURL)
	}
	hostNameParts := strings.Split(parsedURL.Hostname(), ".")
	hostNameTLD := hostNameParts[len(hostNameParts)-1]
	if parsedURL.Scheme != "https" && !isAllowlistedLocalhost(parsedURL, hostNameTLD) {
		return fmt.Errorf("invalid base url: %q must be https:// if not targeting localhost", baseURL)
	}
	return nil
}

func isAllowlistedLocalhost(parsedURL *url.URL, hostNameTLD string) bool {
	if parsedURL.Hostname() == "localhost" || hostNameTLD == "local" || hostNameTLD == "internal" {
		return true
	}
	asIP := net.ParseIP(parsedURL.Hostname())
	return asIP != nil && asIP.IsLoopback()
}

const DefaultBaseURL = "https://api.dev.dev.sparkinfra.net/graphql/spark/rc"

var graphQLPattern = regexp.MustCompile(`(?i)\s*(?:query|mutation)\s+(?P<OperationName>\w+)`)

func (r *Requester) ExecuteGraphqlWithContext(ctx context.Context, query string, variables map[string]any) (map[string]any, error) {
	matches := graphQLPattern.FindStringSubmatch(query)
	index := graphQLPattern.SubexpIndex("OperationName")
	if len(matches) <= index {
		return nil, errors.New("invalid query payload")
	}
	operationName := matches[index]

	payload := map[string]any{
		"operationName": operationName,
		"query":         query,
		"variables":     variables,
	}

	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error when encoding payload: %w", err)
	}

	body := encodedPayload
	compressed := len(encodedPayload) > 1024
	if compressed {
		body, err = zstd.Compress(nil, encodedPayload)
		if err != nil {
			return nil, err
		}
	}

	var serverURL string
	if len(r.BaseURL) == 0 {
		serverURL = DefaultBaseURL
	} else {
		serverURL = r.BaseURL
	}
	if err := ValidateBaseURL(serverURL); err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	if len(r.IdentityPublicKey) != 0 {
		request.Header.Add("Spark-Identity-Public-Key", r.IdentityPublicKey)
	}
	request.Header.Add("Content-Type", "application/json")
	if compressed {
		request.Header.Add("Content-Encoding", "zstd")
	}
	request.Header.Add("Accept-Encoding", "zstd")
	request.Header.Add("X-GraphQL-Operation", operationName)
	request.Header.Add("User-Agent", r.getUserAgent())
	request.Header.Add("X-Lightspark-SDK", r.getUserAgent())

	httpClient := r.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, RequestError{Message: response.Status, StatusCode: response.StatusCode}
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.Header.Get("Content-Encoding") == "zstd" {
		data, err = zstd.Decompress(nil, data)
		if err != nil {
			return nil, fmt.Errorf("invalid zstd compression: %w", err)
		}
	}

	var result map[string]any
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if errs, ok := result["errors"]; ok {
		err := errs.([]any)[0]
		errMap := err.(map[string]any)
		errorMessage := errMap["message"].(string)
		if errMap["extensions"] == nil {
			return nil, GraphQLInternalError{Message: errorMessage}
		}
		extensions := errMap["extensions"].(map[string]any)
		if extensions["error_name"] == nil {
			return nil, GraphQLInternalError{Message: errorMessage}
		}
		errorName := extensions["error_name"].(string)
		return nil, GraphQLError{Message: errorMessage, Type: errorName}
	}

	return result["data"].(map[string]any), nil
}

func (r *Requester) getUserAgent() string {
	return "spark"
}
