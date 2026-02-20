// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneapi

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"unikctl.sh/config"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	authToken  string
	tenantID   string
}

type ClientOptions struct {
	AuthToken   string
	TenantID    string
	TLSCAFile   string
	TLSInsecure bool
	Timeout     time.Duration
}

func Enabled(ctx context.Context) bool {
	if InServerMode(ctx) {
		return false
	}

	endpoint := controlPlaneURL(ctx)
	return endpoint != ""
}

func NewClientFromContext(ctx context.Context) (*Client, error) {
	baseURL := controlPlaneURL(ctx)
	if baseURL == "" {
		return nil, fmt.Errorf("control plane URL is not configured")
	}

	controlPlaneCfg := config.G[config.KraftKit](ctx).ControlPlane
	authToken := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_TOKEN"))
	if authToken == "" {
		authToken = strings.TrimSpace(controlPlaneCfg.Token)
	}
	tenantID := strings.TrimSpace(os.Getenv("UNIKCTL_TENANT"))

	return NewClient(baseURL, ClientOptions{
		AuthToken:   authToken,
		TenantID:    tenantID,
		TLSCAFile:   controlPlaneCfg.TLSCAFile,
		TLSInsecure: controlPlaneCfg.TLSInsecure || parseBoolEnv("UNIKCTL_CONTROL_PLANE_TLS_INSECURE_SKIP_VERIFY"),
		Timeout:     30 * time.Second,
	})
}

func NewClient(baseURL string, opts ClientOptions) (*Client, error) {
	parsed, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid control plane URL: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.EqualFold(parsed.Scheme, "https") {
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if strings.TrimSpace(opts.TLSCAFile) != "" {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}

			pemBytes, err := os.ReadFile(strings.TrimSpace(opts.TLSCAFile))
			if err != nil {
				return nil, fmt.Errorf("reading control plane CA file: %w", err)
			}

			block, _ := pem.Decode(pemBytes)
			if block == nil {
				return nil, fmt.Errorf("invalid CA file: no PEM data found")
			}

			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("invalid CA file: could not append certificate")
			}

			transport.TLSClientConfig.RootCAs = pool
		}

		if opts.TLSInsecure {
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		authToken: strings.TrimSpace(opts.AuthToken),
		tenantID:  strings.TrimSpace(opts.TenantID),
	}, nil
}

func controlPlaneURL(ctx context.Context) string {
	if endpoint := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_URL")); endpoint != "" {
		return endpoint
	}

	return strings.TrimSpace(config.G[config.KraftKit](ctx).ControlPlane.URL)
}

func (client *Client) Deploy(ctx context.Context, req DeployRequest) (*DeployResponse, error) {
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newTraceID()
	}

	var res DeployResponse
	if err := client.doJSON(ctx, http.MethodPost, "/v1/deployments", req, &res); err != nil {
		return nil, err
	}
	if strings.TrimSpace(res.TraceID) == "" {
		res.TraceID = req.TraceID
	}
	return &res, nil
}

func (client *Client) Destroy(ctx context.Context, req DestroyRequest) (*DestroyResponse, error) {
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newTraceID()
	}

	var res DestroyResponse
	if err := client.doJSON(ctx, http.MethodPost, "/v1/destroy", req, &res); err != nil {
		return nil, err
	}
	if strings.TrimSpace(res.TraceID) == "" {
		res.TraceID = req.TraceID
	}
	return &res, nil
}

func (client *Client) Status(ctx context.Context) (*StatusResponse, error) {
	var res StatusResponse
	if err := client.doJSON(ctx, http.MethodGet, "/v1/status", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (client *Client) Inspect(ctx context.Context, name string) (*InspectResponse, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("inspect target is required")
	}

	var res InspectResponse
	if err := client.doJSON(ctx, http.MethodGet, "/v1/inspect/"+url.PathEscape(name), nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (client *Client) SubstrateStatus(ctx context.Context) (*SubstrateStatusResponse, error) {
	var res SubstrateStatusResponse
	if err := client.doJSON(ctx, http.MethodGet, "/v1/substrate/status", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (client *Client) RegisterNode(ctx context.Context, req NodeRegisterRequest) (*NodeActionResponse, error) {
	var res NodeActionResponse
	if err := client.doJSON(ctx, http.MethodPost, "/v1/nodes/register", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (client *Client) HeartbeatNode(ctx context.Context, req NodeHeartbeatRequest) (*NodeActionResponse, error) {
	var res NodeActionResponse
	if err := client.doJSON(ctx, http.MethodPost, "/v1/nodes/heartbeat", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (client *Client) CordonNode(ctx context.Context, nodeName string) (*NodeActionResponse, error) {
	var res NodeActionResponse
	if err := client.doJSON(ctx, http.MethodPost, "/v1/nodes/"+url.PathEscape(strings.TrimSpace(nodeName))+"/cordon", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (client *Client) UncordonNode(ctx context.Context, nodeName string) (*NodeActionResponse, error) {
	var res NodeActionResponse
	if err := client.doJSON(ctx, http.MethodPost, "/v1/nodes/"+url.PathEscape(strings.TrimSpace(nodeName))+"/uncordon", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (client *Client) DrainNode(ctx context.Context, nodeName string) (*NodeActionResponse, error) {
	var res NodeActionResponse
	if err := client.doJSON(ctx, http.MethodPost, "/v1/nodes/"+url.PathEscape(strings.TrimSpace(nodeName))+"/drain", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (client *Client) Logs(ctx context.Context, machine string, follow bool, out io.Writer) error {
	url := fmt.Sprintf("%s/v1/logs/%s", client.baseURL, url.PathEscape(machine))
	if follow {
		url += "?follow=1"
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating logs request: %w", err)
	}
	client.attachCommonHeaders(httpReq, newTraceID())

	res, err := client.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("requesting logs: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("control plane logs request failed: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		if _, err := fmt.Fprintln(out, scanner.Text()); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading logs stream: %w", err)
	}

	return nil
}

func (client *Client) UploadSource(ctx context.Context, sourcePath string) (string, error) {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return "", fmt.Errorf("source path cannot be empty")
	}

	absolutePath, err := filepath.Abs(sourcePath)
	if err != nil {
		return "", fmt.Errorf("resolving source path: %w", err)
	}

	if _, err := os.Stat(absolutePath); err != nil {
		return "", fmt.Errorf("invalid source path: %w", err)
	}

	bodyReader, bodyWriter := io.Pipe()
	go func() {
		bodyWriter.CloseWithError(writeSourceArchive(absolutePath, bodyWriter))
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+"/v1/artifacts", bodyReader)
	if err != nil {
		return "", fmt.Errorf("creating artifact upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/gzip")
	client.attachCommonHeaders(req, newTraceID())

	res, err := client.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("uploading source artifact: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return "", fmt.Errorf("artifact upload failed: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}

	var response ArtifactUploadResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("decoding artifact upload response: %w", err)
	}

	if strings.TrimSpace(response.ArtifactID) == "" {
		return "", fmt.Errorf("artifact upload did not return an artifact ID")
	}

	return response.ArtifactID, nil
}

func (client *Client) doJSON(ctx context.Context, method, path string, requestBody any, responseBody any) error {
	var payload io.Reader
	if requestBody != nil {
		raw, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		payload = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, payload)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	traceID := newTraceID()
	client.attachCommonHeaders(req, traceID)

	res, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return formatAPIError(res.Status, body)
	}

	if responseBody == nil {
		return nil
	}

	if err := json.NewDecoder(res.Body).Decode(responseBody); err != nil {
		return fmt.Errorf("decoding response body: %w", err)
	}

	return nil
}

func writeSourceArchive(sourcePath string, writer io.Writer) error {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return fmt.Errorf("stating source path: %w", err)
	}

	gzipWriter := gzip.NewWriter(writer)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	if info.IsDir() {
		return filepath.WalkDir(sourcePath, func(path string, dirEntry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			rel, err := filepath.Rel(sourcePath, path)
			if err != nil {
				return err
			}

			if rel == "." {
				return nil
			}

			if shouldSkipSourcePath(rel, dirEntry) {
				if dirEntry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}

			return addArchiveEntry(tarWriter, path, rel, dirEntry)
		})
	}

	return addArchiveEntry(tarWriter, sourcePath, filepath.Base(sourcePath), nil)
}

func addArchiveEntry(tarWriter *tar.Writer, sourcePath, archivePath string, dirEntry fs.DirEntry) error {
	fileInfo, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return nil
	}

	header, err := tar.FileInfoHeader(fileInfo, "")
	if err != nil {
		return fmt.Errorf("creating tar header for %s: %w", sourcePath, err)
	}

	header.Name = filepath.ToSlash(archivePath)
	if fileInfo.IsDir() && !strings.HasSuffix(header.Name, "/") {
		header.Name += "/"
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("writing tar header for %s: %w", sourcePath, err)
	}

	if fileInfo.IsDir() {
		return nil
	}

	// When walk metadata is already available, avoid reopening via os.Stat paths.
	if dirEntry != nil && dirEntry.IsDir() {
		return nil
	}

	file, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("opening source file %s: %w", sourcePath, err)
	}
	defer file.Close()

	if _, err := io.Copy(tarWriter, file); err != nil {
		return fmt.Errorf("writing source file %s: %w", sourcePath, err)
	}

	return nil
}

func shouldSkipSourcePath(path string, entry fs.DirEntry) bool {
	name := strings.ToLower(entry.Name())

	switch name {
	case ".git", ".unikctl":
		return true
	}

	// Ignore editor/OS noise files when bundling source.
	if !entry.IsDir() {
		lower := strings.ToLower(filepath.Base(path))
		if lower == ".ds_store" || lower == "thumbs.db" {
			return true
		}
	}

	return false
}

func (client *Client) attachCommonHeaders(req *http.Request, traceID string) {
	if req == nil {
		return
	}

	if strings.TrimSpace(traceID) != "" {
		req.Header.Set("X-Trace-ID", strings.TrimSpace(traceID))
	}

	if strings.TrimSpace(client.authToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(client.authToken))
	}
	if strings.TrimSpace(client.tenantID) != "" {
		req.Header.Set("X-Tenant-ID", strings.TrimSpace(client.tenantID))
	}
}

func formatAPIError(status string, body []byte) error {
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return fmt.Errorf("control plane request failed: %s", status)
	}

	var apiErr ErrorResponse
	if err := json.Unmarshal(body, &apiErr); err == nil && strings.TrimSpace(apiErr.Error) != "" {
		if strings.TrimSpace(apiErr.TraceID) != "" {
			return fmt.Errorf("control plane request failed: %s (%s, trace=%s): %s", status, firstNonEmpty(apiErr.Code, "error"), apiErr.TraceID, apiErr.Error)
		}
		return fmt.Errorf("control plane request failed: %s (%s): %s", status, firstNonEmpty(apiErr.Code, "error"), apiErr.Error)
	}

	return fmt.Errorf("control plane request failed: %s: %s", status, msg)
}

func parseBoolEnv(name string) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

func newTraceID() string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("trace-%d", time.Now().UTC().UnixNano())
	}
	return fmt.Sprintf("trace-%x", random)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
