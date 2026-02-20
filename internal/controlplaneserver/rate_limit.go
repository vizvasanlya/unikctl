// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

type requestRateLimiter struct {
	mu      sync.Mutex
	burst   int
	limit   rate.Limit
	clients map[string]*rate.Limiter
}

func newRequestRateLimiterFromEnv() *requestRateLimiter {
	rps := 50.0
	burst := 100

	if raw := strings.TrimSpace(strings.ToLower(strings.TrimSpace(getEnv("UNIKCTL_CONTROL_PLANE_RATE_LIMIT_RPS")))); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed > 0 {
			rps = parsed
		}
	}

	if raw := strings.TrimSpace(getEnv("UNIKCTL_CONTROL_PLANE_RATE_LIMIT_BURST")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			burst = parsed
		}
	}

	return &requestRateLimiter{
		burst:   burst,
		limit:   rate.Limit(rps),
		clients: map[string]*rate.Limiter{},
	}
}

func (limiter *requestRateLimiter) allow(client string) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	entry, ok := limiter.clients[client]
	if !ok {
		entry = rate.NewLimiter(limiter.limit, limiter.burst)
		limiter.clients[client] = entry
	}

	return entry.Allow()
}

func (server *Server) withRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := requestTraceID(r)
		if server.rateLimiter != nil {
			client := requestClientIdentifier(r)
			if !server.rateLimiter.allow(client) {
				writeErrorTrace(w, http.StatusTooManyRequests, "rate limit exceeded", traceID)
				return
			}
		}
		next(w, r)
	}
}

func requestClientIdentifier(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			first := strings.TrimSpace(parts[0])
			if first != "" {
				return first
			}
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}

	if trimmed := strings.TrimSpace(r.RemoteAddr); trimmed != "" {
		return trimmed
	}
	return "unknown"
}

func getEnv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func parseBoolEnv(name string) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if raw == "" {
		return false
	}

	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false
	}

	return parsed
}
