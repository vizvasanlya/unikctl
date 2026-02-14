// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package runtimeutil

import (
	"fmt"
	"strings"
)

var aliases = map[string]string{
	"base":       "base",
	"node":       "nodejs",
	"nodejs":     "nodejs",
	"javascript": "nodejs",
	"js":         "nodejs",
	"python":     "python",
	"py":         "python",
	"java":       "java",
	"dotnet":     "dotnet",
	"csharp":     "dotnet",
	"cs":         "dotnet",
	"net":        "dotnet",
}

type Reference struct {
	Name    string
	Version string
}

func Parse(reference string) Reference {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return Reference{}
	}

	lastSlash := strings.LastIndex(reference, "/")
	lastColon := strings.LastIndex(reference, ":")
	if lastColon > lastSlash {
		return Reference{
			Name:    strings.TrimSpace(reference[:lastColon]),
			Version: strings.TrimSpace(reference[lastColon+1:]),
		}
	}

	return Reference{Name: reference}
}

func NormalizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	// Keep already-qualified names.
	if strings.Contains(name, "/") {
		return name
	}

	if mapped, ok := aliases[strings.ToLower(name)]; ok {
		return "unikraft.org/" + mapped
	}

	return "unikraft.org/" + strings.ToLower(name)
}

func Normalize(reference, defaultVersion string) string {
	ref := Parse(reference)
	if ref.Name == "" {
		return ""
	}

	name := NormalizeName(ref.Name)
	version := strings.TrimSpace(ref.Version)
	if version == "" {
		version = strings.TrimSpace(defaultVersion)
	}

	if version == "" {
		return name
	}

	return fmt.Sprintf("%s:%s", name, version)
}

func Candidates(reference, defaultVersion string) []Reference {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return nil
	}

	normalized := Parse(Normalize(reference, defaultVersion))
	raw := Parse(reference)
	if raw.Version == "" {
		raw.Version = strings.TrimSpace(defaultVersion)
	}

	candidates := []Reference{}
	seen := map[string]struct{}{}

	appendUnique := func(candidate Reference) {
		candidate.Name = strings.TrimSpace(candidate.Name)
		candidate.Version = strings.TrimSpace(candidate.Version)
		if candidate.Name == "" {
			return
		}
		key := candidate.Name + "::" + candidate.Version
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, candidate)
	}

	appendUnique(normalized)
	appendUnique(raw)

	// Allow fallback to short name for registries that index runtime without prefix.
	if strings.HasPrefix(normalized.Name, "unikraft.org/") {
		appendUnique(Reference{
			Name:    strings.TrimPrefix(normalized.Name, "unikraft.org/"),
			Version: normalized.Version,
		})
	}

	// Allow fallback to official index namespace.
	if strings.HasPrefix(normalized.Name, "unikraft.org/") {
		appendUnique(Reference{
			Name:    "index.unikraft.io/official/" + strings.TrimPrefix(normalized.Name, "unikraft.org/"),
			Version: normalized.Version,
		})
	}

	return candidates
}
