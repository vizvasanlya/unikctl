// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package runtimeutil

import (
	"fmt"
	"strings"
)

const (
	RuntimeRegistryHost      = "ghcr.io"
	RuntimeRegistryNamespace = "vizvasanlya/unikctl"
	RuntimeRegistryPrefix    = RuntimeRegistryHost + "/" + RuntimeRegistryNamespace
	DefaultRuntime           = RuntimeRegistryPrefix + "/base:latest"
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
	Digest  string
}

func (ref Reference) String() string {
	name := strings.TrimSpace(ref.Name)
	if name == "" {
		return ""
	}

	digest := strings.TrimSpace(ref.Digest)
	version := strings.TrimSpace(ref.Version)
	if digest != "" {
		return fmt.Sprintf("%s@%s", name, digest)
	}
	if version != "" {
		return fmt.Sprintf("%s:%s", name, version)
	}

	return name
}

func Parse(reference string) Reference {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return Reference{}
	}

	digest := ""
	lastAt := strings.LastIndex(reference, "@")
	lastSlashAtDigest := strings.LastIndex(reference, "/")
	if lastAt > lastSlashAtDigest {
		digest = strings.TrimSpace(reference[lastAt+1:])
		reference = strings.TrimSpace(reference[:lastAt])
	}

	lastSlash := strings.LastIndex(reference, "/")
	lastColon := strings.LastIndex(reference, ":")
	if lastColon > lastSlash {
		return Reference{
			Name:    strings.TrimSpace(reference[:lastColon]),
			Version: strings.TrimSpace(reference[lastColon+1:]),
			Digest:  digest,
		}
	}

	return Reference{Name: reference, Digest: digest}
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
		return RuntimeRegistryPrefix + "/" + mapped
	}

	return RuntimeRegistryPrefix + "/" + strings.ToLower(name)
}

func Normalize(reference, defaultVersion string) string {
	ref := Parse(reference)
	if ref.Name == "" {
		return ""
	}

	name := NormalizeName(ref.Name)
	if ref.Digest != "" {
		return Reference{
			Name:   name,
			Digest: ref.Digest,
		}.String()
	}

	version := strings.TrimSpace(ref.Version)
	if version == "" {
		version = strings.TrimSpace(defaultVersion)
	}

	return Reference{
		Name:    name,
		Version: version,
	}.String()
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
		candidate.Digest = strings.TrimSpace(candidate.Digest)
		if candidate.Name == "" {
			return
		}
		key := candidate.String()
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, candidate)
	}

	if locked, ok := lockedReferenceFor(normalized.Name, normalized.Version); ok {
		appendUnique(locked)
	}

	appendUnique(normalized)
	appendUnique(raw)

	// Allow fallback to namespace-qualified and short names.
	if normalized.Digest == "" && strings.HasPrefix(normalized.Name, RuntimeRegistryPrefix+"/") {
		short := strings.TrimPrefix(normalized.Name, RuntimeRegistryPrefix+"/")
		appendUnique(Reference{
			Name:    RuntimeRegistryNamespace + "/" + short,
			Version: normalized.Version,
		})
		appendUnique(Reference{
			Name:    short,
			Version: normalized.Version,
		})
	}

	return candidates
}

func MissingRuntimeHint(reference string) string {
	ref := Parse(strings.TrimSpace(reference))
	if ref.Name == "" {
		return ""
	}

	key := lockRuntimeKey(ref.Name)
	switch key {
	case "base", "nodejs", "python", "java", "dotnet":
		return fmt.Sprintf(
			"hint: runtime image '%s/%s:%s' was not found; publish it first (workflow: build-runtimes/publish-runtimes) or set unik.yaml runtime to an available image",
			RuntimeRegistryPrefix,
			key,
			firstNonEmpty(ref.Version, "latest"),
		)
	}

	if strings.HasPrefix(ref.Name, RuntimeRegistryPrefix+"/") {
		return fmt.Sprintf(
			"hint: ensure '%s' is published and accessible in GHCR (configure registry credentials in ~/.docker/config.json or runtime auth settings)",
			ref.String(),
		)
	}

	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
