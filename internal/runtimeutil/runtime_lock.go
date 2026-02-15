// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package runtimeutil

import (
	_ "embed"
	"encoding/json"
	"os"
	"path"
	"strings"
	"sync"
)

//go:embed runtime-lock.json
var embeddedRuntimeLockJSON []byte

type runtimeLockFile struct {
	SchemaVersion int                           `json:"schema_version"`
	Runtimes      map[string]runtimeLockRuntime `json:"runtimes"`
}

type runtimeLockRuntime struct {
	Reference string `json:"reference"`
	Tag       string `json:"tag"`
	Digest    string `json:"digest"`
}

var (
	runtimeLockOnce sync.Once
	runtimeLockData runtimeLockFile
)

func loadRuntimeLock() runtimeLockFile {
	runtimeLockOnce.Do(func() {
		runtimeLockData = runtimeLockFile{
			SchemaVersion: 1,
			Runtimes:      map[string]runtimeLockRuntime{},
		}

		raw := embeddedRuntimeLockJSON
		if override := strings.TrimSpace(os.Getenv("UNIKCTL_RUNTIME_LOCKFILE")); override != "" {
			loaded, err := os.ReadFile(override)
			if err == nil {
				raw = loaded
			}
		}

		candidate := runtimeLockFile{}
		if err := json.Unmarshal(raw, &candidate); err != nil {
			return
		}

		if candidate.Runtimes == nil {
			candidate.Runtimes = map[string]runtimeLockRuntime{}
		}

		runtimeLockData = candidate
	})

	return runtimeLockData
}

func lockDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("UNIKCTL_RUNTIME_LOCK_DISABLE"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func lockRuntimeKey(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	ref := Parse(name)
	name = strings.TrimSpace(ref.Name)
	if name == "" {
		return ""
	}

	if strings.Contains(name, "/") {
		trimmed := strings.TrimPrefix(name, RuntimeRegistryPrefix+"/")
		trimmed = strings.TrimPrefix(trimmed, RuntimeRegistryNamespace+"/")
		if strings.Contains(trimmed, "/") {
			return strings.ToLower(path.Base(trimmed))
		}
		return strings.ToLower(trimmed)
	}

	if mapped, ok := aliases[strings.ToLower(name)]; ok {
		return mapped
	}

	return strings.ToLower(name)
}

func lockedReferenceFor(name, version string) (Reference, bool) {
	if lockDisabled() {
		return Reference{}, false
	}

	key := lockRuntimeKey(name)
	if key == "" {
		return Reference{}, false
	}

	lock := loadRuntimeLock()
	entry, ok := lock.Runtimes[key]
	if !ok {
		return Reference{}, false
	}

	digest := strings.TrimSpace(entry.Digest)
	if digest == "" {
		return Reference{}, false
	}

	tag := strings.TrimSpace(entry.Tag)
	if tag != "" && strings.TrimSpace(version) != "" && strings.TrimSpace(version) != tag {
		return Reference{}, false
	}

	reference := strings.TrimSpace(entry.Reference)
	if reference == "" {
		reference = RuntimeRegistryPrefix + "/" + key
	}

	return Reference{
		Name:   reference,
		Digest: digest,
	}, true
}
