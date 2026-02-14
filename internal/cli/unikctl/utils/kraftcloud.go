package utils

import (
	"strings"
)

const cloudRegistryPrefix = "ghcr.io/vizvasanlya/unikctl"

// RewrapAsKraftCloudPackage returns the equivalent package name in the
// configured cloud registry namespace.
func RewrapAsKraftCloudPackage(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return cloudRegistryPrefix + "/base:latest"
	}

	if strings.HasPrefix(name, cloudRegistryPrefix) {
		return name
	}

	trimmed := name
	trimmed = strings.TrimPrefix(trimmed, "ghcr.io/official/")
	trimmed = strings.TrimPrefix(trimmed, "official/")
	trimmed = strings.TrimPrefix(trimmed, "/")

	if strings.HasPrefix(trimmed, "ghcr.io/") {
		return trimmed
	}

	if strings.Contains(trimmed, "/") {
		return "ghcr.io/" + trimmed
	}

	return cloudRegistryPrefix + "/" + trimmed
}
