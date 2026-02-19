// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package runtimeutil

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ResolveDigest queries a registry reference and returns its content digest.
// It uses the default keychain and does not require a local Docker daemon.
func ResolveDigest(ctx context.Context, reference string) (string, error) {
	refValue := strings.TrimSpace(reference)
	if refValue == "" {
		return "", fmt.Errorf("empty reference")
	}

	ref, err := name.ParseReference(refValue)
	if err != nil {
		return "", fmt.Errorf("parsing reference: %w", err)
	}

	headDesc, err := remote.Head(
		ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err == nil && headDesc != nil {
		return headDesc.Digest.String(), nil
	}

	getDesc, getErr := remote.Get(
		ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if getErr != nil {
		if err != nil {
			return "", fmt.Errorf("head failed (%v); get failed: %w", err, getErr)
		}
		return "", fmt.Errorf("get failed: %w", getErr)
	}

	return getDesc.Digest.String(), nil
}
