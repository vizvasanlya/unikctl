// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package initrd

import (
	"context"
)

type ociimage struct{}

// NewFromOCIImage creates a new initrd from a remote container image.
func NewFromOCIImage(ctx context.Context, path string, opts ...InitrdOption) (Initrd, error) {
	return nil, nil
}

// Build implements Initrd.
func (initrd *ociimage) Name() string {
	return "OCI image"
}

// Build implements Initrd.
func (initrd *ociimage) Build(ctx context.Context) (string, error) {
	return "", nil
}

// Env implements Initrd.
func (initrd *ociimage) Env() []string {
	return nil
}

// Args implements Initrd.
func (initrd *ociimage) Args() []string {
	return nil
}
