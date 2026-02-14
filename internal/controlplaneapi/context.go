// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneapi

import "context"

type serverModeKey struct{}

func WithServerMode(ctx context.Context) context.Context {
	return context.WithValue(ctx, serverModeKey{}, true)
}

func InServerMode(ctx context.Context) bool {
	v, ok := ctx.Value(serverModeKey{}).(bool)
	return ok && v
}
