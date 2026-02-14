// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

// Package bootstrap lets us keep kraftkit initialization logic in one place.
package bootstrap

import (
	"context"

	"unikctl.sh/api"
	"unikctl.sh/machine/qemu"
	"unikctl.sh/manifest"
	"unikctl.sh/oci"
	"unikctl.sh/packmanager"
)

// InitKraftkit performs a set of kraftkit setup steps.
// It allows us to move away from in-package init() magic.
// It also allows us to propagate initialization errors easily.
func InitKraftkit(ctx context.Context) error {
	registerAdditionalFlags()

	if err := registerSchemes(); err != nil {
		return err
	}

	return registerPackageManagers(ctx)
}

func registerAdditionalFlags() {
	manifest.RegisterFlags()
	qemu.RegisterFlags()
}

func registerSchemes() error {
	return api.RegisterSchemes()
}

func registerPackageManagers(ctx context.Context) error {
	managerConstructors := []func(u *packmanager.UmbrellaManager) error{
		oci.RegisterPackageManager(),
		manifest.RegisterPackageManager(),
	}

	return packmanager.InitUmbrellaManager(ctx, managerConstructors)
}
