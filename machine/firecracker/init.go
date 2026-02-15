// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package firecracker

import (
	"encoding/gob"
	"reflect"
	"strings"
)

func registerLegacyGobAlias(v any) {
	t := reflect.TypeOf(v)
	if t == nil {
		return
	}

	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t.Name() == "" || t.PkgPath() == "" {
		return
	}

	legacyPath := strings.Replace(t.PkgPath(), "unikctl.sh/", "kraftkit.sh/", 1)
	if legacyPath == t.PkgPath() {
		return
	}

	gob.RegisterName(legacyPath+"."+t.Name(), v)
}

func init() {
	gob.Register(FirecrackerConfig{})
	registerLegacyGobAlias(FirecrackerConfig{})
}
