//go:build windows
// +build windows

// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package erofs

import (
	"archive/tar"
	"io/fs"
)

// Partially stubbed
func getOwner(fi fs.FileInfo) (uid, gid int) {
	switch fi.Sys().(type) {
	case *tar.Header:
		hdr := fi.Sys().(*tar.Header)

		uid = hdr.Uid
		gid = hdr.Gid
	}

	return
}

// Stubbed
func getNLinks(_ fs.FileInfo) int {
	return 1
}

// Stubbed
func getIno(_ fs.FileInfo) uint64 {
	return 0
}
