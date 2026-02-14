// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package erofs_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"
	"unikctl.sh/fs/erofs"

	"github.com/stretchr/testify/require"
)

func TestEROFS(t *testing.T) {
	f, err := os.Open("testdata/toybox.img")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, f.Close())
	})

	fsys, err := erofs.Open(f)
	require.NoError(t, err)

	t.Run("Open", func(t *testing.T) {
		t.Run("File", func(t *testing.T) {
			f, err := fsys.Open("/usr/bin/toybox")
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, f.Close())
			})

			info, err := f.Stat()
			require.NoError(t, err)

			require.Equal(t, "toybox", info.Name())
			require.Equal(t, 849544, int(info.Size()))
			require.Equal(t, os.FileMode(0o555), info.Mode()&fs.ModePerm)
			require.False(t, info.IsDir())

			h := sha256.New()

			n, err := io.Copy(h, f)
			require.NoError(t, err)

			require.Equal(t, int64(849544), n)

			require.Equal(t, "31aa01d6d46f63edcadc00fd5c40f3474f0df6c22a39ed0c5751ba3efa2855ac", hex.EncodeToString(h.Sum(nil)))
		})

		t.Run("Symlink", func(t *testing.T) {
			f, err := fsys.Open("bin/sh")
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, f.Close())
			})

			info, err := f.Stat()
			require.NoError(t, err)

			require.Equal(t, "toybox", info.Name())
			require.Equal(t, os.FileMode(0o555), info.Mode()&fs.ModePerm)
			require.False(t, info.IsDir())

			h := sha256.New()

			n, err := io.Copy(h, f)
			require.NoError(t, err)

			require.Equal(t, int64(849544), n)

			require.Equal(t, "31aa01d6d46f63edcadc00fd5c40f3474f0df6c22a39ed0c5751ba3efa2855ac", hex.EncodeToString(h.Sum(nil)))
		})
	})

	t.Run("ReadDir", func(t *testing.T) {
		entries, err := fsys.ReadDir("/etc")
		require.NoError(t, err)

		require.Len(t, entries, 5)

		require.Equal(t, "group", entries[0].Name())
		require.False(t, entries[0].IsDir())
		require.Equal(t, 0o644, int(entries[0].Type()))

		require.Equal(t, "os-release", entries[1].Name())
		require.False(t, entries[1].IsDir())
		require.Equal(t, 0o644, int(entries[1].Type()))

		require.Equal(t, "passwd", entries[2].Name())
		require.False(t, entries[2].IsDir())
		require.Equal(t, 0o644, int(entries[2].Type()))

		require.Equal(t, "rc", entries[3].Name())
		require.True(t, entries[3].IsDir())
		require.True(t, entries[3].Type()&fs.ModeDir > 0)

		require.Equal(t, "resolv.conf", entries[4].Name())
		require.False(t, entries[4].IsDir())
		require.Equal(t, 0o644, int(entries[4].Type()))
	})

	t.Run("Stat", func(t *testing.T) {
		t.Run("File", func(t *testing.T) {
			info, err := fsys.Stat("/usr/bin/toybox")
			require.NoError(t, err)

			require.Equal(t, "toybox", info.Name())
			require.Equal(t, 849544, int(info.Size()))
			require.Equal(t, os.FileMode(0o555), info.Mode()&fs.ModePerm)
			require.False(t, info.IsDir())

			ino, ok := info.Sys().(*erofs.Inode)
			require.True(t, ok)

			require.Equal(t, uint64(0x327), ino.Nid())
			require.Zero(t, ino.UID())
			require.Zero(t, ino.GID())
		})

		t.Run("Dir", func(t *testing.T) {
			info, err := fsys.Stat("usr")
			require.NoError(t, err)

			require.Equal(t, "usr", info.Name())
			require.Equal(t, os.FileMode(0o755), info.Mode()&fs.ModePerm)
			require.True(t, info.IsDir())

			ino, ok := info.Sys().(*erofs.Inode)
			require.True(t, ok)

			require.Equal(t, uint64(0x9c), ino.Nid())
			require.Zero(t, ino.UID())
			require.Zero(t, ino.GID())
		})

		t.Run("Symlink", func(t *testing.T) {
			info, err := fsys.Stat("bin/sh")
			require.NoError(t, err)

			require.Equal(t, "toybox", info.Name())
			require.Equal(t, os.FileMode(0o555), info.Mode()&fs.ModePerm)
			require.False(t, info.IsDir())

			ino, ok := info.Sys().(*erofs.Inode)
			require.True(t, ok)

			require.Equal(t, uint64(0x327), ino.Nid())
			require.Zero(t, ino.UID())
			require.Zero(t, ino.GID())
		})
	})

	t.Run("Readlink", func(t *testing.T) {
		target, err := fsys.ReadLink("bin")
		require.NoError(t, err)

		require.Equal(t, "usr/bin", target)
	})

	t.Run("StatLink", func(t *testing.T) {
		info, err := fsys.StatLink("bin")
		require.NoError(t, err)

		require.Equal(t, "bin", info.Name())
		require.Equal(t, os.FileMode(0o777), info.Mode()&fs.ModePerm)
		require.False(t, info.IsDir())

		ino, ok := info.Sys().(*erofs.Inode)
		require.True(t, ok)

		require.Equal(t, uint64(0x2f), ino.Nid())
		require.Zero(t, ino.UID())
		require.Zero(t, ino.GID())
	})

	t.Run("WalkDir", func(t *testing.T) {
		var paths []string
		err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			paths = append(paths, path)

			return nil
		})
		require.NoError(t, err)

		require.Len(t, paths, 266)

		require.Equal(t, []string{
			".",
			"bin",
			"dev",
			"etc",
			"etc/group",
		}, paths[:5])
	})

	t.Run("DirHash", func(t *testing.T) {
		var files []string
		err = fs.WalkDir(fsys, ".", func(file string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
				return nil
			}

			files = append(files, filepath.ToSlash(file))
			return nil
		})
		require.NoError(t, err)

		h, err := dirhash.Hash1(files, func(name string) (io.ReadCloser, error) {
			return fsys.Open(name)
		})
		require.NoError(t, err)

		require.Equal(t, "h1:adgxkqVceeKMyJdMZMvcUIbg94TthnXUmOeufCPuzQI=", h)
	})
}

func TestEROFSCreate(t *testing.T) {
	input := "testdata/testfs.erofs"
	output := "testdata/testfs-test.erofs"
	inputFS := "testdata/testfs.tar.gz"

	inputFile, err := os.Open(input)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, inputFile.Close())
	})

	err = erofs.CreateFS(t.Context(), output, inputFS, erofs.WithAllRoot(true))
	t.Cleanup(func() {
		require.NoError(t, os.Remove(output))
	})
	require.NoError(t, err)

	// Original file as created by `mkfs.erofs`
	refSys, err := erofs.Open(inputFile)
	require.NoError(t, err)

	// Created file as created by `erofs.Create`
	outputFile, err := os.Open(output)
	require.NoError(t, err)
	testSys, err := erofs.Open(outputFile)
	require.NoError(t, err)

	t.Run("Readlink Dir", func(t *testing.T) {
		refLink, err := refSys.ReadLink("dir-link")
		require.NoError(t, err)

		testLink, err := testSys.ReadLink("dir-link")
		require.NoError(t, err)

		require.Equal(t, "dir", refLink)
		require.Equal(t, "dir", testLink)
	})

	t.Run("Readlink File", func(t *testing.T) {
		refLink, err := refSys.ReadLink("file-link")
		require.NoError(t, err)

		testLink, err := testSys.ReadLink("file-link")
		require.NoError(t, err)

		require.Equal(t, "file.txt", refLink)
		require.Equal(t, "file.txt", testLink)
	})

	t.Run("Stat", func(t *testing.T) {
		t.Run("File", func(t *testing.T) {
			infoRef, err := refSys.Stat("dir/file2.txt")
			require.NoError(t, err)

			infoTest, err := testSys.Stat("dir/file2.txt")
			require.NoError(t, err)

			require.Equal(t, "file2.txt", infoRef.Name())
			require.Equal(t, "file2.txt", infoTest.Name())

			require.Equal(t, 5, int(infoRef.Size()))
			require.Equal(t, 5, int(infoTest.Size()))

			// Inconsistent unpacking in CI
			// require.Equal(t, os.FileMode(0o644), infoRef.Mode()&fs.ModePerm)
			require.Equal(t, os.FileMode(0o644), infoTest.Mode()&fs.ModePerm)

			require.False(t, infoRef.IsDir())
			require.False(t, infoTest.IsDir())

			inoRef, ok := infoRef.Sys().(*erofs.Inode)
			require.True(t, ok)
			require.Zero(t, inoRef.UID())
			require.Zero(t, inoRef.GID())

			inoTest, ok := infoTest.Sys().(*erofs.Inode)
			require.True(t, ok)
			require.Zero(t, inoTest.UID())
			require.Zero(t, inoTest.GID())
		})

		t.Run("Hardlink", func(t *testing.T) {
			infoRef, err := refSys.Stat("file2-hard-link")
			require.NoError(t, err)

			infoTest, err := testSys.Stat("file2-hard-link")
			require.NoError(t, err)

			require.Equal(t, "file2-hard-link", infoRef.Name())
			require.Equal(t, "file2-hard-link", infoTest.Name())

			require.Equal(t, 5, int(infoRef.Size()))
			require.Equal(t, 5, int(infoTest.Size()))

			// Inconsistent unpacking in CI
			// require.Equal(t, os.FileMode(0o644), infoRef.Mode()&fs.ModePerm)
			require.Equal(t, os.FileMode(0o644), infoTest.Mode()&fs.ModePerm)

			require.False(t, infoRef.IsDir())
			require.False(t, infoTest.IsDir())

			inoRef, ok := infoRef.Sys().(*erofs.Inode)
			require.True(t, ok)
			require.Zero(t, inoRef.UID())
			require.Zero(t, inoRef.GID())
			require.Equal(t, uint32(0x2), inoRef.Nlink())

			inoTest, ok := infoTest.Sys().(*erofs.Inode)
			require.True(t, ok)
			require.Zero(t, inoTest.UID())
			require.Zero(t, inoTest.GID())
			require.Equal(t, uint32(0x2), inoTest.Nlink())
		})

		t.Run("Dir", func(t *testing.T) {
			infoRef, err := refSys.Stat("dir")
			require.NoError(t, err)

			infoTest, err := testSys.Stat("dir")
			require.NoError(t, err)

			require.Equal(t, "dir", infoRef.Name())
			require.Equal(t, "dir", infoTest.Name())

			// Inconsistent unpacking in CI
			// require.Equal(t, os.FileMode(0o755), infoRef.Mode()&fs.ModePerm)
			require.Equal(t, os.FileMode(0o755), infoTest.Mode()&fs.ModePerm)

			require.True(t, infoRef.IsDir())
			require.True(t, infoTest.IsDir())

			inoRef, ok := infoRef.Sys().(*erofs.Inode)
			require.True(t, ok)
			require.Zero(t, inoRef.UID())
			require.Zero(t, inoRef.GID())

			inoTest, ok := infoTest.Sys().(*erofs.Inode)
			require.True(t, ok)
			require.Zero(t, inoTest.UID())
		})
		t.Run("Symlink", func(t *testing.T) {
			infoRef, err := refSys.StatLink("file-link")
			require.NoError(t, err)

			infoTest, err := testSys.StatLink("file-link")
			require.NoError(t, err)

			require.Equal(t, "file-link", infoRef.Name())
			require.Equal(t, "file-link", infoTest.Name())

			require.Equal(t, os.FileMode(0o777), infoRef.Mode()&fs.ModePerm)
			require.Equal(t, os.FileMode(0o777), infoTest.Mode()&fs.ModePerm)

			require.False(t, infoRef.IsDir())
			require.False(t, infoTest.IsDir())

			ino, ok := infoRef.Sys().(*erofs.Inode)
			require.True(t, ok)
			require.Zero(t, ino.UID())
			require.Zero(t, ino.GID())

			inoTest, ok := infoTest.Sys().(*erofs.Inode)
			require.True(t, ok)
			require.Zero(t, inoTest.UID())
			require.Zero(t, inoTest.GID())
		})
	})
}
