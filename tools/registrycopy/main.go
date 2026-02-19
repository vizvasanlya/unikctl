// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
)

func main() {
	src := flag.String("src", "", "Source image reference")
	dst := flag.String("dst", "", "Destination image reference")
	flag.Parse()

	if *src == "" || *dst == "" {
		fmt.Fprintln(os.Stderr, "usage: registrycopy --src <src-ref> --dst <dst-ref>")
		os.Exit(2)
	}

	if err := crane.Copy(
		*src,
		*dst,
		crane.WithAuthFromKeychain(authn.DefaultKeychain),
	); err != nil {
		fmt.Fprintf(os.Stderr, "copy image: %v\n", err)
		os.Exit(1)
	}
}
