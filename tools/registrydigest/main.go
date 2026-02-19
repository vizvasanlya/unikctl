// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"unikctl.sh/internal/runtimeutil"
)

func main() {
	ref := flag.String("ref", "", "OCI image reference")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Parse()

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "missing --ref")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	digest, err := runtimeutil.ResolveDigest(ctx, *ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve digest: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(digest)
}
