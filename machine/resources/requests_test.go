// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package resources

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	machinev1alpha1 "unikctl.sh/api/machine/v1alpha1"
)

func TestApplyDefaultsAndValidate_PreservesExplicitCPUAndMemory(t *testing.T) {
	reqs := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("3"),
			corev1.ResourceMemory: resource.MustParse("384Mi"),
		},
	}

	if err := ApplyDefaultsAndValidate(&reqs, DefaultCPURequest, DefaultMemoryRequest); err != nil {
		t.Fatalf("unexpected validation failure: %v", err)
	}

	if got := reqs.Requests.Cpu().String(); got != "3" {
		t.Fatalf("cpu request was mutated, got %q, want %q", got, "3")
	}

	if got := reqs.Requests.Memory().String(); got != "384Mi" {
		t.Fatalf("memory request was mutated, got %q, want %q", got, "384Mi")
	}
}

func TestBackfillMissingFromPlatform_DoesNotOverwriteExplicitRequests(t *testing.T) {
	reqs := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("4"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}

	if err := BackfillMissingFromPlatform(&reqs, "1", "64Mi"); err != nil {
		t.Fatalf("unexpected validation failure: %v", err)
	}

	if got := reqs.Requests.Cpu().String(); got != "4" {
		t.Fatalf("cpu request was overwritten, got %q, want %q", got, "4")
	}

	if got := reqs.Requests.Memory().String(); got != "512Mi" {
		t.Fatalf("memory request was overwritten, got %q, want %q", got, "512Mi")
	}
}

func TestValidate_RejectsInvalidValues(t *testing.T) {
	reqs := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("0"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
	}

	if err := Validate(reqs); err == nil {
		t.Fatalf("expected CPU validation error")
	}

	reqs = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("0"),
		},
	}

	if err := Validate(reqs); err == nil {
		t.Fatalf("expected memory validation error")
	}
}

func TestMachineResourceRoundTripSerialization(t *testing.T) {
	in := machinev1alpha1.Machine{
		Spec: machinev1alpha1.MachineSpec{
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("2500m"),
					corev1.ResourceMemory: resource.MustParse("640Mi"),
				},
			},
		},
	}

	payload, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var out machinev1alpha1.Machine
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if got := out.Spec.Resources.Requests.Cpu().String(); got != "2500m" {
		t.Fatalf("cpu round-trip mismatch, got %q, want %q", got, "2500m")
	}

	if got := out.Spec.Resources.Requests.Memory().String(); got != "640Mi" {
		t.Fatalf("memory round-trip mismatch, got %q, want %q", got, "640Mi")
	}
}
