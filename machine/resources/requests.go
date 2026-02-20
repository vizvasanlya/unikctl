// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package resources

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	DefaultCPURequest    = "1"
	DefaultMemoryRequest = "64Mi"
)

// ValidationError describes a concrete field-level resource validation failure.
type ValidationError struct {
	Field   string
	Message string
}

func (err ValidationError) Error() string {
	if strings.TrimSpace(err.Field) == "" {
		return strings.TrimSpace(err.Message)
	}
	if strings.TrimSpace(err.Message) == "" {
		return fmt.Sprintf("invalid resource request for %s", err.Field)
	}
	return fmt.Sprintf("invalid resource request for %s: %s", err.Field, err.Message)
}

// ApplyDefaultsAndValidate ensures requests exist, applies defaults for missing values,
// then validates both CPU and memory are set and positive.
func ApplyDefaultsAndValidate(resources *corev1.ResourceRequirements, defaultCPU, defaultMemory string) error {
	if resources == nil {
		return ValidationError{Field: "resources", Message: "resource requirements are required"}
	}

	ensureRequests(resources)

	if resources.Requests.Cpu().Sign() == 0 {
		quantity, err := resource.ParseQuantity(firstNonEmpty(defaultCPU, DefaultCPURequest))
		if err != nil {
			return ValidationError{Field: "cpu", Message: fmt.Sprintf("could not parse default CPU quantity: %v", err)}
		}
		resources.Requests[corev1.ResourceCPU] = quantity
	}

	if resources.Requests.Memory().Sign() == 0 {
		quantity, err := resource.ParseQuantity(firstNonEmpty(defaultMemory, DefaultMemoryRequest))
		if err != nil {
			return ValidationError{Field: "memory", Message: fmt.Sprintf("could not parse default memory quantity: %v", err)}
		}
		resources.Requests[corev1.ResourceMemory] = quantity
	}

	return Validate(*resources)
}

// BackfillMissingFromPlatform fills only missing CPU/memory requests using
// platform-derived values. It never overwrites explicit user requests.
func BackfillMissingFromPlatform(resources *corev1.ResourceRequirements, cpuText, memoryText string) error {
	if resources == nil {
		return ValidationError{Field: "resources", Message: "resource requirements are required"}
	}

	ensureRequests(resources)

	if resources.Requests.Cpu().Sign() == 0 && strings.TrimSpace(cpuText) != "" {
		quantity, err := resource.ParseQuantity(strings.TrimSpace(cpuText))
		if err != nil {
			return ValidationError{Field: "cpu", Message: fmt.Sprintf("could not parse platform CPU quantity %q: %v", cpuText, err)}
		}
		resources.Requests[corev1.ResourceCPU] = quantity
	}

	if resources.Requests.Memory().Sign() == 0 && strings.TrimSpace(memoryText) != "" {
		quantity, err := resource.ParseQuantity(strings.TrimSpace(memoryText))
		if err != nil {
			return ValidationError{Field: "memory", Message: fmt.Sprintf("could not parse platform memory quantity %q: %v", memoryText, err)}
		}
		resources.Requests[corev1.ResourceMemory] = quantity
	}

	return Validate(*resources)
}

// Validate ensures CPU and memory requests are present and strictly positive.
func Validate(resources corev1.ResourceRequirements) error {
	if resources.Requests == nil {
		return ValidationError{Field: "requests", Message: "resource requests must be set"}
	}

	cpu := resources.Requests.Cpu()
	if cpu == nil || cpu.Sign() <= 0 {
		return ValidationError{Field: "cpu", Message: "CPU request must be greater than zero"}
	}

	memory := resources.Requests.Memory()
	if memory == nil || memory.Sign() <= 0 {
		return ValidationError{Field: "memory", Message: "memory request must be greater than zero"}
	}

	return nil
}

func ensureRequests(resources *corev1.ResourceRequirements) {
	if resources.Requests == nil {
		resources.Requests = corev1.ResourceList{}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

