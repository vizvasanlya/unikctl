// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import "fmt"

type apiError struct {
	StatusCode int
	Code       string
	Message    string
}

func (err *apiError) Error() string {
	return err.Message
}

func newAPIError(statusCode int, code, message string) error {
	return &apiError{
		StatusCode: statusCode,
		Code:       code,
		Message:    message,
	}
}

func newAdmissionError(code, message string) error {
	return newAPIError(409, code, message)
}

func apiErrorParts(err error) (status int, code string, message string, ok bool) {
	if err == nil {
		return 0, "", "", false
	}

	typed, yes := err.(*apiError)
	if !yes {
		return 0, "", "", false
	}

	return typed.StatusCode, typed.Code, typed.Message, true
}

func formatCapacityRequirement(memoryBytes, cpuMilli int64) string {
	return fmt.Sprintf("requested resources exceed node capacity (cpu=%dm, memory=%d bytes)", cpuMilli, memoryBytes)
}
