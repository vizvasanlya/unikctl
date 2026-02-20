// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"fmt"
	"sync/atomic"
	"time"

	"unikctl.sh/internal/operations"
)

type metricsCollector struct {
	startedAtNanos uint64

	deployTotal   uint64
	deployFailed  uint64
	destroyTotal  uint64
	destroyFailed uint64
	retryTotal    uint64

	deployLatencyNanos  uint64
	deployLatencyCount  uint64
	destroyLatencyNanos uint64
	destroyLatencyCount uint64

	warmResumeLatencyNanos uint64
	warmResumeLatencyCount uint64
	warmPauseLatencyNanos  uint64
	warmPauseLatencyCount  uint64
	snapshotLatencyNanos   uint64
	snapshotLatencyCount   uint64
	warmGCTotal            uint64
	resumeSLOViolation     uint64
}

func newMetricsCollector() *metricsCollector {
	return &metricsCollector{
		startedAtNanos: uint64(time.Now().UTC().UnixNano()),
	}
}

func (metrics *metricsCollector) Record(kind operations.Kind, success bool, latency time.Duration, retries int) {
	if retries > 0 {
		atomic.AddUint64(&metrics.retryTotal, uint64(retries))
	}

	switch kind {
	case operations.KindDeploy:
		atomic.AddUint64(&metrics.deployTotal, 1)
		if !success {
			atomic.AddUint64(&metrics.deployFailed, 1)
		}
		atomic.AddUint64(&metrics.deployLatencyNanos, uint64(latency.Nanoseconds()))
		atomic.AddUint64(&metrics.deployLatencyCount, 1)
	case operations.KindDestroy:
		atomic.AddUint64(&metrics.destroyTotal, 1)
		if !success {
			atomic.AddUint64(&metrics.destroyFailed, 1)
		}
		atomic.AddUint64(&metrics.destroyLatencyNanos, uint64(latency.Nanoseconds()))
		atomic.AddUint64(&metrics.destroyLatencyCount, 1)
	}
}

func (metrics *metricsCollector) RecordWarmResumeLatency(latency time.Duration) {
	if metrics == nil {
		return
	}
	atomic.AddUint64(&metrics.warmResumeLatencyNanos, uint64(latency.Nanoseconds()))
	atomic.AddUint64(&metrics.warmResumeLatencyCount, 1)
}

func (metrics *metricsCollector) RecordWarmPauseLatency(latency time.Duration) {
	if metrics == nil {
		return
	}
	atomic.AddUint64(&metrics.warmPauseLatencyNanos, uint64(latency.Nanoseconds()))
	atomic.AddUint64(&metrics.warmPauseLatencyCount, 1)
}

func (metrics *metricsCollector) RecordSnapshotLatency(latency time.Duration) {
	if metrics == nil {
		return
	}
	atomic.AddUint64(&metrics.snapshotLatencyNanos, uint64(latency.Nanoseconds()))
	atomic.AddUint64(&metrics.snapshotLatencyCount, 1)
}

func (metrics *metricsCollector) IncrementWarmGC(removed int) {
	if metrics == nil || removed <= 0 {
		return
	}
	atomic.AddUint64(&metrics.warmGCTotal, uint64(removed))
}

func (metrics *metricsCollector) IncrementResumeSLOViolation() {
	if metrics == nil {
		return
	}
	atomic.AddUint64(&metrics.resumeSLOViolation, 1)
}

func (metrics *metricsCollector) Render() string {
	startedAt := time.Unix(0, int64(atomic.LoadUint64(&metrics.startedAtNanos))).UTC()
	deployTotal := atomic.LoadUint64(&metrics.deployTotal)
	deployFailed := atomic.LoadUint64(&metrics.deployFailed)
	destroyTotal := atomic.LoadUint64(&metrics.destroyTotal)
	destroyFailed := atomic.LoadUint64(&metrics.destroyFailed)
	retryTotal := atomic.LoadUint64(&metrics.retryTotal)

	deployLatencyAvgMs := averageMillis(
		atomic.LoadUint64(&metrics.deployLatencyNanos),
		atomic.LoadUint64(&metrics.deployLatencyCount),
	)
	destroyLatencyAvgMs := averageMillis(
		atomic.LoadUint64(&metrics.destroyLatencyNanos),
		atomic.LoadUint64(&metrics.destroyLatencyCount),
	)

	deployFailureRate := ratio(deployFailed, deployTotal)
	destroyFailureRate := ratio(destroyFailed, destroyTotal)

	warmResumeAvgMs := averageMillis(
		atomic.LoadUint64(&metrics.warmResumeLatencyNanos),
		atomic.LoadUint64(&metrics.warmResumeLatencyCount),
	)
	warmPauseAvgMs := averageMillis(
		atomic.LoadUint64(&metrics.warmPauseLatencyNanos),
		atomic.LoadUint64(&metrics.warmPauseLatencyCount),
	)
	snapshotAvgMs := averageMillis(
		atomic.LoadUint64(&metrics.snapshotLatencyNanos),
		atomic.LoadUint64(&metrics.snapshotLatencyCount),
	)
	warmGCTotal := atomic.LoadUint64(&metrics.warmGCTotal)
	resumeSLOViolation := atomic.LoadUint64(&metrics.resumeSLOViolation)

	return fmt.Sprintf(
		"# HELP unikctl_control_plane_uptime_seconds Control-plane uptime in seconds.\n"+
			"# TYPE unikctl_control_plane_uptime_seconds gauge\n"+
			"unikctl_control_plane_uptime_seconds %.0f\n"+
			"# HELP unikctl_control_plane_deploy_total Total deploy operations processed.\n"+
			"# TYPE unikctl_control_plane_deploy_total counter\n"+
			"unikctl_control_plane_deploy_total %d\n"+
			"# HELP unikctl_control_plane_deploy_failure_total Failed deploy operations.\n"+
			"# TYPE unikctl_control_plane_deploy_failure_total counter\n"+
			"unikctl_control_plane_deploy_failure_total %d\n"+
			"# HELP unikctl_control_plane_deploy_failure_rate Deploy operation failure ratio.\n"+
			"# TYPE unikctl_control_plane_deploy_failure_rate gauge\n"+
			"unikctl_control_plane_deploy_failure_rate %.6f\n"+
			"# HELP unikctl_control_plane_deploy_latency_ms_avg Average deploy latency in milliseconds.\n"+
			"# TYPE unikctl_control_plane_deploy_latency_ms_avg gauge\n"+
			"unikctl_control_plane_deploy_latency_ms_avg %.3f\n"+
			"# HELP unikctl_control_plane_destroy_total Total destroy operations processed.\n"+
			"# TYPE unikctl_control_plane_destroy_total counter\n"+
			"unikctl_control_plane_destroy_total %d\n"+
			"# HELP unikctl_control_plane_destroy_failure_total Failed destroy operations.\n"+
			"# TYPE unikctl_control_plane_destroy_failure_total counter\n"+
			"unikctl_control_plane_destroy_failure_total %d\n"+
			"# HELP unikctl_control_plane_destroy_failure_rate Destroy operation failure ratio.\n"+
			"# TYPE unikctl_control_plane_destroy_failure_rate gauge\n"+
			"unikctl_control_plane_destroy_failure_rate %.6f\n"+
			"# HELP unikctl_control_plane_destroy_latency_ms_avg Average destroy latency in milliseconds.\n"+
			"# TYPE unikctl_control_plane_destroy_latency_ms_avg gauge\n"+
			"unikctl_control_plane_destroy_latency_ms_avg %.3f\n"+
			"# HELP unikctl_control_plane_retry_total Total retry attempts.\n"+
			"# TYPE unikctl_control_plane_retry_total counter\n"+
			"unikctl_control_plane_retry_total %d\n"+
			"# HELP unikctl_control_plane_warm_resume_latency_ms_avg Average warm-resume latency in milliseconds.\n"+
			"# TYPE unikctl_control_plane_warm_resume_latency_ms_avg gauge\n"+
			"unikctl_control_plane_warm_resume_latency_ms_avg %.3f\n"+
			"# HELP unikctl_control_plane_warm_pause_latency_ms_avg Average warm-pause latency in milliseconds.\n"+
			"# TYPE unikctl_control_plane_warm_pause_latency_ms_avg gauge\n"+
			"unikctl_control_plane_warm_pause_latency_ms_avg %.3f\n"+
			"# HELP unikctl_control_plane_snapshot_latency_ms_avg Average snapshot creation latency in milliseconds.\n"+
			"# TYPE unikctl_control_plane_snapshot_latency_ms_avg gauge\n"+
			"unikctl_control_plane_snapshot_latency_ms_avg %.3f\n"+
			"# HELP unikctl_control_plane_warm_gc_total Total number of warm-pool entries removed by garbage collection.\n"+
			"# TYPE unikctl_control_plane_warm_gc_total counter\n"+
			"unikctl_control_plane_warm_gc_total %d\n"+
			"# HELP unikctl_control_plane_resume_slo_violation_total Number of warm starts exceeding configured resume threshold.\n"+
			"# TYPE unikctl_control_plane_resume_slo_violation_total counter\n"+
			"unikctl_control_plane_resume_slo_violation_total %d\n",
		time.Since(startedAt).Seconds(),
		deployTotal,
		deployFailed,
		deployFailureRate,
		deployLatencyAvgMs,
		destroyTotal,
		destroyFailed,
		destroyFailureRate,
		destroyLatencyAvgMs,
		retryTotal,
		warmResumeAvgMs,
		warmPauseAvgMs,
		snapshotAvgMs,
		warmGCTotal,
		resumeSLOViolation,
	)
}

func averageMillis(totalNanos, count uint64) float64 {
	if count == 0 {
		return 0
	}
	return (float64(totalNanos) / float64(count)) / float64(time.Millisecond)
}

func ratio(numerator, denominator uint64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func (metrics *metricsCollector) AverageDeployLatencyMillis() float64 {
	if metrics == nil {
		return 0
	}
	return averageMillis(
		atomic.LoadUint64(&metrics.deployLatencyNanos),
		atomic.LoadUint64(&metrics.deployLatencyCount),
	)
}

func (metrics *metricsCollector) AverageWarmResumeLatencyMillis() float64 {
	if metrics == nil {
		return 0
	}
	return averageMillis(
		atomic.LoadUint64(&metrics.warmResumeLatencyNanos),
		atomic.LoadUint64(&metrics.warmResumeLatencyCount),
	)
}

func (metrics *metricsCollector) WarmResumeSamples() uint64 {
	if metrics == nil {
		return 0
	}
	return atomic.LoadUint64(&metrics.warmResumeLatencyCount)
}
