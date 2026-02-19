// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/config"
	"unikctl.sh/internal/cli/unikctl/remove"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/operations"
	"unikctl.sh/log"
	mplatform "unikctl.sh/machine/platform"
)

type Server struct {
	addr         string
	ctx          context.Context
	ops          *operations.Store
	nodes        *nodeStore
	workloads    *workloadStore
	services     *serviceStore
	artifactsDir string
	jobsDir      string
	httpServer   *http.Server
	jobs         chan job
	workers      int
	maxRetries   int
	tlsCertFile  string
	tlsKeyFile   string
	authToken    string
	tokenScopes  map[string]map[string]struct{}
	jwtSecret    string
	metrics      *metricsCollector
	wg           sync.WaitGroup
	shutdownOnce sync.Once
	recoverMu    sync.Mutex
	recoverAt    map[string]time.Time
}

const (
	maxArtifactUploadBytes = int64(2 << 30) // 2 GiB
	artifactRetention      = 24 * time.Hour
	defaultMaxRetries      = 3
	operationStaleAfter    = 15 * time.Minute
)

type job struct {
	operationID string
	traceID     string
	attempt     int
	deploy      *controlplaneapi.DeployRequest
	destroy     *controlplaneapi.DestroyRequest
}

func (queued job) kind() operations.Kind {
	if queued.destroy != nil {
		return operations.KindDestroy
	}
	return operations.KindDeploy
}

func New(ctx context.Context, addr string, workers int) (*Server, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, fmt.Errorf("control plane listen address cannot be empty")
	}

	if workers <= 0 {
		workers = 1
	}

	ops, err := operations.NewStore(ctx)
	if err != nil {
		return nil, err
	}
	nodes, err := newNodeStore(ctx)
	if err != nil {
		return nil, err
	}
	workloads, err := newWorkloadStore(ctx)
	if err != nil {
		return nil, err
	}
	services, err := newServiceStore(ctx)
	if err != nil {
		return nil, err
	}

	runtimeDir := strings.TrimSpace(config.G[config.KraftKit](ctx).RuntimeDir)
	if runtimeDir == "" {
		return nil, fmt.Errorf("runtime directory is not configured")
	}

	artifactsDir := filepath.Join(runtimeDir, "control-plane-artifacts")
	if err := os.MkdirAll(artifactsDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating artifacts directory: %w", err)
	}

	jobsDir := filepath.Join(runtimeDir, "control-plane-jobs")
	if err := os.MkdirAll(jobsDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating jobs directory: %w", err)
	}

	controlPlaneCfg := config.G[config.KraftKit](ctx).ControlPlane
	tokenScopes, err := parseRBACPolicy(strings.TrimSpace(controlPlaneCfg.RBACTokens))
	if err != nil {
		return nil, err
	}

	server := &Server{
		addr:         addr,
		ctx:          ctx,
		ops:          ops,
		nodes:        nodes,
		workloads:    workloads,
		services:     services,
		artifactsDir: artifactsDir,
		jobsDir:      jobsDir,
		jobs:         make(chan job, 1024),
		workers:      workers,
		maxRetries:   defaultMaxRetries,
		tlsCertFile:  strings.TrimSpace(controlPlaneCfg.TLSCertFile),
		tlsKeyFile:   strings.TrimSpace(controlPlaneCfg.TLSKeyFile),
		authToken:    strings.TrimSpace(controlPlaneCfg.Token),
		tokenScopes:  tokenScopes,
		jwtSecret:    strings.TrimSpace(controlPlaneCfg.JWTSecret),
		metrics:      newMetricsCollector(),
		recoverAt:    map[string]time.Time{},
	}

	if envMaxRetries := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_MAX_RETRIES")); envMaxRetries != "" {
		if parsed, parseErr := strconv.Atoi(envMaxRetries); parseErr == nil && parsed >= 0 {
			server.maxRetries = parsed
		}
	}

	if envToken := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_TOKEN")); envToken != "" {
		server.authToken = envToken
	}
	if envJWT := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_JWT_HS256_SECRET")); envJWT != "" {
		server.jwtSecret = envJWT
	}
	if envPolicy := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_RBAC_TOKENS")); envPolicy != "" {
		tokenScopes, err := parseRBACPolicy(envPolicy)
		if err != nil {
			return nil, err
		}
		server.tokenScopes = tokenScopes
	}
	if envCert := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_TLS_CERT_FILE")); envCert != "" {
		server.tlsCertFile = envCert
	}
	if envKey := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_TLS_KEY_FILE")); envKey != "" {
		server.tlsKeyFile = envKey
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.handleHealth)
	mux.HandleFunc("/v1/artifacts", server.handleArtifacts)
	mux.HandleFunc("/v1/deployments", server.handleDeploy)
	mux.HandleFunc("/v1/destroy", server.handleDestroy)
	mux.HandleFunc("/v1/status", server.handleStatus)
	mux.HandleFunc("/v1/logs/", server.handleLogs)
	mux.HandleFunc("/v1/metrics", server.handleMetrics)
	mux.HandleFunc("/v1/nodes/register", server.handleNodeRegister)
	mux.HandleFunc("/v1/nodes/heartbeat", server.handleNodeHeartbeat)
	mux.HandleFunc("/v1/nodes/", server.handleNodeAction)

	server.httpServer = &http.Server{Addr: addr, Handler: mux}
	server.httpServer.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	return server, nil
}

func (server *Server) Run() error {
	if err := server.requeuePersistedJobs(); err != nil {
		log.G(server.ctx).WithError(err).Warn("could not requeue persisted jobs")
	}

	for i := 0; i < server.workers; i++ {
		server.wg.Add(1)
		go server.worker()
	}

	go server.reconcileNodes(server.ctx)
	go server.reconcileWorkloads(server.ctx)

	go func() {
		<-server.ctx.Done()
		server.shutdown()
	}()

	err := server.listenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		server.wg.Wait()
		return nil
	}

	server.shutdown()
	server.wg.Wait()
	return err
}

func (server *Server) listenAndServe() error {
	cert := strings.TrimSpace(server.tlsCertFile)
	key := strings.TrimSpace(server.tlsKeyFile)
	if cert == "" && key == "" {
		return server.httpServer.ListenAndServe()
	}

	if cert == "" || key == "" {
		return fmt.Errorf("both TLS cert and key are required when TLS is enabled")
	}

	return server.httpServer.ListenAndServeTLS(cert, key)
}

func (server *Server) shutdown() {
	server.shutdownOnce.Do(func() {
		close(server.jobs)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.httpServer.Shutdown(ctx)
	})
}

func (server *Server) worker() {
	defer server.wg.Done()

	for queued := range server.jobs {
		server.processJob(queued)
	}
}

func (server *Server) processJob(queued job) {
	kind := queued.kind()
	createdAt := time.Now().UTC()
	if record, err := server.ops.Get(queued.operationID); err == nil && !record.CreatedAt.IsZero() {
		createdAt = record.CreatedAt
	}

	if err := server.ops.IncrementAttempts(queued.operationID, "processing"); err != nil {
		log.G(server.ctx).WithError(err).WithField("operation", queued.operationID).Debug("could not increment operation attempts")
	}

	var err error
	switch {
	case queued.deploy != nil:
		err = server.executeDeploy(queued.operationID, queued.deploy)
	case queued.destroy != nil:
		err = server.executeDestroy(queued.operationID, queued.destroy)
	default:
		err = fmt.Errorf("invalid job payload")
	}

	if err == nil {
		log.G(server.ctx).WithFields(map[string]interface{}{
			"operation": queued.operationID,
			"trace_id":  queued.traceID,
			"kind":      kind,
		}).Info("operation completed")
		server.metrics.Record(kind, true, time.Since(createdAt), 0)
		_ = server.deleteJob(queued.operationID)
		return
	}

	if queued.attempt < server.maxRetries {
		queued.attempt++
		backoff := retryBackoff(queued.attempt)
		server.metrics.Record(kind, false, time.Since(createdAt), 1)
		_ = server.persistJob(queued)
		_ = server.ops.SetState(
			queued.operationID,
			operations.StateRunning,
			fmt.Sprintf("retry %d/%d in %s: %v", queued.attempt, server.maxRetries, backoff, err),
		)
		log.G(server.ctx).WithFields(map[string]interface{}{
			"operation": queued.operationID,
			"trace_id":  queued.traceID,
			"kind":      kind,
			"attempt":   queued.attempt,
		}).WithError(err).Warn("operation attempt failed, scheduling retry")

		time.AfterFunc(backoff, func() {
			select {
			case server.jobs <- queued:
			default:
				_ = server.ops.Fail(queued.operationID, fmt.Errorf("control plane queue is full during retry"))
				_ = server.deleteJob(queued.operationID)
			}
		})
		return
	}

	server.metrics.Record(kind, false, time.Since(createdAt), 0)
	_ = server.ops.Fail(queued.operationID, err)
	_ = server.deleteJob(queued.operationID)
	log.G(server.ctx).WithFields(map[string]interface{}{
		"operation": queued.operationID,
		"trace_id":  queued.traceID,
		"kind":      kind,
	}).WithError(err).Error("operation failed")
}

func (server *Server) executeDeploy(operationID string, request *controlplaneapi.DeployRequest) error {
	if err := server.ops.SetState(operationID, operations.StateRunning, "deploying"); err != nil {
		log.G(server.ctx).WithError(err).Debug("could not set deploy operation state to running")
	}

	deployArgs := append([]string{}, request.Args...)
	if request.ArtifactID != "" {
		resolvedPath, err := server.resolveArtifactPath(request.ArtifactID, request.ArtifactPath)
		if err != nil {
			return err
		}
		if len(deployArgs) == 0 {
			deployArgs = []string{resolvedPath}
		} else {
			deployArgs[0] = resolvedPath
		}
	}

	if request.Name == "" {
		request.Name = suggestMachineName(deployArgs)
	}

	rootfsPath := request.Rootfs
	if request.RootfsArtifactID != "" {
		resolvedRootfsPath, err := server.resolveArtifactPath(request.RootfsArtifactID, request.RootfsArtifactPath)
		if err != nil {
			return err
		}
		rootfsPath = resolvedRootfsPath
	}

	targetRequest := *request
	targetRequest.Args = append([]string{}, deployArgs...)
	targetRequest.Rootfs = rootfsPath
	targetRequest.ArtifactID = ""
	targetRequest.ArtifactPath = ""
	targetRequest.RootfsArtifactID = ""
	targetRequest.RootfsArtifactPath = ""

	if requestWantsRollout(&targetRequest) {
		return server.executeServiceRollout(server.ctx, operationID, &targetRequest)
	}

	nodeName, err := server.deploySingle(server.ctx, &targetRequest, targetRequest.Name, map[string]struct{}{})
	if err != nil {
		return err
	}

	msg := fmt.Sprintf("deployment submitted for %s", targetRequest.Name)
	if strings.TrimSpace(nodeName) != "" && nodeName != hostname() {
		msg = fmt.Sprintf("deployment submitted for %s on %s", targetRequest.Name, nodeName)
	}

	_ = server.ops.SetMachine(operationID, targetRequest.Name)
	_ = server.ops.SetState(operationID, operations.StateSubmitted, msg)
	return nil
}

func (server *Server) executeDestroy(operationID string, request *controlplaneapi.DestroyRequest) error {
	if err := server.ops.SetState(operationID, operations.StateRunning, "destroying"); err != nil {
		log.G(server.ctx).WithError(err).Debug("could not set destroy operation state to running")
	}

	localTargets := []string{}
	remoteTargets := map[string][]string{}
	nodeIndex := map[string]nodeRecord{}
	nodes, _ := server.nodes.List()
	for _, node := range nodes {
		nodeIndex[node.Name] = node
	}

	if request.All {
		for _, node := range nodes {
			if node.AgentURL == "" {
				continue
			}
			remoteTargets[node.Name] = []string{}
		}
		localTargets = []string{}
	} else {
		for _, name := range request.Names {
			workload, ok, err := server.workloads.Get(name)
			if err != nil {
				return err
			}

			if ok && workload.Node != "" && workload.Node != hostname() {
				remoteTargets[workload.Node] = append(remoteTargets[workload.Node], name)
				continue
			}

			localTargets = append(localTargets, name)
		}
	}

	for nodeName, names := range remoteTargets {
		node, ok := nodeIndex[nodeName]
		if !ok {
			continue
		}

		if err := server.destroyOnNode(server.ctx, node, &controlplaneapi.DestroyRequest{
			Names: names,
			All:   request.All && len(names) == 0,
		}); err != nil {
			return err
		}
	}

	execCtx := controlplaneapi.WithServerMode(server.ctx)
	removeOptions := &remove.RemoveOptions{
		All: request.All,
	}

	if request.All || len(localTargets) > 0 {
		if err := remove.Remove(execCtx, removeOptions, localTargets...); err != nil {
			return err
		}
	}

	if request.All {
		_ = server.workloads.Clear()
	} else {
		_ = server.workloads.RemoveMachines(request.Names...)
	}

	msg := "destroy request submitted"
	if request.All {
		msg = "destroyed all machines"
	} else if len(request.Names) > 0 {
		msg = fmt.Sprintf("destroyed %d machine(s)", len(request.Names))
	}

	_ = server.ops.SetState(operationID, operations.StateSucceeded, msg)
	return nil
}

func (server *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (server *Server) handleArtifacts(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodPost {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "deploy"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	defer r.Body.Close()

	if err := server.pruneArtifacts(artifactRetention); err != nil {
		log.G(server.ctx).WithError(err).Debug("could not prune old artifacts")
	}

	artifactID := newArtifactID()
	artifactRoot := filepath.Join(server.artifactsDir, artifactID)
	extractRoot := filepath.Join(artifactRoot, "src")

	if err := os.MkdirAll(extractRoot, 0o755); err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("creating artifact storage: %v", err), traceID)
		return
	}

	limitedBody := http.MaxBytesReader(w, r.Body, maxArtifactUploadBytes)
	if err := extractTarGz(limitedBody, extractRoot); err != nil {
		_ = os.RemoveAll(artifactRoot)

		if strings.Contains(err.Error(), "http: request body too large") {
			writeErrorTrace(w, http.StatusRequestEntityTooLarge, "artifact exceeds maximum upload size", traceID)
			return
		}

		writeErrorTrace(w, http.StatusBadRequest, fmt.Sprintf("invalid artifact archive: %v", err), traceID)
		return
	}

	writeJSON(w, http.StatusCreated, controlplaneapi.ArtifactUploadResponse{
		ArtifactID: artifactID,
	})
}

func (server *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodPost {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "deploy"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	var request controlplaneapi.DeployRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeErrorTrace(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err), traceID)
		return
	}

	if len(request.Args) == 0 {
		writeErrorTrace(w, http.StatusBadRequest, "deploy request requires at least one argument", traceID)
		return
	}

	request.TraceID = firstNonEmpty(request.TraceID, traceID)
	request.IdempotencyKey = firstNonEmpty(request.IdempotencyKey, strings.TrimSpace(r.Header.Get("Idempotency-Key")))

	if request.Name == "" {
		request.Name = suggestMachineName(request.Args)
	}

	record, reused, err := server.ops.StartIdempotent(
		operations.KindDeploy,
		request.Args,
		"queued by control plane",
		operations.StartOptions{
			TraceID:        request.TraceID,
			IdempotencyKey: request.IdempotencyKey,
		},
	)
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("creating operation: %v", err), request.TraceID)
		return
	}

	if reused {
		writeJSON(w, http.StatusAccepted, controlplaneapi.DeployResponse{
			OperationID: record.ID,
			TraceID:     record.TraceID,
			Reused:      true,
		})
		return
	}

	if err := server.ops.SetMachine(record.ID, request.Name); err != nil {
		log.G(server.ctx).WithError(err).Debug("could not store machine name on deploy operation")
	}

	queuedJob := job{
		operationID: record.ID,
		traceID:     request.TraceID,
		deploy:      &request,
	}
	if err := server.persistJob(queuedJob); err != nil {
		_ = server.ops.Fail(record.ID, err)
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("persisting operation: %v", err), request.TraceID)
		return
	}

	select {
	case server.jobs <- queuedJob:
		writeJSON(w, http.StatusAccepted, controlplaneapi.DeployResponse{
			OperationID: record.ID,
			TraceID:     request.TraceID,
		})
	default:
		_ = server.ops.Fail(record.ID, fmt.Errorf("control plane queue is full"))
		_ = server.deleteJob(record.ID)
		writeErrorTrace(w, http.StatusServiceUnavailable, "control plane queue is full", request.TraceID)
	}
}

func (server *Server) handleDestroy(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodPost {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "destroy"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	var request controlplaneapi.DestroyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeErrorTrace(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err), traceID)
		return
	}

	if !request.All && len(request.Names) == 0 {
		writeErrorTrace(w, http.StatusBadRequest, "destroy request requires names or all=true", traceID)
		return
	}

	request.TraceID = firstNonEmpty(request.TraceID, traceID)
	request.IdempotencyKey = firstNonEmpty(request.IdempotencyKey, strings.TrimSpace(r.Header.Get("Idempotency-Key")))

	targets := request.Names
	if request.All {
		targets = []string{"*"}
	}

	record, reused, err := server.ops.StartIdempotent(
		operations.KindDestroy,
		targets,
		"queued by control plane",
		operations.StartOptions{
			TraceID:        request.TraceID,
			IdempotencyKey: request.IdempotencyKey,
		},
	)
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("creating operation: %v", err), request.TraceID)
		return
	}

	if reused {
		writeJSON(w, http.StatusAccepted, controlplaneapi.DestroyResponse{
			OperationID: record.ID,
			TraceID:     record.TraceID,
			Reused:      true,
		})
		return
	}

	queuedJob := job{
		operationID: record.ID,
		traceID:     request.TraceID,
		destroy:     &request,
	}
	if err := server.persistJob(queuedJob); err != nil {
		_ = server.ops.Fail(record.ID, err)
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("persisting operation: %v", err), request.TraceID)
		return
	}

	select {
	case server.jobs <- queuedJob:
		writeJSON(w, http.StatusAccepted, controlplaneapi.DestroyResponse{
			OperationID: record.ID,
			TraceID:     request.TraceID,
		})
	default:
		_ = server.ops.Fail(record.ID, fmt.Errorf("control plane queue is full"))
		_ = server.deleteJob(record.ID)
		writeErrorTrace(w, http.StatusServiceUnavailable, "control plane queue is full", request.TraceID)
	}
}

func (server *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodGet {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "status"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	records, err := server.ops.List(50)
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("listing operations: %v", err), traceID)
		return
	}

	machines, err := server.aggregateMachines(server.ctx)
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("listing machines: %v", err), traceID)
		return
	}

	machineStates := map[string]machineapi.MachineState{}
	for _, machine := range machines {
		machineStates[machine.Name] = machine.State
		machineStates[machine.ID] = machine.State
	}

	operationsOut := make([]controlplaneapi.Operation, 0, len(records))
	for _, record := range records {
		target := record.Machine
		if target == "" && len(record.Targets) > 0 {
			target = strings.Join(record.Targets, ",")
		}

		state := deriveOperationState(record, machineStates)
		message := record.Message
		if staleOperationRecord(record, state, machineStates) {
			lowerMessage := strings.ToLower(strings.TrimSpace(message))
			if strings.TrimSpace(message) == "" || strings.EqualFold(strings.TrimSpace(message), "resolving deployment input") || strings.HasPrefix(lowerMessage, "deployment submitted for ") {
				message = "stale operation record (machine missing after restart or interrupted deploy)"
			}
		}
		operationsOut = append(operationsOut, controlplaneapi.Operation{
			ID:        record.ID,
			Kind:      string(record.Kind),
			State:     string(state),
			Target:    target,
			TraceID:   record.TraceID,
			Attempts:  record.Attempts,
			Message:   message,
			Error:     record.Error,
			CreatedAt: record.CreatedAt,
			UpdatedAt: record.UpdatedAt,
		})
	}

	machinesOut := make([]controlplaneapi.Machine, 0, len(machines))
	for _, machine := range machines {
		machinesOut = append(machinesOut, controlplaneapi.Machine{
			ID:        machine.ID,
			Name:      machine.Name,
			Node:      machine.Node,
			Kernel:    machine.Kernel,
			Args:      machine.Args,
			CreatedAt: machine.CreatedAt,
			State:     string(machine.State),
			Mem:       machine.Mem,
			Ports:     machine.Ports,
			Pid:       machine.Pid,
			Arch:      machine.Arch,
			Plat:      machine.Plat,
			IPs:       machine.IPs,
		})
	}

	nodeRecords, err := server.nodes.List()
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("listing nodes: %v", err), traceID)
		return
	}
	nodesOut := make([]controlplaneapi.Node, 0, len(nodeRecords))
	for _, node := range nodeRecords {
		nodesOut = append(nodesOut, nodeRecordToAPI(node))
	}
	if len(nodesOut) == 0 {
		nodesOut = append(nodesOut, controlplaneapi.Node{
			Name:      hostname(),
			Address:   server.addr,
			State:     string(nodeStateReady),
			Machines:  len(machinesOut),
			UpdatedAt: time.Now().UTC(),
		})
	}

	serviceRecords, err := server.services.List()
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("listing services: %v", err), traceID)
		return
	}

	servicesOut := make([]controlplaneapi.Service, 0, len(serviceRecords))
	for _, service := range serviceRecords {
		ready := 0
		for _, machine := range service.Current {
			if serviceMachineReady(machineStates[machine]) {
				ready++
			}
		}

		servicesOut = append(servicesOut, controlplaneapi.Service{
			Name:        service.Name,
			Strategy:    service.Strategy,
			Phase:       service.Phase,
			Message:     service.Message,
			LastError:   service.LastError,
			Desired:     service.Desired,
			Ready:       ready,
			Machines:    append([]string{}, service.Current...),
			LastHealthy: service.LastHealthy,
			UpdatedAt:   service.UpdatedAt,
		})
	}

	writeJSON(w, http.StatusOK, controlplaneapi.StatusResponse{
		Operations: operationsOut,
		Machines:   machinesOut,
		Nodes:      nodesOut,
		Services:   servicesOut,
	})
}

func (server *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodGet {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "logs"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/v1/logs/")
	name = strings.TrimSpace(name)
	if name == "" {
		writeErrorTrace(w, http.StatusBadRequest, "machine name is required", traceID)
		return
	}

	follow := parseBoolQuery(r.URL.Query().Get("follow"))

	service, serviceFound, err := server.services.Get(name)
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("loading service: %v", err), traceID)
		return
	}
	if serviceFound && len(service.Current) == 0 {
		writeErrorTrace(w, http.StatusNotFound, fmt.Sprintf("service %s has no machines", service.Name), traceID)
		return
	}

	if !serviceFound {
		if err := server.validateMachineLogTarget(r.Context(), name); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "could not find instance") {
				writeErrorTrace(w, http.StatusNotFound, err.Error(), traceID)
				return
			}
			writeErrorTrace(w, http.StatusBadGateway, err.Error(), traceID)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	flushWriter := newFlushLockedWriter(w)

	if serviceFound && len(service.Current) > 0 {
		if err := server.streamServiceLogs(r.Context(), service, follow, flushWriter); err != nil && !errors.Is(err, context.Canceled) {
			_, _ = io.WriteString(flushWriter, "log stream error: "+err.Error()+"\n")
		}
		return
	}

	if err := server.streamMachineLogs(r.Context(), name, follow, flushWriter); err != nil {
		_, _ = io.WriteString(flushWriter, "log stream error: "+err.Error()+"\n")
	}
}

func (server *Server) validateMachineLogTarget(ctx context.Context, machineName string) error {
	workload, ok, err := server.workloads.Get(machineName)
	if err != nil {
		return fmt.Errorf("loading workload: %w", err)
	}

	if ok && workload.Node != "" && workload.Node != hostname() {
		_, found, err := server.nodes.Get(workload.Node)
		if err != nil {
			return fmt.Errorf("loading workload node: %w", err)
		}
		if !found {
			return fmt.Errorf("node not found for workload %s", workload.Node)
		}

		return nil
	}

	controller, err := mplatform.NewMachineV1alpha1ServiceIterator(ctx)
	if err != nil {
		return fmt.Errorf("loading machine controller: %w", err)
	}

	_, err = findMachine(ctx, controller, machineName)
	return err
}

func (server *Server) streamServiceLogs(ctx context.Context, service serviceRecord, follow bool, writer io.Writer) error {
	machines := append([]string{}, service.Current...)
	if len(machines) == 0 {
		return fmt.Errorf("service %s has no machines", service.Name)
	}

	errs := []error{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, machineName := range machines {
		machineName := strings.TrimSpace(machineName)
		if machineName == "" {
			continue
		}

		wg.Add(1)
		go func(name string) {
			defer wg.Done()

			prefixed := &prefixedLineWriter{
				out:    writer,
				prefix: "[" + name + "] ",
			}
			defer prefixed.Flush()

			if err := server.streamMachineLogs(ctx, name, follow, prefixed); err != nil && !errors.Is(err, context.Canceled) {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				mu.Unlock()
			}
		}(machineName)
	}

	wg.Wait()
	return errors.Join(errs...)
}

func (server *Server) streamMachineLogs(ctx context.Context, machineName string, follow bool, writer io.Writer) error {
	machineName = strings.TrimSpace(machineName)
	if machineName == "" {
		return fmt.Errorf("machine name is required")
	}

	workload, ok, err := server.workloads.Get(machineName)
	if err != nil {
		return fmt.Errorf("loading workload: %w", err)
	}

	if ok && workload.Node != "" && workload.Node != hostname() {
		node, found, err := server.nodes.Get(workload.Node)
		if err != nil {
			return fmt.Errorf("loading workload node: %w", err)
		}
		if !found {
			return fmt.Errorf("node not found for workload %s", workload.Node)
		}

		client, err := server.nodeClient(ctx, node)
		if err != nil {
			return fmt.Errorf("creating node client: %w", err)
		}

		if err := client.Logs(ctx, machineName, follow, writer); err != nil {
			return fmt.Errorf("proxying node logs: %w", err)
		}
		return nil
	}

	controller, err := mplatform.NewMachineV1alpha1ServiceIterator(ctx)
	if err != nil {
		return fmt.Errorf("loading machine controller: %w", err)
	}

	machine, err := findMachine(ctx, controller, machineName)
	if err != nil {
		return err
	}

	logs, errs, err := controller.Logs(ctx, machine)
	if err != nil {
		return fmt.Errorf("accessing logs: %w", err)
	}

	for {
		select {
		case line := <-logs:
			if _, err := io.WriteString(writer, line+"\n"); err != nil {
				return err
			}

		case streamErr := <-errs:
			if streamErr == nil || errors.Is(streamErr, io.EOF) || errors.Is(streamErr, context.Canceled) {
				return nil
			}
			return streamErr

		case <-ctx.Done():
			return ctx.Err()
		}

		if !follow && machine.Status.State != machineapi.MachineStateRunning {
			return nil
		}
	}
}

type flushLockedWriter struct {
	writer  io.Writer
	flusher http.Flusher
	mu      sync.Mutex
}

func newFlushLockedWriter(w http.ResponseWriter) *flushLockedWriter {
	flusher, _ := w.(http.Flusher)
	return &flushLockedWriter{
		writer:  w,
		flusher: flusher,
	}
}

func (writer *flushLockedWriter) Write(p []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()

	n, err := writer.writer.Write(p)
	if err == nil && writer.flusher != nil {
		writer.flusher.Flush()
	}
	return n, err
}

type prefixedLineWriter struct {
	out    io.Writer
	prefix string
	buf    string
}

func (writer *prefixedLineWriter) Write(p []byte) (int, error) {
	if writer == nil || writer.out == nil {
		return len(p), nil
	}

	writer.buf += string(p)
	for {
		index := strings.Index(writer.buf, "\n")
		if index < 0 {
			break
		}

		line := writer.buf[:index]
		writer.buf = writer.buf[index+1:]
		if _, err := io.WriteString(writer.out, writer.prefix+line+"\n"); err != nil {
			return len(p), err
		}
	}

	return len(p), nil
}

func (writer *prefixedLineWriter) Flush() {
	if writer == nil || writer.out == nil {
		return
	}

	if strings.TrimSpace(writer.buf) == "" {
		writer.buf = ""
		return
	}

	_, _ = io.WriteString(writer.out, writer.prefix+writer.buf+"\n")
	writer.buf = ""
}

func (server *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodGet {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "status"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, server.metrics.Render())
}

type machineStatus struct {
	ID        string
	Name      string
	Node      string
	Kernel    string
	Args      string
	CreatedAt time.Time
	State     machineapi.MachineState
	Mem       string
	Ports     string
	Pid       int32
	Arch      string
	Plat      string
	IPs       []string
}

func listMachines(ctx context.Context) ([]machineStatus, error) {
	controller, err := mplatform.NewMachineV1alpha1ServiceIterator(ctx)
	if err != nil {
		return nil, err
	}

	machines, err := controller.List(ctx, &machineapi.MachineList{})
	if err != nil {
		return nil, err
	}

	ret := make([]machineStatus, 0, len(machines.Items))
	for _, machine := range machines.Items {
		entry := machineStatus{
			ID:        string(machine.UID),
			Name:      machine.Name,
			Node:      hostname(),
			Args:      strings.Join(machine.Spec.ApplicationArgs, " "),
			Kernel:    machine.Spec.Kernel,
			State:     machine.Status.State,
			Mem:       machine.Spec.Resources.Requests.Memory().String(),
			CreatedAt: machine.ObjectMeta.CreationTimestamp.Time.UTC(),
			Arch:      machine.Spec.Architecture,
			Pid:       machine.Status.Pid,
			Plat:      machine.Spec.Platform,
			IPs:       []string{},
		}

		if machine.Status.State == machineapi.MachineStateRunning {
			entry.Ports = machine.Spec.Ports.String()
		}

		for _, net := range machine.Spec.Networks {
			for _, iface := range net.Interfaces {
				entry.IPs = append(entry.IPs, iface.Spec.CIDR)
			}
		}

		ret = append(ret, entry)
	}

	return ret, nil
}

func (server *Server) aggregateMachines(ctx context.Context) ([]machineStatus, error) {
	localMachines, err := listMachines(ctx)
	if err != nil {
		return nil, err
	}

	nodes, err := server.nodes.List()
	if err != nil {
		return nil, err
	}

	allMachines := make([]machineStatus, 0, len(localMachines)+16)
	allMachines = append(allMachines, localMachines...)
	known := map[string]struct{}{}
	for _, machine := range localMachines {
		known[machine.Node+"/"+machine.Name] = struct{}{}
	}

	for _, node := range nodes {
		if node.State == nodeStateOffline || node.AgentURL == "" {
			continue
		}

		if node.Name == hostname() {
			continue
		}

		machines, err := server.listNodeMachines(ctx, node)
		if err != nil {
			continue
		}

		for _, machine := range machines {
			key := machine.Node + "/" + machine.Name
			if _, exists := known[key]; exists {
				continue
			}
			known[key] = struct{}{}
			allMachines = append(allMachines, machine)
		}
	}

	return allMachines, nil
}

func findMachine(ctx context.Context, controller machineapi.MachineService, name string) (*machineapi.Machine, error) {
	machines, err := controller.List(ctx, &machineapi.MachineList{})
	if err != nil {
		return nil, err
	}

	for _, candidate := range machines.Items {
		if candidate.Name == name || string(candidate.UID) == name {
			machine := candidate
			return &machine, nil
		}
	}

	return nil, fmt.Errorf("could not find instance %s", name)
}

func deriveOperationState(record operations.Record, machineStates map[string]machineapi.MachineState) operations.State {
	if record.State == operations.StateSucceeded || record.State == operations.StateFailed {
		return record.State
	}

	switch record.Kind {
	case operations.KindDeploy:
		if record.Machine == "" {
			if staleOperationRecord(record, record.State, machineStates) {
				return operations.StateFailed
			}
			return record.State
		}

		state, ok := machineStates[record.Machine]
		if !ok {
			if staleOperationRecord(record, record.State, machineStates) {
				return operations.StateFailed
			}
			return record.State
		}

		switch state {
		case machineapi.MachineStateRunning, machineapi.MachineStateExited:
			return operations.StateSucceeded
		case machineapi.MachineStateFailed, machineapi.MachineStateErrored:
			return operations.StateFailed
		default:
			return operations.StateRunning
		}

	case operations.KindDestroy:
		if len(record.Targets) == 0 {
			return record.State
		}

		for _, target := range record.Targets {
			if _, ok := machineStates[target]; ok {
				return operations.StateRunning
			}
		}

		return operations.StateSucceeded
	}

	return record.State
}

func staleOperationRecord(record operations.Record, state operations.State, machineStates map[string]machineapi.MachineState) bool {
	if record.Kind != operations.KindDeploy {
		return false
	}
	if state != operations.StateRunning && state != operations.StatePending && state != operations.StateSubmitted {
		return false
	}

	machineName := strings.TrimSpace(record.Machine)
	if machineName != "" {
		if _, ok := machineStates[machineName]; ok {
			return false
		}
	}

	updated := record.UpdatedAt
	if updated.IsZero() {
		updated = record.CreatedAt
	}
	if updated.IsZero() {
		return false
	}

	return time.Since(updated) > operationStaleAfter
}

func serviceMachineReady(state machineapi.MachineState) bool {
	switch state {
	case machineapi.MachineStateRunning, machineapi.MachineStateExited:
		return true
	default:
		return false
	}
}

func (server *Server) resolveArtifactPath(artifactID, artifactPath string) (string, error) {
	artifactID = strings.TrimSpace(artifactID)
	if artifactID == "" {
		return "", fmt.Errorf("artifact ID is required")
	}

	extractRoot := filepath.Join(server.artifactsDir, artifactID, "src")
	rootInfo, err := os.Stat(extractRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("artifact not found: %s", artifactID)
		}
		return "", fmt.Errorf("loading artifact %s: %w", artifactID, err)
	}
	if !rootInfo.IsDir() {
		return "", fmt.Errorf("artifact is invalid: %s", artifactID)
	}

	normalizedPath, err := sanitizeRelativePath(firstNonEmpty(artifactPath, "."))
	if err != nil {
		return "", fmt.Errorf("invalid artifact path %q: %w", artifactPath, err)
	}

	resolved := extractRoot
	if normalizedPath != "." {
		resolved = filepath.Join(extractRoot, normalizedPath)
	}

	if _, err := os.Stat(resolved); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("artifact path does not exist: %s", artifactPath)
		}
		return "", fmt.Errorf("resolving artifact path: %w", err)
	}

	return resolved, nil
}

func (server *Server) pruneArtifacts(maxAge time.Duration) error {
	entries, err := os.ReadDir(server.artifactsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	cutoff := time.Now().UTC().Add(-maxAge)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().UTC().After(cutoff) {
			continue
		}

		_ = os.RemoveAll(filepath.Join(server.artifactsDir, entry.Name()))
	}

	return nil
}

func extractTarGz(reader io.Reader, destDir string) error {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	fileCount := 0
	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("reading tar entry: %w", err)
		}

		relativePath, err := sanitizeRelativePath(header.Name)
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, relativePath)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("creating directory %s: %w", target, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("creating parent directory: %w", err)
			}

			mode := os.FileMode(0o644)
			if header.FileInfo() != nil {
				mode = header.FileInfo().Mode().Perm()
				if mode == 0 {
					mode = 0o644
				}
			}

			file, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return fmt.Errorf("creating file %s: %w", target, err)
			}

			if _, err := io.Copy(file, tarReader); err != nil {
				_ = file.Close()
				return fmt.Errorf("extracting file %s: %w", target, err)
			}

			if err := file.Close(); err != nil {
				return fmt.Errorf("closing file %s: %w", target, err)
			}
			fileCount++
		default:
			return fmt.Errorf("unsupported tar entry type in artifact: %d", header.Typeflag)
		}
	}

	if fileCount == 0 {
		return fmt.Errorf("artifact archive does not contain files")
	}

	return nil
}

func sanitizeRelativePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is empty")
	}

	cleaned := filepath.Clean(path)
	if cleaned == "." {
		return cleaned, nil
	}

	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute paths are not allowed")
	}

	if volume := filepath.VolumeName(cleaned); volume != "" {
		return "", fmt.Errorf("volume paths are not allowed")
	}

	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes artifact root")
	}

	return cleaned, nil
}

func newArtifactID() string {
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("art-%d", time.Now().UTC().UnixNano())
	}

	return fmt.Sprintf("art-%d-%s", time.Now().UTC().Unix(), hex.EncodeToString(random))
}

func suggestMachineName(args []string) string {
	name := "app"
	if len(args) > 0 {
		candidate := strings.TrimSpace(args[0])
		candidate = filepath.Base(candidate)
		candidate = strings.ToLower(candidate)
		candidate = strings.ReplaceAll(candidate, " ", "-")
		candidate = strings.ReplaceAll(candidate, "_", "-")
		candidate = strings.ReplaceAll(candidate, ".", "-")
		candidate = strings.ReplaceAll(candidate, ":", "-")
		candidate = strings.ReplaceAll(candidate, "/", "-")
		candidate = strings.ReplaceAll(candidate, "\\", "-")
		candidate = strings.Trim(candidate, "-")
		if candidate != "" {
			name = candidate
		}
	}

	suffix := strconv.FormatInt(time.Now().UTC().Unix()%100000, 10)
	return fmt.Sprintf("%s-%s", name, suffix)
}

func parseBoolQuery(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

type persistedJob struct {
	OperationID string                          `json:"operation_id"`
	TraceID     string                          `json:"trace_id,omitempty"`
	Attempt     int                             `json:"attempt"`
	Deploy      *controlplaneapi.DeployRequest  `json:"deploy,omitempty"`
	Destroy     *controlplaneapi.DestroyRequest `json:"destroy,omitempty"`
}

func (server *Server) persistJob(queued job) error {
	persisted := persistedJob{
		OperationID: queued.operationID,
		TraceID:     queued.traceID,
		Attempt:     queued.attempt,
		Deploy:      queued.deploy,
		Destroy:     queued.destroy,
	}

	raw, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing job: %w", err)
	}

	target := filepath.Join(server.jobsDir, queued.operationID+".json")
	temp := target + ".tmp"
	if err := os.WriteFile(temp, raw, 0o600); err != nil {
		return fmt.Errorf("writing job file: %w", err)
	}

	if err := os.Rename(temp, target); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("moving job file into place: %w", err)
	}

	return nil
}

func (server *Server) deleteJob(operationID string) error {
	target := filepath.Join(server.jobsDir, operationID+".json")
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (server *Server) requeuePersistedJobs() error {
	entries, err := os.ReadDir(server.jobsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}

		raw, err := os.ReadFile(filepath.Join(server.jobsDir, entry.Name()))
		if err != nil {
			continue
		}

		var persisted persistedJob
		if err := json.Unmarshal(raw, &persisted); err != nil {
			continue
		}
		if strings.TrimSpace(persisted.OperationID) == "" {
			continue
		}

		queued := job{
			operationID: persisted.OperationID,
			traceID:     persisted.TraceID,
			attempt:     persisted.Attempt,
			deploy:      persisted.Deploy,
			destroy:     persisted.Destroy,
		}

		select {
		case server.jobs <- queued:
		default:
			return fmt.Errorf("control plane queue is full while requeueing persisted jobs")
		}
	}

	return nil
}

func retryBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 1 * time.Second
	}
	if attempt == 2 {
		return 2 * time.Second
	}
	return 4 * time.Second
}

func requestTraceID(r *http.Request) string {
	if r == nil {
		return newTraceID()
	}

	traceID := strings.TrimSpace(r.Header.Get("X-Trace-ID"))
	if traceID == "" {
		traceID = strings.TrimSpace(r.URL.Query().Get("trace_id"))
	}
	if traceID != "" {
		return traceID
	}

	return newTraceID()
}

func newTraceID() string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("trace-%d", time.Now().UTC().UnixNano())
	}
	return fmt.Sprintf("trace-%s", hex.EncodeToString(random))
}

func (server *Server) authorize(r *http.Request, scope string) (int, error) {
	token := strings.TrimSpace(server.authToken)
	jwtSecret := strings.TrimSpace(server.jwtSecret)
	if token == "" && len(server.tokenScopes) == 0 && jwtSecret == "" {
		return 0, nil
	}

	candidate := parseBearerToken(r.Header.Get("Authorization"))
	if candidate == "" {
		candidate = strings.TrimSpace(r.Header.Get("X-Unikctl-Token"))
	}
	if candidate == "" {
		return http.StatusUnauthorized, fmt.Errorf("authorization token is required")
	}

	if token != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
		return 0, nil
	}

	if len(server.tokenScopes) > 0 {
		scopes, ok := server.tokenScopes[candidate]
		if !ok {
			if jwtSecret == "" {
				return http.StatusUnauthorized, fmt.Errorf("invalid authorization token")
			}
		} else {
			if _, allowed := scopes["*"]; allowed {
				return 0, nil
			}
			if _, allowed := scopes[strings.TrimSpace(scope)]; allowed {
				return 0, nil
			}

			return http.StatusForbidden, fmt.Errorf("token is missing required scope: %s", scope)
		}
	}

	if jwtSecret != "" {
		if err := validateJWT(candidate, jwtSecret, scope, time.Now().UTC()); err != nil {
			return http.StatusUnauthorized, err
		}
		return 0, nil
	}

	return http.StatusUnauthorized, fmt.Errorf("invalid authorization token")
}

func parseRBACPolicy(raw string) (map[string]map[string]struct{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]map[string]struct{}{}, nil
	}

	policy := map[string]map[string]struct{}{}
	for _, pair := range strings.Split(raw, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		token, scopesRaw, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("invalid RBAC token policy entry %q, expected token=scope1,scope2", pair)
		}

		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("RBAC token entry contains empty token")
		}

		scopes := map[string]struct{}{}
		for _, scope := range strings.Split(scopesRaw, ",") {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			scopes[scope] = struct{}{}
		}
		if len(scopes) == 0 {
			return nil, fmt.Errorf("RBAC token entry %q does not declare scopes", token)
		}

		policy[token] = scopes
	}

	return policy, nil
}

func parseBearerToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	fields := strings.Fields(value)
	if len(fields) == 2 && strings.EqualFold(fields[0], "bearer") {
		return strings.TrimSpace(fields[1])
	}
	return ""
}

func validateJWT(token, secret, scope string, now time.Time) error {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid JWT header")
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid JWT payload")
	}

	signatureRaw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid JWT signature")
	}

	var header map[string]any
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return fmt.Errorf("invalid JWT header JSON")
	}
	alg, _ := header["alg"].(string)
	if !strings.EqualFold(strings.TrimSpace(alg), "HS256") {
		return fmt.Errorf("unsupported JWT algorithm: %s", alg)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(signatureRaw, expected) != 1 {
		return fmt.Errorf("invalid JWT signature")
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return fmt.Errorf("invalid JWT claims")
	}

	if exp, ok := claims["exp"]; ok {
		if !jwtNumericDateAfter(exp, now) {
			return fmt.Errorf("JWT token is expired")
		}
	}

	if nbf, ok := claims["nbf"]; ok {
		if !jwtNumericDateReached(nbf, now) {
			return fmt.Errorf("JWT token is not active yet")
		}
	}

	if scope == "" {
		return nil
	}

	if claimAllowsScope(claims["scope"], scope) || claimAllowsScope(claims["scopes"], scope) {
		return nil
	}

	return fmt.Errorf("JWT missing required scope: %s", scope)
}

func jwtNumericDateAfter(value any, now time.Time) bool {
	sec, ok := jwtToUnixSeconds(value)
	if !ok {
		return false
	}
	return now.Unix() < sec
}

func jwtNumericDateReached(value any, now time.Time) bool {
	sec, ok := jwtToUnixSeconds(value)
	if !ok {
		return false
	}
	return now.Unix() >= sec
}

func jwtToUnixSeconds(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case json.Number:
		v, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return v, true
	default:
		return 0, false
	}
}

func claimAllowsScope(claim any, required string) bool {
	required = strings.TrimSpace(required)
	if required == "" {
		return true
	}

	switch typed := claim.(type) {
	case string:
		for _, token := range strings.FieldsFunc(typed, func(r rune) bool {
			return r == ' ' || r == ','
		}) {
			if strings.TrimSpace(token) == required || strings.TrimSpace(token) == "*" {
				return true
			}
		}
	case []any:
		for _, v := range typed {
			s, _ := v.(string)
			s = strings.TrimSpace(s)
			if s == required || s == "*" {
				return true
			}
		}
	}

	return false
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeErrorTrace(w, code, message, "")
}

func writeErrorTrace(w http.ResponseWriter, code int, message, traceID string) {
	writeJSON(w, code, controlplaneapi.ErrorResponse{
		Error:   message,
		Code:    errorCodeFromStatus(code),
		TraceID: strings.TrimSpace(traceID),
	})
}

func errorCodeFromStatus(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusConflict:
		return "conflict"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	default:
		if statusCode >= 500 {
			return "internal_error"
		}
		return "error"
	}
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "node-local"
	}
	return name
}
