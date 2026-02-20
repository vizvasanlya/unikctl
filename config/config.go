// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package config

// AuthConfig represents a very abstract representation of authentication used
// by some service.  Most APIs and services which can be authenticated have the
// defined four parameters found within AuthConfig.
type AuthConfig struct {
	User      string `yaml:"user" env:"UNIKCTL_AUTH_%s_USER" long:"auth-%s-user"`
	Token     string `yaml:"token" env:"UNIKCTL_AUTH_%s_TOKEN" long:"auth-%s-token"`
	Endpoint  string `yaml:"endpoint" env:"UNIKCTL_AUTH_%s_ENDPOINT" long:"auth-%s-endpoint"`
	VerifySSL bool   `yaml:"verify_ssl" env:"UNIKCTL_AUTH_%s_VERIFY_SSL" long:"auth-%s-verify-ssl" default:"true"`
}

type KraftKit struct {
	NoPrompt                  bool   `yaml:"no_prompt" env:"UNIKCTL_NO_PROMPT" long:"no-prompt" usage:"Do not prompt for user interaction" default:"false"`
	NoParallel                bool   `yaml:"no_parallel" env:"UNIKCTL_NO_PARALLEL" long:"no-parallel" usage:"Do not run internal tasks in parallel" default:"false"`
	NoEmojis                  bool   `yaml:"no_emojis" env:"UNIKCTL_NO_EMOJIS" long:"no-emojis" usage:"Do not use emojis in any console output" default:"true"`
	NoCheckUpdates            bool   `yaml:"no_check_updates" env:"UNIKCTL_NO_CHECK_UPDATES" long:"no-check-updates" usage:"Do not check for updates" default:"false"`
	NoColor                   bool   `yaml:"no_color" env:"UNIKCTL_NO_COLOR" long:"no-color" usage:"Disable color output"`
	NoWarnSudo                bool   `yaml:"no_warn_sudo" env:"UNIKCTL_NO_WARN_SUDO" long:"no-warn-sudo" usage:"Do not warn on running via sudo" default:"false"`
	Editor                    string `yaml:"editor" env:"UNIKCTL_EDITOR" long:"editor" usage:"Set the text editor to open when prompt to edit a file"`
	GitProtocol               string `yaml:"git_protocol" env:"UNIKCTL_GIT_PROTOCOL" long:"git-protocol" usage:"Preferred Git protocol to use" default:"https"`
	Pager                     string `yaml:"pager,omitempty" env:"UNIKCTL_PAGER" long:"pager" usage:"System pager to pipe output to" default:"cat"`
	Qemu                      string `yaml:"qemu,omitempty" env:"UNIKCTL_QEMU" long:"qemu" usage:"Path to QEMU executable" default:""`
	HTTPUnixSocket            string `yaml:"http_unix_socket,omitempty" env:"UNIKCTL_HTTP_UNIX_SOCKET" long:"http-unix-sock" usage:"When making HTTP(S) connections, pipe requests via this shared socket"`
	RuntimeDir                string `yaml:"runtime_dir" env:"UNIKCTL_RUNTIME_DIR" long:"runtime-dir" usage:"Directory for placing runtime files (e.g. pidfiles)"`
	DefaultPlat               string `yaml:"default_plat" env:"UNIKCTL_DEFAULT_PLAT" usage:"The default platform to use when invoking platform-specific code" noattribute:"true"`
	DefaultArch               string `yaml:"default_arch" env:"UNIKCTL_DEFAULT_ARCH" usage:"The default architecture to use when invoking architecture-specific code" noattribute:"true"`
	ContainerdAddr            string `yaml:"containerd_addr,omitempty" env:"UNIKCTL_CONTAINERD_ADDR" long:"containerd-addr" usage:"Address of containerd daemon socket" default:""`
	EventsPidFile             string `yaml:"events_pidfile" env:"UNIKCTL_EVENTS_PIDFILE" long:"events-pid-file" usage:"Events process ID used when running multiple unikernels"`
	BuildKitHost              string `yaml:"buildkit_host" env:"UNIKCTL_BUILDKIT_HOST" long:"buildkit-host" usage:"Path to the buildkit host" default:""`
	CollectAnonymousTelemetry bool   `yaml:"collect_anonymous_telemetry" env:"UNIKCTL_COLLECT_ANONYMOUS_TELEMETRY" long:"collect-anonymous-telemetry" usage:"Collect anonymous telemetry" default:"false"`

	Paths struct {
		Config    string `yaml:"-" env:"UNIKCTL_PATHS_CONFIG" long:"config-dir" usage:"Path to unikctl config directory"`
		Manifests string `yaml:"manifests,omitempty" env:"UNIKCTL_PATHS_MANIFESTS" long:"manifests-dir" usage:"Path to Unikraft manifest cache"`
		Sources   string `yaml:"sources,omitempty" env:"UNIKCTL_PATHS_SOURCES" long:"sources-dir" usage:"Path to Unikraft component cache"`
	} `yaml:"paths,omitempty"`

	Log struct {
		Level      string `yaml:"level" env:"UNIKCTL_LOG_LEVEL" long:"log-level" usage:"Log level verbosity. Choice of: [panic, fatal, error, warn, info, debug, trace]" default:"info"`
		Timestamps bool   `yaml:"timestamps" env:"UNIKCTL_LOG_TIMESTAMPS" long:"log-timestamps" usage:"Enable log timestamps"`
		Type       string `yaml:"type" env:"UNIKCTL_LOG_TYPE" long:"log-type" usage:"Log type. Choice of: [fancy, basic, json]" default:"fancy"`
	} `yaml:"log"`

	Unikraft struct {
		Mirrors   []string `yaml:"mirrors" env:"UNIKCTL_UNIKRAFT_MIRRORS" long:"with-mirror" usage:"Paths to mirrors of Unikraft component artifacts"`
		Manifests []string `yaml:"manifests" env:"UNIKCTL_UNIKRAFT_MANIFESTS" long:"with-manifest" usage:"Paths to package or component manifests"`
	} `yaml:"unikraft"`

	Auth map[string]AuthConfig `yaml:"auth,omitempty" noattribute:"true"`

	Aliases map[string]map[string]string `yaml:"aliases" noattribute:"true"`

	ControlPlane struct {
		URL              string `yaml:"url,omitempty" env:"UNIKCTL_CONTROL_PLANE_URL" noattribute:"true"`
		Listen           string `yaml:"listen,omitempty" env:"UNIKCTL_CONTROL_PLANE_LISTEN" noattribute:"true" default:"127.0.0.1:7689"`
		MaxConcurrentOps int    `yaml:"max_concurrent_ops,omitempty" env:"UNIKCTL_CONTROL_PLANE_MAX_CONCURRENT_OPS" noattribute:"true" default:"4"`
		Token            string `yaml:"token,omitempty" env:"UNIKCTL_CONTROL_PLANE_TOKEN" noattribute:"true"`
		RBACTokens       string `yaml:"rbac_tokens,omitempty" env:"UNIKCTL_CONTROL_PLANE_RBAC_TOKENS" noattribute:"true"`
		JWTSecret        string `yaml:"jwt_hs256_secret,omitempty" env:"UNIKCTL_CONTROL_PLANE_JWT_HS256_SECRET" noattribute:"true"`
		JWTIssuer        string `yaml:"jwt_issuer,omitempty" env:"UNIKCTL_CONTROL_PLANE_JWT_ISSUER" noattribute:"true"`
		JWTAudience      string `yaml:"jwt_audience,omitempty" env:"UNIKCTL_CONTROL_PLANE_JWT_AUDIENCE" noattribute:"true"`
		TLSCertFile      string `yaml:"tls_cert_file,omitempty" env:"UNIKCTL_CONTROL_PLANE_TLS_CERT_FILE" noattribute:"true"`
		TLSKeyFile       string `yaml:"tls_key_file,omitempty" env:"UNIKCTL_CONTROL_PLANE_TLS_KEY_FILE" noattribute:"true"`
		TLSCAFile        string `yaml:"tls_ca_file,omitempty" env:"UNIKCTL_CONTROL_PLANE_TLS_CA_FILE" noattribute:"true"`
		TLSInsecure      bool   `yaml:"tls_insecure_skip_verify,omitempty" env:"UNIKCTL_CONTROL_PLANE_TLS_INSECURE_SKIP_VERIFY" noattribute:"true" default:"false"`
		AllowInsecure    bool   `yaml:"allow_insecure_http,omitempty" env:"UNIKCTL_CONTROL_PLANE_ALLOW_INSECURE_HTTP" noattribute:"true" default:"false"`
		AllowUnauth      bool   `yaml:"allow_unauthenticated,omitempty" env:"UNIKCTL_CONTROL_PLANE_ALLOW_UNAUTHENTICATED" noattribute:"true" default:"false"`
	} `yaml:"control_plane,omitempty"`
}

type ConfigDetail struct {
	Key           string
	Description   string
	AllowedValues []string
}

// Descriptions of each configuration parameter as well as valid values
var configDetails = []ConfigDetail{
	{
		Key:         "no_prompt",
		Description: "toggle interactive prompting in the terminal",
	},
	{
		Key:         "editor",
		Description: "the text editor program to use for authoring text",
	},
	{
		Key:         "browser",
		Description: "the web browser to use for opening URLs",
	},
	{
		Key:         "git_protocol",
		Description: "the protocol to use for git clone and push operations",
		AllowedValues: []string{
			"https",
			"ssh",
		},
	},
	{
		Key:         "pager",
		Description: "the terminal pager program to send standard output to",
	},
	{
		Key:         "log.level",
		Description: "Set the logging verbosity",
		AllowedValues: []string{
			"fatal",
			"error",
			"warn",
			"info",
			"debug",
			"trace",
		},
	},
	{
		Key:         "log.type",
		Description: "Set the logging verbosity",
		AllowedValues: []string{
			"quiet",
			"basic",
			"fancy",
			"json",
		},
	},
	{
		Key:         "log.timestamps",
		Description: "Show timestamps with log output",
	},
}

func ConfigDetails() []ConfigDetail {
	return configDetails
}
