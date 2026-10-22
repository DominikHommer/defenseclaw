// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// provenanceGateway is the process a provenance read may send the gateway
// credential to (PID) and, under systemd socket activation, the service
// manager that holds the gateway's API socket with it (SocketManagerPID).
type provenanceGateway struct {
	PID              int
	SocketManagerPID int
}

// Use the service manager for a standalone deployment, and the existing
// process-identity record for a per-user gateway. Never trust a loopback
// listener merely because it answers on the configured port.
var provenanceGatewayIdentity = func(ctx context.Context) (provenanceGateway, error) {
	if cfg.StandaloneEnterprise() {
		return provenanceManagedGateway(ctx)
	}
	if running, pid := gatewayManagedState(); running && pid > 0 {
		return provenanceGateway{PID: pid}, nil
	}
	return provenanceGateway{}, fmt.Errorf("gateway process identity is unavailable")
}

// provenanceLookupIP resolves a configured API host name. A seam for tests.
var provenanceLookupIP = net.DefaultResolver.LookupIPAddr

var provenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Print the binary and config provenance (schema, content hash, generation, version)",
}

var provenanceShowCmd = &cobra.Command{
	Use:               "show",
	Short:             "Show the running gateway schema, content hash, generation, and binary version",
	Annotations:       map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	PersistentPreRunE: prepareProvenanceShow,
	RunE:              runProvenanceShow,
}

func init() {
	provenanceCmd.AddCommand(provenanceShowCmd)
	rootCmd.AddCommand(provenanceCmd)
}

// prepareProvenanceShow pins the managed caller and config, then loads the
// config. When the gateway rejected config.yaml it keeps running on the
// config it last applied, so a rejected file does not stop the read: the
// endpoint and credential then come from what was applied
// (provenanceAppliedConfig).
func prepareProvenanceShow(cmd *cobra.Command, _ []string) error {
	if err := managedStandardUserGatewayRefusal(); err != nil {
		return err
	}
	if err := prepareProvenanceEnvironment(); err != nil {
		return err
	}
	applyManagedStandaloneAdminEnv(cmd.ErrOrStderr())
	if err := loadGatewayCommandConfigFor(cmd); err != nil {
		applied, appliedErr := provenanceAppliedConfig(err)
		if appliedErr != nil {
			return fmt.Errorf("cannot locate the running gateway: %w; run `defenseclaw-gateway status`", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v; the running gateway keeps the config it last applied\n", err)
		cfg = applied
	}
	return nil
}

func prepareProvenanceEnvironment() error {
	return pinManagedAdministratorEnvironment("provenance show", func() string {
		return windowsManagedStandardUserViewAnswer("the managed provenance", "provenance show")
	})
}

func runProvenanceShow(cmd *cobra.Command, _ []string) error {
	version.SetBinaryVersion(appVersion)
	p := version.Current()
	if cfg == nil || !cfg.SecureClientIntegration() {
		var err error
		p, err = runningGatewayProvenance(cmd)
		if err != nil {
			return fmt.Errorf("cannot read the running gateway provenance: %w; run `defenseclaw-gateway status`", err)
		}
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "schema_version: %d\n", p.SchemaVersion)
	fmt.Fprintf(out, "content_hash: %s\n", p.ContentHash)
	fmt.Fprintf(out, "generation: %d\n", p.Generation)
	fmt.Fprintf(out, "binary_version: %s\n", p.BinaryVersion)
	return nil
}

// provenanceConfigFields are the only fields provenanceAppliedConfig reads
// from a config: the deployment, the API endpoint and the credential.
type provenanceConfigFields struct {
	DeploymentMode string `yaml:"deployment_mode"`
	Enterprise     struct {
		Profile string `yaml:"profile"`
	} `yaml:"enterprise"`
	Gateway struct {
		APIBind  string `yaml:"api_bind"`
		APIPort  int    `yaml:"api_port"`
		Token    string `yaml:"token"`
		TokenEnv string `yaml:"token_env"`
	} `yaml:"gateway"`
}

// provenanceConfigMaxBytes bounds a config read for its endpoint fields.
const provenanceConfigMaxBytes = 8 << 20

// provenanceAppliedConfig locates the running gateway after the strict load
// of config.yaml failed with loadErr. The gateway rejected that file and
// kept the config it last applied, so the endpoint and credential come
// from what was applied. A standalone deployment's API address is the one
// its administrator-owned runtime descriptor publishes, and its credential
// fields come from the root-only copy of the config its lifecycle last
// applied (Linux, macOS); the rejected file is not read. A per-user gateway
// keeps no such copy: its credential comes from the environment and its
// .env (loaded before the strict load), and only the API endpoint fields of
// its own config are read, as a hint. Either way the credential goes only to
// a listener proven to belong to the gateway process, and that process must
// answer as itself. A missing or unreadable config is not a rejected one:
// there is nothing to fall back on.
func provenanceAppliedConfig(loadErr error) (*config.Config, error) {
	if errors.Is(loadErr, fs.ErrNotExist) || errors.Is(loadErr, fs.ErrPermission) {
		return nil, loadErr
	}
	c := config.DefaultConfig()
	c.DeploymentMode = strings.TrimSpace(os.Getenv(managed.DeploymentModeEnv))
	c.Enterprise.Profile = strings.TrimSpace(os.Getenv(managed.EnterpriseProfileEnv))
	var desired provenanceConfigFields
	if !c.StandaloneEnterprise() {
		raw, err := readProvenanceConfig(config.ConfigPath())
		if err != nil {
			return nil, err
		}
		desired = provenanceEndpointFields(raw)
		if c.DeploymentMode == "" {
			c.DeploymentMode = strings.TrimSpace(desired.DeploymentMode)
		}
		if c.Enterprise.Profile == "" {
			c.Enterprise.Profile = strings.TrimSpace(desired.Enterprise.Profile)
		}
	}
	if !c.StandaloneEnterprise() {
		applyProvenanceEndpointFields(c, desired)
		return c, nil
	}
	_, descriptor, err := managedStandaloneAdminDeployment()
	if err != nil {
		return nil, err
	}
	host, rawPort, err := net.SplitHostPort(descriptor.APIAddr)
	if err != nil {
		return nil, fmt.Errorf("managed runtime descriptor api_addr %q: %w", descriptor.APIAddr, err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("managed runtime descriptor api_addr %q has no valid port", descriptor.APIAddr)
	}
	if committed, err := provenanceCommittedConfig(); err == nil {
		applied := provenanceEndpointFields(committed)
		c.Gateway.Token = applied.Gateway.Token
		if tokenEnv := strings.TrimSpace(applied.Gateway.TokenEnv); tokenEnv != "" {
			c.Gateway.TokenEnv = tokenEnv
		}
	}
	c.Gateway.APIBind, c.Gateway.APIPort = host, port
	return c, nil
}

func readProvenanceConfig(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, provenanceConfigMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > provenanceConfigMaxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, provenanceConfigMaxBytes)
	}
	return raw, nil
}

// provenanceEndpointFields reads the provenanceConfigFields of raw. A file
// that is not valid YAML still yields the fields of its top-level gateway
// section when that section parses on its own (the rejected edit is
// elsewhere); otherwise none.
func provenanceEndpointFields(raw []byte) provenanceConfigFields {
	var fields provenanceConfigFields
	if yaml.Unmarshal(raw, &fields) == nil {
		return fields
	}
	fields = provenanceConfigFields{}
	if section := topLevelYAMLSection(string(raw), "gateway"); section != "" {
		var only provenanceConfigFields
		if yaml.Unmarshal([]byte(section), &only) == nil {
			fields.Gateway = only.Gateway
		}
	}
	return fields
}

// topLevelYAMLSection returns the lines of the top-level key name: its
// "name:" line and every following line that is indented, blank or a
// comment.
func topLevelYAMLSection(doc, name string) string {
	var section []string
	in := false
	for _, line := range strings.Split(strings.ReplaceAll(doc, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		top := line != "" && line[0] != ' ' && line[0] != '\t' && !strings.HasPrefix(trimmed, "#")
		switch {
		case top && (trimmed == name+":" || strings.HasPrefix(trimmed, name+": ") || strings.HasPrefix(trimmed, name+":#")):
			if in {
				return "" // a duplicate key: ambiguous
			}
			in = true
			section = append(section, line)
		case top:
			if in && len(section) > 0 {
				return strings.Join(section, "\n")
			}
		case in:
			section = append(section, line)
		}
	}
	return strings.Join(section, "\n")
}

func applyProvenanceEndpointFields(c *config.Config, fields provenanceConfigFields) {
	if bind := strings.TrimSpace(fields.Gateway.APIBind); bind != "" {
		c.Gateway.APIBind = bind
	}
	if port := fields.Gateway.APIPort; port > 0 && port <= 65535 {
		c.Gateway.APIPort = port
	}
	c.Gateway.Token = fields.Gateway.Token
	if tokenEnv := strings.TrimSpace(fields.Gateway.TokenEnv); tokenEnv != "" {
		c.Gateway.TokenEnv = tokenEnv
	}
}

// provenanceLoopbackAddresses is where the configured API host may be
// reached: a loopback literal, localhost (always loopback, RFC 6761: the
// loopback addresses the resolver gives it, then 127.0.0.1 and ::1), or
// another name only when it resolves to loopback addresses alone. The
// credential is never sent off the computer.
func provenanceLoopbackAddresses(ctx context.Context, host string) ([]net.IP, error) {
	name := strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), ".")
	if ip := net.ParseIP(name); ip != nil {
		if !ip.IsLoopback() {
			return nil, fmt.Errorf("the gateway API address %s is not a loopback address", host)
		}
		return []net.IP{ip}, nil
	}
	if name == "" {
		return nil, errors.New("the gateway API address is empty")
	}
	localhost := strings.EqualFold(name, "localhost")
	resolved, err := provenanceLookupIP(ctx, name)
	if err != nil && !localhost {
		return nil, fmt.Errorf("resolve the gateway API address %s: %w", host, err)
	}
	var addresses []net.IP
	add := func(ip net.IP) {
		for _, known := range addresses {
			if known.Equal(ip) {
				return
			}
		}
		addresses = append(addresses, ip)
	}
	for _, addr := range resolved {
		switch {
		case addr.IP.IsLoopback():
			add(addr.IP)
		case !localhost:
			return nil, fmt.Errorf("the gateway API address %s resolves to %s, not a loopback address", host, addr.IP)
		}
	}
	if localhost {
		add(net.IPv4(127, 0, 0, 1))
		add(net.IPv6loopback)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("the gateway API address %s resolves to no loopback address", host)
	}
	return addresses, nil
}

// provenanceListenerHeldBy reports whether gateway holds the listening
// socket and nothing else does, apart from the service manager that passed
// it to the gateway under socket activation.
func provenanceListenerHeldBy(holders []daemon.PortHolder, gateway provenanceGateway) bool {
	held := false
	for _, holder := range holders {
		switch {
		case gateway.PID > 0 && holder.PID == gateway.PID:
			held = true
		case gateway.SocketManagerPID > 0 && holder.PID == gateway.SocketManagerPID:
		default:
			return false
		}
	}
	return held
}

// dialProvenanceGateway connects to the first address whose listener the
// gateway holds. It inspects the listener after connecting, so the one that
// accepted is the one checked, and before HTTP can send the credential.
func dialProvenanceGateway(ctx context.Context, addresses []net.IP, port int, gateway provenanceGateway) (net.Conn, error) {
	for _, ip := range addresses {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			continue
		}
		holders, err := gatewayPortHolders(ip.String(), port)
		if err == nil && provenanceListenerHeldBy(holders, gateway) {
			return conn, nil
		}
		_ = conn.Close()
	}
	return nil, errors.New("gateway listener identity is unproven; the gateway token was not sent")
}

// runningGatewayProvenance reads the authenticated gateway snapshot. The
// short-lived CLI process has never applied a configuration and cannot
// report the daemon's generation from its own version.Current().
func runningGatewayProvenance(cmd *cobra.Command) (version.Provenance, error) {
	var envelope struct {
		Provenance *version.Provenance `json:"provenance"`
		Runtime    struct {
			PID int `json:"pid"`
		} `json:"runtime"`
	}
	if cfg == nil {
		return version.Provenance{}, fmt.Errorf("gateway configuration is unavailable")
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
	defer cancel()
	addresses, err := provenanceLoopbackAddresses(ctx, gatewayClientHost(cfg))
	if err != nil {
		return version.Provenance{}, err
	}
	gateway, err := provenanceGatewayIdentity(ctx)
	if err != nil || gateway.PID <= 0 {
		return version.Provenance{}, fmt.Errorf("gateway process identity is unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sidecarStatusURL(cfg), nil)
	if err != nil {
		return version.Provenance{}, err
	}
	if token := strings.TrimSpace(cfg.Gateway.ResolvedToken()); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	port := cfg.Gateway.APIPort
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			// Dial a pinned, proven loopback address, never the name again.
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialProvenanceGateway(ctx, addresses, port, gateway)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return version.Provenance{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return version.Provenance{}, fmt.Errorf("gateway returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, gatewayHealthDocumentMaxBytes+1))
	if err != nil {
		return version.Provenance{}, err
	}
	if len(body) > gatewayHealthDocumentMaxBytes {
		return version.Provenance{}, fmt.Errorf("gateway response is too large")
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return version.Provenance{}, fmt.Errorf("invalid gateway response")
	}
	if envelope.Runtime.PID != gateway.PID {
		return version.Provenance{}, fmt.Errorf("the authenticated answer did not come from the gateway process (PID %d)", gateway.PID)
	}
	if envelope.Provenance == nil || envelope.Provenance.SchemaVersion == 0 || envelope.Provenance.BinaryVersion == "" {
		return version.Provenance{}, fmt.Errorf("gateway did not report its provenance")
	}
	return *envelope.Provenance, nil
}
