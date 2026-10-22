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
	"slices"
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

// Use the service manager for a standalone deployment, and the per-user
// gateway's process-identity record otherwise. Never trust a loopback
// listener merely because it answers on the configured port.
var provenanceGatewayIdentity = func(ctx context.Context) (provenanceGateway, error) {
	if cfg.StandaloneEnterprise() {
		return provenanceManagedGateway(ctx)
	}
	running, pid := gatewayManagedState()
	if !running || pid <= 0 {
		return provenanceGateway{}, errors.New("gateway process identity is unavailable")
	}
	if !provenanceGatewayProven(pid) {
		return provenanceGateway{}, fmt.Errorf("the gateway PID record names PID %d without proving its process identity; "+
			"restart the gateway with `defenseclaw-gateway restart`", pid)
	}
	return provenanceGateway{PID: pid}, nil
}

// provenanceGatewayProven reports whether this home's PID record proves pid
// is the gateway it started: a current record (executable, kernel start
// identity, data directory), the strong record of the release before it
// (executable and start identity), or a current record of a gateway whose
// file was replaced while it ran. The read then sends the credential only
// to a listener that process holds, and accepts only an answer that names
// it. A bare PID or an older record without both identities names only a
// PID, which the OS may since have given to another account's process
// (start and status still use it to detect a running gateway). A seam for
// tests.
var provenanceGatewayProven = func(pid int) bool {
	d := daemon.New(config.DefaultDataPath())
	return d.HasManagedProcessIdentity(pid) || d.HasAuthenticatedMigrationProcessIdentity(pid)
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
// deployment, endpoint and credential then come from what was applied and
// the running gateway, never from the rejected file
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
		ctx, cancel := context.WithTimeout(provenanceContext(cmd), 5*time.Second)
		defer cancel()
		applied, appliedErr := provenanceAppliedConfig(ctx, err)
		if appliedErr != nil {
			return fmt.Errorf("cannot locate the running gateway: %w; run `defenseclaw-gateway status`", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v; the running gateway keeps the config it last applied\n", err)
		cfg = applied
	}
	return nil
}

func provenanceContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
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

// provenanceCredentialFields are the only fields provenanceAppliedConfig
// reads from the config a standalone lifecycle last applied.
type provenanceCredentialFields struct {
	Gateway struct {
		Token    string `yaml:"token"`
		TokenEnv string `yaml:"token_env"`
	} `yaml:"gateway"`
}

// provenanceGatewayListeners lists the TCP listeners of the gateway
// process. A seam for tests.
var provenanceGatewayListeners = daemon.ProcessTCPListeners

// provenanceAppliedConfig locates the running gateway after the strict load
// of config.yaml failed with loadErr. The gateway rejected that file and
// kept the config it last applied, and any setting of the rejected file may
// be the rejected edit, so nothing is read from it: not the deployment, the
// endpoint or the credential. The deployment comes from the environment
// (pinned for an administrator of a managed computer); without one this is
// a per-user gateway, which is always read from the gateway itself. A
// standalone deployment's API address is the one its administrator-owned
// runtime descriptor publishes, and its credential fields come from the
// root-only copy of the config its lifecycle last applied (Linux, macOS). A
// per-user gateway keeps no copy of what it applied: its endpoint is the API
// listener the proven gateway process holds (provenancePerUserEndpoint),
// and its credential the default gateway token of the environment and its
// .env (loaded before the strict load). Either way the credential goes only
// to a listener proven to belong to the gateway process, and that process
// must answer as itself. A missing or unreadable config is not a rejected
// one: there is nothing to fall back on.
func provenanceAppliedConfig(ctx context.Context, loadErr error) (*config.Config, error) {
	if errors.Is(loadErr, fs.ErrNotExist) || errors.Is(loadErr, fs.ErrPermission) {
		return nil, loadErr
	}
	c := config.DefaultConfig()
	c.DeploymentMode = strings.TrimSpace(os.Getenv(managed.DeploymentModeEnv))
	c.Enterprise.Profile = strings.TrimSpace(os.Getenv(managed.EnterpriseProfileEnv))
	c.Gateway.Token = ""
	if !c.StandaloneEnterprise() {
		if err := provenancePerUserEndpoint(ctx, c); err != nil {
			return nil, err
		}
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
		var applied provenanceCredentialFields
		if yaml.Unmarshal(committed, &applied) == nil {
			c.Gateway.Token = applied.Gateway.Token
			if tokenEnv := strings.TrimSpace(applied.Gateway.TokenEnv); tokenEnv != "" {
				c.Gateway.TokenEnv = tokenEnv
			}
		}
	}
	c.Gateway.APIBind, c.Gateway.APIPort = host, port
	return c, nil
}

// provenancePerUserEndpoint points c at the API listener of the proven
// per-user gateway process: of the loopback TCP listeners that process
// holds, the one whose unauthenticated health document names that listener
// as the API. No credential is sent while it looks.
func provenancePerUserEndpoint(ctx context.Context, c *config.Config) error {
	gateway, err := provenanceGatewayIdentity(ctx)
	if err != nil {
		return err
	}
	if gateway.PID <= 0 {
		return errors.New("gateway process identity is unavailable")
	}
	listeners, err := provenanceGatewayListeners(gateway.PID)
	if err != nil {
		return fmt.Errorf("list the listeners of the gateway process: %w", err)
	}
	// The default API port first, then by port, so a slow listener of
	// another kind is asked last where it can be.
	defaultPort := config.DefaultConfig().Gateway.APIPort
	slices.SortStableFunc(listeners, func(a, b daemon.TCPListenAddr) int {
		if (a.Port == defaultPort) != (b.Port == defaultPort) {
			if a.Port == defaultPort {
				return -1
			}
			return 1
		}
		return a.Port - b.Port
	})
	for _, listener := range listeners {
		for _, ip := range provenanceLoopbackOf(listener.IP) {
			if provenanceListenerServesAPI(ctx, ip, listener.Port, gateway) {
				c.Gateway.APIBind, c.Gateway.APIPort = ip.String(), listener.Port
				return nil
			}
		}
	}
	return errors.New("the gateway process holds no API listener on a loopback address")
}

// provenanceLoopbackOf is where a listener bound to ip is reached on this
// computer: a loopback address itself, the loopback addresses for a
// wildcard one, none for any other.
func provenanceLoopbackOf(ip net.IP) []net.IP {
	switch {
	case ip == nil:
		return nil
	case ip.IsLoopback():
		return []net.IP{ip}
	case ip.IsUnspecified() && ip.To4() != nil:
		return []net.IP{net.IPv4(127, 0, 0, 1)}
	case ip.IsUnspecified():
		return []net.IP{net.IPv6loopback, net.IPv4(127, 0, 0, 1)}
	}
	return nil
}

// provenanceListenerServesAPI reports whether the gateway's listener on
// ip:port is its API: GET /health, which needs no credential, answers with
// the health document whose API address is this port. Another listener of
// the process (the guardrail proxy, a sandbox ingress) does not.
func provenanceListenerServesAPI(ctx context.Context, ip net.IP, port int, gateway provenanceGateway) bool {
	client := provenanceHTTPClient([]net.IP{ip}, port, gateway)
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(ip.String(), strconv.Itoa(port))+"/health", nil)
	if err != nil {
		return false
	}
	response, err := client.Do(req)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, gatewayHealthDocumentMaxBytes+1))
	if err != nil || len(body) > gatewayHealthDocumentMaxBytes {
		return false
	}
	var health struct {
		API struct {
			Details map[string]any `json:"details"`
		} `json:"api"`
	}
	if json.Unmarshal(body, &health) != nil {
		return false
	}
	addr, _ := health.API.Details["addr"].(string)
	_, apiPort, err := net.SplitHostPort(addr)
	return err == nil && apiPort == strconv.Itoa(port)
}

// provenanceHTTPClient sends requests only to a listener on one of
// addresses:port that the gateway holds, proven per connection; it never
// resolves a name again and never follows a redirect.
func provenanceHTTPClient(addresses []net.IP, port int, gateway provenanceGateway) *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialProvenanceGateway(ctx, addresses, port, gateway)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
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
	ctx, cancel := context.WithTimeout(provenanceContext(cmd), 5*time.Second)
	defer cancel()
	addresses, err := provenanceLoopbackAddresses(ctx, gatewayClientHost(cfg))
	if err != nil {
		return version.Provenance{}, err
	}
	gateway, err := provenanceGatewayIdentity(ctx)
	if err != nil {
		return version.Provenance{}, err
	}
	if gateway.PID <= 0 {
		return version.Provenance{}, errors.New("gateway process identity is unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sidecarStatusURL(cfg), nil)
	if err != nil {
		return version.Provenance{}, err
	}
	if token := strings.TrimSpace(cfg.Gateway.ResolvedToken()); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := provenanceHTTPClient(addresses, cfg.Gateway.APIPort, gateway)
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
