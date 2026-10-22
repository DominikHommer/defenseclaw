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
	"path/filepath"
	"runtime"
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
// StartIdentity is the kernel start identity of a per-user gateway the
// operating system proved (provenanceProveGateway); every connection proves
// that process again before the credential is sent on it.
type provenanceGateway struct {
	PID              int
	SocketManagerPID int
	StartIdentity    string
}

// provenanceGatewayIdentity is the gateway a provenance read at
// addresses:port may send the credential to, proven now. A standalone
// deployment's is the gateway its service manager runs. A per-user
// gateway's is the process the kernel names as the holder of that API
// listener, and only when the operating system shows it runs as this
// account from this DefenseClaw binary and was started as this home's
// gateway (provenanceListenerGateway). No PID record is read: a record names
// a process but not whose it is, and a copied, stale or crafted one named
// another home's or another account's gateway. A listener is never trusted
// because it answers on the port.
var provenanceGatewayIdentity = func(ctx context.Context, addresses []net.IP, port int) (provenanceGateway, error) {
	if cfg.StandaloneEnterprise() {
		return provenanceManagedGateway(ctx)
	}
	return provenanceListenerGateway(addresses, port)
}

// provenanceProveGateway proves from the operating system that pid runs as
// this account from this DefenseClaw binary, started as the gateway of the
// DefenseClaw home home, and returns its kernel start identity
// (daemon.ProveOwnGateway). A seam for tests.
var provenanceProveGateway = daemon.ProveOwnGateway

// provenanceListenerGateway is the per-user gateway that holds the listener
// on the first of addresses:port where one is held: the one process the
// kernel names as its holder, proven to be this account's gateway of this
// home.
// Otherwise the gateway is not verified and nothing is sent.
func provenanceListenerGateway(addresses []net.IP, port int) (provenanceGateway, error) {
	reason := errors.New("no process holds the gateway API listener")
	for _, ip := range addresses {
		holders, err := gatewayPortHolders(ip.String(), port)
		switch {
		case errors.Is(err, daemon.ErrNoListener):
			continue
		case err != nil:
			reason = fmt.Errorf("the gateway API listener cannot be inspected: %v", err)
			continue
		case len(holders) != 1 || holders[0].PID <= 0:
			reason = errors.New("the gateway API listener is not held by one process of this account")
			continue
		}
		gateway, err := provenanceProvenProcess(holders[0].PID)
		if err != nil {
			reason = err
			continue
		}
		return gateway, nil
	}
	return provenanceGateway{}, provenanceNotVerified(reason)
}

// provenanceProvenProcess is process pid as a proven per-user gateway of
// this home (config.DefaultDataPath, the data directory Daemon.Start gives
// the gateway it launches and where its PID record lives).
func provenanceProvenProcess(pid int) (provenanceGateway, error) {
	startIdentity, err := provenanceProveGateway(pid, config.DefaultDataPath())
	if err != nil {
		return provenanceGateway{}, err
	}
	return provenanceGateway{PID: pid, StartIdentity: startIdentity}, nil
}

// provenanceNotVerified is the error of a read that sent nothing because
// the gateway was not proven.
func provenanceNotVerified(reason error) error {
	if errors.Is(reason, daemon.ErrGatewayNotVerified) {
		return fmt.Errorf("%w; the gateway token was not sent", reason)
	}
	return fmt.Errorf("%w: %v; the gateway token was not sent", daemon.ErrGatewayNotVerified, reason)
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
	// The environment before this command reads any .env: the gateway
	// resolved its token from its own environment, then the home's .env,
	// then its data directory's (provenanceResolveToken).
	provenanceStartEnvironment = os.Environ()
	if err := loadGatewayCommandConfigFor(cmd); err != nil {
		ctx, cancel := context.WithTimeout(provenanceContext(cmd), 5*time.Second)
		defer cancel()
		applied, appliedErr := provenanceAppliedConfig(ctx, err)
		if appliedErr != nil {
			return fmt.Errorf("cannot locate the running gateway: %w (%v); run `defenseclaw-gateway status`", err, appliedErr)
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
// per-user gateway's endpoint is the API listener the proven gateway
// process holds (provenancePerUserEndpoint), and its credential fields come
// from the record that process wrote of the ones it started with
// (provenanceGatewayToken). Either way the credential goes only to a
// listener proven to belong to the gateway process, and that process must
// answer as itself. A missing or unreadable config is not a rejected one:
// there is nothing to fall back on.
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

// provenancePerUserEndpoint points c at the API listener of the per-user
// gateway process: of the loopback TCP listeners that process holds, the
// one whose unauthenticated health document names that listener as the
// API. The rejected file cannot say where the gateway listens, so this
// home's PID record says which process to look at, and nothing more: that
// process must be proven this account's gateway now, every connection is
// made only to a listener it holds, and the credential is sent later only
// after runningGatewayProvenance proved the holder of the endpoint found
// here again. A process of this account and binary that another home
// started is not this home's gateway, whatever the record says. No
// credential is sent while it looks.
func provenancePerUserEndpoint(ctx context.Context, c *config.Config) error {
	_, candidate := gatewayManagedState()
	gateway, err := provenanceProvenProcess(candidate)
	if err != nil {
		return provenanceNotVerified(err)
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
// accepted is the one checked, and before HTTP can send the credential. A
// per-user gateway is proven again on every connection: the same process,
// still this account's gateway.
func dialProvenanceGateway(ctx context.Context, addresses []net.IP, port int, gateway provenanceGateway) (net.Conn, error) {
	for _, ip := range addresses {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			continue
		}
		holders, err := gatewayPortHolders(ip.String(), port)
		if err == nil && provenanceListenerHeldBy(holders, gateway) && provenanceStillProven(gateway) {
			return conn, nil
		}
		_ = conn.Close()
	}
	return nil, provenanceNotVerified(errors.New("the listener is not held by the proven gateway process"))
}

// provenanceStillProven reports whether a per-user gateway is still the
// process proven before: this account's gateway with the same kernel start
// identity. A standalone gateway is the service manager's, proven by it.
func provenanceStillProven(gateway provenanceGateway) bool {
	if gateway.StartIdentity == "" {
		return true
	}
	again, err := provenanceProveGateway(gateway.PID, config.DefaultDataPath())
	return err == nil && again == gateway.StartIdentity
}

// provenanceGatewayCredential is the credential the proven gateway applied
// and the data directory it runs on. A per-user gateway reads both once,
// when it starts, and records the token_env, inline token and data
// directory it started with (daemon.AppliedAuth); the token resolves here as
// the gateway resolved it (provenanceResolveToken), through the environment,
// the home's .env and that data directory's .env. A config.yaml edited
// since, whether the gateway rejected the edit or holds it until a restart,
// is not what it authenticates with or where it runs, so an explicit
// data_dir survives a rejected file or a held data_dir edit. Without that
// record (a gateway of an earlier release) the loaded config's fields are
// used, which for a rejected file leave only the default gateway token and
// the home; a standalone deployment's are those its lifecycle last applied.
func provenanceGatewayCredential(c *config.Config, gateway provenanceGateway) (string, string) {
	fields, dataDir := c.Gateway, c.DataDir
	if c.StandaloneEnterprise() {
		return strings.TrimSpace(fields.ResolvedToken()), dataDir
	}
	applied, ok := daemon.New(config.DefaultDataPath()).AppliedAuth(gateway.PID)
	if !ok {
		return strings.TrimSpace(fields.ResolvedToken()), dataDir
	}
	fields.TokenEnv, fields.Token = applied.TokenEnv, applied.Token
	if strings.TrimSpace(applied.DataDir) != "" {
		dataDir = applied.DataDir
	}
	return strings.TrimSpace(provenanceResolveToken(fields, dataDir)), dataDir
}

// provenanceStartEnvironment is the environment of this command before it
// read any .env; nil (a test that set cfg itself) is the current one.
var provenanceStartEnvironment []string

// provenanceResolveToken resolves fields as the gateway resolved them when
// it started: a variable comes from the environment, else the home's .env,
// else the .env of the data directory the gateway runs on (the order and
// first-wins rule of loadDotEnvIntoOS). The .env of a data_dir the gateway
// does not run on is not read.
func provenanceResolveToken(fields config.GatewayConfig, dataDir string) string {
	sources := [][][2]string{provenanceEnvironmentPairs(provenanceStartEnvironment)}
	home := filepath.Join(config.DefaultDataPath(), ".env")
	sources = append(sources, dotEnvValues(home))
	if own := filepath.Join(dataDir, ".env"); strings.TrimSpace(dataDir) != "" && own != home {
		sources = append(sources, dotEnvValues(own))
	}
	return fields.ResolvedTokenWith(func(name string) string {
		for _, pairs := range sources {
			for _, pair := range pairs {
				if pair[1] != "" && provenanceEnvironmentKeyIs(pair[0], name) {
					return pair[1]
				}
			}
		}
		return ""
	})
}

// provenanceEnvironmentPairs is environment (nil: this process's now) as
// KEY, VALUE pairs.
func provenanceEnvironmentPairs(environment []string) [][2]string {
	if environment == nil {
		environment = os.Environ()
	}
	pairs := make([][2]string, 0, len(environment))
	for _, entry := range environment {
		if key, value, ok := strings.Cut(entry, "="); ok && key != "" {
			pairs = append(pairs, [2]string{key, value})
		}
	}
	return pairs
}

// provenanceEnvironmentKeyIs compares variable names as the operating
// system does: without case on Windows.
func provenanceEnvironmentKeyIs(key, name string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(key, name)
	}
	return key == name
}

// runningGatewayProvenance reads the authenticated gateway snapshot. The
// short-lived CLI process has never applied a configuration and cannot
// report the daemon's generation from its own version.Current().
func runningGatewayProvenance(cmd *cobra.Command) (version.Provenance, error) {
	var envelope struct {
		Provenance *version.Provenance `json:"provenance"`
		Runtime    struct {
			PID     int    `json:"pid"`
			DataDir string `json:"data_dir"`
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
	gateway, err := provenanceGatewayIdentity(ctx, addresses, cfg.Gateway.APIPort)
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
	token, dataDir := provenanceGatewayCredential(cfg, gateway)
	if token != "" {
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
	// The gateway runs on the data directory it started with: an answer
	// from another one is not this home's provenance.
	if !cfg.StandaloneEnterprise() && !sameGatewayDataDir(envelope.Runtime.DataDir, dataDir) {
		return version.Provenance{}, errors.New("the gateway process serves another DefenseClaw home; " +
			"start this home's gateway with `defenseclaw-gateway start`")
	}
	if envelope.Provenance == nil || envelope.Provenance.SchemaVersion == 0 || envelope.Provenance.BinaryVersion == "" {
		return version.Provenance{}, fmt.Errorf("gateway did not report its provenance")
	}
	return *envelope.Provenance, nil
}
