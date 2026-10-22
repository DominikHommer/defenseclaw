// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

var provenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Print the binary and config provenance (schema, content hash, generation, version)",
}

var provenanceShowCmd = &cobra.Command{
	Use:         "show",
	Short:       "Show the running gateway schema, content hash, generation, and binary version",
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := managedStandardUserGatewayRefusal(); err != nil {
			return err
		}
		applyManagedStandaloneAdminEnv(cmd.ErrOrStderr())
		if err := loadGatewayCommandConfigFor(cmd); err != nil {
			return fmt.Errorf("cannot locate the running gateway: %w; run `defenseclaw-gateway status`", err)
		}
		return nil
	},
	RunE: runProvenanceShow,
}

func init() {
	provenanceCmd.AddCommand(provenanceShowCmd)
	rootCmd.AddCommand(provenanceCmd)
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

// runningGatewayProvenance reads the authenticated gateway snapshot. The
// short-lived CLI process has never applied a configuration and cannot
// report the daemon's generation from its own version.Current().
func runningGatewayProvenance(cmd *cobra.Command) (version.Provenance, error) {
	var envelope struct {
		Provenance *version.Provenance `json:"provenance"`
	}
	if cfg == nil {
		return version.Provenance{}, fmt.Errorf("gateway configuration is unavailable")
	}
	host := gatewayClientHost(cfg)
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return version.Provenance{}, fmt.Errorf("the gateway API address must be a loopback IP")
	}
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, sidecarStatusURL(cfg), nil)
	if err != nil {
		return version.Provenance{}, err
	}
	if token := strings.TrimSpace(cfg.Gateway.ResolvedToken()); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{
		Timeout:       2 * time.Second,
		Transport:     &http.Transport{Proxy: nil},
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
	if envelope.Provenance == nil || envelope.Provenance.SchemaVersion == 0 || envelope.Provenance.BinaryVersion == "" {
		return version.Provenance{}, fmt.Errorf("gateway did not report its provenance")
	}
	return *envelope.Provenance, nil
}
