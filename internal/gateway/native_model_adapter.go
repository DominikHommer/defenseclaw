// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

const (
	nativeModelRequestLimit = 1 << 20
	nativeModelOutputLimit  = 8 << 20
	nativeModelHeaderLimit  = 16 << 10
	nativeModelInFlight     = 8
	nativeModelBodyTimeout  = 15 * time.Second
	nativeClaudeProfile     = "defenseclaw-anthropic"
	nativeClaudeEndpoint    = "https://api.anthropic.com"
)

var errNativeModelAdapter = errors.New("native model adapter is unavailable")
var errNativeModelOutputLimit = errors.New("native model response exceeds its limit")

// nativeModelGrant is host-only input. No guest field, receipt, name lookup or
// request header can choose a provider, endpoint, credential or authority.
// The caller owns the same FileStore, binding and lifetime as the native hook
// assets. This deliberately has no production constructor call or listener.
type nativeModelGrant struct {
	Identity   sandboxruntime.SessionIdentity
	Binding    sandboxauth.Binding
	Bearer     string
	Authority  sandboxruntime.PolicyAuthorityBinding
	Current    func() sandboxruntime.PolicyAuthorityBinding
	Policy     *sandboxruntime.ExecutionPolicy
	Selection  sandboxruntime.ModelBrokerPolicy
	Spec       sandboxruntime.Spec
	Profile    string
	Endpoint   string
	Model      string
	MaxTokens  int
	Credential string
}

func (nativeModelGrant) String() string   { return "native-model-grant:<redacted>" }
func (nativeModelGrant) GoString() string { return "native-model-grant:<redacted>" }

type nativeModelAdapter struct {
	proxy   *GuardrailProxy
	store   *sandboxauth.FileStore
	grant   nativeModelGrant
	client  *http.Client
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closing bool
	active  sync.WaitGroup
	slots   chan struct{}
	close   sync.Once
	drained chan struct{}
}

type nativeModelExchangeKey struct{}

type nativeModelExchange struct {
	adapter    *nativeModelAdapter
	binding    sandboxauth.Binding
	inspection string
	cancel     context.CancelFunc
}

func (*nativeModelExchange) String() string   { return "native-model-exchange:<redacted>" }
func (*nativeModelExchange) GoString() string { return "native-model-exchange:<redacted>" }

func (*nativeModelAdapter) String() string   { return "native-model-adapter:<redacted>" }
func (*nativeModelAdapter) GoString() string { return "native-model-adapter:<redacted>" }

func nativeModelExchangeFromContext(ctx context.Context) *nativeModelExchange {
	exchange, _ := ctx.Value(nativeModelExchangeKey{}).(*nativeModelExchange)
	return exchange
}

// newNativeModelAdapter prepares a private, inert handler for one fixed Claude
// Anthropic profile. It does not install a route, open a socket, start a worker,
// mint a binding, enable online AXIS policy or expose a model credential to a
// guest. A future qualified producer must retain and Close this exact owner.
func newNativeModelAdapter(owner context.Context, proxy *GuardrailProxy, store *sandboxauth.FileStore, grant nativeModelGrant) (*nativeModelAdapter, error) {
	if owner == nil || owner.Err() != nil || proxy == nil ||
		store == nil || grant.Identity.Validate() != nil || grant.Identity.Runtime.Runtime != sandboxruntime.Axis ||
		grant.Binding.ID == "" || grant.Binding.SandboxID != grant.Identity.ID || grant.Binding.SandboxName != grant.Identity.Name ||
		grant.Binding.ExecutionOS != grant.Identity.Runtime.ExecutionOS || grant.Binding.Connector != "claudecode" ||
		len(grant.Binding.Routes) != 1 || grant.Binding.Routes[0] != sandboxauth.RouteHook ||
		grant.Authority.SnapshotID == "" || grant.Authority.Generation == 0 || grant.Current == nil ||
		grant.Policy == nil || grant.Policy.AuthorityBinding() != grant.Authority ||
		grant.Spec.Identity != grant.Identity || grant.Spec.Harness != "claudecode" ||
		grant.Spec.HarnessIdentity != grant.Selection.HarnessIdentity || grant.Spec.BindingID != grant.Binding.ID ||
		grant.Spec.CredentialProfile != grant.Profile || grant.Spec.Offline ||
		grant.Profile != nativeClaudeProfile || grant.Endpoint != nativeClaudeEndpoint ||
		grant.Model == "" || len(grant.Model) > 256 || strings.ContainsAny(grant.Model, "\x00\r\n") ||
		grant.MaxTokens <= 0 || grant.MaxTokens > 8192 ||
		grant.Credential == "" || len(grant.Credential) > 16<<10 || strings.ContainsAny(grant.Credential, "\x00\r\n") {
		return nil, errNativeModelAdapter
	}
	deadline, bounded := owner.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour || !nativeModelActionMode(proxy) ||
		grant.Current() != grant.Authority || !nativeModelPolicyAllows(grant.Policy, grant.Selection) {
		return nil, errNativeModelAdapter
	}
	matched, err := store.Match(grant.Bearer)
	if err != nil || !reflect.DeepEqual(matched, grant.Binding) {
		return nil, errNativeModelAdapter
	}
	grant.Binding = matched // store returns an independent copy; caller slices cannot change the grant
	ctx, cancel := context.WithCancel(owner)
	adapter := &nativeModelAdapter{proxy: proxy, store: store, grant: grant,
		ctx: ctx, cancel: cancel, slots: make(chan struct{}, nativeModelInFlight), drained: make(chan struct{})}
	client := netguard.SafeHTTPClient(5 * time.Minute)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		cancel()
		return nil, errNativeModelAdapter
	}
	// A dedicated dial-guarded transport has no ambient proxy, pooled peer or
	// redirect inheritance. The outer wrapper checks authority at RoundTrip.
	transport.DisableKeepAlives = true
	transport.MaxResponseHeaderBytes = nativeModelHeaderLimit
	client.Transport = &nativeModelTransport{adapter: adapter, upstream: transport}
	adapter.client = client
	return adapter, nil
}

func nativeModelPolicyAllows(policy *sandboxruntime.ExecutionPolicy, selection sandboxruntime.ModelBrokerPolicy) bool {
	if policy == nil || !policy.DecideEgress("api.anthropic.com", 443).Allowed {
		return false
	}
	actual, valid := policy.ModelBrokerPolicy()
	if !valid || actual != selection || selection.Authority.SnapshotID == "" || selection.PolicyDigest == "" ||
		selection.Harness != "claudecode" || selection.HarnessIdentity.Validate() != nil ||
		selection.LLM != config.OpenShellLLMAnthropic || selection.Profile == "" || selection.Offline {
		return false
	}
	required := policy.RequiredCapabilities()
	return slices.Contains(required, sandboxruntime.BrokerEgress) &&
		slices.Contains(required, sandboxruntime.HostCredentials) &&
		slices.Contains(required, sandboxruntime.ExecutableCredentialBinding)
}

func nativeModelActionMode(proxy *GuardrailProxy) bool {
	proxy.rtMu.RLock()
	defer proxy.rtMu.RUnlock()
	return proxy.mode == "action" && proxy.cfg != nil && proxy.cfg.Enabled && proxy.inspector != nil
}

func (adapter *nativeModelAdapter) admit() bool {
	if adapter == nil || adapter.ctx.Err() != nil || !nativeModelActionMode(adapter.proxy) ||
		adapter.grant.Current() != adapter.grant.Authority || !nativeModelPolicyAllows(adapter.grant.Policy, adapter.grant.Selection) {
		return false
	}
	matched, err := adapter.store.Match(adapter.grant.Bearer)
	return err == nil && reflect.DeepEqual(matched, adapter.grant.Binding)
}

// ServeHTTP is only an in-process handler seam. The guest has no route to it
// until a separately reviewed native transport, policy compiler and launch
// producer bind the same held session. It always feeds GuardrailProxy's real
// Anthropic passthrough inspection/streaming path.
func (adapter *nativeModelAdapter) ServeHTTP(w http.ResponseWriter, incoming *http.Request) {
	if adapter == nil || w == nil || incoming == nil {
		return
	}
	adapter.mu.Lock()
	if adapter.closing || adapter.ctx.Err() != nil {
		adapter.mu.Unlock()
		http.Error(w, "model unavailable", http.StatusServiceUnavailable)
		return
	}
	select {
	case adapter.slots <- struct{}{}:
	default:
		adapter.mu.Unlock()
		http.Error(w, "model busy", http.StatusTooManyRequests)
		return
	}
	adapter.active.Add(1)
	adapter.mu.Unlock()
	defer func() { <-adapter.slots; adapter.active.Done() }()
	if incoming.Body != nil {
		defer incoming.Body.Close()
	}
	// Start with an empty value context so neither guest nor ambient owner
	// context values can claim another gateway session, profile or provider.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopOwner := context.AfterFunc(adapter.ctx, cancel)
	defer stopOwner()
	stopIncoming := context.AfterFunc(incoming.Context(), cancel)
	defer stopIncoming()
	// Monitoring exists only for an admitted request. A changed generation or
	// revoked binding cancels a stalled upstream read, not merely the next turn.
	monitorDone := make(chan struct{})
	go adapter.monitor(ctx, cancel, monitorDone)
	defer func() { cancel(); <-monitorDone }()
	if !adapter.admit() {
		http.Error(w, "model unavailable", http.StatusServiceUnavailable)
		return
	}
	if incoming.Method != http.MethodPost || incoming.URL == nil || incoming.Body == nil || incoming.URL.Path != "/v1/messages" ||
		incoming.URL.RawQuery != "" || incoming.URL.Fragment != "" || incoming.ContentLength > nativeModelRequestLimit {
		http.Error(w, "invalid model request", http.StatusBadRequest)
		return
	}
	headers, ok := nativeModelHeaders(incoming.Header)
	if !ok {
		http.Error(w, "invalid model headers", http.StatusBadRequest)
		return
	}
	// Close the body to release a blocked Read on owner close, caller cancel,
	// authority rotation, or a bounded read deadline.
	bodyCtx, stopBodyTimeout := context.WithTimeout(ctx, nativeModelBodyTimeout)
	stopBodyRead := context.AfterFunc(bodyCtx, func() { _ = incoming.Body.Close() })
	body, err := io.ReadAll(io.LimitReader(incoming.Body, nativeModelRequestLimit+1))
	bodyDeadlineErr := bodyCtx.Err()
	stopBodyTimeout()
	stopBodyRead()
	_ = incoming.Body.Close()
	inspection, inspectable := nativeModelBody(body, adapter.grant.Model, adapter.grant.MaxTokens)
	if bodyDeadlineErr != nil || err != nil || len(body) > nativeModelRequestLimit || !inspectable {
		http.Error(w, "invalid model body", http.StatusBadRequest)
		return
	}
	if !adapter.admit() {
		http.Error(w, "model unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx = context.WithValue(ctx, nativeModelExchangeKey{}, &nativeModelExchange{adapter: adapter,
		binding: adapter.grant.Binding, inspection: inspection, cancel: cancel})
	request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/v1/messages"},
		Host: "api.anthropic.com", Header: headers, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
	request = request.WithContext(ctx)
	writer := &nativeModelWriter{adapter: adapter, ctx: ctx, target: w, header: make(http.Header), cancel: cancel}
	adapter.proxy.handlePassthrough(writer, request)
	if writer.limited {
		// Once response headers were written there is no safe success status.
		// Abort the stream instead of returning a truncated successful model turn.
		panic(http.ErrAbortHandler)
	}
}

func (adapter *nativeModelAdapter) monitor(ctx context.Context, cancel context.CancelFunc, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !adapter.admit() {
				cancel()
				return
			}
		}
	}
}

func nativeModelHeaders(input http.Header) (http.Header, bool) {
	result := make(http.Header)
	result.Set("Content-Type", "application/json")
	result.Set("Anthropic-Version", "2023-06-01")
	budget := 0
	for name, values := range input {
		budget += len(name)
		for _, value := range values {
			budget += len(value)
		}
		if budget > nativeModelHeaderLimit {
			return nil, false
		}
	}
	return result, true
}

func nativeModelBody(body []byte, model string, maxTokens int) (string, bool) {
	if len(body) == 0 || !nativeModelUniqueJSON(body) {
		return "", false
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(body, &members) != nil {
		return "", false
	}
	for name := range members {
		switch name {
		case "model", "messages", "max_tokens", "stream", "system", "tools", "tool_choice":
		default:
			return "", false
		}
	}
	var shape struct {
		Model     string `json:"model"`
		MaxTokens int    `json:"max_tokens"`
	}
	if json.Unmarshal(body, &shape) != nil || shape.Model != model ||
		shape.MaxTokens <= 0 || shape.MaxTokens > maxTokens {
		return "", false
	}
	if rawStream, ok := members["stream"]; ok {
		var stream bool
		if len(rawStream) == 0 || (rawStream[0] != 't' && rawStream[0] != 'f') || json.Unmarshal(rawStream, &stream) != nil {
			return "", false
		}
	}
	inspection, err := nativeAnthropicInspection(body)
	if err != nil || strings.TrimSpace(inspection) == "" {
		return "", false
	}
	return inspection, true
}

// nativeModelTransport is the last private boundary before the existing
// provider egress pipeline. It caps returned headers and body before the
// shared proxy can buffer or stream them. The underlying netguard transport
// still re-resolves and rejects private/reserved peers on every new dial.
type nativeModelTransport struct {
	adapter  *nativeModelAdapter
	upstream http.RoundTripper
}

func (transport *nativeModelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if transport == nil || transport.adapter == nil || transport.upstream == nil || req == nil || req.URL == nil {
		return nil, errNativeModelAdapter
	}
	exchange := nativeModelExchangeFromContext(req.Context())
	if exchange == nil || exchange.adapter != transport.adapter ||
		req.Method != http.MethodPost || req.URL.Scheme != "https" || req.URL.Host != "api.anthropic.com" ||
		req.Host != "api.anthropic.com" || req.URL.Path != "/v1/messages" || req.URL.RawQuery != "" || req.URL.Fragment != "" ||
		!nativeModelUpstreamHeaders(req.Header, transport.adapter.grant.Credential) ||
		!transport.adapter.admit() {
		return nil, errNativeModelAdapter
	}
	resp, err := transport.upstream.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || !nativeModelBoundedHeaders(resp.Header) || !transport.adapter.admit() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, errNativeModelAdapter
	}
	originalBody := resp.Body
	stop := context.AfterFunc(req.Context(), func() { _ = originalBody.Close() })
	resp.Body = &nativeModelResponseBody{body: originalBody, adapter: transport.adapter, cancel: exchange.cancel, stop: stop}
	return resp, nil
}

func nativeModelUpstreamHeaders(headers http.Header, credential string) bool {
	if len(headers) != 3 || len(headers.Values("Content-Type")) != 1 || headers.Get("Content-Type") != "application/json" ||
		len(headers.Values("Anthropic-Version")) != 1 || headers.Get("Anthropic-Version") != "2023-06-01" ||
		len(headers.Values("X-Api-Key")) != 1 || headers.Get("X-Api-Key") != credential {
		return false
	}
	for name := range headers {
		if !strings.EqualFold(name, "Content-Type") && !strings.EqualFold(name, "Anthropic-Version") && !strings.EqualFold(name, "X-Api-Key") {
			return false
		}
	}
	return true
}

func (transport *nativeModelTransport) CloseIdleConnections() {
	if closer, ok := transport.upstream.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func nativeModelBoundedHeaders(headers http.Header) bool {
	total := 0
	for name, values := range headers {
		total += len(name)
		for _, value := range values {
			total += len(value)
		}
		if total > nativeModelHeaderLimit {
			return false
		}
	}
	return true
}

type nativeModelResponseBody struct {
	body    io.ReadCloser
	adapter *nativeModelAdapter
	read    int
	cancel  context.CancelFunc
	stop    func() bool
}

func (body *nativeModelResponseBody) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if !body.adapter.admit() {
		body.cancel()
		return 0, errNativeModelAdapter
	}
	remaining := nativeModelOutputLimit - body.read
	if len(buf) > remaining+1 {
		buf = buf[:remaining+1]
	}
	n, err := body.body.Read(buf)
	if n > remaining {
		body.cancel()
		return 0, errNativeModelOutputLimit
	}
	if !body.adapter.admit() {
		body.cancel()
		return 0, errNativeModelAdapter
	}
	body.read += n
	return n, err
}

func (body *nativeModelResponseBody) Close() error {
	body.stop()
	return body.body.Close()
}

// The proxy and upstream may use different JSON parsers. Refuse duplicate or
// case-aliased members at every depth so they cannot inspect one value and
// execute another. The outer request cap bounds decoder work and memory.
func nativeModelUniqueJSON(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if !nativeModelJSONValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func nativeModelJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > 64 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			name, err := decoder.Token()
			key, valid := name.(string)
			if err != nil || !valid || seen[strings.ToLower(key)] {
				return false
			}
			seen[strings.ToLower(key)] = true
			if !nativeModelJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !nativeModelJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}

// Close seals admission, cancels active model requests and drains them. The
// enclosing native owner revokes this same sandboxauth binding and releases
// the transport after all holders (including hook ingress) have closed.
func (adapter *nativeModelAdapter) Close(ctx context.Context) error {
	if adapter == nil || ctx == nil {
		return errNativeModelAdapter
	}
	adapter.close.Do(func() {
		adapter.mu.Lock()
		adapter.closing = true
		adapter.mu.Unlock()
		adapter.cancel()
		adapter.client.CloseIdleConnections()
		go func() { adapter.active.Wait(); close(adapter.drained) }()
	})
	select {
	case <-adapter.drained:
		return nil
	case <-ctx.Done():
		return errors.Join(errNativeModelAdapter, ctx.Err())
	}
}

type nativeModelWriter struct {
	adapter *nativeModelAdapter
	ctx     context.Context
	target  http.ResponseWriter
	header  http.Header
	cancel  context.CancelFunc
	wrote   bool
	limited bool
	bytes   int
}

func (writer *nativeModelWriter) Header() http.Header { return writer.header }

// A detached completion-inspection context may finish after the owner or
// binding has been revoked. Check again at the final downstream commit, even
// when the upstream body has already been fully buffered.
func (writer *nativeModelWriter) ensureCurrent() {
	if writer.ctx.Err() != nil || !writer.adapter.admit() {
		writer.cancel()
		panic(http.ErrAbortHandler)
	}
}

func (writer *nativeModelWriter) WriteHeader(status int) {
	writer.ensureCurrent()
	if writer.wrote {
		return
	}
	writer.wrote = true
	if value := writer.header.Get("Content-Type"); len(value) <= 128 &&
		(strings.HasPrefix(value, "application/json") || strings.HasPrefix(value, "text/event-stream")) {
		writer.target.Header().Set("Content-Type", value)
	}
	writer.target.WriteHeader(status)
}

func (writer *nativeModelWriter) Write(data []byte) (int, error) {
	writer.ensureCurrent()
	if writer.limited || len(data) > nativeModelOutputLimit-writer.bytes {
		writer.limited = true
		writer.cancel()
		return 0, errNativeModelOutputLimit
	}
	if !writer.wrote {
		writer.WriteHeader(http.StatusOK)
	}
	writer.ensureCurrent()
	n, err := writer.target.Write(data)
	writer.bytes += n
	return n, err
}

func (writer *nativeModelWriter) Flush() {
	writer.ensureCurrent()
	if !writer.wrote {
		writer.WriteHeader(http.StatusOK)
	}
	writer.ensureCurrent()
	if flush, ok := writer.target.(http.Flusher); ok {
		flush.Flush()
	}
}

var _ http.Handler = (*nativeModelAdapter)(nil)
var _ http.Flusher = (*nativeModelWriter)(nil)
