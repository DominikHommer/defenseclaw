// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The gateway reports the signed policy bundle receipts of a standalone
// managed device: it reads the public receipt-events spool the enterprise
// lifecycle writes when a receipt ends, emits one config.bundle.receipt audit event
// (with the defenseclaw.policy.bundle.applies counter) per terminal receipt,
// and records the defenseclaw.policy.bundle.version gauge for the bundle the
// live generation runs. It also drains the change spool the root trust
// anchor and credential commands write (enterprisestatus.ChangeEvent) and
// emits one config.trust_anchors.changed, config.secret.changed or
// config.secret.change_failed audit event per change, so a change made
// while the gateway was stopped is reported at its next start. Reporting
// only: nothing here changes what is enforced.
//
// Each receipt or change is reported in two phases. The poll writes and
// syncs its local audit row, a bounded number per poll, receipts and changes
// in turn. Delivery to the destinations that row owes then runs off the poll,
// a bounded number at once, and the reported marker the lifecycle and the
// change commands wait for is written only after every destination
// acknowledged it. An unresponsive destination therefore delays neither the
// next poll nor the local audit rows of later receipts and changes.

var (
	// bundleReceiptPollInterval is how often the receipt spool is read.
	bundleReceiptPollInterval = 5 * time.Second
	// bundleReportPersistPerPoll bounds the local audit rows one poll writes.
	bundleReportPersistPerPoll = 32
	// bundleReportConfirmInFlight bounds the deliveries that await a
	// destination acknowledgement at once.
	bundleReportConfirmInFlight = 8
	// bundleReportConfirmTimeout bounds one acknowledgement wait.
	bundleReportConfirmTimeout = 10 * time.Second
)

// Single-slot markers cover the receipt.json fallback. Only the confirmed
// marker format can suppress replay after a restart.
const bundleReceiptMarkerName = "bundle-receipt.reported"
const bundleRefusalMarkerName = "bundle-refusal.reported"

// bundleReceiptSink is the audit surface the reporter uses (*audit.Logger).
// The Log methods persist the local row; the Confirm methods deliver it.
type bundleReceiptSink interface {
	LogPolicyBundleReceipt(principal string, bundle audit.PolicyBundle, receipt audit.PolicyBundleReceipt) error
	ConfirmPolicyBundleReceipt(ctx context.Context, principal string, bundle audit.PolicyBundle, receipt audit.PolicyBundleReceipt) error
	RecordPolicyBundleVersion(ctx context.Context, bundleVersion uint64) error
	LogConfigChange(change audit.ConfigChange) error
	ConfirmConfigChange(ctx context.Context, change audit.ConfigChange) error
}

type bundleReceiptReporter struct {
	receiptPath, markerPath, refusalMarkerPath string
	sink                                       bundleReceiptSink
	// enforcedVersion is the bundle version the live generation runs.
	enforcedVersion func() uint64

	lastModTime     time.Time
	lastSize        int64
	reported        string
	reportedRefusal string
	gaugeVersion    uint64
	seen            map[string]bool

	// persisted items have a durable local row and await delivery; inFlight
	// items await an acknowledgement; attempted orders the next poll least
	// recently tried first. Only the poll goroutine reads or writes them:
	// deliveries hand their result back on results.
	persisted     map[string]bool
	inFlight      map[string]bool
	attempted     map[string]time.Time
	results       chan reportResult
	confirmations sync.WaitGroup
}

// reportItem is one receipt or change event the reporter owes the audit log:
// persist writes and syncs its local row, confirm delivers it to every
// destination it owes, and done records its markers once both succeeded.
type reportItem struct {
	key     string
	persist func() error
	confirm func(context.Context) error
	done    func()
}

type reportResult struct {
	item reportItem
	err  error
}

// newBundleReceiptReporter returns the reporter of a standalone enterprise
// gateway, nil on every other profile (per-user, Secure Client) and without
// an audit logger.
func newBundleReceiptReporter(cfg *config.Config, configPath string, logger *audit.Logger) *bundleReceiptReporter {
	if cfg == nil || logger == nil || !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() ||
		strings.TrimSpace(configPath) == "" || strings.TrimSpace(cfg.DataDir) == "" {
		return nil
	}
	return &bundleReceiptReporter{
		receiptPath:       enterprisestatus.PublicReceiptPath(filepath.Dir(configPath)),
		markerPath:        filepath.Join(cfg.DataDir, bundleReceiptMarkerName),
		refusalMarkerPath: filepath.Join(cfg.DataDir, bundleRefusalMarkerName),
		sink:              logger,
		enforcedVersion:   liveBundleVersion,
	}
}

func liveBundleVersion() uint64 {
	if g := currentGeneration(); g != nil {
		return g.BundleVersion
	}
	return 0
}

func (r *bundleReceiptReporter) run(ctx context.Context) {
	r.reported = r.readMarker()
	r.reportedRefusal = r.readRefusalMarker()
	r.prepare()
	ticker := time.NewTicker(bundleReceiptPollInterval)
	defer ticker.Stop()
	defer r.confirmations.Wait()
	for {
		r.poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case result := <-r.results:
			r.finish(result)
		}
	}
}

func (r *bundleReceiptReporter) prepare() {
	if r.results == nil {
		// Each delivery sends one result and at most
		// bundleReportConfirmInFlight are outstanding, so a send never blocks.
		r.results = make(chan reportResult, bundleReportConfirmInFlight)
		r.persisted, r.inFlight, r.attempted = map[string]bool{}, map[string]bool{}, map[string]time.Time{}
	}
}

// poll records the version gauge and drains every terminal receipt in the
// spool and every change event. receipt.json remains a fallback for
// lifecycle versions without the spool.
func (r *bundleReceiptReporter) poll(ctx context.Context) {
	r.prepare()
	r.drainResults()
	if v := r.enforcedVersion(); v != 0 && v != r.gaugeVersion {
		if r.sink.RecordPolicyBundleVersion(ctx, v) == nil {
			r.gaugeVersion = v
		}
	}
	receipts := append(r.spoolItems(), r.fallbackItems()...)
	r.dispatch(ctx, interleaveReportItems(receipts, r.changeItems()))
}

// interleaveReportItems alternates receipts and changes, so neither family
// waits behind a backlog of the other.
func interleaveReportItems(receipts, changes []reportItem) []reportItem {
	items := make([]reportItem, 0, len(receipts)+len(changes))
	for index := 0; index < len(receipts) || index < len(changes); index++ {
		if index < len(receipts) {
			items = append(items, receipts[index])
		}
		if index < len(changes) {
			items = append(items, changes[index])
		}
	}
	return items
}

// dispatch persists the local rows of up to bundleReportPersistPerPoll items
// and starts up to bundleReportConfirmInFlight deliveries, least recently
// attempted first, so an item whose destination never answers cannot starve
// the others. It does not wait for any destination.
func (r *bundleReceiptReporter) dispatch(ctx context.Context, items []reportItem) {
	queue := make([]reportItem, 0, len(items))
	pending := make(map[string]bool, len(items))
	for _, item := range items {
		if !pending[item.key] {
			pending[item.key] = true
			queue = append(queue, item)
		}
	}
	for key := range r.persisted {
		if !pending[key] && !r.inFlight[key] {
			delete(r.persisted, key)
		}
	}
	for key := range r.attempted {
		if !pending[key] && !r.inFlight[key] {
			delete(r.attempted, key)
		}
	}
	sort.SliceStable(queue, func(i, j int) bool {
		return r.attempted[queue[i].key].Before(r.attempted[queue[j].key])
	})
	persists := 0
	for _, item := range queue {
		if r.inFlight[item.key] {
			continue
		}
		if !r.persisted[item.key] {
			if persists == bundleReportPersistPerPoll {
				continue
			}
			persists++
			if item.persist() != nil {
				r.attempted[item.key] = time.Now()
				continue
			}
			r.persisted[item.key] = true
		}
		if len(r.inFlight) >= bundleReportConfirmInFlight || ctx.Err() != nil {
			continue
		}
		r.inFlight[item.key] = true
		r.attempted[item.key] = time.Now()
		r.confirmations.Go(func() {
			confirmCtx, cancel := context.WithTimeout(ctx, bundleReportConfirmTimeout)
			err := item.confirm(confirmCtx)
			cancel()
			r.results <- reportResult{item: item, err: err}
		})
	}
}

// finish records one delivery result on the poll goroutine. A refused or
// unacknowledged delivery is offered again; its local row is not repeated.
func (r *bundleReceiptReporter) finish(result reportResult) {
	delete(r.inFlight, result.item.key)
	if result.err != nil {
		return
	}
	delete(r.persisted, result.item.key)
	delete(r.attempted, result.item.key)
	result.item.done()
}

func (r *bundleReceiptReporter) drainResults() {
	for {
		select {
		case result := <-r.results:
			r.finish(result)
		default:
			return
		}
	}
}

func (r *bundleReceiptReporter) spoolDir() string {
	return filepath.Join(filepath.Dir(r.receiptPath), enterprisestatus.PublicReceiptEventsDirName)
}

func (r *bundleReceiptReporter) changeDir() string {
	return filepath.Join(filepath.Dir(r.receiptPath), enterprisestatus.ChangeEventsDirName)
}

// seenDir is <data_dir>/bundle-receipt.reported.d, one marker per reported
// receipt and change event: the lifecycle reads it before it removes a
// receipt event (enterprisestatus.ReceiptEventReported), the change commands
// before they remove a change event (enterprisestatus.ChangeReported).
func (r *bundleReceiptReporter) seenDir() string {
	return filepath.Join(filepath.Dir(r.markerPath), enterprisestatus.ReportedMarkersDirName)
}

// reportableID accepts a receipt id or a change event id as a marker name.
func reportableID(id string) bool {
	return enterprisestatus.ValidReceiptID(id) || enterprisestatus.ValidChangeEventID(id)
}

func (r *bundleReceiptReporter) hasSeen(id string) bool {
	if !reportableID(id) {
		return false
	}
	if r.seen[id] {
		return true
	}
	if enterprisestatus.ValidReceiptID(id) {
		return enterprisestatus.ReceiptEventReported(filepath.Dir(r.markerPath), id)
	}
	return enterprisestatus.ChangeReported(filepath.Dir(r.markerPath), id)
}

func (r *bundleReceiptReporter) markSeen(id string) {
	if !reportableID(id) {
		return
	}
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	r.seen[id] = true
	if err := os.MkdirAll(r.seenDir(), 0o700); err == nil {
		_ = configwrite.WriteFileDurable(filepath.Join(r.seenDir(), id), []byte(enterprisestatus.ConfirmedDeliveryMarker), 0o600)
	}
}

// spoolItems are the terminal receipts of the spool not reported yet, oldest
// first.
func (r *bundleReceiptReporter) spoolItems() []reportItem {
	entries, err := os.ReadDir(r.spoolDir())
	if err != nil {
		return nil
	}
	var receipts []enterprisestatus.PublicReceipt
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !enterprisestatus.ValidReceiptID(id) || !entry.Type().IsRegular() || r.hasSeen(id) {
			continue
		}
		receipt, err := enterprisestatus.ReadPublicReceipt(filepath.Join(r.spoolDir(), entry.Name()))
		if err == nil && receipt.ReceiptID == id {
			receipts = append(receipts, receipt)
		}
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].FinishedAt != receipts[j].FinishedAt {
			return receipts[i].FinishedAt < receipts[j].FinishedAt
		}
		return receipts[i].ReceiptID < receipts[j].ReceiptID
	})
	var items []reportItem
	for _, receipt := range receipts {
		if receipt.Key() == r.reported || receipt.ReceiptID+"|"+receipt.FinishedAt == r.reportedRefusal {
			r.markSeen(receipt.ReceiptID)
			continue
		}
		items = append(items, r.receiptItem(receipt, nil))
	}
	return items
}

// fallbackItems are the receipt and the separate refusal receipt.json names
// that are not reported yet. The file is read again at every poll until both
// are reported.
func (r *bundleReceiptReporter) fallbackItems() []reportItem {
	info, err := os.Lstat(r.receiptPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	if info.ModTime().Equal(r.lastModTime) && info.Size() == r.lastSize {
		return nil
	}
	seen := func() { r.lastModTime, r.lastSize = info.ModTime(), info.Size() }
	receipt, err := enterprisestatus.ReadPublicReceipt(r.receiptPath)
	if err != nil {
		seen()
		return nil
	}
	var items []reportItem
	key := receipt.Key()
	refusal := receipt.LastRefusal
	// The public receipt remains confirmed when a pre-staging delivery is
	// refused. That refusal is covered by the receipt; a separate refusal
	// still needs its own audit event.
	coverRefusal := func() {
		if refusal != nil && refusal.ReceiptID == receipt.ReceiptID {
			r.reportedRefusal = refusal.ReceiptID + "|" + refusal.Time
			if r.refusalMarkerPath != "" {
				_ = configwrite.WriteFileDurable(r.refusalMarkerPath, []byte(enterprisestatus.ConfirmedDeliveryMarker+r.reportedRefusal+"\n"), 0o600)
			}
		}
	}
	if key == r.reported || r.hasSeen(receipt.ReceiptID) {
		coverRefusal()
	} else {
		items = append(items, r.receiptItem(receipt, func() {
			r.reported = key
			_ = configwrite.WriteFileDurable(r.markerPath, []byte(enterprisestatus.ConfirmedDeliveryMarker+key+"\n"), 0o600)
			coverRefusal()
		}))
	}
	if refusal != nil && refusal.ReceiptID != receipt.ReceiptID {
		refusalKey := refusal.ReceiptID + "|" + refusal.Time
		if refusalKey != r.reportedRefusal && !r.hasSeen(refusal.ReceiptID) {
			items = append(items, r.receiptItem(enterprisestatus.PublicReceipt{ReceiptID: refusal.ReceiptID, DeliveryID: refusal.DeliveryID,
				BundleID: refusal.BundleID, Version: refusal.Version, State: enterprisestatus.BundleFailed,
				ErrorCode: refusal.ErrorCode, FinishedAt: refusal.Time,
				WarningCodes: refusal.WarningCodes, DisabledByBundle: refusal.DisabledByBundle,
				CurrentBundleID: receipt.CurrentBundleID, CurrentVersion: receipt.CurrentVersion}, func() {
				r.reportedRefusal = refusalKey
				if r.refusalMarkerPath != "" {
					_ = configwrite.WriteFileDurable(r.refusalMarkerPath, []byte(enterprisestatus.ConfirmedDeliveryMarker+refusalKey+"\n"), 0o600)
				}
			}))
		}
	}
	if len(items) == 0 {
		seen()
	}
	return items
}

// changeItems are the change events not reported yet, oldest first. A file
// that does not validate is skipped. An event is marked reported only once
// its local row is durable and every destination acknowledged it; the
// logger stores each change event id once, so a marker lost after the audit
// write cannot report it twice.
func (r *bundleReceiptReporter) changeItems() []reportItem {
	dir := r.changeDir()
	var items []reportItem
	for _, id := range enterprisestatus.ListChangeEventIDs(dir) {
		if r.hasSeen(id) {
			continue
		}
		ev, err := enterprisestatus.ReadChangeEvent(filepath.Join(dir, id+".json"))
		if err != nil || ev.EventID != id {
			continue
		}
		change := audit.ConfigChange{
			EventID: ev.EventID, Kind: ev.Kind, Action: ev.Action, Outcome: ev.Outcome, ReasonCode: ev.ReasonCode,
			Actor: ev.Actor, ChangedAt: ev.Time, SHA256: ev.SHA256, PreviousSHA256: ev.PreviousSHA256,
			KeyIDsAdded: ev.KeyIDsAdded, KeyIDsRemoved: ev.KeyIDsRemoved, SecretName: ev.SecretName,
		}
		items = append(items, reportItem{key: "change:" + id,
			persist: func() error { return r.sink.LogConfigChange(change) },
			confirm: func(ctx context.Context) error { return r.sink.ConfirmConfigChange(ctx, change) },
			done:    func() { r.markSeen(id) },
		})
	}
	return items
}

// receiptItem reports one terminal receipt; done adds the single-slot
// markers of the receipt.json fallback.
func (r *bundleReceiptReporter) receiptItem(p enterprisestatus.PublicReceipt, done func()) reportItem {
	bundle := audit.PolicyBundle{ID: p.BundleID, Version: p.Version, SignerKeyID: p.SignerKeyID, ChangeSummary: p.ChangeSummary}
	receipt := audit.PolicyBundleReceipt{
		ReceiptID: p.ReceiptID, DeliveryID: p.DeliveryID, Actor: p.Actor, State: p.State, ErrorCode: p.ErrorCode,
		FinishedAt:            p.FinishedAt,
		EffectivePolicyDigest: p.EffectivePolicyDigest, EnforcingDigest: p.EnforcingDigest,
		ConfigGeneration: p.ConfigGeneration, RolledBack: p.RolledBack, Restart: p.Restart,
		RestartRequired:  p.RestartRequired,
		EnforcingVersion: p.CurrentVersion,
		WarningCodes:     p.WarningCodes, DisabledByBundle: p.DisabledByBundle,
	}
	return reportItem{key: "receipt:" + p.ReceiptID,
		persist: func() error {
			err := r.sink.LogPolicyBundleReceipt(p.Principal, bundle, receipt)
			if err == nil && p.CurrentVersion != 0 {
				r.gaugeVersion = p.CurrentVersion
			}
			return err
		},
		confirm: func(ctx context.Context) error {
			return r.sink.ConfirmPolicyBundleReceipt(ctx, p.Principal, bundle, receipt)
		},
		done: func() {
			r.markSeen(p.ReceiptID)
			if done != nil {
				done()
			}
		},
	}
}

func (r *bundleReceiptReporter) readMarker() string {
	return readBundleMarker(r.markerPath)
}

func (r *bundleReceiptReporter) readRefusalMarker() string {
	return readBundleMarker(r.refusalMarkerPath)
}

func readBundleMarker(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	raw, _ := io.ReadAll(io.LimitReader(f, 512))
	value, confirmed := strings.CutPrefix(string(raw), enterprisestatus.ConfirmedDeliveryMarker)
	if !confirmed {
		return ""
	}
	return strings.TrimSpace(value)
}
