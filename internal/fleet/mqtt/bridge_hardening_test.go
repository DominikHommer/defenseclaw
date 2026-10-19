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

package mqtt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

// mapKeyStore implements DeviceKeyLookup with rotation support.
type mapKeyStore struct {
	mu   sync.Mutex
	keys map[uint64][]byte
}

func (m *mapKeyStore) LoadDeviceKey(id uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), k...), nil
}

// productionEnv clears every development override so isProductionMode()
// takes its fail-closed default.
func productionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DCLAW_DEV_MODE", "")
	t.Setenv("DCLAW_PRODUCTION", "")
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DCLAW_DEVICE_KEY", "")
}

func quietBridge(b *Bridge) { b.logger = log.New(io.Discard, "", 0) }

func signedHB(topic string, key []byte, deviceID, uptime, boot uint32, flags uint8) []byte {
	body := makeHeartbeatPayload(deviceID, 1, 0, flags)
	binary.BigEndian.PutUint32(body[4:8], uptime)
	binary.BigEndian.PutUint32(body[32:36], boot)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(topic))
	mac.Write(body)
	return append(body, mac.Sum(nil)...)
}

func signedVerdictReq(topic string, key []byte, vr *VerdictRequest) []byte {
	body := EncodeVerdictRequestCBOR(vr)
	body = append(body, encodeCBORBytes(vr.RequestNonce[:])...)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(topic))
	mac.Write(body)
	return append(body, mac.Sum(nil)...)
}

func newVR(id uint16, boot [16]byte, rn [4]byte) *VerdictRequest {
	return &VerdictRequest{RequestID: id, ToolHash: [32]byte{0xAA}, ToolName: "shell",
		Destination: "x", Content: "c", BootNonce: boot, RequestNonce: rn}
}

func verdictPublishes(c *mockClient) []Message {
	var out []Message
	for _, m := range c.getPublished() {
		if strings.HasSuffix(m.Topic, "/verdict/resp") {
			out = append(out, m)
		}
	}
	return out
}

func allowCache() *verdict.Cache {
	return verdict.NewCache(10, func(_, _ uint16, _ [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})
}

// Outside development mode a fleet-wide DCLAW_DEVICE_KEY must never stand in
// for a missing per-device key: unsigned verdict requests from such a device
// are refused, and a heartbeat signed with the shared key is rejected.
func TestProductionIgnoresSharedDeviceKeyFallback(t *testing.T) {
	productionEnv(t)
	fleetKey := []byte("FLEETWIDE-KEY-0123456789abcdef!!")
	t.Setenv("DCLAW_DEVICE_KEY", hex.EncodeToString(fleetKey))
	if !isProductionMode() {
		t.Fatal("setup: expected production mode")
	}
	if k := newStoreBackedKeyProvider(nil).KeyForDevice(1); k != nil {
		t.Fatal("store provider returned the shared fleet key in production")
	}
	if k := newEnvDeviceKeyProvider().KeyForDevice(1); k != nil {
		t.Fatal("legacy env provider returned the shared fleet key in production")
	}

	fm := manager.New(nil)
	fm.RegisterDevice(2, 1, 7, "sbc", "1", 1, 0)
	c := newMockClient()
	b := NewBridge(c, fm, allowCache())
	quietBridge(b)
	b.SetDeviceKeyStore(&mapKeyStore{keys: map[uint64][]byte{}}) // no per-device key
	b.SetHeartbeatRateLimit(0)

	unsigned := EncodeVerdictRequestCBOR(newVR(9, [16]byte{1}, [4]byte{1}))
	unsigned = append(unsigned, make([]byte, 32)...)
	b.handleVerdictRequest(Message{Topic: "defenseclaw/2/1/7/verdict/req", Payload: unsigned})
	if n := len(verdictPublishes(c)); n != 0 {
		t.Fatalf("unsigned verdict request from an unkeyed device answered in production: %d", n)
	}

	topic := "defenseclaw/2/1/7/heartbeat"
	b.handleHeartbeat(Message{Topic: topic, Payload: signedHB(topic, fleetKey, 7, 500, 1, 0x04)})
	if d, _ := fm.GetDevice(manager.ComposeID(2, 1, 7)); d.Status == manager.StatusLockdown {
		t.Fatal("heartbeat signed with the shared fleet key accepted in production")
	}
}

// A custom key provider that reports an all-zero key cannot make a production
// gateway answer unsigned verdict requests.
func TestProductionVerdictRequiresHMACWithZeroKeyProvider(t *testing.T) {
	productionEnv(t)
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	c := newMockClient()
	b := NewBridge(c, fm, allowCache())
	quietBridge(b)
	b.SetKeyProvider(&fixedKeyProvider{key: make([]byte, 32)})
	unsigned := EncodeVerdictRequestCBOR(newVR(9, [16]byte{1}, [4]byte{1}))
	unsigned = append(unsigned, make([]byte, 32)...)
	b.handleVerdictRequest(Message{Topic: "defenseclaw/1/2/42/verdict/req", Payload: unsigned})
	if n := len(verdictPublishes(c)); n != 0 {
		t.Fatalf("unsigned verdict request answered in production: %d", n)
	}
	b.SetKeyProvider(nil)
	b.handleVerdictRequest(Message{Topic: "defenseclaw/1/2/42/verdict/req", Payload: unsigned})
	if n := len(verdictPublishes(c)); n != 0 {
		t.Fatalf("verdict request answered without a key provider: %d", n)
	}
}
