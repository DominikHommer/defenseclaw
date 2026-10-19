// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

type unavailableAttachmentController struct{ *attachController }

func (*unavailableAttachmentController) AttachmentAvailable() bool { return false }

func TestSandboxAttachmentOptionalNativeDependencyKeepsLegacyRouteClosed(t *testing.T) {
	legacy := &unavailableAttachmentController{attachController: &attachController{
		fakeSandboxController: &fakeSandboxController{},
		attachment:            newFakeAttachment(),
		entered:               make(chan struct{}),
	}}
	_, handler := sandboxTestAPI(t, legacy, true)
	response := serve(handler, sandboxRequest(http.MethodGet, sandboxapi.PathSandboxes+"/box/attach", ""))
	if response.Code != http.StatusServiceUnavailable || legacy.attached.Load() != 0 {
		t.Fatalf("legacy route status=%d, attachments=%d", response.Code, legacy.attached.Load())
	}
}
