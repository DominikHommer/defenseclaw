// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"encoding/binary"
	"testing"
)

func fixedFrame() []byte {
	a, b := `C:\fixed\fixture\work`, `C:\Windows`
	raw := []byte("DCAXIS-WINCAN1\x00\x00")
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(a)))
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(b)))
	raw = binary.BigEndian.AppendUint16(raw, 12345)
	raw = binary.BigEndian.AppendUint16(raw, 23456)
	raw = append(raw, a...)
	raw = append(raw, b...)
	return append(raw, input...)
}

func TestFixedPrivateInputFrameRefusesTruncationExtraTargetAndMissingPort(t *testing.T) {
	raw := fixedFrame()
	if value, err := decode(raw); err != nil || value.work != `C:\fixed\fixture\work` || value.system != `C:\Windows` {
		t.Fatal("fixed synthetic frame refused")
	}
	for i := range raw {
		if _, err := decode(raw[:i]); err == nil {
			t.Fatal("truncation admitted")
		}
	}
	for _, alter := range []func([]byte){
		func(raw []byte) { raw[0] = 'X' },
		func(raw []byte) { raw[20], raw[21] = 0, 0 },
		func(raw []byte) { raw[24] = 0 },
		func(raw []byte) { raw[24] = '1' },
		func(raw []byte) { raw[len(raw)-1] = 'X' },
	} {
		candidate := append([]byte{}, raw...)
		alter(candidate)
		if _, err := decode(candidate); err == nil {
			t.Fatal("altered fixed frame admitted")
		}
	}
	if _, err := decode(append(raw, 'X')); err == nil {
		t.Fatal("extra byte admitted")
	}
}
