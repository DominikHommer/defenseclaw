// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccompArch is the audit architecture of each Linux release build.
var seccompArch = map[string]uint32{"amd64": unix.AUDIT_ARCH_X86_64, "arm64": unix.AUDIT_ARCH_AARCH64}

// seccomp_data offsets: the syscall number, the architecture and the low
// 32 bits of each argument (both release architectures are little endian).
const (
	seccompNROffset   = 0
	seccompArchOffset = 4
)

// The ioctls that set an I/O owner (asm-generic/sockios.h).
const (
	ioctlFIOSETOWN = 0x8901
	ioctlSIOCSPGRP = 0x8902
)

func seccompArg(i uint32) uint32 { return 16 + 8*i }

// guardCustodian keeps what the calling thread starts from signaling the
// custodian with pid custodian: a scanner that SIGKILLed it, its
// grandparent, took the runner and the command down with the parent-death
// signals, and the kernel handed the command's setsid child to init, which
// kept running (GAP-0631). Every way to signal a given process is refused
// for the custodian's process and group, and for every process at once
// (kill -1): kill, tgkill, rt_sigqueueinfo, rt_tgsigqueueinfo, an I/O owner
// set by fcntl, and tkill and pidfd_send_signal, whose target the filter
// cannot see (pidfd_send_signal reports ENOSYS, so the Go and Python
// runtimes use kill instead). The filter is installed with prctl, which
// applies to this thread alone and which the gateway unit's system-call
// filter allows, unlike seccomp(2).
func guardCustodian(custodian int) error {
	filter, err := custodianGuardFilter(uint32(custodian))
	if err != nil {
		return err
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	err = unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
	runtime.KeepAlive(filter)
	return err
}

// custodianGuardFilter assembles guardCustodian's filter for the running
// architecture.
func custodianGuardFilter(custodian uint32) ([]unix.SockFilter, error) {
	arch, ok := seccompArch[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("processutil: no seccomp architecture for %s", runtime.GOARCH)
	}
	group := -custodian // two's complement, as the kernel reads the pid_t
	var a bpfAssembler
	a.load(seccompArchOffset)
	a.jeq(arch, "", "eperm")
	a.load(seccompNROffset)
	if runtime.GOARCH == "amd64" {
		// x32 system calls share the architecture with a flag in the number.
		a.jge(0x40000000, "eperm", "")
	}
	a.jeq(unix.SYS_KILL, "kill", "")
	a.jeq(unix.SYS_TGKILL, "process", "")
	a.jeq(unix.SYS_RT_SIGQUEUEINFO, "process", "")
	a.jeq(unix.SYS_RT_TGSIGQUEUEINFO, "process", "")
	a.jeq(unix.SYS_TKILL, "eperm", "")
	a.jeq(unix.SYS_PIDFD_SEND_SIGNAL, "enosys", "")
	a.jeq(unix.SYS_FCNTL, "fcntl", "")
	a.jeq(unix.SYS_IOCTL, "ioctl", "")
	a.ret(unix.SECCOMP_RET_ALLOW)

	a.label("kill")
	a.load(seccompArg(0))
	a.jeq(custodian, "eperm", "")
	a.jeq(group, "eperm", "")
	a.jeq(0xffffffff, "eperm", "allow")

	a.label("process")
	a.load(seccompArg(0))
	a.jeq(custodian, "eperm", "allow")

	a.label("fcntl")
	a.load(seccompArg(1))
	a.jeq(unix.F_SETOWN_EX, "eperm", "")
	a.jeq(unix.F_SETOWN, "", "allow")
	a.load(seccompArg(2))
	a.jeq(custodian, "eperm", "")
	a.jeq(group, "eperm", "allow")

	a.label("ioctl")
	a.load(seccompArg(1))
	a.jeq(ioctlFIOSETOWN, "eperm", "")
	a.jeq(ioctlSIOCSPGRP, "eperm", "allow")

	a.label("allow")
	a.ret(unix.SECCOMP_RET_ALLOW)
	a.label("eperm")
	a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	a.label("enosys")
	a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS))
	return a.assemble()
}

// bpfAssembler builds a classic BPF program whose conditional jumps name
// their targets; "" falls through to the next instruction.
type bpfAssembler struct {
	insns  []unix.SockFilter
	jumps  map[int][2]string
	labels map[string]int
}

func (a *bpfAssembler) emit(code uint16, k uint32) {
	a.insns = append(a.insns, unix.SockFilter{Code: code, K: k})
}

func (a *bpfAssembler) load(offset uint32) { a.emit(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offset) }

func (a *bpfAssembler) ret(k uint32) { a.emit(unix.BPF_RET|unix.BPF_K, k) }

func (a *bpfAssembler) jeq(k uint32, jt, jf string) { a.jump(unix.BPF_JEQ, k, jt, jf) }

func (a *bpfAssembler) jge(k uint32, jt, jf string) { a.jump(unix.BPF_JGE, k, jt, jf) }

func (a *bpfAssembler) jump(op uint16, k uint32, jt, jf string) {
	if a.jumps == nil {
		a.jumps = map[int][2]string{}
	}
	a.jumps[len(a.insns)] = [2]string{jt, jf}
	a.emit(unix.BPF_JMP|op|unix.BPF_K, k)
}

func (a *bpfAssembler) label(name string) {
	if a.labels == nil {
		a.labels = map[string]int{}
	}
	a.labels[name] = len(a.insns)
}

func (a *bpfAssembler) assemble() ([]unix.SockFilter, error) {
	for at, targets := range a.jumps {
		var offsets [2]uint8
		for i, name := range targets {
			if name == "" {
				continue
			}
			to, ok := a.labels[name]
			if !ok || to <= at || to-at-1 > 255 {
				return nil, fmt.Errorf("processutil: bad seccomp jump to %q", name)
			}
			offsets[i] = uint8(to - at - 1)
		}
		a.insns[at].Jt, a.insns[at].Jf = offsets[0], offsets[1]
	}
	return a.insns, nil
}
