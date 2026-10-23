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
	"os"
	"runtime"
	"strconv"
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

// guardCustodian protects the custodian and its gateway parent while allowing
// a scanner to signal itself and the children it starts by positive PID. A
// non-leader thread ID can signal its entire group, so list every thread ID
// before the command starts. The gateway is also a subreaper and sweeps any
// orphan it adopts if the custodian nevertheless dies (GAP-0631).
// tgkill and rt_tgsigqueueinfo expose the target's thread-group ID and are
// refused for both protected processes; tkill and pidfd_send_signal hide the
// group and are refused outright (pidfd_send_signal reports ENOSYS so runtimes
// can fall back to kill). Ptrace and cross-process memory/fd access cannot
// inject a signal from an unfiltered thread. The filter is installed with
// prctl, which applies to this thread alone and which the gateway unit allows.
func guardCustodian(custodian int) error {
	gateway, err := parentPID(custodian)
	if err != nil {
		return err
	}
	gatewayGroup, err := unix.Getpgid(gateway)
	if err != nil {
		return err
	}
	protected, err := protectedThreadIDs(custodian, gateway)
	if err != nil {
		return err
	}
	filter, err := custodianGuardFilter(uint32(custodian), uint32(gateway), uint32(-gatewayGroup), protected)
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

func protectedThreadIDs(processes ...int) ([]uint32, error) {
	var ids []uint32
	for _, process := range processes {
		entries, err := os.ReadDir("/proc/" + strconv.Itoa(process) + "/task")
		if err != nil {
			return nil, fmt.Errorf("processutil: cannot list protected threads of %d: %w", process, err)
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("processutil: no protected threads of %d", process)
		}
		for _, entry := range entries {
			id, err := strconv.ParseUint(entry.Name(), 10, 32)
			if err != nil {
				return nil, err
			}
			ids = append(ids, uint32(id))
		}
	}
	return ids, nil
}

// custodianGuardFilter assembles guardCustodian's filter for the running
// architecture.
func custodianGuardFilter(custodian, gateway, gatewayGroup uint32, protected []uint32) ([]unix.SockFilter, error) {
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
	a.jeq(unix.SYS_RT_SIGQUEUEINFO, "signal", "")
	a.jeq(unix.SYS_RT_TGSIGQUEUEINFO, "process", "")
	a.jeq(unix.SYS_TKILL, "eperm", "")
	a.jeq(unix.SYS_PIDFD_SEND_SIGNAL, "enosys", "")
	a.jeq(unix.SYS_PRLIMIT64, "prlimit", "")
	a.jeq(unix.SYS_FCNTL, "fcntl", "")
	a.jeq(unix.SYS_IOCTL, "ioctl", "")
	a.jeq(unix.SYS_PTRACE, "eperm", "")
	a.jeq(unix.SYS_PROCESS_VM_READV, "eperm", "")
	a.jeq(unix.SYS_PROCESS_VM_WRITEV, "eperm", "")
	a.jeq(unix.SYS_PIDFD_GETFD, "eperm", "")
	a.ret(unix.SECCOMP_RET_ALLOW)

	a.label("kill")
	a.load(seccompArg(1))
	a.jeq(0, "allow", "") // a liveness probe sends no signal
	a.load(seccompArg(0))
	a.jeq(0, "allow", "") // only the caller's group; a different session
	a.jge(0x80000000, "killgroup", "signal")

	a.label("killgroup")
	a.jeq(group, "eperm", "")
	a.jeq(gatewayGroup, "eperm", "")
	a.jeq(0xffffffff, "eperm", "allow")

	a.label("signal")
	a.load(seccompArg(0))
	for _, id := range protected {
		a.denyIfEqual(id)
	}
	a.ret(unix.SECCOMP_RET_ALLOW)

	a.label("process")
	a.load(seccompArg(0))
	a.jeq(custodian, "eperm", "")
	a.jeq(gateway, "eperm", "allow")

	a.label("prlimit")
	a.load(seccompArg(0))
	a.jeq(0, "allow", "eperm")

	a.label("fcntl")
	a.load(seccompArg(1))
	a.jeq(unix.F_SETOWN_EX, "eperm", "")
	a.jeq(unix.F_SETOWN, "", "allow")
	a.load(seccompArg(2))
	a.jeq(0, "allow", "")
	a.jge(0x80000000, "fcntlgroup", "signalOwner")

	a.label("fcntlgroup")
	a.jeq(group, "eperm", "")
	a.jeq(gatewayGroup, "eperm", "allow")
	a.label("signalOwner")
	for _, id := range protected {
		a.denyIfEqual(id)
	}
	a.ret(unix.SECCOMP_RET_ALLOW)

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

// bpfAssembler builds a classic BPF program whose jumps name their targets.
// Conditional BPF branches have only eight-bit offsets. Two adjacent JA
// trampolines give each branch the full 32-bit forward range, including when
// a busy gateway has many protected threads.
type bpfAssembler struct {
	insns  []unix.SockFilter
	jumps  map[int]bpfJumpTarget
	labels map[string]int
}

type bpfJumpTarget struct {
	label         string
	fallthroughTo int
}

func (a *bpfAssembler) emit(code uint16, k uint32) {
	a.insns = append(a.insns, unix.SockFilter{Code: code, K: k})
}

func (a *bpfAssembler) load(offset uint32) { a.emit(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offset) }

func (a *bpfAssembler) ret(k uint32) { a.emit(unix.BPF_RET|unix.BPF_K, k) }

func (a *bpfAssembler) jeq(k uint32, jt, jf string) { a.jump(unix.BPF_JEQ, k, jt, jf) }

func (a *bpfAssembler) jge(k uint32, jt, jf string) { a.jump(unix.BPF_JGE, k, jt, jf) }

func (a *bpfAssembler) denyIfEqual(k uint32) {
	deny := fmt.Sprintf("deny%d", len(a.insns))
	next := fmt.Sprintf("next%d", len(a.insns))
	a.jeq(k, deny, next)
	a.label(deny)
	a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	a.label(next)
}

func (a *bpfAssembler) jump(op uint16, k uint32, jt, jf string) {
	if a.jumps == nil {
		a.jumps = map[int]bpfJumpTarget{}
	}
	at := len(a.insns)
	a.emit(unix.BPF_JMP|op|unix.BPF_K, k)
	a.insns[at].Jt, a.insns[at].Jf = 0, 1
	a.jumps[at+1] = bpfJumpTarget{label: jt, fallthroughTo: at + 3}
	a.jumps[at+2] = bpfJumpTarget{label: jf, fallthroughTo: at + 3}
	a.emit(unix.BPF_JMP|unix.BPF_JA, 0)
	a.emit(unix.BPF_JMP|unix.BPF_JA, 0)
}

func (a *bpfAssembler) label(name string) {
	if a.labels == nil {
		a.labels = map[string]int{}
	}
	a.labels[name] = len(a.insns)
}

func (a *bpfAssembler) assemble() ([]unix.SockFilter, error) {
	for at, target := range a.jumps {
		to := target.fallthroughTo
		if target.label == "" {
			// Both arms fall through beyond the two JA instructions.
		} else {
			var ok bool
			to, ok = a.labels[target.label]
			if !ok || to <= at {
				return nil, fmt.Errorf("processutil: bad seccomp jump to %q", target.label)
			}
		}
		a.insns[at].K = uint32(to - at - 1)
	}
	return a.insns, nil
}
