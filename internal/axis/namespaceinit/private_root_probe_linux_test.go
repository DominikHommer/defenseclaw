// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux && axis_private_root_probe

package namespaceinit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const privateRootReady = "DCAX_PRIVATE_ROOT_READY_V1\n"
const privateRootGrant = "DCAX_PRIVATE_ROOT_GRANT_V1\n"
const privateRootOutputLimit = 16 << 10

type privateRootCapture struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (c *privateRootCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) > privateRootOutputLimit-len(c.data) {
		c.overflow = true
		return 0, errors.New("fixed private-root probe output bound exceeded")
	}
	c.data = append(c.data, p...)
	return len(p), nil
}

func (c *privateRootCapture) snapshot() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.data), c.overflow
}

func closePrivateRootFile(file **os.File) error {
	if *file == nil {
		return nil
	}
	err := (*file).Close()
	*file = nil
	return err
}

func privateRootPipe(file *os.File, wanted int) error {
	if file == nil {
		return errors.New("fixed private-root pipe absent")
	}
	var st unix.Stat_t
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || unix.Fstat(int(file.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != wanted {
		return errors.New("fixed private-root pipe identity refused")
	}
	return nil
}

func privateRootChild() (resultErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if runtime.GOARCH != "amd64" || os.Getpid() != 1 || os.Getppid() != 0 || os.Getuid() <= 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return errors.New("fixed private-root child identity refused")
	}
	// Go's pre-exec Pdeathsig comparison cannot be used with CLONE_NEWPID:
	// the namespace init sees PPID 0. The fixed parent holds this creating
	// thread; no mount or workload is possible until its GRANT arrives.
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Errorf("parent death guard: %w", err)
	}
	proofFile := os.NewFile(3, "fixed-private-root-proof")
	grant := os.NewFile(4, "fixed-private-root-grant")
	ready := os.NewFile(5, "fixed-private-root-ready")
	defer func() {
		resultErr = errors.Join(resultErr, closePrivateRootFile(&proofFile), closePrivateRootFile(&grant), closePrivateRootFile(&ready))
	}()
	if proofFile == nil || privateRootPipe(grant, unix.O_RDONLY) != nil || privateRootPipe(ready, unix.O_WRONLY) != nil {
		return errors.New("fixed private-root inherited descriptors refused")
	}
	info, statErr := proofFile.Stat()
	seals, sealErr := unix.FcntlInt(proofFile.Fd(), unix.F_GET_SEALS, 0)
	if statErr != nil || sealErr != nil || !info.Mode().IsRegular() || info.Size() != proofSize || seals != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
		return errors.New("fixed private-root sealed proof refused")
	}
	var raw [proofSize]byte
	if n, err := proofFile.ReadAt(raw[:], 0); err != nil || n != len(raw) {
		return errors.New("fixed private-root proof read refused")
	}
	parent, err := decode(raw[:])
	if err != nil {
		return err
	}
	if err := closePrivateRootFile(&proofFile); err != nil {
		return err
	}
	b := &nativeBootstrap{parent: parent, fds: [3]int{-1, -1, -1}, proc: -1}
	defer func() {
		for i := range b.fds {
			if b.fds[i] >= 0 {
				resultErr = errors.Join(resultErr, unix.Close(b.fds[i]))
				b.fds[i] = -1
			}
		}
		if b.proc >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(b.proc))
			b.proc = -1
		}
	}()
	if err := b.validate(); err != nil {
		return fmt.Errorf("owned namespace proof: %w", err)
	}
	if _, err := io.WriteString(ready, privateRootReady); err != nil {
		return fmt.Errorf("fixed READY: %w", err)
	}
	if err := closePrivateRootFile(&ready); err != nil {
		return err
	}
	message, err := io.ReadAll(io.LimitReader(grant, int64(len(privateRootGrant)+1)))
	if err != nil || string(message) != privateRootGrant {
		return errors.New("fixed GRANT missing or malformed")
	}
	if err := closePrivateRootFile(&grant); err != nil {
		return err
	}
	// Every mount is made only after the exact owner has an atomic pidfd and
	// has granted this already validated private namespace init.
	if err := b.privateMounts(); err != nil {
		return fmt.Errorf("private propagation: %w", err)
	}
	options := fmt.Sprintf("size=4m,nr_inodes=256,mode=0700,uid=%d,gid=%d", os.Getuid(), os.Getgid())
	if err := unix.Mount("tmpfs", "/tmp", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, options); err != nil {
		return fmt.Errorf("private tmpfs mount: %w", err)
	}
	// Open AFTER the mount. A descriptor held before it would still name the
	// covered host /tmp and must never become pivot_root authority.
	rootFD, err := unix.Open("/tmp", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("new tmpfs root open: %w", err)
	}
	defer func() {
		if rootFD >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(rootFD))
		}
	}()
	var before unix.Stat_t
	var rootFS unix.Statfs_t
	if err := unix.Fstat(rootFD, &before); err != nil {
		return err
	}
	if err := unix.Fstatfs(rootFD, &rootFS); err != nil || rootFS.Type != unix.TMPFS_MAGIC || before.Mode&unix.S_IFMT != unix.S_IFDIR || before.Mode&07777 != 0700 || before.Uid != uint32(os.Getuid()) || before.Gid != uint32(os.Getgid()) {
		return errors.New("new tmpfs root identity or mapped ownership refused")
	}
	if err := unix.Mkdir("/tmp/tmp", 0700); err != nil {
		return err
	}
	if err := unix.Mkdir("/tmp/proc", 0700); err != nil {
		return err
	}
	if err := unix.Fchdir(rootFD); err != nil {
		return fmt.Errorf("new tmpfs root chdir: %w", err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("private pivot_root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("old root detach: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Close(rootFD); err != nil {
		return err
	}
	rootFD = -1
	var after, ownedTmp unix.Stat_t
	if err := unix.Stat("/", &after); err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Uid != uint32(os.Getuid()) || after.Gid != uint32(os.Getgid()) || after.Mode&07777 != 0700 {
		return errors.New("pivoted root identity or owner differs")
	}
	if err := unix.Stat("/tmp", &ownedTmp); err != nil || ownedTmp.Mode&unix.S_IFMT != unix.S_IFDIR || ownedTmp.Mode&07777 != 0700 || ownedTmp.Uid != uint32(os.Getuid()) || ownedTmp.Gid != uint32(os.Getgid()) {
		return errors.New("private /tmp mapped ownership refused")
	}
	var unexpected unix.Stat_t
	if err := unix.Stat("/etc", &unexpected); !errors.Is(err, unix.ENOENT) {
		return errors.New("old root pathname remains visible")
	}
	if err := b.mountProc(); err != nil {
		return fmt.Errorf("fresh PID proc mount: %w", err)
	}
	if err := b.dropCaps(); err != nil {
		return fmt.Errorf("all-thread capability drop: %w", err)
	}
	if err := b.verify(); err != nil {
		return fmt.Errorf("private bootstrap verification: %w", err)
	}
	for i := range b.fds {
		if err := unix.Close(b.fds[i]); err != nil {
			return err
		}
		b.fds[i] = -1
	}
	if err := unix.Close(b.proc); err != nil {
		return err
	}
	b.proc = -1
	fmt.Printf("DCAX_PRIVATE_ROOT_PASS uid=%d gid=%d tmpfs=true pivot=true detached=true proc=true caps_zero=true\n", os.Getuid(), os.Getgid())
	return nil
}

func privateRootParent() (resultErr error) {
	if runtime.GOARCH != "amd64" || os.Getpid() == 1 || os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return errors.New("nonroot fixed probe parent required")
	}
	proofFile, err := Capture()
	if err != nil {
		return err
	}
	var grantRead, grantWrite, readyRead, readyWrite *os.File
	defer func() {
		resultErr = errors.Join(resultErr, closePrivateRootFile(&proofFile), closePrivateRootFile(&grantRead), closePrivateRootFile(&grantWrite), closePrivateRootFile(&readyRead), closePrivateRootFile(&readyWrite))
	}()
	grantRead, grantWrite, err = os.Pipe()
	if err != nil {
		return err
	}
	readyRead, readyWrite, err = os.Pipe()
	if err != nil {
		return err
	}
	stdout, stderr := &privateRootCapture{}, &privateRootCapture{}
	pidfd := -1
	command := &exec.Cmd{
		Path: "/proc/self/exe",
		Args: []string{"fixed-private-root-probe.test", "-test.v=true", "-test.run=^TestPrivateTmpfsRootProbe$"},
		Env:  []string{}, Dir: "/", ExtraFiles: []*os.File{proofFile, grantRead, readyWrite},
		Stdout: stdout, Stderr: stderr,
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
			AmbientCaps:                []uintptr{unix.CAP_SYS_ADMIN},
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
			GidMappingsEnableSetgroups: false, PidFD: &pidfd,
		},
	}
	// The child death signal attaches to the thread which calls Start. Keep
	// that exact thread alive until the namespace init has been reaped.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	started, waited := false, false
	var waitDone chan error
	defer func() {
		if started && !waited {
			if pidfd >= 0 {
				signalErr := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
				if signalErr != nil && !errors.Is(signalErr, unix.ESRCH) {
					resultErr = errors.Join(resultErr, signalErr)
				}
			} else if command.Process != nil {
				resultErr = errors.Join(resultErr, command.Process.Kill())
			}
			select {
			case waitErr := <-waitDone:
				var exitErr *exec.ExitError
				if waitErr != nil && !errors.As(waitErr, &exitErr) {
					resultErr = errors.Join(resultErr, waitErr)
				}
			case <-time.After(5 * time.Second):
				resultErr = errors.Join(resultErr, errors.New("private PID namespace init was not reaped"))
			}
		}
		if pidfd >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(pidfd))
		}
		out, outOverflow := stdout.snapshot()
		diagnostics, errOverflow := stderr.snapshot()
		if outOverflow || errOverflow {
			resultErr = errors.Join(resultErr, errors.New("fixed private-root output overflow"))
		}
		if resultErr != nil {
			resultErr = fmt.Errorf("%w; bounded child stdout=%q stderr=%q", resultErr, out, diagnostics)
		}
	}()
	if err := command.Start(); err != nil {
		return fmt.Errorf("private PID namespace start: %w", err)
	}
	started = true
	waitDone = make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	if pidfd < 0 {
		return errors.New("atomic pidfd custody unavailable")
	}
	if err := errors.Join(closePrivateRootFile(&proofFile), closePrivateRootFile(&grantRead), closePrivateRootFile(&readyWrite)); err != nil {
		return err
	}
	if err := readyRead.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	readyMessage, err := io.ReadAll(io.LimitReader(readyRead, int64(len(privateRootReady)+1)))
	if err != nil || string(readyMessage) != privateRootReady {
		return errors.New("fixed private-root READY absent or malformed")
	}
	if err := closePrivateRootFile(&readyRead); err != nil {
		return err
	}
	if err := grantWrite.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(grantWrite, privateRootGrant); err != nil {
		return err
	}
	if err := closePrivateRootFile(&grantWrite); err != nil {
		return err
	}
	select {
	case err := <-waitDone:
		waited = true
		if err != nil {
			return fmt.Errorf("private-root child exit: %w", err)
		}
	case <-time.After(25 * time.Second):
		return errors.New("private-root child lifetime exceeded")
	}
	out, overflow := stdout.snapshot()
	diagnostics, stderrOverflow := stderr.snapshot()
	want := fmt.Sprintf("DCAX_PRIVATE_ROOT_PASS uid=%d gid=%d tmpfs=true pivot=true detached=true proc=true caps_zero=true\n", os.Getuid(), os.Getgid())
	if overflow || stderrOverflow || diagnostics != "" || strings.Count(out, want) != 1 || !strings.Contains(out, "--- PASS: TestPrivateTmpfsRootProbe") || !strings.Contains(out, "\nPASS\n") {
		return errors.New("fixed private-root proof or test pass inventory differs")
	}
	fmt.Println("DCAX_PRIVATE_ROOT_CUSTODY pidfd=true namespace_init_reaped=true fixed_grant=true")
	return nil
}

// TestPrivateTmpfsRootProbe is a manually dispatched, trusted filesystem
// compatibility experiment. It does not run a peer, hook, model or agent and
// is not AXIS production or vendor runtime qualification.
func TestPrivateTmpfsRootProbe(t *testing.T) {
	if os.Getpid() == 1 {
		if err := privateRootChild(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := privateRootParent(); err != nil {
		t.Fatal(err)
	}
}
