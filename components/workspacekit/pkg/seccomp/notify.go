// Copyright (c) 2021 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package seccomp

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/gitpod-io/gitpod/common-go/log"
	"github.com/gitpod-io/gitpod/workspacekit/pkg/readarg"
	"golang.org/x/sys/unix"

	daemonapi "github.com/gitpod-io/gitpod/ws-daemon/api"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

type syscallHandler func(req *libseccomp.ScmpNotifReq) (val uint64, errno int32, flags uint32)

// SyscallHandler handles seccomp syscall notifications
type SyscallHandler interface {
	Mount(req *libseccomp.ScmpNotifReq) (val uint64, errno int32, flags uint32)
	Bind(req *libseccomp.ScmpNotifReq) (val uint64, errno int32, flags uint32)
}

func mapHandler(h SyscallHandler) map[string]syscallHandler {
	return map[string]syscallHandler{
		"mount": h.Mount,
		"bind":  h.Bind,
	}
}

// LoadFilter loads the syscall filter required to make the handler work.
// Calling this function has a range of side-effects:
//   - we'll lock the caller using `runtime.LockOSThread()`
//   - we'll set no_new_privs on the process
func LoadFilter() (libseccomp.ScmpFd, error) {
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return 0, fmt.Errorf("cannot create filter: %w", err)
	}
	err = filter.SetTsync(false)
	if err != nil {
		return 0, fmt.Errorf("cannot set tsync: %w", err)
	}
	err = filter.SetNoNewPrivsBit(false)
	if err != nil {
		return 0, fmt.Errorf("cannot set no_new_privs: %w", err)
	}

	handledSyscalls := mapHandler(&InWorkspaceHandler{})
	for sc := range handledSyscalls {
		syscallID, err := libseccomp.GetSyscallFromName(sc)
		if err != nil {
			return 0, fmt.Errorf("unknown syscall %s: %w", sc, err)
		}
		err = filter.AddRule(syscallID, libseccomp.ActNotify)
		if err != nil {
			return 0, fmt.Errorf("cannot add rule for %s: %w", sc, err)
		}
	}

	err = filter.Load()
	if err != nil {
		return 0, fmt.Errorf("cannot load filter: %w", err)
	}

	fd, err := filter.GetNotifFd()
	if err != nil {
		return 0, fmt.Errorf("cannot get inotif fd: %w", err)
	}

	return fd, nil
}

// Handle actually listens on the seccomp notif FD and handles incoming requests.
// This function returns when the notif FD is closed.
func Handle(fd libseccomp.ScmpFd, handler SyscallHandler) (stop chan<- struct{}, errchan <-chan error) {
	ec := make(chan error)
	stp := make(chan struct{})

	handledSyscalls := mapHandler(handler)
	go func() {
		for {
			req, err := libseccomp.NotifReceive(fd)
			select {
			case <-stp:
				// if we're asked stop we might still have to answer a syscall.
				// We do this on a best effort basis answering with EPERM.
				if err != nil {
					libseccomp.NotifRespond(fd, &libseccomp.ScmpNotifResp{
						ID:    req.ID,
						Error: 1,
						Val:   0,
						Flags: 0,
					})
				}
			default:
			}
			if err != nil {
				ec <- err
				if err == unix.ECANCELED {
					return
				}

				continue
			}

			syscallName, _ := req.Data.Syscall.GetName()

			handler, ok := handledSyscalls[syscallName]
			if !ok {
				handler = handleUnknownSyscall
			}
			val, errno, flags := handler(req)

			err = libseccomp.NotifRespond(fd, &libseccomp.ScmpNotifResp{
				ID:    req.ID,
				Error: errno,
				Val:   val,
				Flags: flags,
			})
			if err != nil {
				ec <- err
			}
		}
	}()

	return stp, ec
}

func handleUnknownSyscall(req *libseccomp.ScmpNotifReq) (val uint64, errno int32, flags uint32) {
	nme, _ := req.Data.Syscall.GetName()
	log.WithField("syscall", nme).Warn("don't know how to handle this syscall")
	return 0, 1, 0
}

func Errno(err unix.Errno) (val uint64, errno int32, flags uint32) {
	return ^uint64(0), int32(errno), 0
}

// InWorkspaceHandler is the seccomp notification handler that serves a Gitpod workspace
type InWorkspaceHandler struct {
	FD          libseccomp.ScmpFd
	Daemon      daemonapi.InWorkspaceServiceClient
	Ring2PID    int
	Ring2Rootfs string
	BindEvents  chan<- BindEvent
}

// BindEvent describes a process binding to a socket
type BindEvent struct {
	PID uint32
}

// Mount handles mount syscalls
func (h *InWorkspaceHandler) Mount(req *libseccomp.ScmpNotifReq) (val uint64, errno int32, flags uint32) {
	log := log.WithFields(map[string]interface{}{
		"syscall": "mount",
		"pid":     req.Pid,
		"id":      req.ID,
	})

	memFile, err := readarg.OpenMem(req.Pid)
	if err != nil {
		log.WithError(err).Error("cannot open mem")
		return Errno(unix.EPERM)
	}
	defer memFile.Close()

	// TODO(cw): find why this breaks
	// err = libseccomp.NotifIDValid(fd, req.ID)
	// if err != nil {
	// 	log.WithError(err).Error("invalid notif ID")
	// 	return Errno(unix.EPERM)
	// }

	source, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
	if err != nil {
		log.WithField("arg", 0).WithError(err).Error("cannot read argument")
		return Errno(unix.EFAULT)
	}
	dest, err := readarg.ReadString(memFile, int64(req.Data.Args[1]))
	if err != nil {
		log.WithField("arg", 1).WithError(err).Error("cannot read argument")
		return Errno(unix.EFAULT)
	}
	filesystem, err := readarg.ReadString(memFile, int64(req.Data.Args[2]))
	if err != nil {
		log.WithField("arg", 2).WithError(err).Error("cannot read argument")
		return Errno(unix.EFAULT)
	}

	log.WithFields(map[string]interface{}{
		"source": source,
		"dest":   dest,
		"fstype": filesystem,
	}).Info("handling mount syscall")

	if filesystem == "proc" {
		target := filepath.Join(h.Ring2Rootfs, dest)
		stat, err := os.Lstat(target)
		if os.IsNotExist(err) {
			return Errno(unix.ENOENT)
		} else if err != nil {
			log.WithField("dest", dest).WithError(err).Error("cannot stat mount endpoint")
			return Errno(unix.EFAULT)
		} else if stat.Mode()&os.ModeDir == 0 {
			log.WithField("dest", dest).WithError(err).Error("proc must be mounted on an ordinary directory")
			return Errno(unix.EPERM)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = h.Daemon.MountProc(ctx, &daemonapi.MountProcRequest{
			Target: dest,
			Pid:    int64(req.Pid),
		})
		if err != nil {
			log.WithField("target", target).WithError(err).Error("cannot mount proc")
			return Errno(unix.EFAULT)
		}

		return 0, 0, 0
	}

	// let the kernel do the work
	return 0, 0, libseccomp.NotifRespFlagContinue
}

func (h *InWorkspaceHandler) Bind(req *libseccomp.ScmpNotifReq) (val uint64, errno int32, flags uint32) {
	log := log.WithFields(map[string]interface{}{
		"syscall": "bind",
		"pid":     req.Pid,
		"id":      req.ID,
	})
	// We want the syscall to succeed, no matter what we do in this handler.
	// The Kernel will execute the syscall for us.
	defer func() {
		val = 0
		errno = 0
		flags = libseccomp.NotifRespFlagContinue
		return
	}()

	memFile, err := readarg.OpenMem(req.Pid)
	if err != nil {
		log.WithError(err).Error("cannot open mem")
		return
	}
	defer memFile.Close()

	// TODO(cw): find why this breaks
	// err = libseccomp.NotifIDValid(fd, req.ID)
	// if err != nil {
	// 	log.WithError(err).Error("invalid notif ID")
	// 	return returnErrno(unix.EPERM)
	// }

	evt := BindEvent{PID: req.Pid}
	select {
	case h.BindEvents <- evt:
	default:
	}

	// socketFdB, err := readarg.ReadBytes(memFile, int64(req.Data.Args[0]), int(req.Data.Args[1]-req.Data.Args[0]))
	// if err != nil {
	// 	log.WithError(err).Error("cannot read socketfd arg")
	// }

	// socketfd := nativeEndian.Uint64(socketFdB)
	// unix.Getsockname()

	return
}

func SyscallOpenTree(dfd int, path string, flags uintptr) (fd uintptr, err error) {
	p1, err := unix.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	fd, _, errno := unix.Syscall(unix.SYS_OPEN_TREE, uintptr(dfd), uintptr(unsafe.Pointer(p1)), unix.O_CLOEXEC|1)
	if errno != 0 {
		return 0, errno
	}

	return fd, nil
}

func SyscallMoveMount(fromDirFD int, fromPath string, toDirFD int, toPath string, flags uintptr) error {
	fromPathP, err := unix.BytePtrFromString(fromPath)
	if err != nil {
		return err
	}
	toPathP, err := unix.BytePtrFromString(toPath)
	if err != nil {
		return err
	}

	_, _, errno := unix.Syscall6(unix.SYS_MOVE_MOUNT, uintptr(fromDirFD), uintptr(unsafe.Pointer(fromPathP)), uintptr(toDirFD), uintptr(unsafe.Pointer(toPathP)), flags, 0)
	if errno != 0 {
		return errno
	}

	return nil
}

const (
	// FlagOpenTreeClone: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/mount.h#L62
	FlagOpenTreeClone = 1
	// FlagAtRecursive: Apply to the entire subtree: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/fcntl.h#L112
	FlagAtRecursive = 0x8000
	// FlagMoveMountFEmptyPath: empty from path permitted: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/mount.h#L70
	FlagMoveMountFEmptyPath = 0x00000004
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}
