// Copyright (c) 2021 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package main

import (
	"os"

	"github.com/gitpod-io/gitpod/common-go/log"
	_ "github.com/gitpod-io/gitpod/workspacekit/pkg/nsenter"
	"github.com/gitpod-io/gitpod/workspacekit/pkg/seccomp"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("destination path missing")
	}

	err := seccomp.SyscallMoveMount(3, "", unix.AT_FDCWD, os.Args[1], seccomp.FlagMoveMountFEmptyPath)
	if err != nil {
		log.WithError(err).Fatal()
	}
}
