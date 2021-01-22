// Copyright (c) 2021 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package cmd

import (
	"github.com/gitpod-io/gitpod/common-go/log"
	"github.com/gitpod-io/gitpod/workspacekit/pkg/seccomp"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var handlerMoveMountOpts struct {
	FD   int
	Dest string
}

// handlerCmd represents the base command for all syscall handler
var handlerMoveMountCmd = &cobra.Command{
	Use:   "move-mount",
	Short: "calls move_mount in a workspace",
	Run: func(cmd *cobra.Command, args []string) {
		err := seccomp.SyscallMoveMount(handlerMoveMountOpts.FD, "", unix.AT_FDCWD, handlerMoveMountOpts.Dest, seccomp.FlagMoveMountFEmptyPath)
		if err != nil {
			log.WithError(err).Fatal("cannot move mount")
		}
	},
}

func init() {
	handlerCmd.AddCommand(handlerMoveMountCmd)

	handlerMoveMountCmd.Flags().StringVar(&handlerMoveMountOpts.Dest, "dest", "", "destination for the mount")
	handlerMoveMountCmd.Flags().IntVar(&handlerMoveMountOpts.FD, "fd", 3, "from fd")
}
