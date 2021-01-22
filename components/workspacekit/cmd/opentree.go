// Copyright (c) 2021 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package cmd

import (
	"github.com/gitpod-io/gitpod/workspacekit/pkg/seccomp"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// openTreeCmd represents the base command for all syscall handler
var openTreeCmd = &cobra.Command{
	Use:   "opentree <from> <to>",
	Short: "Calls opentree",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		fd, err := seccomp.SyscallOpenTree(unix.AT_FDCWD, args[0], unix.O_CLOEXEC|seccomp.FlagOpenTreeClone|seccomp.FlagAtRecursive)
		if err != nil {
			return err
		}
		err = seccomp.SyscallMoveMount(int(fd), "", unix.AT_FDCWD, args[1], seccomp.FlagMoveMountFEmptyPath)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(openTreeCmd)
}
