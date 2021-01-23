// Copyright (c) 2020 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package util_test

import (
	"fmt"
	"testing"

	"github.com/gitpod-io/gitpod/common-go/util"
)

func TestGenerateWorkspaceID(t *testing.T) {

	t.Run(fmt.Sprintf("check names are valid"), func(t *testing.T) {
		for i := 0; i < 10000; i++ {
			name := util.GenerateWorkspaceID()

			if !util.WorkspaceIdPattern.MatchString(name) {
				t.Errorf("The workspace id \"%s\" didn't met the expectation.", name)
			}
		}
	})
}
