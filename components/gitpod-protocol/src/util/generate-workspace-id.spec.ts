/**
 * Copyright (c) 2020 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License-AGPL.txt in the project root for license information.
 */

import { suite, test } from "mocha-typescript"
import * as chai from "chai"
import { generateWorkspaceID } from "./generate-workspace-id";
import { workspaceIDRegex } from "./gitpod-host-url";

const expect = chai.expect

@suite class TestGitpodFileParser {

    @test public testGenerateName() {
        for (let i = 0; i < 100000; i++) {
            const name = generateWorkspaceID();
            expect(workspaceIDRegex.test(name), name).to.be.true;
        }
    }

}
module.exports = new TestGitpodFileParser()   // Only to circumvent no usage warning :-/
