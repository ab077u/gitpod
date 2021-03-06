#!/bin/bash
# Copyright (c) 2020 Gitpod GmbH. All rights reserved.
# Licensed under the GNU Affero General Public License (AGPL).
# See License-AGPL.txt in the project root for license information.


# 1. At this point we'll have copied Theia to the node. We must mark the node with the Theia label so that workspaces get scheduled to it.
for i in $(seq 1 10); do
    if kubectl get node $EXECUTING_NODE_NAME -o template='{{ range $k, $v := .metadata.labels}}{{ $k }}{{"\n"}}{{ end }}' | grep -q "gitpod.io/theia.$VERSION"; then
        echo "Theia (version $VERSION) is already available - node is marked"
        break
    fi

    if kubectl patch node $EXECUTING_NODE_NAME --patch '{"metadata":{"labels":{"gitpod.io/theia.'$VERSION'": "available"}}}'; then
        echo "Theia (version $VERSION) became available - we've marked the node"
        break
    fi

    if [ $i -eq 10 ]; then
        echo "Theia (version $VERSION) became available BUT we've failed to mark the node (attempt $i/10)"
        echo "will not retry - failing"
        exit -1
    fi

    echo "Theia (version $VERSION) became available BUT we've failed to mark the node (attempt $i/10)"
    sleep 1
done

# There's nothing left for us to do, but we mustn't exit either. Let's loop a little.
while true; do
    sleep 5m
done
