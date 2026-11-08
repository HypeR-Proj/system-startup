<!--
SPDX-FileCopyrightText: 2026 roolrz
SPDX-License-Identifier: Apache-2.0
-->

# system-startup

Finite bootstrap adoption and formal-service preparation coordinator.

Loads and validates deployment configuration, adopts the committed inventory and
prepares domain services. Parsing/planning are separate from the Native runtime adapter;
ongoing process supervision belongs to component-manager.

See the [implementation entry](src/lib.rs) and [component declaration](component.json)
for the public interfaces, build dependencies and delivered artifacts.

## Boundaries

The component manager owns the namespace commit. This coordinator cannot replace missing
capabilities with declarations or retain independent authority over the same service
lifecycle.

## Build and test

Use this checkout inside the [repo-managed workspace](https://github.com/HypeR-Proj/HypeR).
From this repository directory:

```sh
make
make test
```

An absolute `OUT=/path/to/out` selects a shared output directory. The module
entry delegates to build/system, which prepares the installed SDK and declared
dependencies. Native binaries require HypeR; host module checks cover the tests
selected by component.json. A standalone clone does not contain the workspace’s
other source repositories or Native SDK.


Completion polling retains the original operation deadline through process wait
and each management RPC. A new status query cannot renew the overall budget.
RPC encoding/protocol failures remain distinct diagnostics from Native transport
failures; timeout does not fabricate retirement or release retained owners.

Executable publication authority is retained from bootstrap but is not granted to
ordinary programs by default. A deployment must declare an object capability of
Native type `8`, export it from `bootstrap.executable-authority`, and route it
through explicit `offer`/`use` declarations to startup purpose `4`. Its operational
right is `CREATE_EXECUTABLE`; delegation rights must also exist in the actual
handoff inventory. Missing or insufficient inventory rejects the export before
ownership transfer. Publishing code does not imply permission to launch or
control another process.

Explicit realm exports may also delegate `bootstrap.task-factory`,
`bootstrap.task-group`, and `bootstrap.resource-domain`. Their configured rights
are checked against the actual inventory; no default application receives these
grants. The task-group source is the formal system group, not the retained
bootstrap group.
