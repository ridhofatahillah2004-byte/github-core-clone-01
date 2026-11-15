# forge — a standalone GitHub-compatible git forge

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/ridhofatahillah2004-byte/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/ridhofatahillah2004-byte/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

One process, Node 22 stdlib only, no git binary, no outside service, no UI.
It serves a GitHub-compatible git forge from its own in-memory object store:

- **git smart HTTP** — upload-pack protocol v2 (ls-refs + fetch, shallow),
  upload-pack v0 fallback, receive-pack v0 (report-status, side-band-64k,
  delete-refs, fast-forward enforcement)
- **REST v3** — repos, issues, labels, comments, pull requests, contents,
  branches, commits, git refs, merge (squash, 3-way)
- **GraphQL v4** — repository/issues/pullRequests, viewer, node,
  createIssue, closeIssue, addComment, createPullRequest,
  mergePullRequest, introspection (incl. SearchType enum values), batched
  operations, cursor pagination
- **MCP** — Streamable HTTP JSON-RPC 2.0, 6 tools (create_repo, get_repo,
  create_issue, list_issues, create_pull_request, merge_pull_request)

State is deterministic: a logical clock (seeded by `MAKEFUN_TRIAL_NOW`)
drives every timestamp, so replaying the same trial leaves byte-identical
state. Auth is `Bearer $MAKEFUN_SHOP_TOKEN` on every surface except
`/healthz`. The forge is single-tenant: the token names one login, learned
from the first owner-scoped request; any other owner answers 404.

## Run

```sh
MAKEFUN_SHOP_TOKEN=<token> node main.ts
```

Binds port 0, registers the port at `$MAKEFUN_ENV_URL/register`, then
long-polls `$MAKEFUN_ENV_URL/done` (re-polling on `{"done": false}`) and
exits 0 when it answers `{"done": true}`. Without `MAKEFUN_ENV_URL` it
just serves until killed.

## License

MIT — Copyright (c) 2026 Ridho Fatahillah
