# Contributing to registry-token-service

Thank you for looking. registry-token-service is part of [Meddleware](https://meddleware.co.uk): open tools you can use, take everything when you leave,
and run yourself. This file says how to build it, test it and propose a change.

## Build and test

```bash
go build ./...                         # the binary compiles
go vet ./...                           # static analysis, clean before any commit
go test -race ./...                    # the suite: the token flow against fake Hydra and Keto, scope parsing, configuration, the signing key
golangci-lint run ./...                # the lint CI runs (golangci-lint v2; the revive documentation rules are in .golangci.yml)
sh scripts/check-image-notices.sh      # builds the image and checks it ships the licence notices (CONTAINER_CLI=podman for rootless podman)
```

CI runs the same commands on every push and pull request (`.github/workflows/`). A change is ready when they all pass locally.

## Proposing a change

1. Open an issue first for anything larger than a fix, so the design can be agreed before the work.
2. Keep a change to one purpose. Write a short subject line in the imperative ("Fix the relay timeout"), and say why in the pull request.
3. Add or update tests with the behaviour they cover. A bug fix comes with a test that failed before it.
4. Add a line to `CHANGELOG.md` under `Unreleased`.
5. Security problems go to the address in [`SECURITY.md`](SECURITY.md), never to a public issue.

## House rules

- **Licence.** Everything here is [0BSD](LICENSE). By contributing you agree your contribution is released under it.
- **Versions.** Until the platform's mainnet launch, every release is a patch bump, breaking changes included; the changelog says what broke.
- **No secrets, no personal data** in code, tests, fixtures, comments or commit messages.
- **Privacy.** Nothing is stored in a visitor's browser before they act, and nothing is sent to a host the project does not document. No telemetry, analytics or tracking.
- **Open standards.** Where a standard exists and fits, use it; the standards inventory in [the audit](docs/audit/registry-token-service-audit.md) (B.RFC-1) lists the ones this project speaks.

## Documentation

Every file explains itself, line by line where the code is not self-evident:

- a header on every file saying what it is for;
- a doc comment on every declaration (TSDoc, `///` in Rust and Move, Go doc comments), private ones included;
- comments that say **why**, cite the decision, issue or standard behind a choice, and are updated with the code;
- no `TODO` or `FIXME` without an issue or follow-up reference on the same line;
- every command a document shows has been run, and every link resolves.
