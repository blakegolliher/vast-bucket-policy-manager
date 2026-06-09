# vast-bucket-policy-manager

A small TUI for listing, viewing, editing, and applying S3 bucket policies on
VAST or any other S3-compatible store. It speaks plain S3, so it works against
AWS too.

Built to spare you from a vim-and-`aws s3api put-bucket-policy` workflow when
all you really want to do is fix a typo in one statement.

```
┌─Profiles────┐ ┌─Buckets (3)─┐ ┌─Policy: bucket-x  -- NORMAL -- ────────────────┐
│ • var204    │ │ bucket-x    │ │ {                                              │
│   default   │ │ bucket-y    │ │   "Version": "2012-10-17",                     │
│   prod      │ │ bucket-z    │ │   "Statement": [...]                           │
│             │ │             │ │ }                                              │
│             │ │             │ │ ✓ policy looks valid                           │
└─────────────┘ └─────────────┘ └────────────────────────────────────────────────┘
 ● connected · var204  TLS-skip ON   <status messages here>
 i edit · e $EDITOR · f format · s save · d delete · r reload · ← back · q quit
```

## Features

- **Three-pane layout**: profiles · buckets · policy editor.
- **AWS shared-config aware**: reads `~/.aws/credentials` and `~/.aws/config`,
  including VAST-style `endpoint_url` lines. Picking a profile autofills the
  endpoint and region.
- **Live validation**: JSON syntax (with line:col) plus IAM structural checks
  (`Version`, `Statement`, `Effect`, `Action`/`NotAction`, `Resource`/
  `NotResource`, `Principal`/`NotPrincipal`, `Condition`).
- **In-TUI editor or `$EDITOR` shell-out**: press `i` to edit inline, or `e`
  to drop into vim/nvim/whatever and read the result back on close.
- **Save / discard prompt** on unsaved changes — you can't accidentally
  arrow your way out of an edit.
- **Automatic backups** before every save and delete. Snapshots go to
  `~/.vast-bucket-manager/<endpoint>/<bucket>/<timestamp>-{before,after}-{save,delete}.json`
  so you always have a paper trail.
- **TLS-skip on by default** for self-signed VAST lab certs. Toggle off with
  `Ctrl+T` when pointing at real AWS.

## Build

Requires Go 1.22+.

```
go build .
```

Or run directly:

```
go run .
```

Run the tests:

```
go test ./...
```

## Layout

```
.
├── main.go                # thin entry — just calls app.Run()
├── internal/app/          # all app code (TUI, S3 client, validation, backup)
│   ├── app.go             # three-pane app model + key routing + async cmds
│   ├── editor.go          # editor sub-model (NORMAL/INSERT, validation)
│   ├── modal.go           # manual-entry modal
│   ├── panes.go           # pane rendering + styles + status/help line
│   ├── policy.go          # JSON + IAM structural validation
│   ├── s3client.go        # AWS SDK wrapper + profile discovery
│   └── backup.go          # on-disk backup writer
└── tests/                 # black-box tests against internal/app
    ├── policy_test.go
    ├── s3client_test.go
    └── backup_test.go
```

## Quick start

1. Have a profile in `~/.aws/config` and `~/.aws/credentials`:

   ```ini
   # ~/.aws/config
   [profile var204]
   region = us-east-1
   endpoint_url = https://main.selab-var204.selab.vastdata.com
   ```

   ```ini
   # ~/.aws/credentials
   [var204]
   aws_access_key_id = …
   aws_secret_access_key = …
   ```

2. Run `./vast-bucket-manager`.
3. Pick a profile in the left pane, hit `Enter`.
4. Pick a bucket in the middle pane, hit `Enter`.
5. The current policy loads in the editor. `i` to edit, `s` to save.

If you don't have a profile yet, press `n` for a manual-entry modal that
takes endpoint + access key + secret key directly.

## Keybinds

### Anywhere (when no prompt is up)

| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | Cycle panes |
| `←` / `→` | Move between panes (arrows are captured when the editor is in INSERT mode or the bucket filter is active) |
| `Ctrl+1` / `Ctrl+2` / `Ctrl+3` | Jump to Profiles / Buckets / Editor |
| `Ctrl+T` | Toggle TLS-skip (reconnects if connected) |
| `n` | Open manual-entry modal |
| `q` | Quit (with `y/N` confirm) |
| `Ctrl+C` | Hard quit, no confirm |

### Profiles pane

| Key | Action |
|---|---|
| `Enter` | Connect using the highlighted profile |

### Buckets pane

| Key | Action |
|---|---|
| `Enter` | Load that bucket's policy in the editor |
| `r` | Refresh the bucket list |
| `/` | Filter buckets |

### Editor — NORMAL mode

| Key | Action |
|---|---|
| `i` / `a` / `Enter` | Enter INSERT mode |
| `e` | Edit in `$EDITOR` (vim, nvim, …) |
| `f` | Reformat / pretty-print the JSON |
| `s` | Save (with `y/N` confirm) |
| `d` | Delete the policy (with `y/N` confirm) |
| `r` | Reload the policy from the server |
| `←` | Back to the buckets pane |

### Editor — INSERT mode

All keys go to the textarea except `Esc`. `Esc` leaves INSERT; if you have
unsaved changes you'll be asked to save or discard.

| Key | Action |
|---|---|
| `Esc` | Leave INSERT (raises unsaved-changes prompt if dirty) |

### Unsaved-changes prompt

| Key | Action |
|---|---|
| `s` | Save now and continue |
| `d` | Discard changes (reload from server) |
| `c` / `Esc` | Cancel — stay in INSERT mode |

## Validation

The validator catches:

- JSON syntax errors with line and column.
- Missing or non-string `Version`.
- Missing `Statement`, empty `Statement` array, non-object statements.
- Missing `Effect`, or `Effect` not in `Allow`/`Deny`.
- Missing both `Action` and `NotAction`, or having both.
- Missing both `Resource` and `NotResource`, or having both.
- Missing `Principal` and `NotPrincipal` (warning — required for bucket
  policies).
- Both `Principal` and `NotPrincipal` (error).
- `Condition` is not an object.
- Unknown top-level or statement keys (warning).

It does **not** currently validate action names (`s3:GetObject` vs.
`s3:NotAReal`), ARN shapes, or condition operators. A deeper linter is a
planned follow-up.

## Backups

Every save writes both the pre-change server state and the new content. Every
delete writes the pre-change server state. Layout:

```
~/.vast-bucket-manager/
  main.selab-var204.selab.vastdata.com/
    my-bucket/
      20260519-204512-before-save.json
      20260519-204512-after-save.json
      20260519-211503-before-delete.json
```

- Timestamps are UTC and sort lexically.
- Files are `0600`.
- Backups are written **before** the change is applied to the bucket. If the
  backup fails the change is aborted.

## TLS

`tlsSkip` defaults to **on**. A valid cert chain still works exactly the same;
the flag only changes what happens when verification would have failed.
Toggle off with `Ctrl+T` if you'd like to confirm a real chain.

## Limitations / planned

- IAM action and ARN linting (parliament-go-style).
- Inline syntax highlighting (the validator panel currently lives below the
  textarea — no per-character coloring).
- ETag / If-Match guard on save (someone else writing between fetch and save
  is not detected).
- No diff view between the editor buffer and the server policy.

## License

MIT — see [LICENSE](LICENSE).
