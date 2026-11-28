# The `bw` adapter, measured

What this repository knows about Bitwarden's CLI because it ran it, rather than
because a document said so. Every number here was measured on the machine that runs
the gated half of the test suite.

## The measured state

Measured 2026-11-28, on the operator's host:

```
$ bw --version
2026.10.0

$ bw status                        # no session in the environment
{"serverUrl":"https://bitwarden.bruj0.net",
 "userEmail":"ramakandra@gmail.com",
 "userId":"f2d73977-f689-4fa7-9bee-c5361c6be37a",
 "lastSync":"2026-11-27T21:06:16.219Z",
 "status":"locked"}

$ bw status                        # with BW_SESSION exported
{"…","status":"unlocked"}

$ bw list items --raw              # with BW_SESSION exported
1307 items
```

`bw` is at `/opt/homebrew/bin/bw` and points at a **self-hosted Vaultwarden**, not
bitwarden.com.

### `locked`, not `unauthenticated`

An earlier measurement of the same host recorded `"status":"unauthenticated"` for a
session-less `bw status`. It now reports `locked`, with `userEmail` and `userId`
present, because the account is logged in and only the vault is locked.

The two states need different repairs — `bw login` when unauthenticated, `bw unlock`
when locked — so a refusal that named one would send half its readers to a command
that cannot help. The shipped refusal names `bw unlock` first because that is the
state this host is actually in, and it names `BW_SESSION` because that is where the
session goes.

## Output shapes, and why the declaration has two

| Command | Returns |
|---|---|
| `bw list items --raw` | a JSON **array** |
| `bw get item <id>` | a JSON **object** |
| `bw get password <id>` | a raw string, not JSON |

`integrations/bitwarden.toml` therefore names `shape = "json_array"` on `[ops.list]`
and `shape = "json"` on `[ops.read]`. The two are separate values rather than one
permissive shape, because a `read` that started returning an array is a vendor change
worth refusing rather than a value to parse.

This was found by running the tool: the adapter contract as first written had one
`json` shape meaning object, and the real `list` could not satisfy it. Raised as
CF-145 and corrected in `ksp` rather than worked around here.

## Real edge cases a declaration must survive

Measured from the 1307 items:

```
types: {1: 1263, 2: 36, 5: 5, 3: 3}
```

- **`type: 5` items have no `login` at all** — they are SSH keys, and their key
  material is under `sshKey`. A `read` whose `extract` is `login.password` misses on
  these. A miss must **refuse**, naming the item and the missing path, rather than
  return an empty value: an empty password imports as a secret with no content, and
  nothing downstream can tell it from a real one.
- **Item names are not unique, and one here is literally `--`.** A declaration that
  keys on a name is wrong. `{key}` is an item **id** (a UUID); a name search works
  because `bw` accepts a search term wherever it accepts an id, but only the id makes
  a report trustworthy.

## Running the gated half

```bash
# One-time, and again after any `bw lock`:
bw login --apikey                    # or: bw login <email>
export BW_SESSION="$(bw unlock --raw)"

# The gated half, in addition to the ordinary gate:
KSP_TEST_BW=1 bash scripts/ksp-gate.sh host < /dev/null
```

`login --apikey` alone is **not** enough: it authenticates the account and leaves the
vault locked, so every read fails. Unlock is the step that produces a session.

Without `KSP_TEST_BW=1` the round trip skips and prints why. With `KSP_TEST_BW=1` and
no usable session it **fails**: a gate that skips when it was asked to run reports a
green result for a test that did not happen.

### The vault is real, so the test creates its own item

The round trip runs `bw get template item`, populates a login item, `bw encode`s it,
`bw create item`s it, imports it by the id that returned, compares the value, and
deletes it. A failed delete fails the test.

A test that read one of the 1307 existing items would assert a fact about the
operator's data rather than about this code, and would fail the day a password is
rotated.

## The session never enters the repository

It reaches `bw` through the **environment**, never `argv`: `--session <key>` puts the
key in `ps`, where every user on the host can read it. Two tests enforce that
mechanically rather than by review —

- one greps `crates/ksp/tests`, `integrations/` and the feature documents for a
  session-shaped string;
- one greps the test sources for the argument form, with comments stripped so the
  rule does not flag its own explanation.

## Vaultwarden, and why this is `bw` rather than `bws`

Vaultwarden does not ship Secrets Manager. Its maintainers declined because that code
is commercially licensed
([discussion](https://github.com/dani-garcia/vaultwarden/discussions/3368)), so `bws`
is not an option against a Vaultwarden server and `bw` with a master-password unlock
is the only path. Against bitwarden.com both exist, and a `kind = "cli"` declaration
naming `bws` would work there without a code change.
