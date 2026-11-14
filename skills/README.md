# Keyspout operator skills

Agent skills that drive `ksp`. Each one is a folder with a `SKILL.md` in it, in
the [agentskills.io](https://agentskills.io) open format, which Claude Code,
GitHub Copilot, Cursor, OpenAI Codex and Gemini CLI all read natively.

The skills are instructions, not scripts. Every step is a `ksp` invocation, and
each skill ends by composing a report from `ksp`'s own output rather than from
the agent's memory of what it ran.

## Install

```bash
npx skills add bruj0/keyspout
```

That installs every skill in this directory for the agents it detects. To pick
one:

```bash
npx skills add bruj0/keyspout --skill keyspout-quickstart
```

`npx skills` needs Node 22.20 or later. It keeps one canonical copy under
`~/.agents/skills/` and symlinks it into each agent's own directory.

### Verify the install

The CLI can report success and still leave an agent unable to see the skill: it
symlinks into `~/.claude/skills/` for Claude Code, and there are open issues
where the symlink is never created. Check rather than trust the exit code.

```bash
npx skills list -g                          # what the CLI thinks is installed
ls ~/.agents/skills/keyspout-quickstart/SKILL.md   # the canonical copy exists
ls -la ~/.claude/skills/keyspout-quickstart        # -> ../../.agents/skills/...
```

If the last command reports no such file and you use Claude Code, install through
its own plugin system instead:

```
/plugin marketplace add bruj0/keyspout
```

### Install by hand

Any agent that follows the SKILL.md standard can use a copy. There is nothing to
build.

```bash
git clone https://github.com/bruj0/keyspout
cp -r keyspout/skills/keyspout-* ~/.agents/skills/     # every project
cp -r keyspout/skills/keyspout-* .agents/skills/       # this project only
```

Point the agent at whichever directory it reads: `.agents/skills/` for Codex,
Gemini CLI and OpenCode, `.claude/skills/` for Claude Code, `.cursor/skills/` for
Cursor.

## Prerequisites

The skills drive a `ksp` binary. Install it first:

```bash
brew install bruj0/tap/ksp
```

See the [main README](../README.md) for the other platforms.

## What a skill may not contain

Two checks enforce this, and they run at different times on purpose.

`scripts/ksp-skills.sh` fails when a skill names a `ksp` subcommand the binary
does not have, when its frontmatter `name` disagrees with its folder, or when the
folder is not kebab-case. It runs in the gate, against the built binary.

`crates/ksp-cli/tests/skills_public.rs` fails when a skill names something the
public tree does not carry. It reads its marker list from the sync's own
configuration, so the commit-time check and the publish-time scrub cannot drift
apart.

- an internal path, a design-spec citation or an absolute path on the author's
  machine
- a claim the design specification does not make — no "erases", no "guarantees",
  no deletion deadline
- a password, a key or a fingerprint copied from a real deployment

## The skills

| Skill | Answers |
|---|---|
| `keyspout-quickstart` | "Set up Keyspout for me, single operator, sane defaults" |
| `keyspout-status` | "What is my status right now?" |
| `keyspout-secrets` | "Store, read, list and remove secrets" |
| `keyspout-agents` | "Enrol an agent, grant it a secret, share it, run it" |
| `keyspout-backends` | "Use Valkey instead of a directory", "test a lease", "arm a sweep" |
| `keyspout-recovery` | "Recover the sealed bundle from shares" |
| `keyspout-audit` | "What happened, and can I verify the chain?" |
