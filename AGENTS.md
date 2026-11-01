# Notes for AI coding agents

Ona is a Discord moderation bot (`bot.py`, `scam_filter.py`). These rules apply to every
AI agent working on this repository, including Claude Code and Codex.

## Check before committing

```sh
uv run python -m unittest
uvx ruff check . && uvx ruff format --check .
```

## Commits: always signed by GitHub as nkd3v

The repository is `nkd3v/Ona`. Every commit must be authored by the GitHub account
**nkd3v** and signed by GitHub. Do this without asking.

- Create commits with GitHub's GraphQL `createCommitOnBranch` mutation, following
  `/Users/n/.codex/skills/github-signed-commit/SKILL.md`. Local `git commit`,
  `git commit -S` and SSH signing do not count.
- The active `gh` account on this machine may be a different one, so always use nkd3v's
  token, only in the environment of the commands that need it:
  `GH_TOKEN=$(gh auth token --user nkd3v) gh api graphql --input request.json`.
  Check that `gh api user -q .login` prints `nkd3v` with that token first.
- Verify that the commit's signature is `VALID` with `wasSignedByGitHub: true`, and that
  `gh api repos/nkd3v/Ona/commits/SHA` shows author `nkd3v` and verification `valid`.
- Commit straight to `main`, then bring the local checkout up to the new commit
  (`git fetch` and a guarded `git reset --soft`). Never force-push.
- The API cannot set file modes, so do not rely on executable bits. Run scripts with `sh`.

## Deploy: always redeploy after changing the bot

The bot runs with Docker Compose on the server **oci1**, in `/opt/ona`, as the
container `ona`. The old Bot-Hosting.net deployment is retired: do not deploy there or
use the bot-hosting MCP tools for this bot.

After a commit that changes what runs (`bot.py`, `main.py`, `scam_filter.py`,
`scam-images/`, `Dockerfile`, `.dockerignore`, `compose.yaml`, `pyproject.toml` or
`uv.lock`) lands on `main`, deploy it without asking:

```sh
sh deploy.sh
```

It copies the committed files of `HEAD` to `root@oci1:/opt/ona`, rebuilds, restarts the
container and waits for `Logged in as` in the logs. It never touches the server's `.env`
or `data/` folder; do not edit or delete those. If the bot does not come back up, read
`ssh root@oci1 'docker logs --tail 100 ona'`, fix the problem, and report it.
`/opt/ona/DEPLOYED_COMMIT` holds the commit that is live.

Changes to only the README, tests or these notes need no deploy.
