# Git hooks

Turn them on once per clone:

```sh
git config core.hooksPath .githooks
```

- `pre-commit` runs `scripts/check-public --staged`: gitleaks, your private deny-list and the
  forbidden-file list over what you're committing.
- `pre-push` runs `scripts/check-public`: everything, over the whole history.

The deny-list is a file of terms that must never be published, such as your own host names
and addresses. It lives outside the repository, at `~/.config/soc-thief/public-denylist.txt`
by default, or wherever `SOC_THIEF_DENYLIST` points.
