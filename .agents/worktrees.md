# Worktree Rules

## Required Location

Keep every linked worktree for this repository, except the primary checkout,
under the primary checkout's `worktrees/` directory. Use this shape:

```text
<repository-root>/worktrees/<task-name>
```

Do not create a linked worktree in `/tmp`, a home-directory tool folder, a
sibling repository directory, or another global worktree directory.

Temporary test state and retained evidence can use an owned directory outside
the repository. A linked worktree cannot use that exception.

## Create A Worktree

Run the worktree command from the primary checkout. Use a short task name and
an explicit branch name.

```sh
git worktree add worktrees/<task-name> -b <branch-name>
```

Before you edit, run these commands in the new worktree:

```sh
git rev-parse --show-toplevel
git status --short --branch
git worktree list --porcelain
```

The top-level path must be under `<repository-root>/worktrees/`. The branch
must be the intended task branch. Record or resolve any pre-existing change
before you edit.

## Relocate An Existing Worktree

Use Git to move a clean linked worktree that is outside the required
directory. Do not copy the directory or move it with a filesystem command.

```sh
git worktree move <old-path> worktrees/<task-name>
```

Run the three verification commands again after the move. Confirm that the old
path is absent and the new worktree is clean.

## Repository Boundary

The root `.gitignore` excludes `worktrees/`. Never stage a linked worktree as
repository content. A worktree can contain its own branch changes, but it must
not change the primary checkout's tracked files by filesystem nesting.

Do not remove or relocate the primary checkout. Do not remove a linked
worktree that has uncommitted changes. Use `git worktree remove` only when the
task explicitly includes cleanup and the target path is exact.
