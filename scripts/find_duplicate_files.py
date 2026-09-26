#!/usr/bin/env python3
"""Find duplicate regular files by size and SHA-256 digest."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable


CHUNK_SIZE = 1024 * 1024


def regular_files(root: Path) -> Iterable[tuple[Path, int]]:
    """Yield regular files without following symbolic links."""

    def report_walk_error(error: OSError) -> None:
        print(f"warning: cannot read {error.filename}: {error}", file=sys.stderr)

    for directory, directory_names, file_names in os.walk(
        root, followlinks=False, onerror=report_walk_error
    ):
        directory_names.sort()
        file_names.sort()
        for file_name in file_names:
            path = Path(directory) / file_name
            try:
                file_stat = os.lstat(path)
            except OSError as error:
                print(f"warning: cannot stat {path}: {error}", file=sys.stderr)
                continue
            if stat.S_ISREG(file_stat.st_mode):
                yield path, file_stat.st_size


def sha256_file(path: Path) -> tuple[str, int]:
    """Return a file's SHA-256 digest and the number of bytes read."""

    digest = hashlib.sha256()
    bytes_read = 0
    with path.open("rb") as file:
        while chunk := file.read(CHUNK_SIZE):
            digest.update(chunk)
            bytes_read += len(chunk)
    return digest.hexdigest(), bytes_read


def duplicate_groups(root: Path) -> list[tuple[int, str, list[Path]]]:
    """Return duplicate groups as (size, digest, paths)."""

    files_by_size: dict[int, list[Path]] = defaultdict(list)
    for path, size in regular_files(root):
        files_by_size[size].append(path)

    files_by_digest: dict[tuple[int, str], list[Path]] = defaultdict(list)
    for size, paths in files_by_size.items():
        if len(paths) < 2:
            continue
        for path in paths:
            try:
                digest, bytes_read = sha256_file(path)
            except OSError as error:
                print(f"warning: cannot hash {path}: {error}", file=sys.stderr)
                continue
            if bytes_read != size:
                print(f"warning: skipped file changed while hashing: {path}", file=sys.stderr)
                continue
            files_by_digest[(size, digest)].append(path)

    groups = [
        (size, digest, sorted(paths))
        for (size, digest), paths in files_by_digest.items()
        if len(paths) > 1
    ]
    return sorted(groups, key=lambda group: (-group[0], group[1], group[2]))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Find regular files with identical size and SHA-256 content. "
            "Symlinks are skipped."
        )
    )
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path("/home/navid/Documents"),
        help="directory to scan (default: /home/navid/Documents)",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="prompt before deleting duplicates in each group",
    )
    parser.add_argument(
        "-y",
        "--force",
        action="store_true",
        help="delete duplicates without prompting (implies --delete)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.expanduser().resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    groups = duplicate_groups(root)
    if not groups:
        print(f"No duplicate files found under {root}")
        return 0

    deletion_requested = args.delete or args.force
    if args.force:
        print("Force mode enabled: duplicate files will be deleted without prompting.")

    removed = 0
    failed = 0
    for index, (size, digest, paths) in enumerate(groups, start=1):
        print()
        print(f"=== DUPLICATE GROUP {index}/{len(groups)} ===")
        print(f"All {len(paths)} files have the same size and SHA-256 content.")
        print(f"SIZE   {size} bytes")
        print(f"SHA256 {digest}")
        print(f"KEEP   {paths[0]}")
        for candidate_index, path in enumerate(paths[1:], start=1):
            print(f"DUPLICATE {candidate_index}: {path}")

        if not deletion_requested:
            print()
            continue

        if not args.force:
            try:
                answer = input(
                    f"Delete the {len(paths) - 1} duplicate file(s) shown above? [y/N] "
                )
            except EOFError:
                answer = ""
                print("\nNo answer received; skipping this group.")
            except KeyboardInterrupt:
                print("\nInterrupted; no further groups will be processed.")
                return 130

            if answer.strip().lower() not in {"y", "yes"}:
                print("  SKIPPED")
                print()
                continue

        for path in paths[1:]:

            try:
                file_stat = os.lstat(path)
                if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size != size:
                    raise OSError("file changed since the scan")
                current_digest, bytes_read = sha256_file(path)
                if bytes_read != size or current_digest != digest:
                    raise OSError("file contents changed since the scan")
                path.unlink()
            except OSError as error:
                failed += 1
                print(f"  FAILED {path}: {error}", file=sys.stderr)
                continue
            removed += 1
            print(f"  REMOVED {path}")
        print()
    if deletion_requested:
        print(
            f"Found {len(groups)} duplicate group(s); removed {removed} file(s), "
            f"{failed} failure(s)."
        )
        return 1 if failed else 0

    print(
        f"Found {len(groups)} duplicate group(s). Dry run only; "
        "nothing was removed. Re-run with --delete to review each group, "
        "or --force to delete without prompting."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
