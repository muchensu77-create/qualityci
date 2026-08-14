from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

import pytest


@pytest.fixture
def make_symlink_or_skip() -> Callable[..., None]:
    """Create a symlink or skip only for the precise Windows privilege gap."""

    def create(
        link: Path,
        target: Path,
        *,
        target_is_directory: bool = False,
    ) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except OSError as error:
            if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                reason = (
                    "directory symlinks are not available on this filesystem"
                    if target_is_directory
                    else "symlinks are not available on this filesystem"
                )
                pytest.skip(reason)
            raise

    return create
