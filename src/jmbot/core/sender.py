from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class ApiBot(Protocol):
    """Subset of the NoneBot Bot API used by this module."""

    async def call_api(self, action: str, **params: Any) -> Any: ...


async def upload_group_pdf(bot: ApiBot, group_id: int, file_path: str | Path, folder_name: str) -> None:
    """Upload a QQ group file to the named folder if present, or to the root."""

    path = Path(file_path)
    folder_id = await _find_group_folder(bot, group_id, folder_name)
    await bot.call_api(
        "upload_group_file",
        group_id=group_id,
        file=path.resolve().as_uri(),
        name=path.name,
        folder=folder_id or "/",
    )


async def upload_private_pdf(bot: ApiBot, user_id: int, file_path: str | Path) -> None:
    """Upload the generated PDF to a QQ friend private chat."""

    path = Path(file_path)
    await bot.call_api(
        "upload_private_file",
        user_id=user_id,
        file=path.resolve().as_uri(),
        name=path.name,
    )


async def send_group_image(bot: ApiBot, group_id: int, file_path: str | Path) -> None:
    """Send a local image directly into a QQ group message."""

    path = _require_file(file_path)
    await bot.call_api(
        "send_group_msg",
        group_id=group_id,
        message=[{"type": "image", "data": {"file": path.resolve().as_uri()}}],
    )


async def send_private_image(bot: ApiBot, user_id: int, file_path: str | Path) -> None:
    """Send a local image directly into a QQ private message."""

    path = _require_file(file_path)
    await bot.call_api(
        "send_private_msg",
        user_id=user_id,
        message=[{"type": "image", "data": {"file": path.resolve().as_uri()}}],
    )


async def _find_group_folder(bot: ApiBot, group_id: int, folder_name: str) -> str | None:
    """Find a QQ group file folder by name from the root folder list."""

    root_files = await bot.call_api("get_group_root_files", group_id=group_id)
    folders = root_files.get("folders", []) if isinstance(root_files, dict) else []

    for folder in folders:
        if not isinstance(folder, dict):
            continue

        current_name = folder.get("folder_name") or folder.get("name")
        folder_id = folder.get("folder_id") or folder.get("id")
        if current_name == folder_name and folder_id:
            return str(folder_id)

    return None


def _require_file(file_path: str | Path) -> Path:
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File does not exist: {path}")
    return path
