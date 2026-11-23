"""Expose selected JM management actions through the authenticated WebUI bridge."""
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
import asyncio
import secrets
import time

import httpx


class AdminRequestError(RuntimeError):
    def __init__(self, message: str, *, expired: bool = False) -> None:
        super().__init__(message)
        self.expired = expired

    def response(self) -> dict[str, Any]:
        return {"ok": False, "message": str(self), "expired": self.expired}


@dataclass(frozen=True)
class AdminSession:
    cookie: str
    csrf: str
    expires: float


class JMWebUIAdmin:
    def __init__(
        self, port: int, qq_action: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]
    ) -> None:
        self.base_url = f"http://127.0.0.1:{port}"
        self._sessions: dict[str, AdminSession] = {}
        self._qq_action = qq_action

    def _client(self, session: str | None = None) -> httpx.AsyncClient:
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        if session is not None:
            entry = self._sessions.get(session)
            if entry is None or entry.expires <= time.monotonic():
                self._sessions.pop(session, None)
                raise AdminRequestError("后台登录已过期，请重新登录。", expired=True)
            cookies = {"jmbot_session": entry.cookie, "jmbot_csrf": entry.csrf}
            headers = {"x-csrf-token": entry.csrf}
        return httpx.AsyncClient(
            base_url=self.base_url, timeout=5, trust_env=False, cookies=cookies, headers=headers
        )

    async def _send(
        self, client: httpx.AsyncClient, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> Any:
        try:
            response = await client.request(method, path, json=payload)
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AdminRequestError("JM 管理服务暂不可用，请检查插件和管理端口。") from exc
        if not response.is_success:
            details = body.get("detail") if isinstance(body, dict) else None
            message = details if isinstance(details, str) else "JM 管理服务拒绝了这次操作。"
            raise AdminRequestError(
                message[:420], expired=response.status_code == 401 and path != "/api/login"
            )
        return body

    @staticmethod
    def _parse_qq(value: str) -> int:
        if not value.isascii() or not value.isdecimal() or not 1 <= int(value) < 2**63:
            raise AdminRequestError("请输入有效的 QQ 号或群号。")
        return int(value)

    async def login(self, qq_id: str, password: str) -> dict[str, Any]:
        try:
            async with self._client() as client:
                body = await self._send(
                    client, "POST", "/api/login",
                    {"qq_id": self._parse_qq(qq_id), "password": password},
                )
                cookie = client.cookies.get("jmbot_session")
                csrf = client.cookies.get("jmbot_csrf")
                if not cookie or not csrf:
                    raise AdminRequestError("JM 管理后台未返回有效的登录会话。")
        except AdminRequestError as exc:
            return exc.response()
        now = time.monotonic()
        self._sessions = {key: value for key, value in self._sessions.items() if value.expires > now}
        session = secrets.token_urlsafe(32)
        self._sessions[session] = AdminSession(cookie, csrf, now + 3600)
        return {"ok": True, "session": session, "qq_id": str(body["qq_id"])}

    async def logout(self, session: str) -> dict[str, Any]:
        try:
            return await self.request(session, "POST", "/api/logout")
        finally:
            self._sessions.pop(session, None)

    async def request(
        self, session: str, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            async with self._client(session) as client:
                return await self._send(client, method, path, payload)
        except AdminRequestError as exc:
            if exc.expired:
                self._sessions.pop(session, None)
            return exc.response()

    async def overview(
        self, session: str, *, connected: bool, include_names: bool
    ) -> dict[str, Any]:
        try:
            async with self._client(session) as client:
                queue, scopes, settings, actions = await asyncio.gather(
                    self._send(client, "GET", "/api/download/queue"),
                    self._send(client, "GET", "/api/download/scopes"),
                    self._send(client, "GET", "/api/policies/global"),
                    self._send(client, "GET", "/api/download/actions"),
                )
        except AdminRequestError as exc:
            if exc.expired:
                self._sessions.pop(session, None)
            return exc.response()
        visible_scopes = scopes[:1000]
        destinations = {row["scope_key"] for row in visible_scopes}
        tasks = []
        for row in queue:
            scope = row["destination_type"]
            owner = row["group_id"] if scope == "group" else row["user_id"]
            key = f"{scope}:{owner}"
            destinations.add(key)
            tasks.append({
                "id": row["id"], "album_id": row["album_id"], "target": key,
                "status": row["status"], "stage": row["stage"],
                "format": row["output_format"], "updated_at": row["updated_at"],
                "current": row["progress_current"], "total": row["progress_total"],
                "error": (row["error"] or "")[:340],
            })
        result = {
            "ok": True, "connected": connected, "enabled": settings["download"],
            "queue": tasks, "scopes": visible_scopes, "scope_count": len(scopes),
            "actions": [
                {"id": row["id"], "status": row["status"], "error": str(row.get("error") or "")[:240]}
                for row in actions[:30]
            ],
        }
        if include_names:
            result["names"] = await self._names(destinations)
        return result

    async def _names(self, destinations: set[str]) -> dict[str, str]:
        async def fetch(kind: str, action: str, id_key: str, name_key: str) -> dict[str, str]:
            if not any(key.startswith(kind + ":") for key in destinations):
                return {}
            try:
                async with asyncio.timeout(1.5):
                    result = await self._qq_action(action, {})
            except (TimeoutError, OSError, RuntimeError):
                return {}
            rows = result.get("data")
            if not isinstance(rows, list):
                return {}
            output = {}
            for row in rows:
                key = f"{kind}:{row.get(id_key)}"
                name = str(row.get("remark") or row.get(name_key) or "").strip()
                if key in destinations and name:
                    output[key] = name[:100]
            return output

        group_names, friend_names = await asyncio.gather(
            fetch("group", "get_group_list", "group_id", "group_name"),
            fetch("private", "get_friend_list", "user_id", "nickname"),
        )
        return group_names | friend_names

    async def scope(
        self, session: str, kind: str, owner_id: str, field: str, enabled: bool
    ) -> dict[str, Any]:
        if kind not in {"group", "private"} or field not in {"download_enabled", "download_blacklisted"}:
            return AdminRequestError("会话权限参数无效。").response()
        try:
            owner = self._parse_qq(owner_id)
        except AdminRequestError as exc:
            return exc.response()
        return await self.request(
            session, "PATCH", f"/api/scopes/{kind}/{owner}/policy", {field: enabled}
        )

    async def queue_action(self, session: str, operation: str, job_id: int) -> dict[str, Any]:
        operations = {"priority": ("POST", "priority"), "cancel": ("POST", "cancel"),
                      "delete_failed": ("DELETE", "failed")}
        if operation not in operations or not 1 <= job_id < 2**63:
            return AdminRequestError("下载任务参数无效。").response()
        method, suffix = operations[operation]
        return await self.request(session, method, f"/api/download/queue/{job_id}/{suffix}")
