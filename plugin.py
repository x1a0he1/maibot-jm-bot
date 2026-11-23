"""Run JM-bot behind the current MaiBot OneBot adapter."""
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import url2pathname

import asyncio
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import time

import websockets
from maibot_sdk import API, Field, MaiBotPlugin, PluginConfigBase

ROOT = Path(__file__).resolve().parent
MANIFEST = json.loads((ROOT / "_manifest.json").read_text(encoding="utf-8"))
REPOSITORY = MANIFEST["urls"]["repository"]
RELEASE = MANIFEST["version"]
SOURCE_URL = f"{REPOSITORY}/tree/v{RELEASE}"
ADAPTER_ACTION = "maibot-team.snowluma-adapter.adapter.napcat.action.call"
ACTIONS = frozenset({
    "send_msg", "send_group_msg", "send_private_msg",
    "get_group_root_files", "get_group_files_by_folder", "create_group_file_folder",
    "upload_group_file", "upload_private_file", "get_group_list", "get_friend_list",
    "get_status", "get_login_info",
})
QUEUE_STAGES = {"pending": "queued", "done": "succeeded", "failed": "failed", "canceled": "cancelled"}

# Keep command cards and dispatch patterns together. JM-bot still parses the
# original command text, including aliases, filters and chapter selections.
JM_COMMANDS = (
    ("jm 搜索", "按关键词找作品编号。/jm 搜索 <关键词> [页码]（别名 search）", r"(?:搜索|search)\s+.+"),
    ("jm 作者", "找作者作品。/jm 作者 [文本] <作者名> [页码]", r"作者\s+.+"),
    ("jm 排行", "查看榜单。/jm 排行 [文本] [关键词或类别] [榜单] [页码]，也可用 /jm 排行 类别", r"排行(?:\s+.+)?"),
    ("jm 详情", "查询作品资料。/jm 详情 <编号>（别名 看、info）", r"(?:详情|看|info)\s+[0-9]+"),
    ("jm 封面", "发送作品封面。/jm 封面 <编号>（别名 cover）", r"(?:封面|cover)\s+[0-9]+"),
    ("jm 预览", "生成前几页的预览 PDF。/jm 预览 <编号>（别名 preview）", r"(?:预览|preview)\s+[0-9]+"),
    ("jm 整本下载", "下载整本。/jm <编号> [pdf|zip]", r"[0-9]+(?:\s+(?:pdf|zip))?"),
    ("jm 指定章节", "下载指定章节。/jm <编号> 章节 1,3-5 [pdf|zip]", r"[0-9]+\s+章节\s+[0-9,\s-]+(?:\s+(?:pdf|zip))?"),
    ("jm 收藏", "添加到收藏。/jm 收藏 <编号>", r"收藏\s+[0-9]+"),
    ("jm 取消收藏", "从收藏中移除。/jm 取消收藏 <编号>", r"取消收藏\s+[0-9]+"),
    ("jm 我的收藏", "查看收藏。/jm 我的收藏 或 /jm 收藏", r"(?:我的收藏|收藏)"),
    ("jm 队列", "查看当前下载队列。/jm 队列", r"队列"),
    ("jm 进度", "查看最近或指定作品的任务进度。/jm 进度 [编号]", r"进度(?:\s+[0-9]+)?"),
    ("jm 我的", "查看我在当前会话的任务。/jm 我的（别名 my）", r"(?:我的|my)"),
    ("jm 撤回", "取消自己在当前会话发起的下载。/jm 撤回 <编号>", r"撤回\s+[0-9]+"),
    ("jm 历史", "查看近期记录。/jm 历史 [失败] [条数]（别名 history）", r"(?:历史|history)(?:\s+[0-9]+)?|历史\s+失败(?:\s+[0-9]+)?"),
)


class Settings(PluginConfigBase):
    config_version: str = Field(default="1.0.0", description="配置结构版本")
    operator_qq: str = Field(default="", description="JM 管理后台的管理员 QQ，填写后重载插件")
    initial_group_ids: list[str] = Field(default_factory=list, description="首次为这些群开启 JM 功能，后续用 JM 后台管理")
    download_port: int = Field(default=17860, ge=1024, le=65535, description="本机下载服务端口")
    admin_port: int = Field(default=18081, ge=1024, le=65535, description="本机管理后台端口")
    source_url: str = Field(default="", description="自行修改部署时，填写对应版本的 HTTPS 源码地址")
    task_awareness_enabled: bool = Field(default=False, description="已安装兼容的后台任务感知插件时，可开启上报")


class Config(PluginConfigBase):
    plugin: Settings = Field(default_factory=Settings)


class JmBridge(MaiBotPlugin):
    config_model = Config

    async def on_load(self) -> None:
        self.loop_task: asyncio.Task | None = None
        self.websocket = None
        self.account = 0
        self.next_message_id = 0
        self.scope_streams: dict[tuple[str, int], str] = {}
        self.jobs: dict[int, tuple[str, int, str]] = {}
        self.queue_task = None
        self.state = self.ctx.paths.data_dir.resolve()
        cfg = self.config.plugin
        if os.name != "nt":
            self.ctx.logger.warning("JM-bot 此版本支持 Windows")
            return
        if not cfg.operator_qq:
            self.ctx.logger.info("请在 JM-bot 插件配置填写管理员 QQ，保存后重载")
            return
        self.loop_task = asyncio.create_task(self._run(), name="jm-bot-bridge")
        if cfg.task_awareness_enabled:
            self.queue_task = asyncio.create_task(self._watch_queue(), name="jm-bot-task-status")

    async def on_unload(self) -> None:
        for task in (self.loop_task, self.queue_task):
            if task is not None:
                task.cancel()
        await asyncio.gather(*(task for task in (self.loop_task, self.queue_task) if task is not None), return_exceptions=True)

    async def on_config_update(self, scope: str, config_data: dict[str, Any], version: str) -> None:
        # The operator account identifies the persistent local admin database.
        # Apply launch settings on plugin reload.
        pass

    @API("status", public=False, description="JM 后端连接状态")
    async def status(self) -> dict[str, Any]:
        return {"connected": self.websocket is not None, "admin_port": self.config.plugin.admin_port}

    def get_components(self) -> list[dict[str, Any]]:
        commands = [
            ("jm", "查看目录。/jm 帮助 [查找|排行|下载|收藏|任务]，也可直接发 /jm",
             r"(?i)^\s*/jm(?:\s+(?P<args>(?:帮助|help)(?:\s+.+)?))?\s*$"),
            *((name, description, rf"(?i)^\s*/jm\s+(?P<args>{arguments})\s*$")
              for name, description, arguments in JM_COMMANDS),
        ]
        return [
            *super().get_components(),
            *(
                {
                    "name": name,
                    "type": "COMMAND",
                    "platforms": ["qq"],
                    "metadata": {
                        "description": description,
                        "command_pattern": pattern,
                        "handler_name": "jm_command",
                        "aliases": [],
                    },
                }
                for name, description, pattern in commands
            ),
        ]

    async def jm_command(
        self, stream_id: str = "", group_id: str = "", user_id: str = "",
        platform: str = "", matched_groups: dict | None = None, message: dict | None = None,
        **_command_context: Any,
    ) -> tuple[bool, str, bool]:
        # MaiBot also passes command text and metadata. The captures supply the JM arguments.
        if platform != "qq" or not user_id.isdecimal() or (group_id and not group_id.isdecimal()):
            return False, "请在 QQ 群或 QQ 私聊使用 /jm。", True
        if not self.config.plugin.operator_qq:
            return False, "请先在 JM-bot 插件设置填写管理员 QQ。", True
        if self.websocket is None:
            return False, "JM 下载服务还没连接，请稍后再试。", True
        args = str((matched_groups or {}).get("args") or "帮助").strip()
        if len(args) > 300:
            return False, "JM 指令过长，请缩短后再试。", True
        message = message or {}
        if str(message.get("account_id") or self.account) != str(self.account):
            return False, "当前账号与 JM 下载服务未绑定。", True
        actor = int(user_id)
        is_group = bool(group_id)
        target = int(group_id) if is_group else actor
        kind = "group" if is_group else "private"
        self.scope_streams[kind, target] = stream_id
        self.next_message_id = (self.next_message_id + 1) % 2147483647
        command = f"/jm {args}"
        text_segment = [{"type": "text", "data": {"text": command}}]
        profile = (message.get("message_info") or {}).get("user_info") or {}
        event = {
            "time": int(time.time()), "self_id": self.account, "post_type": "message",
            "message_type": kind, "sub_type": "normal" if is_group else "friend",
            "message_id": self.next_message_id, "user_id": actor, "message": text_segment,
            "raw_message": command, "font": 0,
            "sender": {"user_id": actor, "nickname": str(profile.get("user_nickname") or actor)},
        }
        if is_group:
            event["group_id"] = target
        try:
            await self.websocket.send(json.dumps(event, ensure_ascii=False))
        except (OSError, websockets.ConnectionClosed):
            return False, "JM 服务已断开，请稍后再试。", True
        return True, "", True

    def _environment(self, token: str) -> dict[str, str]:
        cfg = self.config.plugin
        if any(not value.isascii() or not value.isdecimal() or int(value) < 1
               for value in (cfg.operator_qq, *cfg.initial_group_ids)):
            raise ValueError("管理员 QQ 和初始群号必须为正整数")
        if cfg.download_port == cfg.admin_port:
            raise ValueError("下载端口与管理后台端口必须不同")
        source_url = cfg.source_url.strip() or SOURCE_URL
        source = urlsplit(source_url)
        if source.scheme != "https" or not source.hostname or source.username or source.password or any(
            char.isspace() for char in source_url
        ):
            raise ValueError("源码地址必须是可公开访问的 HTTPS 地址")
        scopes = [f"private:{cfg.operator_qq}", *(f"group:{x}" for x in cfg.initial_group_ids)]
        python_paths = [str(ROOT / "src")]
        if inherited_path := os.environ.get("PYTHONPATH"):
            python_paths.append(inherited_path)
        return {
            **os.environ,
            "PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1", "ONEBOT_ACCESS_TOKEN": token, "API_TIMEOUT": "90",
            "PYTHONPATH": os.pathsep.join(python_paths),
            "JM_BRIDGE_STATE": str(self.state), "JM_BRIDGE_OPERATOR": cfg.operator_qq,
            "JM_BRIDGE_RUNNER_PID": str(os.getpid()), "JM_BRIDGE_LAUNCH_ID": secrets.token_hex(8),
            "JM_BRIDGE_INITIAL_SCOPES": ",".join(scopes),
            "JM_BOT_HOST": "127.0.0.1", "JM_BOT_PORT": str(cfg.download_port),
            "JM_BOT_ADMIN_PORT": str(cfg.admin_port), "JM_BOT_SUPERUSERS": cfg.operator_qq,
            "JM_BOT_RUNTIME_LOCK_DIR": str(self.state), "JM_BOT_COMMAND_PREFIX": "/jm",
            "JM_BOT_JMCOMIC_LOG": "false", "JM_BOT_QUERY_TIMEOUT_SECONDS": "45",
            "JM_BOT_DOWNLOAD_ROOT": str(self.state / "downloads"), "JM_BOT_OUTPUT_ROOT": str(self.state / "output"),
            "JM_BOT_OPTION_ROOT": str(self.state / "options"), "JM_BOT_PREVIEW_ROOT": str(self.state / "preview"),
            "JM_BOT_QUEUE_DB": str(self.state / "queue.sqlite3"), "JM_BOT_USER_DB": str(self.state / "user.sqlite3"),
            "JM_BOT_ADMIN_DB": str(self.state / "admin.sqlite3"),
            "JM_BOT_CONVERSATION_DB": str(self.state / "conversation.sqlite3"),
            "JM_BOT_SOURCE_URL": source_url,
        }

    def _launch(self, mode: str, env: dict[str, str]) -> subprocess.Popen:
        with (self.state / f"{mode}.log").open("ab") as log:
            return subprocess.Popen(
                [sys.executable, str(Path(__file__).with_name("launch_jm.py")), str(ROOT), mode],
                cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

    async def _run(self) -> None:
        token = secrets.token_urlsafe(32)
        processes: dict[str, subprocess.Popen] = {}
        env = {}
        last_error = ""
        try:
            self.state.mkdir(parents=True, exist_ok=True)
            env = self._environment(token)
            while True:
                for mode in ("download", "admin"):
                    child = processes.get(mode)
                    if child is None or child.poll() is not None:
                        if child is not None:
                            self.ctx.logger.warning("JM %s 进程退出，返回码 %s", mode, child.returncode)
                        processes[mode] = self._launch(mode, env)
                try:
                    login = await self._action("get_login_info", {})
                    self.account = int((login.get("data") or {})["user_id"])
                    async with websockets.connect(
                        f"ws://127.0.0.1:{env['JM_BOT_PORT']}/onebot/v11/ws",
                        additional_headers={"X-Self-ID": str(self.account), "Authorization": f"Bearer {token}"},
                        proxy=None, open_timeout=3, close_timeout=2, max_size=2**20,
                    ) as socket:
                        self.websocket = socket
                        last_error = ""
                        self.ctx.logger.info("JM-bot 已连接 QQ 适配器")
                        async for packet in socket:
                            reply = await self._handle_action(json.loads(packet))
                            await socket.send(json.dumps(reply, ensure_ascii=False))
                except (OSError, ValueError, KeyError, RuntimeError, websockets.WebSocketException) as exc:
                    error_type = type(exc).__name__
                    if error_type != last_error:
                        self.ctx.logger.warning("JM-bot 等待连接（%s）", error_type)
                        last_error = error_type
                    await asyncio.sleep(3)
                finally:
                    self.websocket = None
        except asyncio.CancelledError:
            raise
        except Exception:
            self.ctx.logger.exception("JM-bot 桥接启动失败")
        finally:
            for mode, process in processes.items():
                if process.poll() is None:
                    stop_path = self.state / f"{mode}-{env['JM_BRIDGE_LAUNCH_ID']}.stop"
                    await asyncio.to_thread(self._stop_child, process, stop_path)

    @staticmethod
    def _stop_child(process: subprocess.Popen, stop_path: Path) -> None:
        stop_path.touch()
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, capture_output=True,
                timeout=8, creationflags=subprocess.CREATE_NO_WINDOW,
            )
            process.wait(timeout=8)
        finally:
            stop_path.unlink(missing_ok=True)

    async def _handle_action(self, packet: dict[str, Any]) -> dict[str, Any]:
        action = str(packet.get("action") or "")
        params = packet.get("params") or {}
        try:
            if action not in ACTIONS or not isinstance(params, dict):
                raise ValueError("JM-bot 请求了未配置的 QQ 动作")
            if action in {"upload_private_file", "upload_group_file"}:
                file_path = self._file_path(params["file"], {"output", "preview"}, {".pdf", ".zip"})
                result = await self._upload(action, dict(params, file=file_path.as_uri()), file_path)
            else:
                if action in {"send_msg", "send_group_msg", "send_private_msg"}:
                    params = self._normalize_message(params)
                result = await self._action(action, params)
        except (KeyError, ValueError, OSError, RuntimeError) as exc:
            self.ctx.logger.warning("JM QQ 动作 %s 失败（%s）", action, type(exc).__name__)
            result = {"status": "failed", "retcode": 100, "data": None, "message": str(exc)}
        return {**result, "echo": packet.get("echo")}

    def _normalize_message(self, params: dict[str, Any]) -> dict[str, Any]:
        message = params.get("message")
        if isinstance(message, str):
            return {**params, "auto_escape": True}
        if not isinstance(message, list):
            raise ValueError("无法识别 QQ 消息格式")
        segments = []
        for segment in message:
            segment_type, data = segment["type"], segment["data"]
            if segment_type == "image":
                path = self._file_path(data["file"], {"preview"}, {".png", ".jpg", ".jpeg", ".webp", ".gif"})
                data = {**data, "file": path.as_uri()}
            elif segment_type not in {"text", "at", "reply"}:
                raise ValueError("JM QQ 消息段不支持")
            segments.append({"type": segment_type, "data": data})
        return {**params, "message": segments}

    def _file_path(self, reference: str, folders: set[str], suffixes: set[str]) -> Path:
        url = urlsplit(reference)
        if url.scheme != "file" or url.netloc or url.query or url.fragment:
            raise ValueError("JM 仅能发送本机生成的文件")
        target = Path(url2pathname(url.path)).resolve(strict=True)
        if not target.is_file() or target.suffix.lower() not in suffixes:
            raise ValueError("JM 文件格式不受支持")
        if not any(target.is_relative_to((self.state / folder).resolve()) for folder in folders):
            raise ValueError("JM 文件不位于本任务目录")
        return target

    async def _upload(self, action: str, params: dict[str, Any], file_path: Path) -> dict[str, Any]:
        # A group upload is confirmed once a new matching entry is visible.
        if action == "upload_private_file":
            return await self._action(action, params)
        listing = {"group_id": params["group_id"], "folder_id": params["folder"]}
        name, size = params["name"], file_path.stat().st_size

        async def matching_ids() -> set[str]:
            result = await self._action("get_group_files_by_folder", listing)
            data = result.get("data") or {}
            return {
                str(row["file_id"]) for row in data.get("files", [])
                if row.get("file_id") and (row.get("file_name") or row.get("name")) == name
                and int(row.get("file_size") or row.get("size") or -1) == size
            }

        before = await matching_ids()
        uploaded = await self._action(action, params)
        for delay in (0, 1, 2, 3):
            await asyncio.sleep(delay)
            if await matching_ids() - before:
                return uploaded
        raise RuntimeError("QQ 已接收上传请求，群文件尚未确认，请先核对文件列表")

    async def _action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        response = await self.ctx.api.call(ADAPTER_ACTION, action_name=action, params=params)
        if isinstance(response, dict) and response.get("success") is True:
            response = response.get("result")
        if not isinstance(response, dict) or response.get("status") != "ok" or response.get("retcode") != 0:
            code = response.get("retcode") if isinstance(response, dict) else None
            raise RuntimeError(f"QQ 适配器动作 {action} 失败（{code}）")
        return response

    def _recent_jobs(self) -> list[sqlite3.Row]:
        database = self.state / "queue.sqlite3"
        if not database.is_file():
            return []
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=2)) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute(
                """SELECT id, group_id, user_id, destination_type, status, stage, error
                   FROM album_queue WHERE status IN ('pending','processing')
                   OR julianday(updated_at) >= julianday('now','-10 minutes') ORDER BY id"""
            ).fetchall()

    async def _watch_queue(self) -> None:
        while True:
            await asyncio.sleep(2)
            try:
                rows = await asyncio.to_thread(self._recent_jobs)
                present = set()
                for row in rows:
                    present.add(row["id"])
                    await self._report_job(row)
                for number in self.jobs.keys() - present:
                    task, seq, previous = self.jobs.pop(number)
                    if previous not in {"succeeded", "failed", "cancelled", ""}:
                        await self._task_call("update_task", task_id=task, seq=seq+1, stage="unknown")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.ctx.logger.warning("JM 任务状态同步失败（%s）", type(exc).__name__)

    async def _task_call(self, method: str, **kwargs: Any) -> dict:
        async with asyncio.timeout(1.5):
            value = await self.ctx.api.call("local.task-awareness." + method, **kwargs)
        if isinstance(value, dict) and isinstance(value.get("result"), dict):
            return value["result"]
        return value if isinstance(value, dict) else {}

    async def _report_job(self, row: sqlite3.Row) -> None:
        number, status = row["id"], row["status"]
        phase = QUEUE_STAGES.get(status, "sending" if row["stage"] == "uploading" else "fetching")
        if status == "failed" and "群文件尚未确认" in (row["error"] or ""):
            phase = "unknown"
        task, seq, previous = self.jobs.get(number, ("", 0, ""))
        if not task:
            group = row["destination_type"] == "group"
            target = row["group_id"] if group else row["user_id"]
            stream = self.scope_streams.get((row["destination_type"], target))
            if not stream:
                return
            registration = await self._task_call(
                "begin_task", stream_id=stream, kind="jm_download", origin=f"jm-queue:{number}",
                user_id=str(row["user_id"]), owner="plugin",
            )
            task = registration.get("task_id") or ""
            if not task:
                return
            if registration.get("created") is False:
                self.jobs[number] = (task, 0, "existing")
                return
        if phase != previous and previous != "existing":
            result = await self._task_call(
                "update_task", task_id=task, seq=seq+1, stage=phase,
                delivery="confirmed" if phase == "succeeded" else "none",
            )
            if result.get("success"):
                self.jobs[number] = (task, seq+1, phase)


def create_plugin() -> JmBridge:
    return JmBridge()
