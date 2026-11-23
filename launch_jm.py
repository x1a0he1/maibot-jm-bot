"""Launch the JM-bot download service and admin panel using this instance's local state."""
from pathlib import Path
from threading import Thread
import ctypes
import os
import secrets
import sys

import uvicorn


def watch_parent(server, runner_pid, stop_path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    process = kernel.OpenProcess(0x00100000, False, runner_pid)
    if not process:
        server.should_exit = True
        return
    try:
        while not stop_path.exists():
            if kernel.WaitForSingleObject(ctypes.c_void_p(process), 500) != 258:
                break
        server.should_exit = True
    finally:
        kernel.CloseHandle(ctypes.c_void_p(process))


def main():
    checkout = Path(sys.argv[1]).resolve()
    mode = sys.argv[2]
    state = Path(os.environ["JM_BRIDGE_STATE"])
    operator = int(os.environ["JM_BRIDGE_OPERATOR"])
    runner_pid = int(os.environ["JM_BRIDGE_RUNNER_PID"])
    stop_path = state / f"{mode}-{os.environ['JM_BRIDGE_LAUNCH_ID']}.stop"
    sys.path.insert(0, str(checkout / "src"))
    from jmbot import admin_app
    from jmbot.core.conversation_state import ConversationStateStore

    admin_app.SUPER_ADMIN_ID = operator
    run_server = uvicorn.Server.run

    def run_until_parent_closes(server, *args, **kwargs):
        # Release the upstream queue lock if the MaiBot runner exits.
        Thread(target=watch_parent, args=(server, runner_pid, stop_path), daemon=True).start()
        return run_server(server, *args, **kwargs)

    uvicorn.Server.run = run_until_parent_closes

    if mode == "download":
        from jmbot.bot import main as run_download

        policies = ConversationStateStore(Path(os.environ["JM_BOT_CONVERSATION_DB"]))
        for scope in os.environ["JM_BRIDGE_INITIAL_SCOPES"].split(","):
            if scope and not policies.has_policy(scope):
                policies.set_policy(scope, download_enabled=True)
        run_download()
    else:
        admin = admin_app.AdminStore(Path(os.environ["JM_BOT_ADMIN_DB"]))
        credential_path = state / "admin-first-login.txt"
        with admin._connection() as connection:
            credential = connection.execute("SELECT password_hash FROM admins WHERE qq_id = ?", (operator,)).fetchone()
        if not credential or not str(credential[0]).startswith("scrypt$"):
            password = secrets.token_urlsafe(24)
            credential_path.write_text(f"QQ: {operator}\nPassword: {password}\n", encoding="utf-8")
            admin.set_password(operator, password, is_super=True)
        sys.argv[:] = [sys.argv[0]]
        admin_app.main()


if __name__ == "__main__":
    main()
