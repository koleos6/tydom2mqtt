#!/usr/bin/env python3
"""Read a Tydom hub's *local* password by pairing with it once.

Why this exists
---------------
The password returned by the Delta Dore cloud API (the one tydom2mqtt fetches
from DELTADORE_LOGIN / DELTADORE_PASSWORD) is **not** the password the gateway
expects for a direct LAN connection: they are two different secrets. Using the
cloud one against a local gateway fails with a permanent HTTP 401 that looks
exactly like a wrong configuration.

The gateway exposes its local password on /configs/gateway/password, but only
accepts an unauthenticated connection during the short window that follows a
press on its physical button. This tool waits for that window, reads the
password once, and prints it. Put the value in TYDOM_PASSWORD and you are done:
subsequent connections authenticate normally, no further button press.

Usage
-----
    python tools/get_local_password.py --host 192.168.1.33 --mac 001A25XXXXXX
"""

import argparse
import asyncio
import json
import re
import ssl
import sys
import time

import websockets

RETRY_DELAY = 3


def dechunk(body):
    """Decode an HTTP chunked-transfer body into its payload."""
    payload = ""
    lines = body.split("\r\n")
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        index += 1
        if not line:
            continue
        if not re.fullmatch(r"[0-9a-fA-F]+", line):
            # Not a chunk header: the gateway is not always strict, keep the
            # line as payload rather than dropping data.
            payload += line
            continue
        if int(line, 16) == 0:
            break
        if index < len(lines):
            payload += lines[index]
            index += 1
    return payload


def extract_password(response):
    """Pull the password out of a /configs/gateway/password response."""
    separator = response.find("\r\n\r\n")
    body = response[separator + 4:] if separator != -1 else response
    payload = dechunk(body)
    try:
        return json.loads(payload)["current"]
    except (ValueError, KeyError):
        return None


async def read_password(host, mac, timeout):
    ssl_context = ssl._create_unverified_context()
    ssl_context.options |= 0x4  # OP_LEGACY_SERVER_CONNECT

    url = f"wss://{host}:443/mediation/client?mac={mac}&appli=1"
    deadline = time.monotonic() + timeout
    attempt = 0

    while time.monotonic() < deadline:
        attempt += 1
        try:
            connection = await websockets.connect(
                url,
                extra_headers={"Sec-WebSocket-Version": "13"},
                ssl=ssl_context,
                ping_timeout=None,
            )
        except Exception as e:
            status = getattr(e, "status_code", None)
            if status == 401:
                print(f"  attempt {attempt}: gateway still locked, "
                      "press its button now...")
            else:
                print(f"  attempt {attempt}: {e}")
            await asyncio.sleep(RETRY_DELAY)
            continue

        print("Pairing window is open, reading the password...")
        request = (
            "GET /configs/gateway/password HTTP/1.1\r\n"
            "Content-Length: 0\r\n"
            "Content-Type: application/json; charset=UTF-8\r\n"
            "Transac-Id: 0\r\n\r\n"
        )
        await connection.send(request.encode("ascii"))
        try:
            # The gateway also pushes unsolicited events; skip them until the
            # answer to our own request shows up.
            for _ in range(5):
                reply = await asyncio.wait_for(connection.recv(), timeout=5)
                text = reply if isinstance(reply, str) else reply.decode(
                    errors="replace")
                if "/configs/gateway/password" in text:
                    return extract_password(text)
        except asyncio.TimeoutError:
            print("  the gateway did not answer, retrying...")
        finally:
            await connection.close()

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Read a Tydom hub's local password (one-time pairing).")
    parser.add_argument("--host", required=True,
                        help="gateway IP address on your LAN")
    parser.add_argument("--mac", required=True,
                        help="gateway MAC address, e.g. 001A25XXXXXX")
    parser.add_argument("--timeout", type=int, default=120,
                        help="how long to wait for the button press (seconds)")
    args = parser.parse_args()

    print(f"Connecting to {args.host} ({args.mac}).")
    print("Press the button on the Tydom hub now; waiting up to "
          f"{args.timeout}s for its pairing window.\n")

    password = asyncio.run(
        read_password(args.host, args.mac, args.timeout))

    if password is None:
        print("\nCould not read the password. Make sure you pressed the "
              "button on the hub, and that the MAC and IP are correct.")
        sys.exit(1)

    print(f"\nLocal password: {password}")
    print("Set it as TYDOM_PASSWORD. Do not use the Delta Dore cloud password "
          "for a local connection: it is a different secret.")


if __name__ == "__main__":
    main()
