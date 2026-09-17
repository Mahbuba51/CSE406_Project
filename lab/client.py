import os
import socket
import time
from .common import log
from .config import CLIENT_IP, SERVER_IP, PORT
from .protocol import authenticated_line


def main():
    protected = os.environ.get("SCENARIO") == "protected"
    with socket.socket() as conn:
        conn.bind((CLIENT_IP, 0))
        conn.settimeout(4)
        conn.connect((SERVER_IP, PORT))
        log("client", "connected", local_port=conn.getsockname()[1])
        stream = conn.makefile("rb")
        for counter, command in enumerate(("STATUS", "PING", "STATUS"), 1):
            wire = authenticated_line(counter, command) if protected else (command + "\n").encode()
            log("client", "send", command=command, wire=wire.decode().strip())
            try:
                conn.sendall(wire)
                reply = stream.readline(8192)
                if not reply:
                    log("client", "disrupted", reason="connection closed")
                    break
                expected = b"PONG\n" if command == "PING" else b"STATUS records=3\n"
                log("client", "reply", text=reply.decode("ascii", "replace").strip(), matches_expected=reply == expected)
                if reply != expected:
                    log("client", "disrupted", reason="unexpected response")
                    break
            except OSError as exc:
                log("client", "disrupted", reason=str(exc))
                break
            # An intentional idle period makes the sequence injection reproducible.
            time.sleep(2)
        log("client", "finished")


if __name__ == "__main__":
    main()
