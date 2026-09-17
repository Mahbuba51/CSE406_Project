import os
import socket
from .common import log
from .config import SERVER_IP, PORT
from .protocol import verify_line


def main():
    protected = os.environ.get("SCENARIO") == "protected"
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((SERVER_IP, PORT))
        listener.listen(5)
        log("server", "listening", protected=protected)
        while True:
            conn, peer = listener.accept()
            records = ["record-A", "record-B", "record-C"]
            expected = 1
            log("server", "connected", peer_ip=peer[0], peer_port=peer[1])
            with conn:
                conn.settimeout(20)
                buffer = b""
                try:
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break
                        buffer += data
                        if len(buffer) > 8192:
                            raise ValueError("Command buffer exceeded")
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            command = verify_line(line, expected) if protected else line.decode("ascii", "replace")
                            if command is None:
                                log("server", "rejected", wire=line.decode("ascii", "replace"),
                                    reason="invalid authentication or counter", records=len(records), peer_ip=peer[0])
                                conn.sendall(b"ERROR authentication\n")
                                continue
                            expected += 1
                            if command == "STATUS":
                                reply = f"STATUS records={len(records)}\n".encode()
                            elif command == "PING":
                                reply = b"PONG\n"
                            elif command == "ADMIN_WIPE":
                                records.clear()
                                reply = b"ADMIN_WIPE OK records=0\n"
                            else:
                                reply = b"ERROR unknown command\n"
                            log("server", "command", command=command, records=len(records),
                                peer_ip=peer[0], peer_port=peer[1])
                            conn.sendall(reply)
                except (OSError, ValueError) as exc:
                    log("server", "connection_end", reason=str(exc))


if __name__ == "__main__":
    main()
