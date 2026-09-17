"""Toy command protocol; ADMIN_WIPE only clears an in-memory list."""
import hashlib
import hmac

DEMO_KEY = b"cse406-demo-only-pre-shared-key"


def authenticated_line(counter, command):
    body = f"{counter} {command}".encode()
    tag = hmac.new(DEMO_KEY, body, hashlib.sha256).hexdigest().encode()
    return body + b" " + tag + b"\n"


def verify_line(line, expected):
    try:
        counter, command, tag = line.decode("ascii").split(" ")
        body = f"{counter} {command}".encode()
        correct = hmac.new(DEMO_KEY, body, hashlib.sha256).hexdigest()
        if int(counter) != expected or not hmac.compare_digest(correct, tag):
            return None
        return command
    except (ValueError, UnicodeDecodeError):
        return None
