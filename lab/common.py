import json
import os
import time
from pathlib import Path


def evidence_dir():
    path = Path(os.environ.get("EVIDENCE_DIR", "./evidence")) / os.environ.get("SCENARIO", "attack")
    path.mkdir(parents=True, exist_ok=True)
    return path


def log(role, event, **fields):
    entry = {"time": time.time(), "role": role, "event": event, **fields}
    line = json.dumps(entry, sort_keys=True)
    print(line, flush=True)
    with (evidence_dir() / f"{role}.jsonl").open("a") as out:
        out.write(line + "\n")
