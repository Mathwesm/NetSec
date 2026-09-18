"""Provision ephemeral lab keys through the trusted Docker control channel."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from netsec.platforms.process import command


def main() -> None:
    """Write only fixed credential paths inside a disposable Linux container."""
    if not Path("/.dockerenv").exists():
        raise RuntimeError("Lab provisioning requires a container")
    directory = Path("/root/.ssh")
    directory.mkdir(mode=0o700, exist_ok=True)
    request = json.loads(sys.stdin.read(100_000))
    if request["operation"] == "identity":
        key = directory / "id_ed25519"
        if not key.exists():
            command("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", str(key)])
        sys.stdout.write(key.with_suffix(".pub").read_text(encoding="utf-8"))
    elif request["operation"] == "authorize":
        public = request["public"].strip()
        if not public.startswith("ssh-ed25519 ") or "\n" in public:
            raise ValueError("Invalid public key")
        path = directory / "authorized_keys"
        path.write_text(
            'restrict,command="/app/.venv/bin/netsec agent" ' + public + "\n", encoding="utf-8"
        )
        path.chmod(0o600)
    elif request["operation"] == "inventory":
        (directory / "known_hosts").write_text(request["known_hosts"], encoding="utf-8")
        targets = {
            address: {
                "user": "root",
                "identity_file": str(directory / "id_ed25519"),
                "known_hosts_file": str(directory / "known_hosts"),
            }
            for address in request["addresses"]
        }
        Path("/app/inventory.json").write_text(json.dumps({"targets": targets}), encoding="utf-8")
    else:
        raise ValueError("Unknown lab provisioning operation")


if __name__ == "__main__":
    main()
