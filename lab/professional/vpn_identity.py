"""Keep ephemeral VPN private keys inside the owned laboratory containers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from netsec.cli import main as cli_main
from netsec.platforms.process import command
from netsec.platforms.wireguard_models import Tunnel


def main() -> int:
    """Return public identity or run the CLI with a container-local secret environment."""
    if not Path("/.dockerenv").exists():
        raise RuntimeError("Ephemeral key provisioning requires a lab container")
    request = json.loads(sys.stdin.read(100_000))
    directory = Path("/root/.netsec-vpn")
    directory.mkdir(mode=0o700, exist_ok=True)
    key = directory / "identity"
    if not key.exists():
        with key.open("x", encoding="utf-8") as stream:
            stream.write(command("wg", ["genkey"]))
        key.chmod(0o600)
    if request["operation"] == "identity":
        sys.stdout.write(command("wg", ["pubkey"], key.read_text(encoding="utf-8")))
        return 0
    tunnel = Tunnel.model_validate(request["tunnel"])
    manifest = Path("/app/vpn.json")
    manifest.write_text(tunnel.model_dump_json(), encoding="utf-8")
    os.environ["NETSEC_WG_PRIVATE_KEY"] = key.read_text(encoding="utf-8").strip()
    return cli_main(["vpn", "up", str(manifest), "--apply"])


if __name__ == "__main__":
    raise SystemExit(main())
