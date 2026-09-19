"""Provision owned HTTP and authoritative-only DNS services on systemd Linux."""

from __future__ import annotations

import hashlib
from pathlib import Path
from shutil import which

from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_random_exponential

from netsec.core.resources import ServerResource
from netsec.platforms import systemd
from netsec.platforms.linux import _addresses
from netsec.platforms.process import command
from netsec.runtime import RuntimeFailureError
from netsec.services.dns import probe_dns
from netsec.services.probes import ProbeResult, probe


def resource_id(resource: ServerResource) -> str:
    """Keep separate local interfaces and groups from colliding on unit names."""
    digest = hashlib.sha256(resource.host.encode("ascii")).hexdigest()[:8]
    return f"netsec-srv-{resource.name}-{digest}"


def nginx_config(resource: ServerResource, directory: Path) -> str:
    """Render an isolated nginx configuration with no user-supplied directives."""
    endpoint = f"[{resource.host}]" if ":" in resource.host else resource.host
    return (
        f"pid /run/{resource_id(resource)}/nginx.pid;\nerror_log stderr warn;\n"
        "events { worker_connections 256; }\nhttp {\naccess_log off;\n"
        + "".join(
            f"{kind}_temp_path /run/{resource_id(resource)}/{kind};\n"
            for kind in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
        )
        + f"server {{ listen {endpoint}:{resource.port};\n"
        f'location / {{ root "{directory}"; default_type text/html; }}\n}}\n}}\n'
    )


def dnsmasq_config(resource: ServerResource) -> str:
    """Serve only the declared exact A/AAAA record without upstream recursion or DHCP."""
    return (
        f"port={resource.port}\nlisten-address={resource.host}\nbind-interfaces\n"
        "no-resolv\nno-hosts\ncache-size=0\n"
        f"host-record={resource.record.rstrip('.')},{resource.address}\n"
        "pid-file=\nlog-facility=-\n"
    )


class ServerManager:
    """Manage exclusively generated service units and keep prior revisions recoverable."""

    def preflight(self, resources: tuple[ServerResource, ...], *, apply: bool) -> None:
        """Check every resource dependency, ownership and local address before writing."""
        if not resources:
            return
        if not apply:
            raise RuntimeFailureError("Server deployment requires --apply")
        systemd.require_systemd()
        systemd.protected_path(systemd.CONFIG)
        addresses = _addresses(command("ip", ["-j", "address", "show"]))
        for resource in resources:
            if resource.host not in addresses:
                raise RuntimeFailureError("Server address is not assigned to this machine")
            self._executable(resource)
            systemd.owned_text(systemd.UNITS / f"{resource_id(resource)}.service")

    def _executable(self, resource: ServerResource) -> str:
        executable = which("nginx" if resource.kind == "http" else "dnsmasq")
        if executable is None:
            package = "nginx" if resource.kind == "http" else "dnsmasq-base"
            raise RuntimeFailureError(f"Install {package} before deployment")
        systemd.protected_path(Path(executable))
        return executable

    def ensure(self, resource: ServerResource) -> ProbeResult:
        """Validate configuration, converge runtime state and enable boot persistence."""
        self.preflight((resource,), apply=True)
        name = resource_id(resource)
        root = systemd.CONFIG / "services" / name
        files = {"resource.json": resource.model_dump_json(indent=2)}
        if resource.kind == "http":
            files["index.html"] = resource.content
        else:
            files["dnsmasq.conf"] = dnsmasq_config(resource)
        directory = systemd.revision(root, files)
        executable = self._executable(resource)
        arguments = self._arguments(resource, directory, executable)
        unit = _service_unit(name, [executable, *arguments])
        changed = systemd.install_unit(f"{name}.service", unit)
        if systemd.unit_state(f"{name}.service", "ActiveState") != "active":
            raise RuntimeFailureError("Service did not remain active; inspect its journal")
        _wait_ready(resource)
        return ProbeResult(
            True,
            "applied" if changed else "unchanged",
            f"Owned {resource.kind} service active and enabled",
        )

    def _arguments(self, resource: ServerResource, directory: Path, executable: str) -> list[str]:
        if resource.kind == "dns":
            arguments = ["--keep-in-foreground", f"--conf-file={directory / 'dnsmasq.conf'}"]
            command(executable, ["--test", arguments[1]])
            return arguments
        configuration = systemd.revision(
            directory.parent / "nginx", {"nginx.conf": nginx_config(resource, directory)}
        )
        # nginx -t attempts to open its PID/log paths; syntax is fixed and validation happens
        # inside the managed unit after RuntimeDirectory has been created by systemd.
        return ["-c", str(configuration / "nginx.conf"), "-g", "daemon off;"]

    def remove(self, resource: ServerResource) -> ProbeResult:
        """Stop only the named owned service and retain its configuration history."""
        self.preflight((resource,), apply=True)
        changed = systemd.remove_unit(f"{resource_id(resource)}.service")
        return ProbeResult(
            True, "removed" if changed else "unchanged", "Owned service stopped; revisions retained"
        )


def _service_unit(name: str, arguments: list[str]) -> str:
    return (
        f"{systemd.OWNER}\n[Unit]\nDescription=NetSec managed server\n"
        "After=network-online.target\nWants=network-online.target\n"
        "[Service]\nType=simple\nDynamicUser=yes\n"
        f"RuntimeDirectory={name}\nExecStart={' '.join(map(systemd.quote, arguments))}\n"
        "Restart=on-failure\nRestartSec=3\nTimeoutStartSec=30\nTimeoutStopSec=15\n"
        "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
        # Linux capability identifiers are public constants, not encoded credentials.
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"  # pragma: allowlist secret
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"  # pragma: allowlist secret
        "[Install]\nWantedBy=multi-user.target\n"
    )


def _wait_ready(resource: ServerResource) -> None:
    for attempt in Retrying(
        stop=stop_after_attempt(4),
        wait=wait_random_exponential(multiplier=0.2, max=1),
        retry=retry_if_exception_type(RuntimeFailureError),
        reraise=True,
    ):
        with attempt:
            result = (
                probe(resource.host, resource.port, "http", 0.5)
                if resource.kind == "http"
                else probe_dns(
                    resource.host, resource.record, resource.address, 0.5, port=resource.port
                )
            )
            if not result.success:
                raise RuntimeFailureError(
                    "Managed service is not responding with its configured protocol"
                )
