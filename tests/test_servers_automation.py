import base64
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from netsec.automation import AutomationJob, run_job
from netsec.core.compiler import compile_source
from netsec.core.model import NetSecError, Source
from netsec.core.resources import ServerResource
from netsec.platforms import scheduler, systemd
from netsec.platforms.scheduler import service_text, timer_text
from netsec.platforms.servers import dnsmasq_config, nginx_config
from netsec.platforms.wireguard_models import Peer, Tunnel
from netsec.runtime import NetworkAdapter, RuntimeFailureError
from netsec.services.ssh import SshInventory, SshTarget


def program(body: str) -> str:
    return (
        'group fleet { host "first" address "192.0.2.10"; } play "deploy" targets fleet {'
        + body
        + "}"
    )


def test_server_resources_are_typed_and_preserve_http_content() -> None:
    plan = compile_source(
        program(
            'server http "site" port 8080 response "Hello $host"; '
            'server dns "resolver" port 5353 record "APP.test" address current_host;'
        )
    )
    assert plan.instructions[0].resource == ServerResource(
        name="site", kind="http", host="192.0.2.10", port=8080, content="Hello $host"
    )
    resource = plan.instructions[1].resource
    assert (
        resource is not None and resource.record == "app.test." and resource.address == "192.0.2.10"
    )
    with pytest.raises(RuntimeFailureError, match="cannot apply"):
        NetworkAdapter(1).preflight(plan)


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ('server http "../../escape" port 80 response "data";', "E_SERVER"),
        ('server http "site" port 0 response "data";', "E_PORT"),
        ('server http "site" port 80 response true;', "E_TYPE"),
        ('server dns "resolver" port 53 record "bad;directive" address current_host;', "E_SERVER"),
        (
            'server http "a" port 80 response "a"; server http "b" port 80 response "b";',
            "E_SERVER_CONFLICT",
        ),
        (
            'server http "a" port 80 response "a"; server http "a" port 81 response "a";',
            "E_SERVER_CONFLICT",
        ),
    ],
)
def test_invalid_or_conflicting_servers_fail_before_execution(body: str, code: str) -> None:
    with pytest.raises(NetSecError, match=code):
        compile_source(program(body))


def test_generated_configs_do_not_embed_http_content_as_directives() -> None:
    resource = ServerResource(
        name="site", kind="http", host="::1", port=8080, content='"; include /private;'
    )
    config = nginx_config(resource, Path("/etc/netsec/revision"))
    assert "include /private" not in config
    assert "listen [::1]:8080;" in config
    dns = ServerResource(
        name="dns",
        kind="dns",
        host="127.0.0.1",
        port=5353,
        record="app.test.",
        address="192.0.2.10",
    )
    assert "no-resolv\nno-hosts\n" in dnsmasq_config(dns)
    assert "host-record=app.test,192.0.2.10" in dnsmasq_config(dns)


def test_automation_rejects_writes_in_network_mode() -> None:
    with pytest.raises(RuntimeFailureError, match="cannot apply"):
        AutomationJob(
            name="audit", source=Source(text=program("firewall deny port 23 protocol tcp;"))
        )
    with pytest.raises(ValidationError, match="interval_seconds"):
        AutomationJob(name="audit", source=Source(text="report 1;"), interval_seconds=1)


def test_persistent_ssh_rejects_paths_dependent_on_working_directory(tmp_path: Path) -> None:
    inventory = SshInventory(
        targets={
            "192.0.2.10": SshTarget(
                user="netsec", identity_file=Path("key"), known_hosts_file=tmp_path / "hosts"
            )
        }
    )
    with pytest.raises(ValidationError, match="absolute SSH"):
        AutomationJob(
            name="audit", mode="ssh", source=Source(text="report 1;"), inventory=inventory
        )


def test_vpn_scheduler_requires_a_boot_available_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    tunnel = Tunnel(
        interface="nswg0",
        address="10.66.0.1/24",
        peers=(
            Peer(
                public_key=base64.b64encode(bytes([1]) * 32).decode("ascii"),
                allowed_ips=("10.66.0.2/32",),
            ),
        ),
    )
    job = AutomationJob(name="vpn", kind="vpn", tunnel=tunnel)
    monkeypatch.setattr(systemd, "require_systemd", lambda: None)
    monkeypatch.setattr(systemd, "protected_path", lambda _: None)
    monkeypatch.setattr(systemd, "owned_text", lambda _: None)
    with pytest.raises(RuntimeFailureError, match="VPN jobs require a secrets_file"):
        scheduler._linux_preflight(job, install=True)


def test_automation_executes_and_retains_separate_run_evidence(tmp_path: Path) -> None:
    job = AutomationJob(name="audit", source=Source(text="report 42;"))
    first, second = run_job(job, tmp_path), run_job(job, tmp_path)
    assert first["success"] is True and first["instructions"] == 1
    assert first["evidence"] != second["evidence"]
    assert (Path(str(first["evidence"])) / "result.json").is_file()


def test_automation_failure_is_visible_and_correlated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = Mock()
    adapter.preflight.side_effect = RuntimeFailureError("unavailable")
    monkeypatch.setattr("netsec.automation.job_adapter", lambda _: adapter)
    job = AutomationJob(name="audit", source=Source(text="report 42;"))
    result = run_job(job, tmp_path)
    assert result["success"] is False and result["failed"] == 1
    assert result["error_type"] == "RuntimeFailureError"


def test_systemd_units_escape_paths_and_include_boot_and_periodic_triggers() -> None:
    job = AutomationJob(name="audit", source=Source(text="report 42;"), interval_seconds=600)
    text = service_text(
        job, Path("/etc/netsec/jobs/test file.json"), ["/opt/NetSec/python", "-m", "netsec"]
    )
    assert '"/etc/netsec/jobs/test file.json"' in text
    assert "Type=oneshot" in text and "TimeoutStartSec=300" in text
    assert "OnUnitInactiveSec=600" in timer_text(job)
    assert "OnBootSec=30" in timer_text(job)
    assert systemd.quote('a%$"b') == '"a%%$$\\"b"'


def test_unowned_systemd_unit_is_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(systemd, "protected_path", lambda _: None)
    unit = tmp_path / "service"
    unit.write_text("unrelated unit", encoding="utf-8")
    with pytest.raises(RuntimeFailureError, match="ownership marker"):
        systemd.atomic_unit(unit, systemd.OWNER + "\nreplacement")
    assert unit.read_text(encoding="utf-8") == "unrelated unit"


def test_immutable_revision_repairs_drift_without_destroying_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(systemd, "protected_path", lambda _: None)
    first = systemd.revision(tmp_path, {"config": "expected"})
    assert systemd.revision(tmp_path, {"config": "expected"}) == first
    (first / "config").write_text("drift", encoding="utf-8")
    repaired = systemd.revision(tmp_path, {"config": "expected"})
    assert repaired != first
    assert (first / "config").read_text(encoding="utf-8") == "drift"
    assert (repaired / "config").read_text(encoding="utf-8") == "expected"
    assert systemd.revision(tmp_path, {"config": "expected"}) == repaired
