"""Dispatch observations shared by local and remote-control execution modes."""

from netsec.core.compiler import Instruction
from netsec.services.dns import probe_dns
from netsec.services.probes import ProbeResult, probe


def observe(instruction: Instruction, timeout: float) -> ProbeResult:
    """Use the domain protocol rather than mistaking a TCP socket for DNS health."""
    if instruction.operation == "check_dns":
        return probe_dns(instruction.host, instruction.message, instruction.expected, timeout)
    return probe(instruction.host, instruction.port, instruction.message, timeout)
