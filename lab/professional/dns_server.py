"""Serve deterministic DNS fixtures exclusively inside the isolated laboratory."""

import socketserver

import dns.message
import dns.rcode
import dns.rrset


class Handler(socketserver.BaseRequestHandler):
    """Answer A/AAAA fixtures without performing recursive external lookups."""

    def handle(self) -> None:
        """Return fixture records or an explicit NXDOMAIN."""
        packet, connection = self.request
        query = dns.message.from_wire(packet)
        response = dns.message.make_response(query)
        question = query.question[0]
        if question.name.to_text() != "app.netsec.test.":
            response.set_rcode(dns.rcode.NXDOMAIN)
        elif question.rdtype in {1, 28}:
            value = "172.30.250.10" if question.rdtype == 1 else "2001:db8::10"
            response.answer.append(
                dns.rrset.from_text(question.name, 60, "IN", question.rdtype, value)
            )
        connection.sendto(response.to_wire(), self.client_address)


if __name__ == "__main__":
    # Isolated container network; no host port publication or recursive resolution.
    with socketserver.UDPServer(("0.0.0.0", 53), Handler) as server:  # noqa: S104
        server.serve_forever()
