import os
import ipaddress
from typing import Set, Optional, List
from fastapi import Request

# Simulation token is configured strictly via the SIMULATION_TOKEN environment variable.
# There is NO default fallback secret; simulation mode is disabled unless explicitly configured.
def get_configured_simulation_token() -> Optional[str]:
    raw = os.getenv("SIMULATION_TOKEN")
    return raw.strip() if raw and raw.strip() else None

SIMULATION_TOKEN: Optional[str] = get_configured_simulation_token()

def is_simulation_token_valid(sim_token: Optional[str]) -> bool:
    """
    Validates client simulation token against configured environment token.
    Securely disables simulation mode if SIMULATION_TOKEN is unset, empty, or whitespace.
    """
    if not sim_token or not sim_token.strip():
        return False
    configured = get_configured_simulation_token()
    if not configured:
        return False  # Simulation mode completely disabled when unset or empty
    return sim_token.strip() == configured

# Known trusted proxy infrastructure IPs: localhost, test runners, Nginx container
TRUSTED_PROXY_IPS: Set[str] = {
    "127.0.0.1",
    "::1",
    "localhost",
    "testclient",
    "172.28.0.10",  # CloudShield Nginx ingress proxy
}

# Protected allowlisted identities that can NEVER be claimed via client headers
PROTECTED_ALLOWLIST_IPS: Set[str] = {
    "127.0.0.1",
    "::1",
    "localhost",
    "172.28.0.10",
    "172.28.0.20",
    "172.28.0.21",
    "172.28.0.22",
    "172.28.0.30",
}

# Trusted CIDR networks for local loopback proxy testing
# NOTE: Docker network 172.28.0.0/16 is NOT trusted as a proxy network because 172.28.0.1 (Docker bridge
# gateway / NAT) is not a reverse proxy. Only the designated Nginx container (172.28.0.10) is a trusted proxy.
TRUSTED_PROXY_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
]

# Designated documentation / test subnets permitted for controlled simulations (RFC 5737 & RFC 2544)
SIMULATION_ALLOWED_NETWORKS = [
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (Attacker simulation pool)
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3 (Honeypot scanner simulation pool)
    ipaddress.ip_network("198.18.0.0/15"),    # Benchmark test net (Flash crowd simulation pool)
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
]

# Disallowed internal and private networks for simulation attribution
DISALLOWED_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def is_trusted_proxy(ip_str: Optional[str]) -> bool:
    """Checks if an IP string belongs to trusted proxy infrastructure."""
    if not ip_str:
        return False
    ip_clean = ip_str.strip()
    if ip_clean in TRUSTED_PROXY_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip_clean)
        return any(addr in net for net in TRUSTED_PROXY_NETWORKS)
    except ValueError:
        return False

def is_simulation_ip_allowed(ip_str: Optional[str]) -> bool:
    """
    Validates that a simulated IP belongs to permitted test ranges or public IPs
    and is strictly NOT an internal, private, loopback, or allowlisted identity.
    """
    if not ip_str:
        return False
    ip_clean = ip_str.strip()
    if ip_clean in PROTECTED_ALLOWLIST_IPS:
        return False
    try:
        addr = ipaddress.ip_address(ip_clean)
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
            return False
        if any(addr in net for net in DISALLOWED_INTERNAL_NETWORKS):
            return False
        return any(addr in net for net in SIMULATION_ALLOWED_NETWORKS) or addr.is_global
    except ValueError:
        return False

def extract_client_ip(
    peer_ip: Optional[str],
    xff_header: Optional[str] = None,
    x_real_ip: Optional[str] = None,
    sim_token: Optional[str] = None,
    sim_ip: Optional[str] = None,
) -> str:
    """
    Deterministically resolves client IP using secure reverse-proxy policies.

    Security Rules:
    1. Controlled Simulation Channel:
       If a valid simulation token is provided and the simulated IP is within authorized
       lab test subnets (and NOT in protected allowlist), attribute the request to the simulated IP.
    2. Public / Untrusted Requests:
       - If peer_ip is NOT a trusted proxy, client-supplied headers are completely ignored.
       - If peer_ip IS a trusted proxy (e.g. Nginx):
         - Traverse XFF right-to-left.
         - The candidate IP must NOT be in PROTECTED_ALLOWLIST_IPS.
         - If all hops are internal/trusted proxies or empty, return peer_ip (NEVER raw_hops[0]).
    3. Loopback / Allowlist Protection:
       Under NO circumstances can client headers grant 127.0.0.1, localhost, or allowlisted status.
    """
    if not peer_ip or not peer_ip.strip():
        peer_ip = "127.0.0.1"
    else:
        peer_ip = peer_ip.strip()

    # Rule 1: Controlled simulation channel with token authentication
    if is_simulation_token_valid(sim_token):
        if sim_ip and is_simulation_ip_allowed(sim_ip):
            return sim_ip.strip()

    # Rule 2: Untrusted direct peer cannot spoof headers
    if not is_trusted_proxy(peer_ip):
        return peer_ip

    # Rule 3: Peer is a trusted reverse proxy (e.g. internal Nginx container)
    candidate_ip = None
    if xff_header and xff_header.strip():
        raw_hops = [h.strip() for h in xff_header.split(",") if h.strip()]
        for hop in reversed(raw_hops):
            if not is_trusted_proxy(hop):
                candidate_ip = hop
                break

    if not candidate_ip and x_real_ip and x_real_ip.strip():
        real_ip_clean = x_real_ip.strip()
        if not is_trusted_proxy(real_ip_clean):
            candidate_ip = real_ip_clean

    # Guard: Candidate IP can NEVER be an allowlisted identity from headers
    if candidate_ip:
        if candidate_ip in PROTECTED_ALLOWLIST_IPS:
            return peer_ip
        return candidate_ip

    # If all hops were internal/trusted, return peer_ip (NEVER raw_hops[0])
    return peer_ip

def get_origin_ip(request: Request) -> str:
    """
    Extracts the verified client origin IP from a FastAPI Request object.
    Protects against client-supplied header spoofing and loopback allowlist bypass.
    """
    peer_ip = request.client.host if request.client else "127.0.0.1"
    xff = request.headers.get("x-forwarded-for")
    x_real_ip = request.headers.get("x-real-ip")
    sim_token = request.headers.get("x-simulation-token")
    sim_ip = request.headers.get("x-simulated-ip")
    return extract_client_ip(
        peer_ip=peer_ip,
        xff_header=xff,
        x_real_ip=x_real_ip,
        sim_token=sim_token,
        sim_ip=sim_ip
    )
