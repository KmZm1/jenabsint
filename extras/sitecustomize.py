"""Termux/Android DNS fixes applied at every Python interpreter startup.

Problem: c-ares (via pycares/aiodns) reads /etc/resolv.conf to discover DNS
servers. Android has no /etc/resolv.conf, so every aiodns resolver ends up
with zero nameservers and aiohttp-based tools (socialscan, maigret,
theHarvester, ...) fail with "Could not contact DNS servers".

Fix: when aiodns.DNSResolver is created without explicit nameservers,
inject nameservers that are verified reachable from this device.
All wrapped in try/except so any failure is harmless to unrelated scripts.
"""

try:
    import aiodns

    _JENAB_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]

    if not getattr(aiodns.DNSResolver, "_jenab_ns_patched", False):
        _orig_init = aiodns.DNSResolver.__init__

        def _init(self, nameservers=None, *args, **kwargs):
            if not nameservers:
                nameservers = list(_JENAB_DNS_SERVERS)
            return _orig_init(self, nameservers, *args, **kwargs)

        aiodns.DNSResolver.__init__ = _init
        aiodns.DNSResolver._jenab_ns_patched = True
except Exception:  # never break interpreter startup
    pass
