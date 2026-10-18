# JenabSint

**Interactive OSINT console for Termux.** A single-file, standard-library-only Python TUI that wraps a full OSINT toolchain behind a friendly, animated terminal menu — usernames, emails, domains, IPs, phones, file metadata, URL harvesting, DNS brute force, Shodan, theHarvester, and more.

Built for Android/Termux (no root required). Runs anywhere with Python 3.11+ and the underlying tools installed.

```
  ██╗███████╗███╗   ██╗ █████╗ ██████╗ ███████╗██╗███╗   ██╗████████╗
  ██║██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝
  ██║█████╗  ██╔██╗ ██║███████║██████╔╝███████╗██║██╔██╗ ██║   ██║
  ██║██╔══╝  ██║╚██╗██║██╔══██║██╔══██╗╚════██║██║██║╚██╗██║   ██║
  ██║███████╗██║ ╚████║██║  ██║██████╔╝███████║██║██║ ╚████║   ██║
  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
              Termux OSINT console · v1.2
```

## Features

- **Animated TUI** — ASCII banner, spinner progress, width-aware layout. Pure Python standard library, zero pip dependencies for the UI itself.
- **14 guided workflows** — username footprint, email footprint, domain recon, DNS brute force, URL harvesting, web crawl, IP/host recon, phone lookup, file metadata, theHarvester, Shodan, doctor, settings.
- **Individual tool picker** — run any single tool from the toolkit (40+ entries, incl. `custom` for free-form commands).
- **Built-in Tor mode** — two-phase connect: tries direct Tor first, automatically falls back to Snowflake bridges when the network blocks plain Tor. `stop` also cleans up bridge helpers.
- **Doctor** — one screen checks all 46 tools plus wordlists and shows what is missing.
- **Consistent output** — every run gets its own timestamped folder under `~/osint-out/`.
- **Bash wrapper included** — `osint.sh` installs as `osint` for one-liner usage without the TUI.

## Requirements

- Termux (or any Linux box — run with `python3 jenabsint.py` outside Termux; the shebang is Termux-specific)
- Python 3.11+ (developed and tested on Python 3.14)
- The OSINT toolchain — this project is the front-end; the tools are installed separately (see table below). Run the built-in **Doctor** (menu 13) to see what's missing on your device.

## Install

```bash
git clone https://github.com/KmZm1/jenabsint.git
cd jenabsint
bash install.sh
jenabsint
```

`install.sh` symlinks the launcher into `$PREFIX/bin` and installs the `osint` bash wrapper. Without the installer:

```bash
python3 jenabsint.py
```

## Usage

### TUI

```bash
jenabsint
```

```
JENABSINT · 03:27 · tor:off · /data/data/com.termux/files/home/osint-out
──────────────────────────────────────────────
 1  Username footprint    sherlock · maigret · socialscan
 2  Email footprint       holehe · socialscan
 3  Domain recon          subdomains · DNS · whois · httpx
 4  DNS brute force       dnsx · wordlist · dnsgen
 5  URL harvesting        gau · waybackurls
 6  Web crawl             katana depth-3
 7  IP / host recon       whois · dig · nmap
 8  Phone lookup          phoneinfoga
 9  File metadata         exiftool
10  theHarvester          emails & hosts
11  Shodan search         needs API key
12  Individual tools…     pick any single tool
13  Doctor                check the toolchain
14  Settings              tor · output dirs
──────────────────────────────────────────────
 0  Exit
```

### Bash wrapper

```bash
osint user <username>     # sherlock + maigret + socialscan + blackbird
osint email <email>       # holehe + socialscan + blackbird
osint gh <user|email>     # blackbird — 600+ site account search (CSV)
osint ig <username>       # Instagram profile media (instaloader)
osint domain <domain>     # subdomain enum + DNS + httpx + whois
osint dns <domain>        # dnsrecon standard enumeration (+ zone transfer)
osint twist <domain>      # dnstwist typosquat / look-alike domains
osint ip <ip|host>        # whois + reverse DNS + nmap + ipinfo
osint urls <domain>       # historical URLs (gau + waybackurls)
osint waymore <domain>    # deep URL harvest (Wayback + CommonCrawl)
osint links <url>         # links/params from pages & JS (xnLinkFinder)
osint crawl <url>         # katana endpoint crawl
osint dork <query>        # DuckDuckGo dork search (ddgr)
osint waf <url>           # WAF vendor detection (wafw00f)
osint cloud <keyword>     # public S3/Azure/GCP scan (cloud_enum)
osint dark <query>        # OnionSearch via Tor
osint leaks <dir>         # secret scanning (gitleaks)
osint phone <number>      # phoneinfoga (E.164, e.g. +12025550123)
osint meta <file>         # exiftool metadata
osint harv <domain>       # theHarvester (otx, rapiddns, duckduckgo, crtsh)
osint brute <domain>      # dnsx + wordlists
osint shodan <query>      # requires: shodan init <API key>
osint check               # toolchain status
```

## Toolchain

| Area | Tools |
|---|---|
| Usernames | `sherlock`, `maigret`, `blackbird`, `socialscan` |
| Email | `holehe`, `socialscan`, `blackbird` |
| Social profiles | `socid_extractor`, `instaloader` |
| Subdomains | `subfinder`, `amass`, `assetfinder`, `crt.sh`, `alterx` |
| DNS | `dnsx`, `dig`, `dnsrecon`, `dnstwist` |
| TLS / CDN / ASN | `tlsx`, `cdncheck`, `asnmap`, `ipinfo` |
| Probing / crawling | `httpx`, `naabu`, `katana`, `nuclei`, `ffuf`, `xnLinkFinder` |
| URL history | `gau`, `waybackurls`, `waymore` |
| People / hosts | `theHarvester`, `phoneinfoga` |
| Secrets / dorking | `gitleaks`, `ddgr` |
| Dark web | `onionsearch` (via Tor) |
| Cloud exposure | `cloud_enum` |
| WAF detection | `wafw00f` |
| Utilities | `whois`, `nmap`, `exiftool`, `jq`, `curl` |
| Anonymity | `tor`, `proxychains4`, `snowflake-client`, `lyrebird` |

How they were installed on Termux (Go tools, pip tools with Python 3.14 workarounds, etc.) is documented in the commit history-friendly style of the scripts themselves; the TUI's Doctor is the canonical check.

## Output layout

```
~/osint-out/
├── users/20261019-032712-torvalds/
│   ├── sherlock.txt
│   ├── socialscan.txt
│   └── maigret/ ...
├── emails/20261019-032647-jenabtest8471@gmail.com/
│   ├── holehe.txt
│   └── socialscan.txt
├── domains/...
└── harvester/...
```

## Tor mode

*Settings → 1* toggles Tor. On start it probes the SOCKS port for a live circuit; if plain Tor cannot complete a handshake (common on mobile carriers that DPI-block Tor), it automatically retries with Snowflake bridges using `~/torrc-snowflake`. Enable/disable at any time; results folders are unaffected.

Requires: `tor` (always), `snowflake-client` (for the fallback path).

## Android DNS note (important for socialscan / maigret / theHarvester)

aiohttp-based tools resolve DNS through `aiodns`/c-ares, which reads `/etc/resolv.conf` — a file Android does not ship. Symptom: `Could not contact DNS servers`, or tools that print "done" with silently empty results.

Fix: install the included `extras/sitecustomize.py` into your Python's site-packages so every interpreter startup injects reachable nameservers:

```bash
cp extras/sitecustomize.py "$PREFIX/lib/python3.14/site-packages/"
```

Adjust the Python version in the path as needed. After that, socialscan, maigret and theHarvester perform real queries (verified: maigret returning 75+ accounts where it previously returned 0).

## Troubleshooting

- **Doctor says a tool is missing** — install it; the TUI degrades gracefully and only skips that step.
- **crt.sh returns 502** — that is crt.sh itself being overloaded, not the toolkit. Retry later.
- **socialscan shows `QueryError - Could not retrieve token`** — platform-side rate limiting on your IP for GitHub/Instagram/Reddit; wait or route via Tor/proxy.
- **asnmap needs a free ProjectDiscovery key** — run `asnmap -auth` once, or set `PDCP_API_KEY`. Everything else works without keys.
- **onionsearch needs Tor running** — the TUI starts it automatically (direct, then Snowflake fallback); the `osint dark` wrapper expects Tor already listening on `127.0.0.1:9050`.
- **theHarvester source lists** — engine names change between versions; the current defaults (`otx,rapiddns,duckduckgo,crtsh`) are validated against v5.0.0.
- **Dork search returns nothing** — DuckDuckGo rate-limits automated queries from one IP (`HTTP 202`); wait a few minutes and retry. Dorking via Tor exits is blocked by DDG (`403`), so use a direct connection.

## Disclaimer

Intended for authorized security research, penetration testing, and investigation of your own accounts and infrastructure. All data accessed is public. You are responsible for complying with the laws and terms of service that apply to you.

## License

MIT — see [LICENSE](LICENSE).
