#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-
"""
JenabSint — interactive OSINT console for Termux.

A friendly menu front-end over the installed OSINT toolchain
(sherlock, blackbird, holehe, maigret, subfinder, amass, dnsx, httpx,
katana, nuclei, theHarvester, phoneinfoga, gitleaks, ...). Pure stdlib.

Run:   jenabsint          (installed launcher)
   or: python3 ~/JenabSint/jenabsint.py
"""

import itertools
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

VERSION = "1.2"

HOME = Path.home()
GOBIN = HOME / "go" / "bin"
OUT_BASE = Path(os.environ.get("OSINT_OUT", str(HOME / "osint-out")))
SUB_WORDLIST = HOME / "wordlists" / "dns" / "bitquark-100k.txt"
SUB_WORDLIST_FALLBACK = HOME / "wordlists" / "dns" / "subdomains-20k.txt"
WEB_WORDLIST = HOME / "wordlists" / "web" / "common.txt"

ENV = os.environ.copy()
ENV["PATH"] = str(GOBIN) + os.pathsep + ENV.get("PATH", "")
ENV["PYTHONIOENCODING"] = "utf-8"

TTY = sys.stdout.isatty()


# --------------------------------------------------------------------------
# ANSI / output helpers
# --------------------------------------------------------------------------

def _c(code: str) -> str:
    return f"\033[{code}m" if TTY else ""

RST = _c("0"); BOLD = _c("1"); DIM = _c("2")
RED = _c("31"); GRN = _c("32"); YEL = _c("33"); BLU = _c("34")
MAG = _c("35"); CYN = _c("36"); WHT = _c("37")
BRED = _c("91"); BGRN = _c("92"); BYEL = _c("93")
BBLU = _c("94"); BMAG = _c("95"); BCYN = _c("96")
GRAY = _c("90")


class BackToMenu(Exception):
    """Raised on Ctrl+C inside a prompt — return to the main menu."""


def out(text: str = "") -> None:
    print(text)


def clear() -> None:
    if TTY:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def trunc(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def term_width() -> int:
    try:
        return shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        return 80


def read_line(prompt: str):
    """input() that never crashes on EOF and turns Ctrl+C into BackToMenu."""
    try:
        return input(prompt)
    except EOFError:
        print()
        raise SystemExit(0)
    except KeyboardInterrupt:
        print()
        raise BackToMenu


def ask(prompt: str, default: str = "") -> str:
    """Prompt for a non-empty value (default allowed). Returns stripped text."""
    while True:
        suffix = f" {GRAY}[{default}]{RST}" if default else ""
        val = read_line(f"  {BCYN}›{RST} {prompt}{suffix}: ").strip()
        if val:
            return val
        if default:
            return default


def pause(msg: str = "Press Enter to return") -> None:
    read_line(f"\n  {GRAY}{msg}…{RST}")


def ok(msg: str) -> None:
    out(f"  {BGRN}✓{RST} {msg}")


def bad(msg: str) -> None:
    out(f"  {BRED}✗{RST} {msg}")


def warn(msg: str) -> None:
    out(f"  {BYEL}⚠{RST} {msg}")


def note(msg: str) -> None:
    out(f"  {GRAY}·{RST} {GRAY}{msg}{RST}")


# --------------------------------------------------------------------------
# Spinner animation
# --------------------------------------------------------------------------

class Spinner:
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, label: str):
        self.label = trunc(label, max(16, term_width() - 24))
        self._stop = threading.Event()
        self._thread = None
        self.t0 = time.time()

    def start(self) -> "Spinner":
        self.t0 = time.time()
        if TTY:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def _spin(self) -> None:
        for frame in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            elapsed = time.time() - self.t0
            sys.stdout.write(f"\r  {BCYN}{frame}{RST} {self.label} "
                             f"{GRAY}[{elapsed:5.1f}s]{RST}\033[K")
            sys.stdout.flush()
            time.sleep(0.09)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        if TTY:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()


# --------------------------------------------------------------------------
# Command execution
# --------------------------------------------------------------------------

class Result:
    def __init__(self, rc, secs, stdout="", stderr="", outfile=None):
        self.rc = rc
        self.secs = secs
        self.stdout = stdout or ""
        self.stderr = stderr or ""
        self.outfile = outfile

    @property
    def ok(self) -> bool:
        return self.rc == 0


TOR_MODE = False


def _kill_tree(proc) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def binary(name: str):
    return shutil.which(name, path=ENV.get("PATH", ""))


def run_tool(cmd, outfile=None, timeout=600, label=None, input_text=None):
    """
    Run an external tool with a live spinner. Captures stdout/stderr,
    optionally writes stdout to `outfile`. Never raises on tool errors;
    returns a Result. Ctrl+C kills the whole process group and re-raises
    KeyboardInterrupt so the caller can return to the menu.
    """
    cmd = list(cmd)
    bin_name = cmd[0]

    if not binary(bin_name):
        bad(f"{bin_name} is not installed — skipping")
        return Result(127, 0.0, outfile=outfile)

    if TOR_MODE and bin_name not in ("tor", "pkill", "proxychains4"):
        cmd = ["proxychains4"] + cmd

    label = label or bin_name
    out(f"  {GRAY}▸{RST} {label}")
    spinner = Spinner(label).start()
    t0 = time.time()
    rc, stdout_, stderr_ = None, "", ""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=ENV,
            start_new_session=True,
        )
        try:
            stdout_, stderr_ = proc.communicate(input=input_text, timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            stdout_, stderr_ = proc.communicate()
            rc = "timeout"
    except KeyboardInterrupt:
        try:
            _kill_tree(proc)
        except Exception:
            pass
        spinner.stop()
        bad(f"{label} — cancelled")
        raise KeyboardInterrupt
    finally:
        spinner.stop()

    secs = time.time() - t0

    if outfile is not None:
        body = stdout_ if stdout_.strip() else stderr_
        try:
            Path(outfile).write_text(body, encoding="utf-8", errors="replace")
        except OSError as exc:
            warn(f"could not write {outfile}: {exc}")

    if rc == 0:
        ok(f"{label} {GRAY}done in {secs:.1f}s{RST}")
    elif rc == "timeout":
        bad(f"{label} timed out after {timeout}s {GRAY}(partial output kept){RST}")
    else:
        warn(f"{label} exited with code {rc} in {secs:.1f}s")
        tail = (stderr_ or "").strip().splitlines()
        if tail:
            note(trunc(tail[-1], max(20, term_width() - 8)))

    return Result(rc, secs, stdout_, stderr_, outfile)


def wc_lines(path) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def read_lines(path, limit=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = [ln.rstrip("\n") for ln in fh]
    except OSError:
        return []
    return lines[:limit] if limit else lines


def write_lines(path, lines) -> None:
    try:
        Path(path).write_text("\n".join(lines) + ("\n" if lines else ""),
                              encoding="utf-8")
    except OSError as exc:
        warn(f"could not write {path}: {exc}")


def preview(path, limit=18, title=None) -> None:
    path = Path(path)
    if not path.exists():
        return
    lines = read_lines(path, limit=limit + 1)
    if not lines:
        note("(no output)")
        return
    shown = lines[:limit]
    out(f"  {DIM}┌─ {title or path.name} {GRAY}({path}){RST}")
    for ln in shown:
        out(f"  {DIM}│{RST} {trunc(ln, max(20, term_width() - 6))}")
    if len(lines) > limit:
        out(f"  {DIM}│ … more in file{RST}")
    out(f"  {DIM}└─{RST}")


def make_outdir(category: str, target: str) -> Path:
    safe = re.sub(r"[^\w.@+-]", "_", str(target))[:60] or "target"
    d = OUT_BASE / category / f"{datetime.now():%Y%m%d-%H%M%S}-{safe}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def summary_box(target: str, outdir: Path, n_found: int = None,
                label: str = "results") -> None:
    out()
    out(f"  {BOLD}{BGRN}✔ done{RST}  {GRAY}target:{RST} {target}")
    if n_found is not None:
        out(f"         {label}: {BOLD}{n_found}{RST}")
    out(f"         {GRAY}saved to:{RST} {outdir}")
    out()


# --------------------------------------------------------------------------
# Domain-agnostic building blocks shared by actions / tool menu
# --------------------------------------------------------------------------

def tor_prefix():
    return ["proxychains4"] if TOR_MODE else []


def subfinder_out(domain, outdir, label=None):
    f = outdir / "subs_subfinder.txt"
    r = run_tool(["subfinder", "-d", domain, "-silent", "-o", str(f)],
                 outfile=outdir / "subfinder.stdout.txt",
                 timeout=600, label=label or f"subfinder — {domain}")
    n = wc_lines(f) if r.ok else 0
    return n


def assetfinder_out(domain, outdir, label=None):
    f = outdir / "subs_assetfinder.txt"
    r = run_tool(["assetfinder", "--subs-only", domain], outfile=f,
                 timeout=300, label=label or f"assetfinder — {domain}")
    n = wc_lines(f) if r.ok else 0
    return n


def crtsh_out(domain, outdir, label=None):
    f = outdir / "subs_crtsh.txt"
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = run_tool(["curl", "-s", "--max-time", "60", url],
                 outfile=outdir / "crtsh.raw.json", timeout=90,
                 label=label or f"crt.sh — {domain}")
    names = set()
    if r.ok and r.stdout.strip():
        try:
            for entry in json.loads(r.stdout):
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name:
                        names.add(name)
        except (json.JSONDecodeError, AttributeError, TypeError):
            warn("crt.sh returned unexpected data")
    lines = sorted(names)
    write_lines(f, lines)
    return len(lines)


def merge_subs(domain, outdir) -> int:
    merged = set()
    for src in ("subs_subfinder.txt", "subs_assetfinder.txt", "subs_crtsh.txt"):
        for ln in read_lines(outdir / src):
            ln = ln.strip().lower().lstrip("*.")
            if ln and (ln == domain or ln.endswith("." + domain)):
                merged.add(ln)
    lines = sorted(merged)
    write_lines(outdir / "subs_all.txt", lines)
    return len(lines)


def dnsx_resolve(outdir, label=None):
    src = outdir / "subs_all.txt"
    dst = outdir / "dns_resolved.txt"
    if wc_lines(src) == 0:
        warn("no subdomains to resolve")
        return 0
    r = run_tool(["dnsx", "-silent", "-l", str(src), "-a", "-resp"],
                 outfile=dst, timeout=900,
                 label=label or "dnsx — resolving subdomains")
    return wc_lines(dst) if r.ok else 0


def httpx_probe(outdir, label=None):
    src = outdir / "subs_all.txt"
    dst = outdir / "httpx.txt"
    if wc_lines(src) == 0:
        warn("no hosts to probe")
        return 0
    r = run_tool(["httpx", "-silent", "-l", str(src), "-status-code", "-title",
                  "-tech-detect", "-timeout", "8", "-retries", "1", "-o", str(dst)],
                 outfile=outdir / "httpx.stdout.txt", timeout=900,
                 label=label or "httpx — probing live hosts")
    return wc_lines(dst) if r.ok else 0


def whois_out(target, outdir, label=None):
    return run_tool(["whois", target], outfile=outdir / "whois.txt",
                    timeout=120, label=label or f"whois — {target}")


def dig_records(target, outdir) -> Path:
    dst = outdir / "dns_records.txt"
    chunks = []
    for rtype in ("A", "NS", "MX", "TXT"):
        r = run_tool(["dig", "+short", rtype, target],
                     timeout=60, label=f"dig {rtype} — {target}")
        chunks.append(f"== {rtype} ==\n{(r.stdout or '').strip()}")
    write_lines(dst, "\n".join(chunks).splitlines())
    return dst


# --------------------------------------------------------------------------
# Actions — the main workflows
# --------------------------------------------------------------------------

def act_username():
    user = ask("Username to search")
    outdir = make_outdir("users", user)
    hits = None

    if binary("sherlock"):
        r = run_tool(["sherlock", user, "--timeout", "10", "--print-found",
                      "--no-color", "--txt", "-o", str(outdir / "sherlock.txt")],
                     outfile=outdir / "sherlock.stdout.txt", timeout=900,
                     label=f"sherlock — hunting '{user}'")
        sf = outdir / "sherlock.txt"
        if sf.exists():
            hits = sum(1 for ln in read_lines(sf) if ln.startswith("http"))
            ok(f"sherlock found {hits} profile(s)")

    run_tool(["socialscan", user], outfile=outdir / "socialscan.txt",
             timeout=300, label=f"socialscan — '{user}'")

    if binary("maigret"):
        run_tool(["maigret", user, "--top-sites", "200", "--timeout", "15",
                  "--folderoutput", str(outdir / "maigret"),
                  "--no-progressbar", "--no-color"],
                 outfile=outdir / "maigret.stdout.txt", timeout=1800,
                 label=f"maigret — '{user}' (200 sites)")

    if binary("blackbird"):
        run_tool(["bash", "-lc",
                  f"cd {shlex.quote(str(outdir))} && blackbird -u {shlex.quote(user)} --csv"],
                 outfile=outdir / "blackbird.stdout.txt", timeout=900,
                 label=f"blackbird — '{user}' (600+ sites)")

    summary_box(user, outdir, hits, "sherlock hits")
    primary = outdir / "sherlock.txt" if wc_lines(outdir / "sherlock.txt") else outdir / "socialscan.txt"
    preview(primary, limit=18)


def act_email():
    email = ask("Email address")
    outdir = make_outdir("emails", email)

    if binary("holehe"):
        run_tool(["holehe", "--only-used", "--no-color", email],
                 outfile=outdir / "holehe.txt", timeout=300,
                 label=f"holehe — {email}")
    run_tool(["socialscan", email], outfile=outdir / "socialscan.txt",
             timeout=300, label=f"socialscan — {email}")

    if binary("blackbird"):
        run_tool(["bash", "-lc",
                  f"cd {shlex.quote(str(outdir))} && blackbird -e {shlex.quote(email)} --csv"],
                 outfile=outdir / "blackbird.stdout.txt", timeout=900,
                 label=f"blackbird — {email} (600+ sites)")

    summary_box(email, outdir)
    preview(outdir / "holehe.txt", limit=18)


def act_domain():
    domain = ask("Domain (e.g. target.com)").lower().lstrip("*.")
    outdir = make_outdir("domains", domain)

    n_sub = subfinder_out(domain, outdir)
    n_asset = assetfinder_out(domain, outdir)
    n_crt = crtsh_out(domain, outdir)
    n_all = merge_subs(domain, outdir)
    ok(f"subdomains — subfinder:{n_sub}  assetfinder:{n_asset}  "
       f"crt.sh:{n_crt}  unique:{n_all}")

    whois_out(domain, outdir)
    dig_records(domain, outdir)

    n_res = dnsx_resolve(outdir)
    n_live = httpx_probe(outdir)

    summary_box(domain, outdir, n_live, "live hosts")
    preview(outdir / "httpx.txt", limit=20)


def act_brute():
    domain = ask("Domain to brute-force").lower().lstrip("*.")
    outdir = make_outdir("brute", domain)
    wordlist = SUB_WORDLIST if SUB_WORDLIST.exists() else SUB_WORDLIST_FALLBACK
    if not wordlist.exists():
        warn("no DNS wordlist found in ~/wordlists — skipping")
        return

    run_tool(["dnsx", "-d", domain, "-w", str(wordlist), "-silent",
              "-a", "-resp", "-t", "40"],
             outfile=outdir / "resolved.txt", timeout=1200,
             label=f"dnsx brute — {wordlist.name}")
    n_res = wc_lines(outdir / "resolved.txt")
    ok(f"resolved: {n_res}")

    hosts = []
    for ln in read_lines(outdir / "resolved.txt"):
        parts = ln.split()
        if parts:
            hosts.append(parts[0])
    hosts = sorted(set(hosts))[:2000]

    if hosts and binary("dnsgen") and binary("dnsx"):
        r = run_tool(["dnsgen", "-"], input_text="\n".join(hosts) + "\n",
                     outfile=outdir / "permutations_candidates.txt",
                     timeout=300, label="dnsgen — permutations")
        if r.ok and r.stdout.strip():
            run_tool(["dnsx", "-silent", "-a", "-resp", "-t", "40"],
                     input_text=r.stdout, outfile=outdir / "permutations.txt",
                     timeout=900, label="dnsx — resolving permutations")
            ok(f"permutations resolved: {wc_lines(outdir / 'permutations.txt')}")

    summary_box(domain, outdir, n_res, "resolved hosts")
    preview(outdir / "resolved.txt", limit=18)


def act_urls():
    domain = ask("Domain (historical URLs)").lower().lstrip("*.")
    outdir = make_outdir("urls", domain)

    if binary("waybackurls"):
        run_tool(["waybackurls"], input_text=domain + "\n",
                 outfile=outdir / "waybackurls.txt", timeout=600,
                 label=f"waybackurls — {domain}")
    if binary("gau"):
        run_tool(["gau", "--threads", "5", domain],
                 outfile=outdir / "gau.txt", timeout=900,
                 label=f"gau — {domain}")

    merged = set()
    for src in ("waybackurls.txt", "gau.txt"):
        merged.update(ln for ln in read_lines(outdir / src) if ln.strip())
    lines = sorted(merged)
    write_lines(outdir / "all_urls.txt", lines)

    summary_box(domain, outdir, len(lines), "unique URLs")
    preview(outdir / "all_urls.txt", limit=15)


def act_crawl():
    url = ask("URL to crawl (https://…)")
    if not re.match(r"^https?://", url):
        url = "https://" + url
    outdir = make_outdir("crawls", url)
    run_tool(["katana", "-u", url, "-d", "3", "-silent", "-o",
              str(outdir / "urls.txt")],
             outfile=outdir / "katana.stdout.txt", timeout=900,
             label=f"katana — crawling {url} (depth 3)")
    n = wc_lines(outdir / "urls.txt")
    summary_box(url, outdir, n, "URLs crawled")
    preview(outdir / "urls.txt", limit=15)


def act_ip():
    target = ask("IP address or hostname")
    outdir = make_outdir("ips", target)

    whois_out(target, outdir)
    chunks = []
    for q, flag in (("reverse DNS", "-x"), ("A", None)):
        args = ["dig", "+short"]
        if flag:
            args.append(flag)
        args.append(target)
        r = run_tool(args, timeout=60, label=f"dig — {q} {target}")
        chunks.append(f"== {q} ==\n{(r.stdout or '').strip()}")
    write_lines(outdir / "dns.txt", "\n".join(chunks).splitlines())

    if binary("nmap"):
        run_tool(["nmap", "-Pn", "-T4", "--top-ports", "1000", "-oN",
                  str(outdir / "nmap.txt"), target],
                 outfile=outdir / "nmap.stdout.txt", timeout=900,
                 label=f"nmap — top 1000 ports on {target}")
        try:
            nmap_txt = (outdir / "nmap.txt").read_text(errors="replace")
        except OSError:
            nmap_txt = ""
        open_ports = len(re.findall(r"\d+/tcp\s+open", nmap_txt))
        ok(f"open ports: {open_ports}")

    summary_box(target, outdir)
    preview(outdir / "nmap.txt", limit=22, title="nmap.txt")


def act_phone():
    number = ask("Phone number in E.164 format (+countrycode…)")
    outdir = make_outdir("phones", number)
    run_tool(["phoneinfoga", "scan", "-n", number],
             outfile=outdir / "scan.txt", timeout=300,
             label=f"phoneinfoga — {number}")
    summary_box(number, outdir)
    lines = read_lines(outdir / "scan.txt")
    tail = lines[-16:]
    out(f"  {DIM}┌─ phoneinfoga tail{RST}")
    for ln in tail:
        out(f"  {DIM}│{RST} {trunc(ln, max(20, term_width() - 6))}")
    out(f"  {DIM}└─{RST}")


def act_meta():
    path = Path(ask("File path").replace("\\ ", " ")).expanduser()
    if not path.exists():
        bad(f"no such file: {path}")
        return
    outdir = make_outdir("meta", path.name)
    if not binary("exiftool"):
        warn("exiftool is not installed — skipping")
        return
    run_tool(["exiftool", "-a", "-G1", "-s", str(path)],
             outfile=outdir / "metadata.txt", timeout=120,
             label=f"exiftool — {path.name}")
    interesting = [ln for ln in read_lines(outdir / "metadata.txt")
                   if re.search(r"gps|author|creator|artist|software|date|make|model",
                                ln, re.I)]
    summary_box(path.name, outdir)
    if interesting:
        preview_lines = interesting[:16]
        out(f"  {DIM}┌─ highlights{RST}")
        for ln in preview_lines:
            out(f"  {DIM}│{RST} {trunc(ln, max(20, term_width() - 6))}")
        out(f"  {DIM}└─{RST}")
    else:
        preview(outdir / "metadata.txt", limit=16)


def act_harvester():
    domain = ask("Domain").lower().lstrip("*.")
    outdir = make_outdir("harvester", domain)
    if not binary("theHarvester"):
        warn("theHarvester is not installed — skipping")
        return
    run_tool(["theHarvester", "-d", domain, "-b", "otx,rapiddns,duckduckgo,crtsh",
              "-l", "200", "-r", "-f", str(outdir / "report")],
             outfile=outdir / "harvester.log", timeout=600,
             label=f"theHarvester — {domain}")
    summary_box(domain, outdir)
    lines = read_lines(outdir / "harvester.log")
    tail = lines[-14:]
    out(f"  {DIM}┌─ harvester tail{RST}")
    for ln in tail:
        out(f"  {DIM}│{RST} {trunc(ln, max(20, term_width() - 6))}")
    out(f"  {DIM}└─{RST}")


def act_shodan():
    if not binary("shodan"):
        warn("shodan CLI is not installed — skipping")
        return
    probe = run_tool(["shodan", "info"], timeout=60, label="shodan — API check")
    if not probe.ok:
        warn("Shodan API key is not configured.")
        note("run once:  shodan init <YOUR_API_KEY>")
        return
    query = ask("Shodan query (e.g. apache country:DE port:80)")
    outdir = make_outdir("shodan", re.sub(r"\W+", "_", query)[:40])
    run_tool(["shodan", "search", "--fields",
              "ip_str,port,org,hostnames,product", query],
             outfile=outdir / "results.txt", timeout=300,
             label=f"shodan — {query}")
    n = wc_lines(outdir / "results.txt")
    summary_box(query, outdir, n, "rows")
    preview(outdir / "results.txt", limit=18)


# --------------------------------------------------------------------------
# Individual tools menu
# --------------------------------------------------------------------------

def t_sherlock(t, d):
    f = d / "sherlock.txt"
    return run_tool(["sherlock", t, "--timeout", "10", "--print-found",
                     "--no-color", "--txt", "-o", str(f)],
                    outfile=d / "sherlock.stdout.txt", timeout=900,
                    label=f"sherlock — {t}"), f


def t_maigret(t, d):
    return run_tool(["maigret", t, "--top-sites", "200", "--timeout", "15",
                     "--folderoutput", str(d / "maigret"),
                     "--no-progressbar", "--no-color"],
                    outfile=d / "maigret.stdout.txt", timeout=1800,
                    label=f"maigret — {t}"), d / "maigret.stdout.txt"


def t_socialscan(t, d):
    return run_tool(["socialscan", t], outfile=d / "socialscan.txt",
                    timeout=300, label=f"socialscan — {t}"), d / "socialscan.txt"


def t_holehe(t, d):
    return run_tool(["holehe", "--only-used", "--no-color", t],
                    outfile=d / "holehe.txt", timeout=300,
                    label=f"holehe — {t}"), d / "holehe.txt"


def t_subfinder(t, d):
    f = d / "subs_subfinder.txt"
    return run_tool(["subfinder", "-d", t, "-silent", "-o", str(f)],
                    outfile=d / "subfinder.stdout.txt", timeout=600,
                    label=f"subfinder — {t}"), f


def t_amass(t, d):
    return run_tool(["amass", "enum", "-d", t, "-timeout", "10"],
                    outfile=d / "amass.txt", timeout=1200,
                    label=f"amass — {t} (up to 10 min)"), d / "amass.txt"


def t_assetfinder(t, d):
    f = d / "subs_assetfinder.txt"
    return run_tool(["assetfinder", "--subs-only", t], outfile=f,
                    timeout=300, label=f"assetfinder — {t}"), f


def t_dnsx_brute(t, d):
    wl = SUB_WORDLIST if SUB_WORDLIST.exists() else SUB_WORDLIST_FALLBACK
    return run_tool(["dnsx", "-d", t, "-w", str(wl), "-silent", "-a", "-resp",
                     "-t", "40"],
                    outfile=d / "resolved.txt", timeout=1200,
                    label=f"dnsx brute — {t}"), d / "resolved.txt"


def t_httpx(t, d):
    return run_tool(["httpx", "-u", t, "-silent", "-status-code", "-title",
                     "-tech-detect"],
                    outfile=d / "httpx.txt", timeout=300,
                    label=f"httpx — {t}"), d / "httpx.txt"


def t_naabu(t, d):
    return run_tool(["naabu", "-host", t, "-silent"],
                    outfile=d / "ports.txt", timeout=600,
                    label=f"naabu — {t}"), d / "ports.txt"


def t_katana(t, d):
    return run_tool(["katana", "-u", t if re.match(r"^https?://", t) else "https://" + t,
                     "-d", "3", "-silent", "-o", str(d / "urls.txt")],
                    outfile=d / "katana.stdout.txt", timeout=900,
                    label=f"katana — {t}"), d / "urls.txt"


def t_nuclei(t, d):
    tpl = HOME / "nuclei-templates"
    if not tpl.exists():
        warn("nuclei templates not found — use 'nuclei: update templates' first")
        note("nuclei will try to auto-download on first scan")
    return run_tool(["nuclei", "-u", t if re.match(r"^https?://", t) else "https://" + t,
                     "-silent"],
                    outfile=d / "nuclei.txt", timeout=1800,
                    label=f"nuclei — {t}"), d / "nuclei.txt"


def t_nuclei_update(_t, d):
    return run_tool(["nuclei", "-update-templates"], outfile=d / "update.txt",
                    timeout=1800, label="nuclei — downloading templates (~250MB)"), d / "update.txt"


def t_ffuf(t, d):
    wl = WEB_WORDLIST
    if not wl.exists():
        warn("web wordlist missing — run: pkg install nothing, see ~/wordlists")
        return None, None
    return run_tool(["ffuf", "-u", t, "-w", str(wl), "-mc", "200,301,302,403",
                     "-s"],
                    outfile=d / "ffuf.txt", timeout=900,
                    label=f"ffuf — {t}"), d / "ffuf.txt"


def t_gau(t, d):
    return run_tool(["gau", "--threads", "5", t], outfile=d / "gau.txt",
                    timeout=900, label=f"gau — {t}"), d / "gau.txt"


def t_waybackurls(t, d):
    return run_tool(["waybackurls"], input_text=t + "\n",
                    outfile=d / "waybackurls.txt", timeout=600,
                    label=f"waybackurls — {t}"), d / "waybackurls.txt"


def t_phoneinfoga(t, d):
    return run_tool(["phoneinfoga", "scan", "-n", t],
                    outfile=d / "scan.txt", timeout=300,
                    label=f"phoneinfoga — {t}"), d / "scan.txt"


def t_harvester(t, d):
    return run_tool(["theHarvester", "-d", t, "-b", "otx,rapiddns,duckduckgo,crtsh",
                     "-l", "200", "-r", "-f", str(d / "report")],
                    outfile=d / "harvester.log", timeout=600,
                    label=f"theHarvester — {t}"), d / "harvester.log"


def t_amass_note(t, d):
    return t_amass(t, d)


def t_nmap(t, d):
    return run_tool(["nmap", "-Pn", "-T4", "--top-ports", "1000", "-oN",
                     str(d / "nmap.txt"), t],
                    outfile=d / "nmap.stdout.txt", timeout=900,
                    label=f"nmap — {t}"), d / "nmap.txt"


def t_whois(t, d):
    return run_tool(["whois", t], outfile=d / "whois.txt", timeout=120,
                    label=f"whois — {t}"), d / "whois.txt"


def t_dig(t, d):
    chunks = []
    for rtype in ("A", "NS", "MX", "TXT"):
        r = run_tool(["dig", "+short", rtype, t], timeout=60,
                     label=f"dig {rtype} — {t}")
        chunks.append(f"== {rtype} ==\n{(r.stdout or '').strip()}")
    dst = d / "dns_records.txt"
    write_lines(dst, "\n".join(chunks).splitlines())
    return Result(0, 0.0, outfile=dst), dst


def t_exiftool(t, d):
    f = Path(t).expanduser()
    if not f.exists():
        bad(f"no such file: {f}")
        return None, None
    return run_tool(["exiftool", "-a", "-G1", "-s", str(f)],
                    outfile=d / "metadata.txt", timeout=120,
                    label=f"exiftool — {f.name}"), d / "metadata.txt"


def t_shodan(t, d):
    return run_tool(["shodan", "search", "--fields",
                     "ip_str,port,org,hostnames,product", t],
                    outfile=d / "results.txt", timeout=300,
                    label=f"shodan — {t}"), d / "results.txt"


def t_crtsh(t, d):
    run_tool(["curl", "-s", "--max-time", "60",
              f"https://crt.sh/?q=%25.{t}&output=json"],
             outfile=d / "crtsh.raw.json", timeout=90, label=f"crt.sh — {t}")
    names = set()
    try:
        data = json.loads((d / "crtsh.raw.json").read_text(errors="replace") or "[]")
        for entry in data:
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name:
                    names.add(name)
    except (json.JSONDecodeError, AttributeError, TypeError, OSError):
        warn("crt.sh returned unexpected data")
    write_lines(d / "subs_crtsh.txt", sorted(names))
    return Result(0, 0.0, outfile=d / "subs_crtsh.txt"), d / "subs_crtsh.txt"


def t_custom(_t, d):
    cmd = ask("Shell command (runs via bash -lc)")
    return run_tool(["bash", "-lc", cmd], outfile=d / "custom_output.txt",
                    timeout=900, label=f"bash — {trunc(cmd, 40)}"), d / "custom_output.txt"


def t_blackbird(t, d):
    flag = "-e" if "@" in t else "-u"
    return run_tool(["bash", "-lc",
                     f"cd {shlex.quote(str(d))} && blackbird {flag} {shlex.quote(t)} --csv"],
                    outfile=d / "blackbird.txt", timeout=900,
                    label=f"blackbird — {t}"), d / "blackbird.txt"


def t_socid(t, d):
    return run_tool(["socid_extractor", "--url", t, "-v"],
                    outfile=d / "socid.txt", timeout=180,
                    label=f"socid_extractor — {t}"), d / "socid.txt"


def t_instaloader(t, d):
    profile = t.strip().lstrip("@").strip("/")
    return run_tool(["bash", "-lc",
                     f"cd {shlex.quote(str(d))} && instaloader --no-videos --count 25 {shlex.quote(profile)}"],
                    outfile=d / "instaloader.txt", timeout=900,
                    label=f"instaloader — @{profile}"), d / "instaloader.txt"


def t_dnsrecon(t, d):
    return run_tool(["dnsrecon", "-d", t], outfile=d / "dnsrecon.txt",
                    timeout=600, label=f"dnsrecon — {t}"), d / "dnsrecon.txt"


def t_dnstwist(t, d):
    return run_tool(["dnstwist", "--registered", "--format", "csv",
                     "-o", str(d / "dnstwist.csv"), t],
                    outfile=d / "dnstwist.stdout.txt", timeout=600,
                    label=f"dnstwist — {t}"), d / "dnstwist.csv"


def t_cloudenum(t, d):
    keyword = t.split(".")[0]
    return run_tool(["cloud_enum", "-k", keyword, "-l", str(d / "cloud_enum.txt")],
                    outfile=d / "cloud_enum.stdout.txt", timeout=900,
                    label=f"cloud_enum — '{keyword}'"), d / "cloud_enum.txt"


def t_wafw00f(t, d):
    url = t if t.startswith(("http://", "https://")) else "https://" + t
    return run_tool(["wafw00f", url], outfile=d / "wafw00f.txt",
                    timeout=180, label=f"wafw00f — {url}"), d / "wafw00f.txt"


def t_waymore(t, d):
    return run_tool(["waymore", "-i", t, "-mode", "U", "-oU", str(d / "urls.txt"),
                     "-t", "15", "-p", "3"],
                    outfile=d / "waymore.stdout.txt", timeout=900,
                    label=f"waymore — {t}"), d / "urls.txt"


def t_onionsearch(t, d):
    if not tor_ready():
        out(f"  {DIM}Tor is not running — starting it (Snowflake fallback if needed)…{RST}")
        if not start_tor():
            warn("could not bring Tor up — skipping onionsearch")
            return None, None
    return run_tool(["onionsearch", t, "--output", str(d / "onionsearch.txt"),
                     "--limit", "2", "--mp_units", "2", "--continuous_write", "1"],
                    outfile=d / "onionsearch.stdout.txt", timeout=600,
                    label=f"onionsearch — '{t}' via Tor"), d / "onionsearch.txt"


def t_xnlinkfinder(t, d):
    url = t if t.startswith(("http://", "https://")) else "https://" + t
    return run_tool(["xnLinkFinder", "-i", url, "-o", str(d / "links.txt")],
                    outfile=d / "xnLinkFinder.txt", timeout=600,
                    label=f"xnLinkFinder — {url}"), d / "links.txt"


def t_gitleaks(t, d):
    path = str(Path(t).expanduser())
    return run_tool(["gitleaks", "dir", path, "--report-format", "json",
                     "--report-path", str(d / "leaks.json"), "-v"],
                    outfile=d / "gitleaks.log", timeout=900,
                    label=f"gitleaks — {path}"), d / "leaks.json"


def t_ddgr(t, d):
    f = d / "dorks.json"
    r = run_tool(["ddgr", "--json", "--noprompt", "--num", "15", t],
                 outfile=f, timeout=120, label=f"ddgr — {t}")
    txt = d / "dorks.txt"
    try:
        rows = json.loads(Path(f).read_text(encoding="utf-8", errors="replace") or "[]")
    except Exception:
        rows = None
    if rows:
        txt.write_text("".join(f"{x.get('title','')} — {x.get('url','')}\n" for x in rows),
                       encoding="utf-8")
    else:
        txt.write_text("(no results — DuckDuckGo may be rate-limiting this IP; "
                       "retry in a few minutes)\n", encoding="utf-8")
    return r, d / "dorks.txt"


def t_ipinfo(t, d):
    return run_tool(["ipinfo", t], outfile=d / "ipinfo.txt", timeout=120,
                    label=f"ipinfo — {t}"), d / "ipinfo.txt"


def t_asnmap(t, d):
    return run_tool(["asnmap", "-d", t, "-silent"], outfile=d / "asnmap.txt",
                    timeout=300, label=f"asnmap — {t} (needs PDCP key)"), d / "asnmap.txt"


def t_cdncheck(t, d):
    return run_tool(["bash", "-lc", f"echo {shlex.quote(t)} | cdncheck -resp"],
                    outfile=d / "cdncheck.txt", timeout=120,
                    label=f"cdncheck — {t}"), d / "cdncheck.txt"


def t_tlsx(t, d):
    return run_tool(["tlsx", "-u", t, "-silent", "-cn", "-san"],
                    outfile=d / "tlsx.txt", timeout=180,
                    label=f"tlsx — {t}"), d / "tlsx.txt"


def t_alterx(t, d):
    return run_tool(["bash", "-lc", f"echo {shlex.quote(t)} | alterx -silent"],
                    outfile=d / "alterx.txt", timeout=120,
                    label=f"alterx — {t}"), d / "alterx.txt"


TOOL_MENU = [
    ("— usernames & emails —", None),
    ("sherlock", "username → 400+ sites", "Username", "users", t_sherlock),
    ("maigret", "username → 200 sites, reports", "Username", "users", t_maigret),
    ("blackbird", "username/email → 600+ sites (CSV)", "Username or email", "users", t_blackbird),
    ("socialscan", "username/email availability", "Username or email", "users", t_socialscan),
    ("holehe", "email → registered accounts", "Email", "emails", t_holehe),
    ("socid_extractor", "profile URL → emails/phones/names", "Profile URL", "users", t_socid),
    ("instaloader", "Instagram profile → posts/media", "Instagram username", "users", t_instaloader),
    ("— domains & dns —", None),
    ("subfinder", "passive subdomain enum", "Domain", "tools", t_subfinder),
    ("amass", "deep subdomain enum (slow)", "Domain", "tools", t_amass_note),
    ("assetfinder", "passive subdomains", "Domain", "tools", t_assetfinder),
    ("crt.sh", "certificate transparency", "Domain", "tools", t_crtsh),
    ("dnsx", "brute-force with 100k wordlist", "Domain", "tools", t_dnsx_brute),
    ("dig", "A / NS / MX / TXT records", "Domain", "tools", t_dig),
    ("dnsrecon", "standard DNS enum (+ zone transfer)", "Domain", "domains", t_dnsrecon),
    ("dnstwist", "typosquat / look-alike domains", "Domain", "domains", t_dnstwist),
    ("alterx", "subdomain permutation generator", "Domain", "tools", t_alterx),
    ("tlsx", "TLS certificate intel (CN/SAN)", "Host or domain", "tools", t_tlsx),
    ("cdncheck", "CDN / WAF detection", "Host or IP", "tools", t_cdncheck),
    ("asnmap", "domain/IP → ASN + CIDR (PDCP key)", "Domain or IP", "tools", t_asnmap),
    ("— web —", None),
    ("httpx", "probe status/title/tech", "URL or host", "tools", t_httpx),
    ("katana", "crawl site (depth 3)", "URL", "tools", t_katana),
    ("nuclei", "vulnerability scan", "URL", "tools", t_nuclei),
    ("nuclei-update", "download templates (~250MB)", "", "tools", t_nuclei_update),
    ("ffuf", "directory fuzz (wordlist FUZZ)", "URL containing FUZZ", "tools", t_ffuf),
    ("wafw00f", "detect WAF vendor", "URL or host", "tools", t_wafw00f),
    ("gau", "historical URLs", "Domain", "tools", t_gau),
    ("waybackurls", "Wayback Machine URLs", "Domain", "tools", t_waybackurls),
    ("waymore", "deep URL harvest (wayback + CC)", "Domain", "urls", t_waymore),
    ("xnLinkFinder", "links/params from JS & pages", "URL", "urls", t_xnlinkfinder),
    ("ddgr", "DuckDuckGo dork search (JSON)", "Dork query", "tools", t_ddgr),
    ("— network & misc —", None),
    ("naabu", "port scan (top 100)", "Host", "tools", t_naabu),
    ("nmap", "top 1000 ports", "Host", "tools", t_nmap),
    ("whois", "registration data", "Domain or IP", "tools", t_whois),
    ("shodan", "Shodan search", "Query", "tools", t_shodan),
    ("ipinfo", "IP / ASN / geo intel", "IP, ASN or host", "ip", t_ipinfo),
    ("phoneinfoga", "phone footprint", "+E.164 number", "tools", t_phoneinfoga),
    ("theHarvester", "emails/hosts via search engines", "Domain", "tools", t_harvester),
    ("exiftool", "file metadata", "File path", "tools", t_exiftool),
    ("gitleaks", "secrets in a local directory", "Local directory", "tools", t_gitleaks),
    ("— dark web & cloud —", None),
    ("onionsearch", "search .onion engines via Tor", "Search query", "tools", t_onionsearch),
    ("cloud_enum", "public S3/Azure/GCP storage", "Domain (keyword used)", "tools", t_cloudenum),
    ("— custom —", None),
    ("custom", "run any shell command", "", "tools", t_custom),
]


def menu_individual():
    entries = []          # ("header", text) or ("tool", (number, item))
    for item in TOOL_MENU:
        if item[1] is None:
            entries.append(("header", item[0]))
        else:
            n = sum(1 for e in entries if e[0] == "tool") + 1
            entries.append(("tool", (n, item)))
    while True:
        clear()
        out(f"  {BOLD}{BCYN}INDIVIDUAL TOOLS{RST}   {GRAY}single tools with sensible defaults{RST}")
        out()
        for kind, payload in entries:
            if kind == "header":
                out(f"  {GRAY}{payload}{RST}")
            else:
                n, (name, desc, _p, _c, _fn) = payload
                out(f"   {BOLD}{n:>2}{RST}  {name:<13}{GRAY}{desc}{RST}")
        out()
        out(f"   {BOLD} b{RST}  {GRAY}back to main menu{RST}")
        choice = read_line(f"  {BCYN}›{RST} tool number: ").strip().lower()
        if choice in ("b", "back", "q"):
            return
        if not choice.isdigit():
            continue
        n = int(choice)
        picked = None
        for kind, payload in entries:
            if kind == "tool" and payload[0] == n:
                picked = payload[1]
                break
        if not picked:
            continue
        name, desc, prompt, category, fn = picked
        target = ask(prompt) if prompt else "custom"
        outdir = make_outdir(category, target)
        try:
            result, primary = fn(target, outdir)
        except KeyboardInterrupt:
            out()
            warn("cancelled")
            continue
        if result is None:
            pause()
            continue
        summary_box(target, outdir,
                    wc_lines(primary) if primary else None)
        if primary:
            preview(primary, limit=18)
        pause()


# --------------------------------------------------------------------------
# Doctor / settings
# --------------------------------------------------------------------------

ALL_TOOLS = [
    "sherlock", "maigret", "blackbird", "socialscan", "holehe", "theHarvester",
    "subfinder", "amass", "assetfinder", "dnsx", "dnsrecon", "dnstwist",
    "httpx", "naabu", "katana", "nuclei", "ffuf", "tlsx", "cdncheck",
    "asnmap", "alterx", "gau", "waybackurls", "waymore", "xnLinkFinder",
    "phoneinfoga", "dnsgen", "shodan", "ipinfo", "gitleaks", "ddgr",
    "socid_extractor", "instaloader", "wafw00f", "cloud_enum", "onionsearch",
    "whois", "dig", "nmap", "exiftool",
    "jq", "curl", "tor", "proxychains4",
    "snowflake-client", "lyrebird",
]


def run_doctor():
    clear()
    out(f"  {BOLD}{BCYN}SYSTEM CHECK{RST}")
    out()
    found = 0
    for name in ALL_TOOLS:
        if binary(name):
            found += 1
            out(f"   {BGRN}✓{RST} {name}")
        else:
            out(f"   {BRED}✗{RST} {name} {GRAY}(missing){RST}")
    out()
    wordlists = [
        SUB_WORDLIST, SUB_WORDLIST_FALLBACK, WEB_WORDLIST,
        HOME / "wordlists" / "web" / "raft-medium-dirs.txt",
    ]
    ok_wl = sum(1 for w in wordlists if w.exists())
    out(f"  tools:      {BOLD}{found}/{len(ALL_TOOLS)}{RST}")
    out(f"  wordlists:  {BOLD}{ok_wl}/{len(wordlists)}{RST} in ~/wordlists")
    out(f"  results:    {OUT_BASE}")
    out(f"  tor mode:   {'ON' if TOR_MODE else 'off'}")
    out()


TORRC_SNOWFLAKE = HOME / "torrc-snowflake"


def tor_port_open() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=0.6):
            return True
    except OSError:
        return False


def tor_ready(timeout: float = 20.0) -> bool:
    """SOCKS5 probe: returns True when Tor can actually build a circuit."""
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=5) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")            # SOCKS5, no auth
            if s.recv(2) != b"\x05\x00":
                return False
            host = b"check.torproject.org"
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host +
                      (443).to_bytes(2, "big"))
            resp = s.recv(10)
            return len(resp) >= 2 and resp[1] == 0x00
    except OSError:
        return False


def _wait_for_tor(deadline_s: float) -> bool:
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        if tor_ready(timeout=8):
            return True
        time.sleep(2)
    return False


def start_tor() -> bool:
    if tor_ready():
        return True
    if not binary("tor"):
        bad("tor is not installed")
        return False

    # Phase 1 — direct Tor (fast, works where the network permits it)
    spinner = Spinner("starting tor — direct relays").start()
    subprocess.Popen(["tor", "--quiet"], stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                     start_new_session=True, env=ENV)
    direct_ok = _wait_for_tor(30)
    spinner.stop()
    if direct_ok:
        ok("tor is up (direct relays)")
        return True

    # Phase 2 — obfuscated fallback: snowflake bridges defeat TLS-level DPI
    warn("direct tor is blocked on this network — trying snowflake bridges")
    if not (binary("snowflake-client") and TORRC_SNOWFLAKE.exists()):
        bad("snowflake fallback unavailable (install: pkg install snowflake-client)")
        subprocess.run(["pkill", "-x", "tor"], env=ENV,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return False
    subprocess.run(["pkill", "-x", "tor"], env=ENV,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    spinner = Spinner("starting tor — snowflake bridges (can take ~1-2 min)").start()
    subprocess.Popen(["tor", "-f", str(TORRC_SNOWFLAKE), "--quiet"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, start_new_session=True, env=ENV)
    snow_ok = _wait_for_tor(150)
    spinner.stop()
    if snow_ok:
        ok("tor is up (snowflake bridges)")
        return True
    bad("tor could not bootstrap — check connectivity or bridges")
    subprocess.run(["pkill", "-x", "tor"], env=ENV,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return False


def stop_tor() -> None:
    if binary("pkill"):
        subprocess.run(["pkill", "-x", "tor"], env=ENV,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "snowflake-client"], env=ENV,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.6)  # give the daemon a moment to release the port
    ok("tor stopped")


def menu_settings():
    global TOR_MODE
    while True:
        clear()
        tor_state = f"{BGRN}ON{RST}" if TOR_MODE else f"{GRAY}off{RST}"
        running = f"{BGRN}running{RST}" if tor_port_open() else f"{GRAY}not running{RST}"
        out(f"  {BOLD}{BCYN}SETTINGS{RST}")
        out()
        out(f"   1   Tor routing ({tor_state}) — route all tools through proxychains")
        out(f"   2   Start tor daemon          {GRAY}(currently {running}){RST}")
        out(f"   3   Stop tor daemon")
        out(f"   4   Show output folders")
        out()
        out(f"   {BOLD} b{RST}  back")
        choice = read_line(f"  {BCYN}›{RST} choice: ").strip().lower()
        if choice in ("b", "back", "q", ""):
            return
        if choice == "1":
            if TOR_MODE:
                TOR_MODE = False
                ok("tor routing disabled")
            else:
                if start_tor():
                    TOR_MODE = True
                    ok("tor routing enabled — tools will run via proxychains4")
        elif choice == "2":
            start_tor()
            pause()
        elif choice == "3":
            stop_tor()
            TOR_MODE = False
            pause()
        elif choice == "4":
            clear()
            out(f"  {BOLD}Output folders{RST}\n")
            if OUT_BASE.exists():
                for cat in sorted(OUT_BASE.iterdir()):
                    if cat.is_dir():
                        n = sum(1 for _ in cat.iterdir())
                        out(f"   {cat.name:<12} {n} run(s)")
            out(f"\n  base: {OUT_BASE}")
            pause()


# --------------------------------------------------------------------------
# Banner / animations
# --------------------------------------------------------------------------

_LETTERS = {
    "J": ["     ██╗", "     ██║", "     ██║", "██   ██║", "╚█████╔╝", " ╚════╝ "],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "B": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "],
    "S": ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
    "I": ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
    "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
}

_RAMP = [BCYN, BBLU, BMAG, BMAG, BBLU, BCYN]


def _big_banner_rows(text: str):
    rows = ["", "", "", "", "", ""]
    for ch in text.upper():
        art = _LETTERS.get(ch)
        if not art:
            continue
        for i in range(6):
            rows[i] += art[i] + " "
    return [r.rstrip() for r in rows]


def _typewrite(text: str, color: str = "", delay: float = 0.006) -> None:
    if not TTY:
        out(f"{color}{text}{RST}" if color else text)
        return
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    out()


def show_banner() -> None:
    width = term_width()
    big = _big_banner_rows("JENABSINT")
    if width >= len(big[0]):
        for i, row in enumerate(big):
            if TTY:
                color = _RAMP[i % len(_RAMP)]
                for ch in row:
                    sys.stdout.write(f"{color}{ch}{RST}")
                    sys.stdout.flush()
                    time.sleep(0.0012)
                out()
            else:
                out(row)
    else:
        inner = " J E N A B S I N T "
        line = "═" * len(inner)
        for s in (f"╔{line}╗", f"║{inner}║", f"╚{line}╝"):
            _typewrite(s, BCYN, 0.004)

    out()
    _typewrite("  Termux OSINT console " + f"· v{VERSION}", GRAY, 0.010)
    out()

    # animated toolchain check
    spinner = Spinner("checking toolchain").start()
    ready = 0
    for name in ALL_TOOLS:
        if binary(name):
            ready += 1
        if TTY:
            time.sleep(0.012)
    spinner.stop()
    if ready == len(ALL_TOOLS):
        ok(f"toolchain ready {GRAY}({ready}/{len(ALL_TOOLS)} tools){RST}")
    elif ready:
        warn(f"toolchain: {ready}/{len(ALL_TOOLS)} tools — run Doctor to see what is missing")
    else:
        bad("no tools found — run Doctor for details")
    out()


def goodbye() -> None:
    clear()
    msg = "  session closed — results stay in ~/osint-out"
    if TTY:
        for _ in range(3):
            sys.stdout.write(f"\r  {GRAY}▁▂▃▄▅▆▇█▇▆▅▄▃▂▁{RST}")
            sys.stdout.flush()
            time.sleep(0.06)
            sys.stdout.write("\r" + " " * 40 + "\r")
            sys.stdout.flush()
            time.sleep(0.04)
        out(f"{GRAY}{msg}{RST}")
    else:
        out()
        out(f"{GRAY}{msg}{RST}")
    out()


# --------------------------------------------------------------------------
# Main menu
# --------------------------------------------------------------------------

MAIN_MENU = [
    ("1", "Username footprint", "sherlock · maigret · socialscan", act_username),
    ("2", "Email footprint", "holehe · socialscan", act_email),
    ("3", "Domain recon", "subdomains · DNS · whois · httpx", act_domain),
    ("4", "DNS brute force", "dnsx · wordlist · dnsgen", act_brute),
    ("5", "URL harvesting", "gau · waybackurls", act_urls),
    ("6", "Web crawl", "katana depth-3", act_crawl),
    ("7", "IP / host recon", "whois · dig · nmap", act_ip),
    ("8", "Phone lookup", "phoneinfoga", act_phone),
    ("9", "File metadata", "exiftool", act_meta),
    ("10", "theHarvester", "emails & hosts", act_harvester),
    ("11", "Shodan search", "needs API key", act_shodan),
    ("12", "Individual tools…", "pick any single tool", menu_individual),
    ("13", "Doctor", "check the toolchain", run_doctor),
    ("14", "Settings", "tor · output dirs", menu_settings),
    ("0", "Exit", "", None),
]


def show_main_menu() -> str:
    clear()
    tor_tag = f"{BGRN}tor:on{RST}" if TOR_MODE else f"{GRAY}tor:off{RST}"
    out(f"  {BOLD}{BCYN}JENABSINT{RST} {GRAY}· {datetime.now():%H:%M} · "
        f"{tor_tag}{GRAY} · {OUT_BASE}{RST}")
    out(f"  {GRAY}{'─' * min(46, max(24, term_width() - 4))}{RST}")
    for key, title, desc, _fn in MAIN_MENU:
        if key == "0":
            out(f"  {GRAY}{'─' * min(46, max(24, term_width() - 4))}{RST}")
        marker = f"{BOLD}{key:>2}{RST}"
        out(f"  {marker}  {title:<22}{GRAY}{desc}{RST}")
    out()
    return read_line(f"  {BCYN}›{RST} choose: ").strip().lower()


def main() -> None:
    show_banner()
    dispatch = {k: fn for k, _t, _d, fn in MAIN_MENU if fn}
    while True:
        try:
            choice = show_main_menu()
        except BackToMenu:
            continue
        if choice in ("0", "q", "exit", "quit"):
            break
        fn = dispatch.get(choice)
        if not fn:
            continue
        try:
            fn()
            if fn not in (run_doctor, menu_individual, menu_settings):
                pause()
        except BackToMenu:
            continue
        except KeyboardInterrupt:
            out()
            warn("cancelled")
            continue
        except Exception as exc:  # keep the TUI alive no matter what
            out()
            bad(f"unexpected error: {exc.__class__.__name__}: {exc}")
            pause()
    goodbye()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        goodbye()
    except SystemExit:
        raise
