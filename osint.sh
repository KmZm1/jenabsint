#!/data/data/com.termux/files/usr/bin/bash
# osint — one-stop OSINT toolkit wrapper for Termux
# Usage: osint <command> <target>   (run `osint help` for details)
set -uo pipefail

export PATH="$HOME/go/bin:$PATH"
OUT_BASE="${OSINT_OUT:-$HOME/osint-out}"
U=$(tput bold 2>/dev/null; tput setaf 4 2>/dev/null)
G=$(tput setaf 2 2>/dev/null)
Y=$(tput setaf 3 2>/dev/null)
R=$(tput setaf 1 2>/dev/null)
N=$(tput sgr0 2>/dev/null)

say()  { printf '%s\n' "${U}[*]${N} $*"; }
ok()   { printf '%s\n' "${G}[+]${N} $*"; }
warn() { printf '%s\n' "${Y}[!]${N} $*"; }
die()  { printf '%s\n' "${R}[-]${N} $*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || { warn "$1 not installed — skipping"; return 1; }
}

newdir() { # newdir <category> <target> -> echoes dir
  local cat="$1" tgt="$2" d
  d="$OUT_BASE/$cat/$(date +%Y%m%d-%H%M%S)-${tgt//[^A-Za-z0-9._@+-]/_}"
  mkdir -p "$d" && printf '%s' "$d"
}

usage() {
  cat <<'EOF'
osint — OSINT toolkit wrapper

Commands:
  osint user <username>       sherlock + maigret + socialscan + blackbird
  osint email <email>         holehe + socialscan + blackbird
  osint gh <user|email>       blackbird — 600+ site account search (CSV)
  osint ig <username>         Instagram profile media (instaloader)
  osint domain <domain>       subdomain enum (subfinder/assetfinder/crt.sh) + DNS + httpx + whois
  osint dns <domain>          dnsrecon standard enumeration (+ zone transfer)
  osint twist <domain>        dnstwist typosquat / look-alike domains
  osint ip <ip|host>          whois + reverse DNS + nmap + ipinfo
  osint urls <domain>         Historical/broken URLs (gau + waybackurls)
  osint waymore <domain>      deep URL harvest (Wayback + CommonCrawl)
  osint links <url>           links/params from pages & JS (xnLinkFinder)
  osint crawl <url>           Crawl site for endpoints/URLs (katana)
  osint dork <query>          Google dorking (go-dork)
  osint waf <url>             detect WAF vendor (wafw00f)
  osint cloud <keyword>       public S3/Azure/GCP storage scan (cloud_enum)
  osint dark <query>          OnionSearch via Tor (requires Tor on 127.0.0.1:9050)
  osint leaks <dir>           Secret scanning with gitleaks
  osint phone <number>        PhoneInfoga scan (use E.164, e.g. +12025550123)
  osint meta <file>           Metadata extraction (exiftool)
  osint harv <domain>         theHarvester (otx, rapiddns, duckduckgo, crtsh)
  osint brute <domain>        DNS brute-force via dnsx + wordlists
  osint shodan <query>        Shodan search (needs `shodan init <API key>` once)
  osint check                 Show which tools are installed
  osint help                  This text

Output: every run gets its own folder under ~/osint-out/<category>/ (override: OSINT_OUT)
EOF
}

cmd_check() {
  local tools=(sherlock maigret blackbird socialscan holehe theHarvester
               subfinder amass assetfinder dnsx dnsrecon dnstwist httpx naabu
               katana nuclei ffuf tlsx cdncheck asnmap alterx gau waybackurls
               waymore xnLinkFinder phoneinfoga dnsgen shodan ipinfo gitleaks
               go-dork socid_extractor instaloader wafw00f cloud_enum onionsearch
               whois dig nmap exiftool jq curl tor proxychains4)
  local missing=0
  printf '%-14s %s\n' "TOOL" "STATUS"
  for t in "${tools[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then printf '%-14s %s\n' "$t" "$(printf '%s' "OK")"; else printf '%-14s %s\n' "$t" "MISSING"; missing=$((missing+1)); fi
  done
  printf '\n%d missing\n' "$missing"
}

cmd_user() {
  local user="${1:?usage: osint user <username>}" dir
  dir=$(newdir users "$user"); say "target: $user  ->  $dir"
  if need sherlock; then
    say "sherlock (top sites)..."
    sherlock "$user" --timeout 10 --print-found --no-color --txt -o "$dir/sherlock.txt" >"$dir/sherlock.log" 2>&1
    ok "sherlock: $(grep -c 'http' "$dir/sherlock.txt" 2>/dev/null || echo '?') hits ($dir/sherlock.txt)"
  fi
  if need socialscan; then
    say "socialscan..."
    socialscan "$user" >"$dir/socialscan.txt" 2>&1 && ok "socialscan done ($dir/socialscan.txt)"
  fi
  if need maigret; then
    say "maigret (200 top sites, this takes a while)..."
    maigret "$user" --top-sites 200 --timeout 15 --folderoutput "$dir/maigret" --no-progressbar --no-color >"$dir/maigret.log" 2>&1
    ok "maigret done ($dir/maigret/)"
  fi
  if need blackbird; then
    say "blackbird (600+ sites)..."
    (cd "$dir" && blackbird -u "$user" --csv >blackbird.log 2>&1) && ok "blackbird done ($dir/*.csv)"
  fi
  ok "results in $dir"
}

cmd_email() {
  local email="${1:?usage: osint email <email>}" dir
  dir=$(newdir emails "$email"); say "target: $email  ->  $dir"
  if need holehe; then
    say "holehe (registered accounts)..."
    holehe --only-used --no-color "$email" >"$dir/holehe.txt" 2>&1
    ok "holehe done ($dir/holehe.txt)"
  fi
  if need socialscan; then
    say "socialscan..."
    socialscan "$email" >"$dir/socialscan.txt" 2>&1 && ok "socialscan done"
  fi
  if need blackbird; then
    say "blackbird (email, 600+ sites)..."
    (cd "$dir" && blackbird -e "$email" --csv >blackbird.log 2>&1) && ok "blackbird done ($dir/*.csv)"
  fi
  ok "results in $dir"
}

cmd_domain() {
  local domain="${1:?usage: osint domain <domain>}" dir
  dir=$(newdir domains "$domain"); say "target: $domain  ->  $dir"

  if need subfinder; then
    say "subfinder..."
    subfinder -d "$domain" -silent -o "$dir/subs_subfinder.txt" 2>"$dir/subfinder.err"
    ok "subfinder: $(wc -l <"$dir/subs_subfinder.txt" 2>/dev/null || echo 0) subdomains"
  fi
  if need assetfinder; then
    say "assetfinder..."
    assetfinder --subs-only "$domain" >"$dir/subs_assetfinder.txt" 2>/dev/null
    ok "assetfinder: $(wc -l <"$dir/subs_assetfinder.txt") subdomains"
  fi
  say "crt.sh..."
  curl -s --max-time 60 "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' \
    | sort -u >"$dir/subs_crtsh.txt"
  ok "crt.sh: $(wc -l <"$dir/subs_crtsh.txt") entries"

  cat "$dir"/subs_*.txt 2>/dev/null | grep -iE "(^|\.)${domain//./\\.}$" | sort -u >"$dir/subs_all.txt"
  ok "unique subdomains: $(wc -l <"$dir/subs_all.txt")"

  say "whois + DNS records..."
  whois "$domain" >"$dir/whois.txt" 2>&1
  { echo "== A =="; dig +short A "$domain"; echo "== NS =="; dig +short NS "$domain";
    echo "== MX =="; dig +short MX "$domain"; echo "== TXT =="; dig +short TXT "$domain"; } >"$dir/dns_records.txt" 2>&1

  if need dnsx && [ -s "$dir/subs_all.txt" ]; then
    say "dnsx (resolve)..."
    dnsx -silent -l "$dir/subs_all.txt" -a -resp >"$dir/dns_resolved.txt" 2>/dev/null
    ok "resolved: $(wc -l <"$dir/dns_resolved.txt")"
  fi
  if need httpx; then
    say "httpx (probe live hosts, titles/tech)..."
    httpx -silent -l "$dir/subs_all.txt" -status-code -title -tech-detect \
          -timeout 8 -retries 1 -o "$dir/httpx.txt" >/dev/null 2>&1
    ok "live hosts: $(wc -l <"$dir/httpx.txt" 2>/dev/null || echo 0)"
  fi
  ok "results in $dir"
}

cmd_ip() {
  local target="${1:?usage: osint ip <ip|host>}" dir
  dir=$(newdir ips "$target"); say "target: $target  ->  $dir"

  whois "$target" >"$dir/whois.txt" 2>&1 && ok "whois saved"
  { echo "== reverse DNS =="; dig +short -x "$target" 2>/dev/null;
    echo "== A =="; dig +short "$target" 2>/dev/null; } >"$dir/dns.txt" 2>&1
  if need ipinfo; then
    say "ipinfo..."
    ipinfo "$target" >"$dir/ipinfo.txt" 2>&1 && ok "ipinfo saved"
  fi
  if command -v nmap >/dev/null 2>&1; then
    say "nmap top-1000 TCP (connect scan)..."
    nmap -Pn -T4 --top-ports 1000 --open "$target" -oN "$dir/nmap.txt" >/dev/null 2>&1
    ok "nmap: $(grep -c '/tcp.*open' "$dir/nmap.txt" 2>/dev/null || echo 0) open ports"
  fi
  ok "results in $dir"
}

cmd_urls() {
  local domain="${1:?usage: osint urls <domain>}" dir
  dir=$(newdir urls "$domain"); say "target: $domain  ->  $dir"
  if need waybackurls; then
    say "waybackurls..." && echo "$domain" | waybackurls >"$dir/waybackurls.txt" 2>/dev/null
  fi
  if need gau; then
    say "gau..." && gau --threads 5 "$domain" >"$dir/gau.txt" 2>/dev/null
  fi
  cat "$dir"/waybackurls.txt "$dir"/gau.txt 2>/dev/null | sort -u >"$dir/all_urls.txt"
  ok "unique URLs: $(wc -l <"$dir/all_urls.txt" 2>/dev/null || echo 0) -> $dir/all_urls.txt"
}

cmd_crawl() {
  local url="${1:?usage: osint crawl <url>}" dir
  dir=$(newdir crawls "$url"); say "target: $url  ->  $dir"
  need katana || return 1
  say "katana (depth 3)..."
  katana -u "$url" -d 3 -silent -o "$dir/urls.txt" >/dev/null 2>&1
  ok "found $(wc -l <"$dir/urls.txt" 2>/dev/null || echo 0) URLs"
}

cmd_phone() {
  local num="${1:?usage: osint phone <+E.164 number>}" dir
  dir=$(newdir phones "$num"); say "target: $num  ->  $dir"
  need phoneinfoga || return 1
  phoneinfoga scan -n "$num" >"$dir/scan.txt" 2>&1
  ok "results in $dir/scan.txt"
}

cmd_meta() {
  local file="${1:?usage: osint meta <file>}" dir
  [ -f "$file" ] || die "no such file: $file"
  dir=$(newdir meta "$(basename "$file")"); say "target: $file  ->  $dir"
  need exiftool || return 1
  exiftool -a -G1 -s "$file" >"$dir/metadata.txt" 2>&1
  ok "metadata -> $dir/metadata.txt"
  exiftool -a -G1 -s "$file" 2>/dev/null | grep -iE 'gps|author|creator|artist|software|date' | head -20
}

cmd_harv() {
  local domain="${1:?usage: osint harv <domain>}" dir
  dir=$(newdir harvester "$domain"); say "target: $domain  ->  $dir"
  need theHarvester || return 1
  say "theHarvester (otx, rapiddns, duckduckgo, crtsh)..."
  theHarvester -d "$domain" -b otx,rapiddns,duckduckgo,crtsh -l 200 -r -f "$dir/report" >"$dir/harvester.log" 2>&1
  ok "results in $dir (report.html / report.xml / harvester.log)"
}

cmd_brute() {
  local domain="${1:?usage: osint brute <domain>}" dir
  dir=$(newdir brute "$domain"); say "target: $domain  ->  $dir"
  need dnsx || return 1
  local wl="$HOME/wordlists/dns/bitquark-100k.txt"
  [ -f "$wl" ] || wl="$HOME/wordlists/dns/subdomains-20k.txt"
  say "dnsx brute-force ($(basename "$wl"))..."
  dnsx -d "$domain" -w "$wl" -silent -a -resp -t 40 >"$dir/resolved.txt" 2>/dev/null
  ok "resolved: $(wc -l <"$dir/resolved.txt") -> $dir/resolved.txt"
  if need dnsgen; then
    say "dnsgen permutations + resolve..."
    grep -oE '^[a-zA-Z0-9._-]+' "$dir/resolved.txt" 2>/dev/null | dnsgen - 2>/dev/null \
      | dnsx -silent -a -resp -t 40 2>/dev/null | sort -u >"$dir/permutations.txt"
    ok "permutations: $(wc -l <"$dir/permutations.txt") -> $dir/permutations.txt"
  fi
}

cmd_shodan() {
  local query="${1:?usage: osint shodan <query>}" dir
  dir=$(newdir shodan "$query"); say "query: $query  ->  $dir"
  need shodan || return 1
  if ! shodan info >/dev/null 2>&1; then
    warn "Shodan API key not set. Run: shodan init <YOUR_API_KEY>"
    return 1
  fi
  shodan search --fields ip_str,port,org,hostnames,product "$query" >"$dir/results.txt" 2>&1
  ok "$(wc -l <"$dir/results.txt") rows -> $dir/results.txt"
}

cmd_ig() {
  local user="${1:?usage: osint ig <username>}" dir
  dir=$(newdir users "$user"); say "target: @${user#@}  ->  $dir"
  need instaloader || return 1
  (cd "$dir" && instaloader --no-videos --count 25 "${user#@}" >instaloader.log 2>&1) \
    && ok "instaloader done -> $dir"
}

cmd_dns() {
  local domain="${1:?usage: osint dns <domain>}" dir
  dir=$(newdir domains "$domain"); say "target: $domain  ->  $dir"
  need dnsrecon || return 1
  dnsrecon -d "$domain" >"$dir/dnsrecon.txt" 2>&1
  ok "dnsrecon done -> $dir/dnsrecon.txt"
}

cmd_twist() {
  local domain="${1:?usage: osint twist <domain>}" dir
  dir=$(newdir domains "$domain"); say "target: $domain  ->  $dir"
  need dnstwist || return 1
  dnstwist --registered --format csv -o "$dir/dnstwist.csv" "$domain" >"$dir/dnstwist.log" 2>&1
  ok "dnstwist: $(wc -l <"$dir/dnstwist.csv" 2>/dev/null || echo 0) rows -> $dir/dnstwist.csv"
}

cmd_waymore() {
  local domain="${1:?usage: osint waymore <domain>}" dir
  dir=$(newdir urls "$domain"); say "target: $domain  ->  $dir"
  need waymore || return 1
  waymore -i "$domain" -mode U -oU "$dir/urls.txt" -t 15 -p 3 >"$dir/waymore.log" 2>&1
  ok "unique URLs: $(wc -l <"$dir/urls.txt" 2>/dev/null || echo 0) -> $dir/urls.txt"
}

cmd_links() {
  local url="${1:?usage: osint links <url>}" dir
  dir=$(newdir urls "$url"); say "target: $url  ->  $dir"
  need xnLinkFinder || return 1
  xnLinkFinder -i "$url" -o "$dir/links.txt" >"$dir/xnLinkFinder.log" 2>&1
  ok "links: $(wc -l <"$dir/links.txt" 2>/dev/null || echo 0) -> $dir/links.txt"
}

cmd_dork() {
  local q="${1:?usage: osint dork <query>}" dir
  dir=$(newdir dorks "$q"); say "query: $q  ->  $dir"
  need go-dork || return 1
  go-dork -q "$q" -e google -p 1 -s >"$dir/dorks.txt" 2>&1
  ok "$(wc -l <"$dir/dorks.txt") lines -> $dir/dorks.txt"
}

cmd_waf() {
  local url="${1:?usage: osint waf <url>}" dir
  case "$url" in http*) ;; *) url="https://$url";; esac
  dir=$(newdir tools "$url"); say "target: $url  ->  $dir"
  need wafw00f || return 1
  wafw00f "$url" >"$dir/waf.txt" 2>&1
  ok "wafw00f done -> $dir/waf.txt"
}

cmd_cloud() {
  local kw="${1:?usage: osint cloud <keyword>}" dir
  dir=$(newdir tools "$kw"); say "keyword: $kw  ->  $dir"
  need cloud_enum || return 1
  cloud_enum -k "$kw" -l "$dir/cloud_enum.txt" >"$dir/cloud_enum.log" 2>&1
  ok "cloud_enum done -> $dir/cloud_enum.txt"
}

cmd_gh() {
  local t="${1:?usage: osint gh <username|email>}" dir flag="-u"
  case "$t" in *@*) flag="-e";; esac
  dir=$(newdir users "$t"); say "target: $t  ->  $dir"
  need blackbird || return 1
  (cd "$dir" && blackbird "$flag" "$t" --csv >blackbird.log 2>&1) && ok "blackbird done -> $dir"
}

cmd_dark() {
  local q="${1:?usage: osint dark <query>}" dir
  dir=$(newdir tools "$q"); say "query: $q  ->  $dir"
  need onionsearch || return 1
  if ! (exec 3<>/dev/tcp/127.0.0.1/9050) 2>/dev/null; then
    warn "Tor SOCKS not reachable on 127.0.0.1:9050 — start Tor first (e.g. via JenabSint settings)"
    return 1
  fi
  onionsearch "$q" --output "$dir/onionsearch.txt" --limit 2 --mp_units 2 --continuous_write 1 >"$dir/onionsearch.log" 2>&1
  ok "onionsearch done -> $dir/onionsearch.txt"
}

cmd_leaks() {
  local path="${1:?usage: osint leaks <dir>}" dir
  [ -d "$path" ] || die "no such directory: $path"
  dir=$(newdir tools "$(basename "$path")"); say "target: $path  ->  $dir"
  need gitleaks || return 1
  gitleaks dir "$path" --report-format json --report-path "$dir/leaks.json" -v >"$dir/gitleaks.log" 2>&1
  ok "gitleaks done -> $dir/leaks.json"
}

case "${1:-help}" in
  user)   shift; cmd_user   "$@";;
  email)  shift; cmd_email  "$@";;
  gh)     shift; cmd_gh     "$@";;
  ig)     shift; cmd_ig     "$@";;
  domain) shift; cmd_domain "$@";;
  dns)    shift; cmd_dns    "$@";;
  twist)  shift; cmd_twist  "$@";;
  ip|host) shift; cmd_ip   "$@";;
  urls)   shift; cmd_urls   "$@";;
  waymore) shift; cmd_waymore "$@";;
  links)  shift; cmd_links  "$@";;
  dork)   shift; cmd_dork   "$@";;
  waf)    shift; cmd_waf    "$@";;
  cloud)  shift; cmd_cloud  "$@";;
  dark)   shift; cmd_dark   "$@";;
  leaks)  shift; cmd_leaks  "$@";;
  crawl)  shift; cmd_crawl  "$@";;
  phone)  shift; cmd_phone  "$@";;
  meta)   shift; cmd_meta   "$@";;
  harv)   shift; cmd_harv   "$@";;
  brute)  shift; cmd_brute  "$@";;
  shodan) shift; cmd_shodan "$@";;
  check)  cmd_check;;
  help|-h|--help|"") usage;;
  *) die "unknown command: $1 (try: osint help)";;
esac
