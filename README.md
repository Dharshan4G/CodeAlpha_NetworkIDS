# CodeAlpha — Task 4: Network Intrusion Detection System (NIDS)

A complete network-based IDS built on **Suricata**, with custom detection rules, an
automated response mechanism, and a live dashboard to visualise attacks.

## What this project delivers
1. **Detection** — a signature-based IDS (Suricata; the rules are Snort-compatible) with 18 custom rules covering port scans, brute force, web attacks and malware/C2 traffic.
2. **Monitoring** — Suricata inspects live traffic continuously and logs every alert to `eve.json`.
3. **Response** — a Python script tails the alerts and automatically firewalls repeat attackers.
4. **Visualisation** — a browser dashboard showing alert timelines, attack categories and top attackers.

```
rules/local.rules              18 custom detection rules
config/suricata-vars.yaml      HOME_NET / EXTERNAL_NET and logging config
response/monitor.py            live alert monitor + auto-block responder
dashboard/dashboard.html       visual console (open in a browser)
sample/eve.sample.json         60 sample alerts so you can demo without live traffic
scripts/setup.sh               installs Suricata + rules and starts everything
```

## Detection rules (rules/local.rules)
| Category | What it catches | SIDs |
|---|---|---|
| Reconnaissance | ICMP ping sweep, TCP SYN scan, Nmap XMAS/NULL scans | 1000001–4 |
| Brute force | SSH and FTP repeated login attempts | 1000010–11 |
| Web attacks | SQL injection, XSS, directory traversal, command injection | 1000020–23 |
| Malware / C2 | scanner user-agents, cleartext passwords, suspicious DNS TLDs | 1000030–32 |
| Policy | Tor connections | 1000040 |

Each rule uses thresholds so a single ping doesn't alert, but a scan does.

## Quick start (no installation needed — demo mode)
See the tools work using the bundled sample data:

```bash
# 1) the response engine: parses alerts, ranks attackers, shows what it would block
python3 response/monitor.py --eve sample/eve.sample.json --replay

# 2) the dashboard: open in any browser and click "Load sample"
xdg-open dashboard/dashboard.html      # or just double-click it
```

Sample run output:
```
 ALERT SUMMARY — 60 alerts
 By severity:   HIGH 40   MEDIUM 15   LOW 5
 Top attackers:  28  203.0.113.7 (blocked)   12  198.51.100.23 (blocked)
```

## Full deployment (real traffic)
Requires a Linux host and root. **Only monitor a network you administer.**
```bash
sudo ./scripts/setup.sh eth0        # replace eth0 with your interface (ip a to list)
```
This installs Suricata, loads the custom rules, validates the config, starts capturing,
and launches the monitor. To turn on automatic blocking of repeat offenders:
```bash
sudo python3 response/monitor.py --eve /var/log/suricata/eve.json --block --threshold 3
```

## Testing the rules safely
From another machine on the same test network:
```bash
nmap -sS <ids-host>                                  # triggers the SYN-scan rule
curl "http://<ids-host>/?q=' OR 1=1--"               # triggers the SQLi rule
curl "http://<ids-host>/../../etc/passwd"            # triggers directory traversal
curl -A "sqlmap/1.5" http://<ids-host>/              # triggers the scanner-UA rule
```

## Snort instead of Suricata
The rule syntax is compatible. Copy `rules/local.rules` into Snort's rules directory,
add `include $RULE_PATH/local.rules` to `snort.conf`, set `HOME_NET`, and run
`snort -c /etc/snort/snort.conf -i eth0 -A console`.

## What I learned
- The difference between signature-based detection (matching known patterns) and the value of thresholds to cut false positives.
- How an IDS becomes an IPS once you add a response mechanism that acts on alerts.
- Reading Suricata's EVE JSON output and turning raw alerts into useful metrics and visualisations.
