# Sample logs (all synthetic)

Every file here is invented for testing. No real people, hosts, or traffic. The external-looking IPs come from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Each file includes at least one malformed record, so you can see rejection reporting.

| File | Format | What it shows |
|---|---|---|
| `auth.log` | Linux auth.log (BSD syslog, OpenSSH) | 15 failed SSH logins from `203.0.113.200` → brute-force alert; one non-syslog line is rejected |
| `windows_security.jsonl` | Windows Security events as JSON lines (4625/4624/4720) | 6 failures, then a success for `jsmith` → "success after failures" alert; a new account is created right after (find it with Event type = user_created) |
| `vpn_events.csv` | CSV | `administrator` logs in at 02:30 UTC → off-hours privileged login alert; a row with a bad IP is rejected |
| `nginx_access.log` | nginx/Apache combined access log | `203.0.113.80` probes 14 scanner paths and injection strings in under a minute → web scanner alert; one 502 becomes `web_error`; one non-log line is rejected |
| `firewall.csv` | CSV (`action` column: allow/deny) | `198.51.100.140` is denied on 16 ports → port sweep alert; `10.0.3.15` uploads 1.8 GB out → large data transfer alert; a row with a non-numeric port is rejected |
| `cloudtrail.json` | CloudTrail-style JSON (`{"Records": [...]}`) | `ops-admin` has history, so its IAM change is quiet; never-seen `svc-deploy-tmp` creates a user and access key → new-principal alert, then reads 1.25 GB → large data transfer alert. One record has a bad timestamp |
| `linux_host.log` | Linux syslog (sshd, openvpn, sudo, su, useradd, auditd, UFW) | `erin` logs in at HQ then over VPN from another continent → impossible travel; `frank` fails 3 times, logs in, and sudoes to root → privilege escalation alert (and correlated into one incident); `grace`'s normal sudo stays quiet; one non-syslog line is rejected |

Upload them from the **Ingest** page. Tick "Mark as synthetic" and set Year = 2026 for `auth.log` and `linux_host.log`, since BSD syslog lines carry no year. Geo positions for the impossible-travel rule come from Watchpost's synthetic geo table (documentation and private ranges mapped to fictional cities), not a real lookup. You can also use the API:

```bash
curl -X POST "http://127.0.0.1:8080/api/ingest/upload?format=authlog&source=bastion01&synthetic=1&year=2026" \
  -H "Authorization: Bearer $SIEM_INGEST_TOKEN" -H "Content-Type: text/plain" --data-binary @samples/auth.log
```
