# Watchpost 2.0 demo script

Two cuts: a **30-second shot list** for the LinkedIn video, and a **2-minute walkthrough** for a live demo or a
longer recording. Both use the attack storyline (workstream C): **Admin → Attack storyline (synthetic) → Start
storyline** streams a six-stage synthetic intrusion (`recon` → `credential_attack` → `foothold` → `escalation` →
`lateral_cloud` → `exfiltration`) with baseline noise throughout, while the dashboard's **Storyline** tile shows the
current stage and progress. The speed selector next to the button sets the pace (1× is about two minutes).

Everything on screen is synthetic. Say so out loud in the walkthrough. The UI also says it (the **SYNTHETIC DATA**
chip, the "synthetic geo" label on the map, and the banner on every report).

## Setup (before recording)

1. Start from a fresh database, either the deployed demo (`deploy/README.md`) or locally:
   `SIEM_DB=/tmp/demo.db SIEM_VIEWER_PASSWORD='<12+ chars>' ./start.sh`.
2. Browser at **1280×800**, zoom 100 %, dark OS theme, bookmarks bar hidden, notifications off.
3. Sign in as **admin** in one window. Leave a second, private window signed in as **viewer** for the closing shot
   of the walkthrough.
4. Do a dry run at a high storyline speed to make sure alerts and an incident appear, then reset to a fresh database.
5. Screen recorder at 30 fps or more, cursor highlighting on. Record the storyline at a speed where the full run
   takes about 60 to 90 seconds, then speed up the middle in editing. The 30-second cut below is **edited** time.

## 30-second shot list

| # | Time | Shot | On screen | Caption / voice-over (optional) |
|---|---|---|---|---|
| 1 | 0:00–0:03 | Dashboard, idle | Dark SOC dashboard: status strip, empty attack map, live stream ticking with baseline noise, clock running | "A SIEM I built from scratch." |
| 2 | 0:03–0:05 | Admin view | Cursor clicks **Start storyline** in the *Attack storyline (synthetic)* card | "Synthetic intrusion, streamed live." |
| 3 | 0:05–0:10 | Dashboard, recon | Storyline tile reads `recon`. Map pulses at attacker cities. Web scan and firewall deny events scroll by in the live stream. First alerts: `web_scanner`, `firewall_port_sweep` | "Recon: web scanning and a port sweep." |
| 4 | 0:10–0:14 | Dashboard, credential attack → foothold | `credential_attack`, then `foothold`. Red auth failures flood the stream; password spray and brute force alerts; the Critical counter ticks up | "Password spray, then a VPN foothold." |
| 5 | 0:14–0:18 | Dashboard, escalation → cloud → exfil | `escalation` → `lateral_cloud` → `exfiltration`. Alerts-over-time bars stack; ATT&CK heat matrix cells light up across tactics | "Root, a new cloud key, data out." |
| 6 | 0:18–0:23 | Incident board → incident detail | Click the critical incident: kill-chain stages across the top, **escalated: 3+ tactics** pill, techniques grouped by tactic, alert timeline | "Every alert chained into one incident, mapped to MITRE ATT&CK." |
| 7 | 0:23–0:27 | Report | Click **Report (PDF)**; the PDF opens with the SYNTHETIC DATA banner, summary, timeline, and techniques | "One-click incident report." |
| 8 | 0:27–0:30 | End card | Dashboard in the background; overlay: "Watchpost · Python standard library only · github.com/talalkashar/watchpost · read-only demo: `<DEMO_URL>`" | — |

Editing notes: keep shot 1 short. Cut straight from the button click to the first map pulse. Let the stage tile stay
readable for at least a second per stage. Burn in captions, since most LinkedIn viewers watch muted. Export 1080p
(1280×800 scaled, or pad to 16:9).

## 2-minute walkthrough

**0:00–0:15 · Frame it.** On the dashboard, as admin:
*"This is Watchpost, a SIEM I built from scratch in plain Python, no frameworks. Everything you'll see is synthetic
data: IPs from reserved documentation ranges, and map positions from a labeled synthetic table."* Point at the
**SYNTHETIC DATA** chip and the **SYNTHETIC GEO** label.

**0:15–0:25 · Start the attack.** **Admin → Attack storyline (synthetic) → Start storyline**, then back to **Dashboard**.
*"This replays a six-stage intrusion against a living system. Normal logins and traffic keep flowing the whole time,
so the attack has to stand out from noise."*

**0:25–0:55 · Watch detection happen.** Follow the **Storyline** tile through the stages.
- Recon: *"A web scanner probing `/.env` and `/wp-login.php`, and the firewall denying a port sweep. Two rules
  fire."*
- Credential attack and foothold: *"A password spray across ten accounts, brute force on one, then a successful VPN
  login from the same IP. Success after failures is critical."*
- Escalation, cloud, exfil: *"sudo to root on `web01`, a new admin user, a login to `db01`, a cloud access key created
  by a principal we've never seen, then a burst of data reads."*
Point at the live stream (color by severity), the alerts-over-time chart, and the ATT&CK heat matrix filling in.

**0:55–1:25 · The incident.** Click the top card on the **Incident board**.
*"Watchpost correlates alerts that share an IP, account, or host within a window. This one incident holds the whole
chain. The stages run in kill-chain order, and because it spans three or more tactics, severity is escalated."*
Scroll the alert timeline. Open one alert and show **Why this fired**, the evidence events, and the related-events
timeline. *"Every alert explains itself and shows its evidence. No black box."*

**1:25–1:40 · Report.** Back on the incident, click **Report (PDF)**.
*"One click gives a handoff report: summary, timeline, entities, techniques by tactic, and recommended actions per
technique. The PDF writer is hand-rolled too."*

**1:40–1:55 · Roles and safety.** Switch to the **viewer** window and reload.
*"This is what the public demo login sees. It's read-only. Viewers can explore incidents and download reports, but
the server refuses every change, and login is rate limited."* Show that there is no Admin item and no
Resolve button.

**1:55–2:00 · Close.**
*"Standard library only, about 200 tests plus an end-to-end smoke check, deployed behind HTTPS with systemd. It's a
portfolio project: synthetic data, no machine learning, single node. Code and demo link are in the post."*

## If something goes wrong on camera

- **No alerts appear:** check **Health**. If detection shows `failing`, the events are still stored; fix the cause and
  click **Run detection (full scan)**.
- **The live badge shows POLLING 3s instead of LIVE · SSE:** the SSE stream dropped and the page fell back to polling every
  3 seconds. It still updates. Behind nginx, check that `/api/stream` has `proxy_buffering off`.
- **The storyline card is missing:** you're not signed in as admin (viewers and analysts can't start it). **Admin → Load
  synthetic demo data** is a fallback that loads the same kinds of scenarios at once.
- **Start storyline answers 409:** a run is already in progress (possibly the `SIEM_DEMO_LOOP` timer). Click **Stop**,
  then start again.
