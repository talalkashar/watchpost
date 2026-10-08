# LinkedIn kit: Watchpost 5.0 follow-up

Draft only. Check every number against the README and `./run_tests.sh` before posting, and confirm Juan Carlos
Munera is happy to be named. The last run had 569 unit tests passing plus the 26-step smoke check.

---

## Post

Watchpost 5.0: this round was about the review side of my SIEM lab project, checking a change before it goes live.

Watchpost is a learning project I build and test in a lab, in plain Python with no packages. I kept asking how a
reviewer would check a change before trusting it, so most of this round is about evidence and review.

What changed:

• Rule backtesting: a proposed rule change is replayed over stored events, and the reviewer sees which findings it
  keeps, adds or loses
• Sigma rules (a subset) and saved searches can become detections, but only after a second person approves them
  and a labeled sample passes. Until then they stay disabled.
• Log source health: a source that stops sending is flagged, with one new rule (15 built-in in total)
• Hunt aggregations (stats, top, timechart) and rule export/import with an ECS field mapping
• Triage metrics: time to acknowledge and resolve, and SLA breaches
• TOTP two-factor sign-in, session management, and optional masking of usernames and internal IPs for the
  read-only role
• Automated security review found issues in my own changes (missing rate limits on backtests, a lockout race in
  the two-factor check, and an oversized Sigma compile); they were fixed in four follow-up PRs, with tests

ATT&CK coverage is still graded by evidence: 17 of the 20 techniques in its small catalog are validated on the
project's own labeled scenarios, and 3 are only mapped. That is not a claim about real-world coverage.

Still true: all the data is synthetic, there is no ML, and this is a single-node portfolio project, not a
production tool. It has 569 automated tests plus an end-to-end smoke check.

Thanks again to Juan Carlos Munera for the asset inventory work it builds on.

Demo: https://watchpost-nxxu.onrender.com (read-only: viewer / watchpost-viewer-demo, first load takes ~30 seconds)
Code: https://github.com/talalkashar/watchpost

What should I try to verify next?

#cybersecurity #SIEM #detectionengineering #MITREATTACK #blueteam

---

## Notes

- The demo link only shows 5.0 after the branch is merged to `main` and Render redeploys.
- A screenshot of a backtest in the review view or the Log source health panel is the natural image.
- Keep the wording about the lab and synthetic data: this is a portfolio project, not work experience.
