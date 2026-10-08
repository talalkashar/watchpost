# LinkedIn kit: Watchpost 4.0 follow-up

Draft only. Check every number against the README and `./run_tests.sh` before posting, and confirm Juan Carlos
Munera is happy to be named. The last run had 405 unit tests passing plus the 25-step smoke check.

---

## Post

Watchpost 4.0: this round was about making every claim in my SIEM project checkable.

Watchpost is a learning project I build and test in a lab, in plain Python with no packages. After the last
update I kept asking one question: how would a reviewer verify that? So this round added fewer new screens and more
evidence.

What changed:

• Tamper-evident audit log: entries are hash-chained, and an admin can verify the chain and see where it breaks
• ATT&CK coverage graded by evidence: 16 of the 19 techniques in its small catalog are validated on the project's
  own labeled scenarios, and 3 are only mapped. That is not a claim about real-world coverage.
• Hunting with a small query language and saved searches
• Two new rules (14 in total): cloud logging disabled, and an admin action from a new source, each tested against
  a benign look-alike
• A reproducible load test: one laptop run ingested 100,000 synthetic events at 5,314 events/s
• Two-person review for asset inventory edits, building on the asset inventory Juan Carlos Munera contributed,
  including a fix so an address shared by several assets matches all of them
• Keyboard triage and an accessibility pass (automated checks, not a screen-reader audit)

Still true: all the data is synthetic, there is no ML, and this is a single-node portfolio project, not a
production tool. It has 405 automated tests plus an end-to-end smoke check.

Thanks again to Juan Carlos Munera for the inventory work it builds on.

Demo: https://watchpost-nxxu.onrender.com (read-only: viewer / watchpost-viewer-demo, first load takes ~30 seconds)
Code: https://github.com/talalkashar/watchpost

What should I try to verify next?

#cybersecurity #SIEM #detectionengineering #MITREATTACK #blueteam

---

## Notes

- The demo link only shows 4.0 after the branch is merged to `main` and Render redeploys.
- A screenshot of the Coverage view (validated / mapped levels) or the audit log badge is the natural image.
- Keep the wording about the lab and synthetic data: this is a portfolio project, not work experience.
