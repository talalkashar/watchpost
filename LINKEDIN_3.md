# LinkedIn kit: Watchpost 3.0 follow-up

Draft only. Check every number against the Noise lab view and `./run_tests.sh` before posting, and confirm each
person is happy to be tagged. The last run had 241 unit tests passing plus the smoke check.

---

## Post

Last week I posted a SIEM I built from scratch and asked what you would add. You answered, so I built it.

The most useful comment came from Charles Vosburgh: test the rules against benign activity that looks like an
attack, and see where they get noisy. I did. The result was humbling.

Every rule still catches its attack. But 7 of my 12 rules also fire on at least one harmless look-alike: an
authorized scanner, an on-call admin logging in at 3 AM, a whole office failing logins the morning after a
password-expiry day.

Watchpost 3.0 shows that instead of hiding it.

What changed, and who asked:

• Noise lab: every rule is scored against benign look-alikes, with recall and precision side by side
  (Charles Vosburgh)
• Baseline-aware exfiltration: an account is compared with its own history, so the nightly backup stays quiet and
  a new 2 GB pull does not (Abderrazak Benarous)
• Tuning exceptions: a reviewed, expiring allowlist for known-benign sources, approved by a second person
  (Issouf D. Dayo)
• A shadow IT rule for cloud services that are not on the sanctioned list (Issouf D. Dayo)
• Entity risk scores for users, IPs, and hosts, where every point traces back to an alert

Still true: the data is synthetic, there is no ML, and this is a single-node learning project. The scores measure
my rules against scenarios I wrote, not real-world accuracy.

Next up from the thread: encrypted syslog, more log sources, and threat intel, which Juan Carlos Munera offered
to contribute.

Demo: https://watchpost-nxxu.onrender.com (read-only: viewer / watchpost-viewer-demo, first load takes ~30 seconds)
Code: https://github.com/talalkashar/watchpost

What would you test it against next?

#cybersecurity #SIEM #detectionengineering #MITREATTACK #blueteam

---

## Notes

- The demo link only shows 3.0 after the branch is merged to `main` and Render redeploys.
- A screenshot of the Noise lab view is the natural image for this post.
- Stdlib-only Python, 241 tests plus the smoke check, if you want a closing technical line.
