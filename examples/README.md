# Investigate a sample

Run these from the repository root. Each command reads one bundled log and applies the default rules in a fresh in-memory database. The terminal prints the rejection reason and the stored explanation for each alert.

## Find the accounts behind an SSH alert

```sh
./start.sh --demo ssh
```

In [auth.log](../samples/auth.log), one address produces 15 failed logins. The IP rule fires at 10 within 300 seconds. The account rule also fires because 12 failures target root. Compare their time spans in the output. The malformed record at position 19 is excluded from both counts.

## Distinguish a Windows success from the failures before it

```sh
./start.sh --demo windows
```

Find the successful sign-in for `jsmith` in [windows_security.jsonl](../samples/windows_security.jsonl). The critical alert links it to six earlier failures from the same address. Eight records are accepted and the invalid timestamp is rejected. Which event would you inspect next to understand what happened after sign-in?

## Separate a port sweep from a high-volume transfer

```sh
./start.sh --demo firewall
```

Compare the two alerts with [firewall.csv](../samples/firewall.csv). The firewall denied one address on 16 distinct ports. A different host transferred 1.8 GB over three events. The malformed port is rejected. Which field groups the evidence for each rule?

To inspect individual evidence rows, follow the [browser walkthrough](../README.md#investigate-in-the-browser) with the corresponding sample. The Windows and firewall records already include a year.
