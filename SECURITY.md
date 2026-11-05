# Security policy

tripline is a portfolio project: Sigma detection rules, a Python test harness and a CI
pipeline. It runs no service and stores no user data, so a security problem here is most
likely one of these:

- a weakness in the CI workflow, such as an action, a download or a cache that could be
  tampered with;
- a fixture or corpus that contains something it shouldn't, such as a credential or personal
  data that wasn't scrubbed;
- a detection rule whose documented behaviour is wrong in a way that would mislead someone
  deploying it.

## Reporting

Please report privately through GitHub: **Security → Report a vulnerability** on this
repository. Don't open a public issue for anything that could be abused.

I'll reply within a week. Since this is a one-person project, a fix may take longer.

## What is already in place

- GitHub Actions are pinned to commit SHAs, the workflow has read-only `contents` permission,
  and CI uses no secrets.
- Every downloaded artefact (the ATT&CK STIX bundle and the background corpora) is pinned by
  URL and checked against a sha256 before use.
- Third-party logs are copied unchanged from public datasets and listed in [NOTICE](NOTICE).
  They come from lab and CTF accounts set up to be published (Stratus Red Team, Invictus,
  Splunk Attack Range, flaws.cloud). Synthetic fixtures use AWS's documentation example keys
  and documentation IP ranges. CloudTrail logs never contain secret keys, only key IDs.
- No malware, attack tooling or Atomic Red Team content is included or run.

## Using the rules

The rules are tested against the fixtures and corpora described in
[docs/results.md](docs/results.md), not against production data. Review the blind spots and
false positives in each rule's doc note (`docs/rules/`) before deploying a rule, and tune the
filters to your environment.
