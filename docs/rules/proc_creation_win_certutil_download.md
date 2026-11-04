# File Download Via Certutil

**Rule:** [`rules/windows/process_creation/proc_creation_win_certutil_download.yml`](../../rules/windows/process_creation/proc_creation_win_certutil_download.yml)

- **Goal:** catch the signed Windows utility `certutil.exe` being used as a downloader.
- **ATT&CK (v20):** T1105 Ingress Tool Transfer, tactic command-and-control.
- **How it works:** all three must hold:
  - the image is `certutil.exe` (or `OriginalFileName`);
  - the command line has a download flag: `-urlcache`, `-verifyctl` or `-f`, matched with
    `windash`;
  - the command line contains `http`.

  The URL requirement keeps out the many legitimate certutil uses (hashing, decoding, clearing
  the URL cache).
- **Blind spots:**
  - Downloads over other schemes (`ftp`, UNC paths) or with flags not in the list.
  - `bitsadmin`, `curl.exe` or PowerShell `Invoke-WebRequest` downloads (other LOLBins).
  - A renamed certutil with a changed `OriginalFileName` (only possible if the binary itself
    is modified).
- **False positives:**
  - Admins refreshing CRLs or CA certificates from an internal HTTP URL.
  - `benign/certutil_without_download.xml` must stay silent: `-hashfile`, `-decode`, and
    `-urlcache * delete`.
- **Validation:** `tests/fixtures/sysmon/proc_creation_win_certutil_download/`
  - **Synthetic only.** No small, licence-compatible dataset with a real certutil download was
    found; Splunk's certutil dataset is 300 MB and about certificate extraction.
  - `tp/certutil_downloads.xml`: `-urlcache -split -f http://…` and `/verifyctl /f https://…`.
  - Results table: generated in a later step; it will mark this rule synthetic-only.
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; numbers from step 9):
  evtx-baseline Sysmon log (1,165 process creations): 0.
- **SigmaHQ relation:** derived from `proc_creation_win_certutil_download.yml` (Florian Roth,
  Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali). Differences:
  - Uses `windash` flags with a leading space, instead of `'urlcache '` etc. with a trailing
    space.
  - Adds `-f`, as the plan asks.
  - Keeps only the T1105 tag; SigmaHQ also tags T1027.
- **KQL:** generated, on the `Sysmon` function (`EventID == 1`).
