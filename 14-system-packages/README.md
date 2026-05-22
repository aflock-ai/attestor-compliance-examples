# 14 — `system-packages` ✅ validated against real infrastructure

Real Amazon Linux 2023 `rpm -qa` inventory from a t3.small EC2 instance. The attestor reads `/etc/os-release` to detect distribution, picks the RPM backend, and shells out to `/usr/bin/rpm -qa --qf '%{NAME}\t%{VERSION}\n'`.

## Predicate excerpt

```json
{
  "os": "linux",
  "distribution": "amzn",
  "version": "2023",
  "packages": [
    {
      "name": "perl-Digest",
      "version": "1.20"
    },
    {
      "name": "vim-filesystem",
      "version": "9.2.240"
    },
    {
      "name": "perl-Data-Dumper",
      "version": "2.191"
    },
    {
      "name": "publicsuffix-list-dafsa",
      "version": "20260116"
    },
    {
      "name": "perl-Text-Tabs+Wrap",
      "version": "2021.0726"
    },
    {
      "name": "openblas-srpm-macros",
      "version": "2"
    },
    {
      "name": "perl-Time-Local",
      "version": "1.300"
    },
    {
      "name": "ncurses-libs",
      "version": "6.6"
    },
    {
      "name": "perl-Net-SSLeay",
      "version": "1.94"
    },
    {
      "name": "setup",
      "version": "2.13.7"
    },
    {
      "name": "perl-IPC-Open3",
      "version": "1.21"
    },
    {
      "name": "libgcc",
      "version": "14.2.1"
    },
    {
      "name": "perl-Pod-Simple",
      "version": "3.42"
    },
    {
      "name": "zlib",
      "version": "1.2.11"
    },
    {
      "name": "perl-Symbol",
      "version": "1.08"
    },
    {
      "name": "libstdc++",
      "version": "14.2.1"
    },
    {
      "name": "perl-Fcntl",
      "version": "1.13"
    },
    {
      "name": "libcom_err",
      "version": "1.46.5"
    },
    {
      "name": "perl-IO",
      "version": "1.43"
    },
    {
      "name": "libxml2",
      "version": "2.10.4"
    },
    {
      "name": "perl-File-Basename",
      "version": "2.85"
    },
    {
      "name": "libunistring",
      "version": "0.9.10"
    },
    {
      "name": "perl-constant",
      "version": "1.33"
    },
    {
      "name": "readline",
      "version": "8.1"
    },
    {
      "name": "perl-vars",
      "version": "1.05"
    }
  ]
}
```

The excerpt above is the first ~15 entries from the captured RPM inventory; the full predicate (several hundred packages) is at `_validation/results/14-system-packages/system-packages.json`.

## What we found

The first run on AL2023 detected `ID=amzn` from `/etc/os-release` and fell through to the Debian backend (because the case statement matches `amazon` but not `amzn`). Filed as a rookery bug; patched the local clone (case statement) to recognize `amzn`. After patch: real RPM inventory captured.

## Reproduce

```bash
cilock run --step host-packages \
  --signer-file-key-path key.pem --outfile system-packages.json --workingdir . \
  --attestations system-packages \
  -- echo "captured host packages"
```
