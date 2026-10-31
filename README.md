# Daily Threat Watch

A web page that updates itself every weekday. It shows:

- **New in CISA KEV.** Bugs that attackers are already using.
- **New critical CVEs.** Bugs scored 9.0 or higher in the last 7 days, ranked by how likely they are to be attacked (EPSS).

Each item has a short "In plain English" line. A simple rule set writes it from the official description. It can be wrong, so read the source before you act.

Live site: `https://rpkjs1-hash.github.io/threat-brief/`

## How it updates

1. GitHub Actions starts the workflow every weekday at 06:37 Singapore time (22:37 UTC, Sunday to Thursday).
2. `scripts/build_feed.py` downloads public data from CISA, NVD and FIRST.
3. It builds the pages and saves a small snapshot in `data/`. The snapshot also feeds the archive.
4. The workflow publishes the pages to GitHub Pages.

There is no server, no token and no secret. The script uses only the Python standard library.

## One-time setup

1. Repo **Settings → Pages → Build and deployment → Source: GitHub Actions**.
2. Push these files. The first run starts by itself. You can also run it any time from **Actions → Daily threat feed → Run workflow**.

## Featured analysis

`analysis.html` is a longer write-up, published by hand. Replace the file and commit. The site publishes again on its own. If the file is missing, the link is left out.

## Settings you may want

| What | How |
|---|---|
| Change the time | Edit the `cron` line in `.github/workflows/daily-feed.yml`. Cron uses UTC. |
| Faster NVD calls | Get a free NVD API key. Add it as a repository secret named `NVD_API_KEY`. Not needed for normal use. |
| Show more or fewer items | Edit the numbers at the top of `scripts/build_feed.py` (`WINDOW_DAYS`, `NVD_TOP`). |

## If something fails

- **KEV cannot be downloaded.** The run stops. The site keeps the last good page. GitHub emails you.
- **NVD is down or slow.** The page still publishes. It shows a notice in the critical section.
- **EPSS is down.** The page publishes without EPSS scores.

GitHub pauses scheduled workflows after 60 days with no repo activity. The daily snapshot commit keeps the repo active.

## Try it on your own computer

```
python3 scripts/build_feed.py --out _site
```

Then open `_site/index.html`.

## Data and credits

- KEV: CISA Known Exploited Vulnerabilities Catalog.
- CVE data: the NVD API. This product uses data from the NVD API but is not endorsed or certified by the NVD.
- EPSS: FIRST (first.org/epss).

Personal project. Not an official SentinelOne publication. An automated summary, not advice.
