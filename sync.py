#!/usr/bin/env python

import argparse
import datetime
import gzip
import hashlib
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

NVD_API_KEY = os.environ.get('NVD_API_KEY')
NVD_FEED_CVE_BASE = 'https://nvd.nist.gov/feeds/json/cve/2.0'


def normalize_iso_datetime(date_str: Optional[str] = None) -> str:
    """
    Converts a valid ISO 8601 datetime string to full ISO format with
    milliseconds and timezone. If no date_str is provided, uses current time.
    """
    if not date_str:
        dt = datetime.datetime.now(datetime.timezone.utc)
    else:
        dt = datetime.datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)

    return dt.isoformat(timespec='milliseconds')


def nvd_request(endpoint: str,
                params: dict,
                resync: Optional[bool] = False) -> list:
    res = []
    start_idx = 0
    retry = 0
    if resync:
        retry_max = 0
    else:
        retry_max = 50

    while True:
        params['startIndex'] = str(start_idx)
        params_enc = urllib.parse.urlencode(params)
        url = (f'https://services.nvd.nist.gov/{endpoint}?{params_enc}')
        print('PARAMS:', params)
        print('URL:', url)
        req = urllib.request.Request(url)
        if NVD_API_KEY:
            req.add_header('apiKey', NVD_API_KEY)

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())

        except (OSError, http.client.HTTPException, json.JSONDecodeError) as e:
            delay = 20
            if isinstance(e, urllib.error.HTTPError):
                if e.code == 404:
                    raise
                if e.code == 429:
                    delay = 60
            retry += 1
            if retry > retry_max and not resync:
                raise
            print((f'Failed to receive a response from NVD ({e}). '
                   f'Trying again ({retry}/{retry_max}) in {delay} seconds...'))
            time.sleep(delay)
            continue

        res.append(data)

        start_idx += int(data['resultsPerPage'])
        if int(data['totalResults']) == start_idx:
            break

        if int(data['resultsPerPage']) == 0:
            raise RuntimeError(
                f'NVD returned resultsPerPage=0 with totalResults='
                f'{data["totalResults"]} > startIndex={start_idx}. '
                f'Aborting to avoid committing partial data.')

    return res


def download_feed(url: str, retry_max: int = 10) -> bytes:
    retry = 0
    while True:
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                return resp.read()

        except (OSError, http.client.HTTPException) as e:
            if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                raise
            retry += 1
            if retry > retry_max:
                raise
            print((f'Failed to download {url} ({e}). '
                   f'Trying again ({retry}/{retry_max}) in 20 seconds...'))
            time.sleep(20)
            continue


def parse_meta(raw: bytes) -> dict:
    meta = {}
    for line in raw.decode().splitlines():
        key, sep, value = line.partition(':')
        if sep:
            meta[key.strip()] = value.strip()
    return meta


def nvd_feed() -> list:
    """
    Download all NVD CVE JSON 2.0 yearly feeds (2002 to the current year)
    and return them as a list of response objects, mirroring the structure
    returned by nvd_request() so that sync_cves() can consume either source
    unchanged. The feeds are static CDN files, unaffected by the REST API's
    rate limits and availability problems, which makes them the reliable way
    to perform a full CVE refresh. Each payload is verified against the
    SHA-256 published in its companion .meta file before being parsed.
    """
    res = []
    current_year = datetime.datetime.now(datetime.timezone.utc).year
    for year in range(2002, current_year + 1):
        base = f'{NVD_FEED_CVE_BASE}/nvdcve-2.0-{year}'
        print('FEED:', f'{base}.json.gz')
        meta = parse_meta(download_feed(f'{base}.meta'))
        payload = gzip.decompress(download_feed(f'{base}.json.gz'))

        expected = meta.get('sha256', '').lower()
        actual = hashlib.sha256(payload).hexdigest()
        if expected and actual != expected:
            raise RuntimeError(
                f'sha256 mismatch for {base}.json.gz: expected {expected}, '
                f'got {actual}. Aborting to avoid writing corrupt data.')

        res.append(json.loads(payload))

    return res


def sync_cves(repo_path: Path,
              resync: bool = False,
              cveid: Optional[str] = None,
              syncdate: Optional[dict] = None,
              feed: bool = False) -> None:
    if resync:
        params = {}
    elif cveid:
        params = {
            'cveID': cveid
        }
    elif syncdate:
        start_date = syncdate['vulnerabilities']['lastModEndDate']
        params = {
            'lastModStartDate': normalize_iso_datetime(start_date),
            'lastModEndDate': normalize_iso_datetime()
        }

    if feed:
        data = nvd_feed()
    else:
        data = nvd_request('rest/json/cves/2.0', params, resync=resync)

    last_modified_dt = None
    cnt = 0
    for res in data:
        for cve in res['vulnerabilities']:
            cnt += 1
            cve_id = cve['cve']['id']
            _, year, _ = cve_id.split('-')
            cve_dir_path = repo_path / 'cve' / year
            cve_dir_path.mkdir(parents=True, exist_ok=True)
            cve_path = cve_dir_path / f'{cve_id}.json'
            print(f'Updating {cve_path}')
            with open(cve_path, "w") as f:
                json.dump(cve, f)

            cve_modified_dt = datetime.datetime.fromisoformat(cve['cve']['lastModified'])
            if last_modified_dt is None or last_modified_dt < cve_modified_dt:
                last_modified_dt = cve_modified_dt

    if last_modified_dt is not None and syncdate is not None:
        last_mod_start = syncdate['vulnerabilities']['lastModEndDate']
        last_mod_end = last_modified_dt.isoformat()
        syncdate['vulnerabilities']['lastModStartDate'] = normalize_iso_datetime(last_mod_start)
        syncdate['vulnerabilities']['lastModEndDate'] = normalize_iso_datetime(last_mod_end)

    print(f'{cnt} CVEs synced')


def sync_cpematch(repo_path: Path,
                  resync: bool = False,
                  matchid: Optional[str] = None,
                  syncdate: Optional[dict] = None) -> None:
    if resync:
        params = {}
    elif matchid:
        params = {
            'matchCriteriaId': matchid
        }
    elif syncdate:
        start_date = syncdate['matchStrings']['lastModEndDate']
        params = {
            'lastModStartDate': normalize_iso_datetime(start_date),
            'lastModEndDate': normalize_iso_datetime()
        }

    data = nvd_request('rest/json/cpematch/2.0', params, resync=resync)

    last_modified_dt = None
    cnt = 0
    for res in data:
        for ms in res['matchStrings']:
            cnt += 1
            ms_id = ms['matchString']['matchCriteriaId']
            ms_dir_path = repo_path / 'cpematch' / ms_id[:2]
            ms_dir_path.mkdir(parents=True, exist_ok=True)
            ms_path = ms_dir_path / f'{ms_id}.json'
            print(f'Updating {ms_path}')
            with open(ms_path, "w") as f:
                json.dump(ms, f)

            ms_modified_dt = datetime.datetime.fromisoformat(ms['matchString']['lastModified'])
            if last_modified_dt is None or last_modified_dt < ms_modified_dt:
                last_modified_dt = ms_modified_dt

    if last_modified_dt is not None and syncdate is not None:
        last_mod_start = syncdate['matchStrings']['lastModEndDate']
        last_mod_end = last_modified_dt.isoformat()
        syncdate['matchStrings']['lastModStartDate'] = normalize_iso_datetime(last_mod_start)
        syncdate['matchStrings']['lastModEndDate'] = normalize_iso_datetime(last_mod_end)

    print(f'{cnt} CPE Match Strings synced')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='sync',
        description=(
            'Synchronize NVD data in the repository specified by the PATH '
            'argument. If only PATH is provided, the synchronization will '
            'be based on the dates listed in the repository\'s syncdata.json '
            'file, which will be updated once the synchronization is complete.'
            )
    )

    parser.add_argument(
        'repo',
        metavar='PATH',
        help='PATH to the NVD data repository.'
    )

    parser.add_argument(
        '--resync', '-r',
        action='store_true',
        help=(
            'Re-synchronize the whole repository.'
        )
    )

    parser.add_argument(
        '--feed',
        action='store_true',
        help=(
            'Only valid together with --resync. Perform the full CVE '
            'resync from the NVD bulk JSON 2.0 yearly feeds '
            '(https://nvd.nist.gov/feeds/json/cve/2.0/) instead of the '
            'REST API. Use this when the REST API is degraded or '
            'rate-limited. CPE match data is skipped and its sync state '
            'in syncdate.json is left untouched.'
        )
    )

    parser.add_argument(
        '--cveid', '-c',
        metavar='CVEID',
        help=(
            'Synchronize only CVE specified by CVEID.'
        )
    )

    parser.add_argument(
        '--matchid', '-m',
        metavar='MATCHCRITERIAID',
        help=(
            'Synchronize only CPE Match Criteria specified '
            'by MATCHCRITERIAID.'
        )
    )

    args = parser.parse_args()

    if args.feed and not args.resync:
        parser.error('--feed can only be used together with --resync')

    repo_path = Path(args.repo)
    syncdate_path = repo_path / 'syncdate.json'

    if args.cveid:
        sync_cves(repo_path, cveid=args.cveid)
    elif args.matchid:
        sync_cpematch(repo_path, matchid=args.matchid)
    elif args.resync:
        epoch_start = '1970-01-01'
        if args.feed:
            # CVE-only resync from the yearly feeds. Preserve the existing
            # CPE match sync state in syncdate.json, since cpematch is not
            # touched here; only the vulnerabilities window is reset.
            if syncdate_path.exists():
                with open(syncdate_path, 'r') as f:
                    syncdate = json.loads(f.read())
            else:
                syncdate = {
                    'matchStrings': {
                        'lastModStartDate': epoch_start,
                        'lastModEndDate': epoch_start
                    }
                }
            syncdate['vulnerabilities'] = {
                'lastModStartDate': epoch_start,
                'lastModEndDate': epoch_start
            }
            sync_cves(repo_path, resync=True, syncdate=syncdate, feed=True)
        else:
            syncdate = {
                'vulnerabilities': {
                    'lastModStartDate': epoch_start,
                    'lastModEndDate': epoch_start
                },
                'matchStrings': {
                    'lastModStartDate': epoch_start,
                    'lastModEndDate': epoch_start
                }
            }
            sync_cpematch(repo_path, resync=True, syncdate=syncdate)
            sync_cves(repo_path, resync=True, syncdate=syncdate)

        with open(syncdate_path, 'w') as f:
            json.dump(syncdate, f, indent=4)
    else:
        with open(syncdate_path, 'r') as f:
            syncdate = json.loads(f.read())

        sync_cpematch(repo_path, syncdate=syncdate)
        sync_cves(repo_path, syncdate=syncdate)

        with open(syncdate_path, 'w') as f:
            json.dump(syncdate, f, indent=4)
