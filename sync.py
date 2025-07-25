#!/usr/bin/env python

import argparse
import datetime
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional


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
        retry_max = 100

    while True:
        params['startIndex'] = str(start_idx)
        params_enc = urllib.parse.urlencode(params)
        url = (f'https://services.nvd.nist.gov/{endpoint}?{params_enc}')
        print('PARAMS:', params)
        print('URL:', url)
        req = urllib.request.Request(url)

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())

        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            retry += 1
            if retry > retry_max and not resync:
                raise
            print((f'Failed to receive a response from NVD ({e}). '
                   f'Trying again ({retry}/{retry_max}) in 10 seconds...'))
            time.sleep(10)
            continue

        res.append(data)

        start_idx += int(data['resultsPerPage'])
        if int(data['totalResults']) == start_idx:
            break

    return res


def sync_cves(repo_path: Path,
              resync: bool = False,
              cveid: Optional[str] = None,
              syncdate: Optional[dict] = None) -> None:
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

    repo_path = Path(args.repo)
    syncdate_path = repo_path / 'syncdate.json'

    if args.cveid:
        sync_cves(repo_path, cveid=args.cveid)
    elif args.matchid:
        sync_cpematch(repo_path, matchid=args.matchid)
    elif args.resync:
        epoch_start = '1970-01-01'
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
