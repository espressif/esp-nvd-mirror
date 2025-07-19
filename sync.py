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


def nvd_request(endpoint: str,
                key: str,
                parameters: Optional[dict] = None,
                syncdate: Optional[dict] = None) -> list:
    res = []
    start_idx = 0
    retry = 0
    retry_max = 100
    params = {}
    if parameters:
        params.update(parameters)

    if syncdate:
        now = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        syncdate[key]['lastModStartDate'] = syncdate[key]['lastModEndDate']
        syncdate[key]['lastModEndDate'] = now
        params.update(syncdate[key])

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
            if retry > retry_max:
                raise
            print((f'Failed to receive a response from NVD ({e}). '
                   f'Trying again ({retry}) in 10 seconds...'))
            time.sleep(10)
            continue

        if syncdate:
            syncdate[key]['lastModEndDate'] = data['timestamp']
        res += data[key]

        start_idx += int(data['resultsPerPage'])
        if int(data['totalResults']) == start_idx:
            break

    return res


def sync_cves(repo_path: Path,
              cveid: Optional[str] = None,
              syncdate: Optional[dict] = None) -> None:
    params = {'cveID': cveid} if cveid else None
    data = nvd_request('rest/json/cves/2.0',
                       'vulnerabilities',
                       parameters=params,
                       syncdate=syncdate)

    for cve in data:
        cve_id = cve['cve']['id']
        _, year, _ = cve_id.split('-')
        cve_dir_path = repo_path / 'cve' / year
        cve_dir_path.mkdir(parents=True, exist_ok=True)
        cve_path = cve_dir_path / f'{cve_id}.json'
        print(f'Updating {cve_path}')
        with open(cve_path, "w") as f:
            json.dump(cve, f)

    print(f'{len(data)} CVEs synced')


def sync_cpematch(repo_path: Path,
                  matchid: Optional[str] = None,
                  syncdate: Optional[dict] = None) -> None:
    params = {'matchCriteriaId': matchid} if matchid else None
    data = nvd_request('rest/json/cpematch/2.0',
                       'matchStrings',
                       parameters=params,
                       syncdate=syncdate)

    for ms in data:
        ms_id = ms['matchString']['matchCriteriaId']
        ms_dir_path = repo_path / 'cpematch' / ms_id[:2]
        ms_dir_path.mkdir(parents=True, exist_ok=True)
        ms_path = ms_dir_path / f'{ms_id}.json'
        print(f'Updating {ms_path}')
        with open(ms_path, "w") as f:
            json.dump(ms, f)

    print(f'{len(data)} CPE Match Strings synced')


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
    else:
        with open(syncdate_path, 'r') as f:
            syncdate = json.loads(f.read())

        sync_cpematch(repo_path, syncdate=syncdate)
        sync_cves(repo_path, syncdate=syncdate)

        with open(syncdate_path, 'w') as f:
            json.dump(syncdate, f, indent=4)
