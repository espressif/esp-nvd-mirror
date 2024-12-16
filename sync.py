#!/usr/bin/env python

import datetime
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


def nvd_request(endpoint: str, syncdate: dict, key: str) -> list:
    res = []
    start_idx = 0
    retry = 0
    retry_max = 100

    now = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
    syncdate[key]['lastModStartDate'] = syncdate[key]['lastModEndDate']
    syncdate[key]['lastModEndDate'] = now
    params = syncdate[key].copy()
    while True:
        params['startIndex'] = str(start_idx)
        params_enc = urllib.parse.urlencode(params)
        url = (f'https://services.nvd.nist.gov/{endpoint}?{params_enc}')
        print(url)
        req = urllib.request.Request(url)

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())

        except (urllib.error.HTTPError, Exception) as e:
            retry += 1
            if retry > retry_max:
                raise
            print((f'Failed to receive a response from NVD ({e}). '
                   f'Trying again ({retry}) in 10 seconds...'))
            time.sleep(10)
            continue

        syncdate[key]['lastModEndDate'] = data['timestamp']
        res += data[key]

        start_idx += int(data['resultsPerPage'])
        if int(data['totalResults']) == start_idx:
            break

    return res


def sync_cves(repo_path: Path, syncdate: dict) -> None:
    data = nvd_request('rest/json/cves/2.0', syncdate, 'vulnerabilities')

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


def sync_cpematch(repo_path: Path, syncdate: dict) -> None:
    data = nvd_request('rest/json/cpematch/2.0', syncdate, 'matchStrings')

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
    if len(sys.argv) != 2:
        sys.exit(f'usage: {sys.argv[0]} <repository>')

    repo_path = Path(sys.argv[1])
    syncdate_path = repo_path / 'syncdate.json'

    with open(syncdate_path, 'r') as f:
        syncdate = json.loads(f.read())

    sync_cpematch(repo_path, syncdate)
    sync_cves(repo_path, syncdate)

    with open(syncdate_path, 'w') as f:
        json.dump(syncdate, f, indent=4)
