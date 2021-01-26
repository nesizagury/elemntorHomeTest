import base64
import json
import sqlite3 as lite
import time
import re

import requests

HEADERS = {
    "x-apikey": "e876d03057208dc7a2b0d98e56d006b28ef041e975d4e40f1b924c46c15df041",
}
CON = lite.connect('sites.db')
SECONDS_TTL = 1800


def get_url_data_from_vt(url):
    result = {}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=HEADERS).json()

    total_votes = r['data']['attributes']['total_votes']

    malicious = total_votes.get('malicious', 0)
    phishing = total_votes.get('phishing', 0)
    malware = total_votes.get('malware', 0)
    if malicious > 1 or phishing > 1 or malware > 1:
        result['safety'] = 'risk'
    else:
        result['safety'] = 'safe'

    result['total_votes'] = re.sub("[^a-zA-Z0-9 :,]+", "", json.dumps(total_votes))
    result['categories'] = re.sub("[^a-zA-Z0-9 :,]+", "", json.dumps(r['data']['attributes']['categories']))

    return result


def get_from_api_and_save(cur, insert, url):
    url_info = get_url_data_from_vt(url)
    total_votes = url_info['total_votes']
    categories = url_info['categories']
    safety = url_info['safety']
    now = int(time.time())
    if insert is True:
        cur.execute(f"""INSERT INTO url_safety_data VALUES('{url}','{safety}','{total_votes}','{categories}',{now})""")
    else:
        cur.execute(
            f"""UPDATE url_safety_data SET (safety, total_votes, categories, updated) = ('{safety}','{total_votes}','{categories}',{now}) where url = '{url}'""")
    CON.commit()

    return url_info


# can be add here flask or some other api framework
def get_url_data(url):
    now = int(time.time())
    cur = CON.cursor()
    cur.execute(f"""INSERT INTO url_safety_data_requests VALUES('{url}',{now})""")
    CON.commit()
    cur.execute(f"""SELECT url, safety, total_votes, categories, updated FROM url_safety_data where url = '{url}'""")

    data = None
    insert = True
    for tablerow in cur.fetchall():
        diff = now - int(tablerow[4])
        if diff > SECONDS_TTL:
            data = None
            insert = False
        else:
            data = {"safety": tablerow[1], "total_votes": tablerow[2], "categories": tablerow[3]}
        break

    if data is None:
        data = get_from_api_and_save(cur, insert, url)

    return data
