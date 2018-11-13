#! /usr/bin/env python

# Standard library imports

import json
import requests
from requests_oauthlib import OAuth1

maas_ip = '10.146.111.217'
maas_api_key = 'rByykC42mzw2CAEGYa:S6rssDE5E6QnptRx8U:SSbnmbyUt4feAu5K6usHQ2rCW599PvgP'


URL = "http://" + maas_ip + ":5240/MAAS/api/2.0/"
AUTH = OAuth1(maas_api_key.split(":")[0], '', maas_api_key.split(":")[1], maas_api_key.split(":")[2])
GET_HEADERS = {'Accept': 'application/json'}

def maas_get(path, get_params=""):
    return json.loads(requests.get(URL + path, headers=GET_HEADERS, auth=AUTH, params=get_params).content)





