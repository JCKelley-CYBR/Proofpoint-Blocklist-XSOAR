register_module_line('ProofPoint-BlockList', 'start', __line__())
######################
# Title: ProofPoint XSOAR Integratioin
# Author: Joshua Kelley
# Version: 1.0
# Description: This integration takes advantage of the Proofpoint API to add functionality to XSOAR
######################

import requests
import json

AUTH_URL = "https://auth.proofpoint.com/v1/token"
PP_URL = "https://threatprotection-api.proofpoint.com/api/v1/emailProtection/modules/spam/orgBlockList?clusterId=REPLACEME"

KEY = demisto.params().get('credentials', {}).get('identifier') or demisto.params().get('client_id')
SECRET = demisto.params().get('credentials', {}).get('password') or demisto.params().get('secret')
CLUSTER_ID = "YOURCLUSTERID" # CHANGE this to your cluster ID

def test_module():
    return 'ok'

def getToken():
    HEADERS = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    BODY = "grant_type=client_credentials&client_id=KEY&client_secret=SECRET"
    BODY = BODY.replace("KEY", KEY)
    BODY = BODY.replace("SECRET", SECRET)

    response = requests.post(url=AUTH_URL, headers=HEADERS, data=BODY)
    token = json.loads(response.text)
    return token['access_token']

def blocklist(action, attribute, operator, value, comment):
    auth_token = getToken()
    authorization = "Bearer " + auth_token
    HEADERS = {
        "Content-Type": "application/json"
        , "Authorization": authorization
    }

    BODY = {
        "action": action
        ,"attribute": attribute
        ,"operator": operator
        ,"value": value
        ,"comment": comment
    }

    url = PP_URL.replace("REPLACEME", CLUSTER_ID)
    response = requests.post(url=url, headers=HEADERS, json=BODY)

    if (response.status_code == 200):
        print(action + " on " + value + " successful.")
    else:
        error_message = json.loads(response.text)
        error_message = error_message['errorMessage']
        if (error_message == "error.api.emailprotection.lists.samelist.duplicate.entry"):
            print(action + " on " + value + " failed.  Entry already exists.")
        else:
            print(action + " on " + value + " failed.")
    return response.text

def main():
    command = demisto.command()
    try:
        if command == "test-module":
            return_results(test_module())
        elif command == "PP-BlockList":
            action = demisto.args()['action'] # add | delete
            attribute = demisto.args()['attribute'] # $from | $hfrom | $ip | $host | $helo | $rcpt
            operator = demisto.args()['operator'] # equal | contain
            value = demisto.args()['value']
            comment = demisto.args()['comment']
            return_results(blocklist(action, attribute, operator, value, comment))
        else:
            raise NotImplementedError(f'ProofPoint API error: '
                                      f'command {command} is not implemented')
    except Exception as e:
        return_error(str(e))
    pass

if __name__ in ('__main__', 'builtin', 'builtins'):
    main()

register_module_line('ProofPoint-BlockList', 'end', __line__())