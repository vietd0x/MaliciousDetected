#!/usr/bin/python3
import requests
import json
import time

# input file contain hash
inpFile = 'fileSha256.csv'
myAPIkey = ["", "", ""]
idx = 0

with open(inpFile, "r") as f:
    for line in f:
        sha256 = line.split(',')[1][:-1]

        url = "https://www.virustotal.com/api/v3/files/" + sha256
        headers = {
            "Accept": "application/json",
            "x-apikey": myAPIkey[idx]
        }
        response = requests.get(url, headers=headers)
        time.sleep(15)
        if(response.status_code == 200): # success
            res = json.loads(response.text.replace("\n", "").replace(" ",""))
            last_stat = res["data"]["attributes"]["last_analysis_stats"]
            if(last_stat['harmless'] > 4 or last_stat['malicious'] > 4):
                print(line.split(',')[0], "MALICIOUS!")
        elif(response.status_code == 429): # quota exceeded
            if(idx == len(myAPIkey)-1):
                break
            idx += 1
        elif(response.status_code == 404):
            print(line.split(',')[0], "Not found!")
        else:
            print(response.status_code)
            print("ERR")
            break
