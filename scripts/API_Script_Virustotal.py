from __future__ import print_function
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import sys
import time


def arg():
    i = 0
    filename = str()
    if len(sys.argv) <= 1:
        print(
            "Entrer le nom du binaire suivi du nombre d'itérations \n soit -f pour file \n ./something.py -f file.bin ")
        sys.exit(0)
    else:
        for arg in sys.argv:
            if arg == "-h":
                print(
                    "Entrer le nom du binaire suivi du nombre d'itérations \n soit -f pour file \n ./something.py -f file.bin")
            if arg == "-f":
                filename = sys.argv[i + 1]
            i += 1
        return filename


filename = arg()


def info_file(filename):
    BUF_SIZE = 65536
    file_md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            file_md5.update(data)
    return file_md5.hexdigest()


file_md5 = info_file(filename)
print(file_md5)

API_KEY = '38afdb6f1267ae26374823c5e80d84fc977ed7b326b152d21fedd15ca29f36dc'

"""EICAR = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode('utf-8')
EICAR_MD5 = hashlib.md5(EICAR).hexdigest()"""

vt = VirusTotalPublicApi('38afdb6f1267ae26374823c5e80d84fc977ed7b326b152d21fedd15ca29f36dc')

"""Check if file is in VT's cache"""

response = vt.get_file_report(file_md5)
json_dump = json.dumps(response, sort_keys=False, indent=4)
json_list = json.loads(json_dump)
verbose_msg = ""
for item_key, item_values in json_list.items():
    if 'results' in item_key:
        print("Scanning... ")
        verbose_msg = json_list['results']['verbose_msg']
print(verbose_msg)

if verbose_msg != "Scan finished, information embedded":
    print("Uploading file..")
    vt.scan_file(filename)
    """while verbose_msg == "The requested resource is not among the finished, queued or pending scans":
        vt.scan_file(filename)
        response = vt.get_file_report(file_md5)
        json_dump = json.dumps(response, sort_keys=False, indent=4)
        json_list = json.loads(json_dump)
        verbose_msg = ""
        for item_key, item_values in json_list.items():
            if 'results' in item_key:
                verbose_msg = json_list['results']['verbose_msg']
                print(verbose_msg)"""
if verbose_msg != "Scan finished, information embedded":
    verbose_msg = ""


"""Scanning file"""

time_check = 0
while verbose_msg != "Scan finished, information embedded":
    if verbose_msg == "Scan finished, information embedded":
        break
    response = vt.get_file_report(file_md5)
    json_dump = json.dumps(response, sort_keys=False, indent=4)
    json_list = json.loads(json_dump)
    for item_key, item_values in json_list.items():
        if 'results' in item_key:
            verbose_msg2 = verbose_msg
            verbose_msg = json_list['results']['verbose_msg']
            if verbose_msg != verbose_msg2:
                if verbose_msg != "The requested resource is not among the finished, queued or pending scans":
                    print(verbose_msg)
    time.sleep(8)
    if time_check >= 120:
        print("Time limit surpassed")
        sys.exit(0)
    if verbose_msg == "Your resource is queued for analysis":
        time_check += 8
        print("Scanning... " + str(time_check) + " seconds elapsed..")

response_code = json_list['response_code']
scan_id = json_list['results']['scan_id']
sha1 = json_list['results']['sha1']
resource = json_list['results']['resource']
scan_date = json_list['results']['scan_date']
permalink = json_list['results']['permalink']
sha256 = json_list['results']['sha256']
positives = json_list['results']['positives']
total = json_list['results']['total']
md5 = json_list['results']['md5']
liste_AV=[i for i in json_list["results"]["scans"]]
liste_AV_Result=[str(i) + " ----- " + str(json_list["results"]["scans"][i]["detected"]) for i in liste_AV]
liste_AV_result_html=[(str(i),str(json_list["results"]["scans"][i]["detected"])) for i in liste_AV]


html=str()
for i,j in liste_AV_result_html:
    html+='</tr><th scope="row">'+i+'</th><td>'+j+'</td></tr>'

print(html)

print(response_code)
print(scan_id)
print(sha1)
print(resource)
print(scan_date)
print(permalink)
print(verbose_msg)
print(sha256)
print(positives)
print(total)
print(md5)
print(liste_AV_Result)
print("Scan time taken: " + str(time_check) + " seconds.")
