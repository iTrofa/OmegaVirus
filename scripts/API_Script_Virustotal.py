from __future__ import print_function
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY = '38afdb6f1267ae26374823c5e80d84fc977ed7b326b152d21fedd15ca29f36dc'

EICAR = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode('utf-8')
EICAR_MD5 = hashlib.md5(EICAR).hexdigest()

vt = VirusTotalPublicApi('38afdb6f1267ae26374823c5e80d84fc977ed7b326b152d21fedd15ca29f36dc')

response = vt.get_file_report(EICAR_MD5)
print(json.dumps(response, sort_keys=False, indent=4))
