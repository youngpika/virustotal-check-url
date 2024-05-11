import requests
import sys
for arg in sys.argv[1:]:
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    param = dict(apikey='abc52ccb2c94db6709e9ac5f4ccaa7a91a688e684e983030c0de04f7e76f4759', resource=f"{arg}", scan=0)
    response = requests.get(api_url, params=param)
    if response.status_code == 200:
       result = response.json()
       print(f"\nScanDate: {result['scan_date']}\nResource: {result['resource']}\nTotalCheck: {result['total']}\nPositiveCheck: {result['positives']}")
       if result["positives"] == 0:
           print(f"URL - {result['resource']} is security")
       else:
           print(f"URL - {result['resource']} with malware")
