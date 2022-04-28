# Convert domain to ip and check IP is ip of Google Cloud or Cloud Flare.
## 
usage: checkdomain.py [-h] [-f FILE] [-i IP]

From domain return ip hostname and check if is ip of Google Cloud or CloudFlare. Only support IPV4

## optional arguments:
  -h, --help            show this help message and exit\
  -f FILE, --file FILE  File subdomains\
  -i IP, --ip IP        IP need check
## EX:
 python3 checkdomain.py -f listsubdomain.txt\
 python3 checkdomain.py -i 8.8.8.8
