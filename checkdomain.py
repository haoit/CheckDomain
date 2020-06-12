#################################################################################
# Parse domain to ip and location and check it is cloud GCP or cloud flare IP   #
# HaoNH																			#
#################################################################################

import argparse
import requests
import json
import socket
import ipaddress
import threading


URL_GCP_IPRANGES = "http://www.gstatic.com/ipranges/cloud.json"
URL_IPV4_ClOUDFLARE = "https://www.cloudflare.com/ips-v4"
URL_IPV6_CLOUDFLARE= "https://www.cloudflare.com/ips-v6"
URL_API_IPINFO = "http://ipinfo.io/"
URL_HOST_JSON2CSV ="https://json-csv.com"


dataip =[]


def get_ipv4_ranges_GCP():
	ranges = []
	r = requests.get(URL_GCP_IPRANGES)
	data =  json.loads(r.content)
	for i in data["prefixes"]:

		if ("ipv4Prefix" in i):
			ranges.append(i["ipv4Prefix"])
	return ranges

def get_ipv4_ranges_CLF():
	ranges = []
	r = requests.get(URL_IPV4_ClOUDFLARE)
	data = r.text.split("\n")[:-1]
	return data

def check_is(ip,typecheck):
	if(typecheck =="GCP"):
		ranges = get_ipv4_ranges_GCP()
	elif(typecheck == "CLF"):
		ranges = get_ipv4_ranges_CLF()
	for i in ranges:
		if(ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(i)):
			print("Check Type: ", typecheck)
			print("Network Found:",i)
			return True
	return False

def get_ip_location(ip):
	r = requests.get(URL_API_IPINFO+ip+"/json")
	data =  json.loads(r.content)
	return data

def get_ip_from_domain(domainName):
	try:
		return socket.gethostbyname(domainName)
	except Exception as e:
		return None
	
def parse_domain(domain):
	ip = get_ip_from_domain(domain)
	if ip:
		datalocation = get_ip_location(ip)
		push_to_data(domain,ip,datalocation)

def parse_get_parentdomain(domain):
	splitdata = domain.split(".")
	if len(splitdata) < 3:
		return "*."+domain
	else:
		return "*."+'.'.join(splitdata[-2:])

def push_to_data(domain,ip,datalocation):
	tmp = {}
	datalocation["host"] = parse_get_parentdomain(domain)
	datalocation["domain"] = domain
	datalocation["IP IN GOOGLE CLOUD"] = check_is(ip,"GCP")
	datalocation["IP IN CloudFlare"] = check_is(ip,"CLF")
	dataip.append(datalocation)

def get_domain_from_file(filename):
	with open(filename) as f:
		content = f.readlines()
	return [x.strip() for x in content if x]
def gen_excel_output_files():	
	data = {"json":json.dumps(dataip)}
	r = requests.post(URL_HOST_JSON2CSV+"/conversion/start", data = data)
	respone =  json.loads(r.content)
	if(respone["errorhtml"]):
		print(errorhtml)
	else:
		print(respone)
		print("[i] Download CSV file: https://json-csv.com/conversion/download?id="+respone["id"]+"&delimeter=0&filename=result&zipped=0")


def main():
	threads =[]
	parser = argparse.ArgumentParser(description='Check domain return ip hostname and check if is ip of Google Cloud or CloudFlare. Only support IPV4')
	parser.add_argument('-f','--file',default="list.txt",
                    help='File subdomains')
	parser.add_argument('-i','--ip',
                    help='IP need check')
	args = vars(parser.parse_args())
	if(args['ip']):
		print("[i] Check IP: ", args['ip'])
		print("[+] IP Location Infor: ",get_ip_location(args['ip']))
		print("[+] IS In CloudFlare: ",check_is(args['ip'],"CLF"))
		print("[+] IS In GoogleCloud: ",check_is(args['ip'],"GCP"))
	else:
		filename = args['file']
		print("[i] Get data from file ",filename )
		domains = get_domain_from_file("list.txt")
		for domain in domains:
			t = threading.Thread(target=parse_domain, args = (domain,))
			t.start()
			threads.append(t)
		for i in threads:
			i.join()
		print("[+] Done. Good Luck! ")
		print(json.dumps(dataip))
		gen_excel_output_files()

main()