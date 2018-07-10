#############################################################################################
#                                                                                           #
# Author:  Sanket R Bhimani @ Crest Data System                                             #
# Date:    4th Mar 2018                                                                     #
# Version: 2.0                                                                              #
# Help:-                                                                                    #
# python app_post_checks.py --app-ids 1234,5678 --stack abcd                                #
# python app_post_checks.py -ids 1234,5678 -s abcd                                          #
# python app_post_checks.py -h                                                              #
# python app_post_checks.py --help                                                          #
#                                                                                           #
#############################################################################################

import urllib, urllib2, urllib3, base64, json, sys, argparse, re, copy, warnings, os
from ansible_vault import Vault
from jira.client import JIRA
import dns.resolver, tarfile
from confluence import Api
from bs4 import BeautifulSoup
from BeautifulSoup import BeautifulSoup as bs

from variables import *

warnings.filterwarnings("ignore")


parser = argparse.ArgumentParser()
parser.add_argument('-ids','--app-ids', help='App id', required=False)
parser.add_argument('-s','--stack', help='Stack name', required=True)
args = parser.parse_args()
 
APP_IDS=args.app_ids
APP_VS={}
STACK=args.stack
JIRA_ID=""
APP_IDSS = []

ERROR = []

SHs = {}


jira_server = JIRA_SERVER
jira_user = AD_USER
jira_password = AD_PASSWORD
TOKEN = GITHUB_PERSONAL_ACCESS_TOKEN
IS_CW = 0 #is the stack cloudworks stack?

USERNAME = "admin"

def get_latest_version(app_id):

	soup = BeautifulSoup(page,"html.parser")
	v_list =[]
	regexp = "^("+app_id+"_)((\.|\d)*)(\.zip|\.tgz|\.tar\.gz|\.tar|\.spl)$"
	_rex = re.compile(regexp)
	for v in soup.findAll('a', {"href":re.compile(app_id)}):
		if _rex.search(v.find(text=True)):
			match = re.search(regexp, v.find(text=True))
			v_list.append(match.group(2))
	if v_list.__len__() != 0:
		v_list.sort(key=lambda s: map(int, s.split('.')))
		return v_list[-1]
	else:
		return "###"

def get_status_code_and_size(url):
	site = urllib.urlopen(url)
	res_code = site.getcode()
	if res_code == 200:
		size = site.info().getheaders("Content-Length")[0]
	else:
		size = 0
	return res_code,size

def get_app_folder_name(app_filename):
	try:
		url="https://internal-1sot.splunkcloud.com/artifactory/splunk-general/prod/apps/"+app_filename
		res_code,size = get_status_code_and_size(url)
		agree = 1
		if res_code == 200:
			try:
				size = int(size)
			except:
				return "ERROR"

		if size > 6000000:
			_input = raw_input("The app "+app_filename+" is more than 5MB.\nDo you want to continue, as it'll take more time to retrive app folder name?(y/n):")
			if _input.lower() == 'y':
				agree = 1
			else:
				agree = 0
		else:
			agree = 1
		if agree == 1:
			app_filename = url.split('/')[-1]
			u = urllib2.urlopen(url)
			f = open(app_filename, 'wb')
			meta = u.info()
			file_size = int(meta.getheaders("Content-Length")[0])

			file_size_dl = 0
			block_sz = 8192
			while True:
			    buffer = u.read(block_sz)
			    if not buffer:
			        break
			    file_size_dl += len(buffer)
			    f.write(buffer)
			    status = r"Downloading the app "+app_filename+": %10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
			    status = status + chr(8)*(len(status)+1)
			    print status,
			f.close()
			print "                                                            "
			tar = tarfile.open(app_filename, mode='r')
			folder_name = os.path.commonprefix(tar.getnames())
			if folder_name[-1:] == '/':
				folder_name = folder_name[:-1]
			if os.path.isfile(app_filename):
				os.remove(app_filename)
			return folder_name
		else:
			return "ERROR_big_file"
	except:
		if os.path.isfile(app_filename):
			os.remove(app_filename)

def self_service_check(app_id):
    url = "https://splunkbase.splunk.com/api/v1/app/"+app_id.__str__()+"/?include=release,release.splunk_compatibility"
    urllib3.contrib.pyopenssl.inject_into_urllib3()
    urllib3.disable_warnings()
    http = urllib3.PoolManager(10)
    result = http.request("GET",url)
    _app_name = ""
    _method = ""
    if result.status == 200:
        res = json.loads(result.data)
        _app_name = res["appid"].__str__()
        _method = res["install_method_distributed"].__str__()
        return _app_name,_method
    else:
        return "ERROR","ERROR"

def query_yes_no(question, default="no"):
	valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
	if default is None:
		prompt = " [y/n] "
	elif default == "yes":
		prompt = " [Y/n] "
	elif default == "no":
		prompt = " [y/N] "
	else:
		raise ValueError("invalid default answer: '%s'" % default)
	while True:
		sys.stdout.write(question + prompt)
		choice = raw_input().lower()
		if default is not None and choice == '':
			return valid[default]
		elif choice in valid:
			return valid[choice]
		else:
			sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

def check_on_splunkbase(app_id,app_v):
	page = urllib2.urlopen(SPLUNKBASE_URL+app_id+'/')
	if page.code.__str__() == "200":
		soup = bs(page)
		splunk_var = ""
		if soup.body.find("option", {"value" : app_v}) != None and soup.body.find("option", {"value" : app_v}).find(text=True).strip() != "":
			for obj in soup.body.findAll("sb-release-select", {"sb-target" : app_v}):
				if "Splunk Versions:" in obj.find(text=True):
					for a_tag in obj.findAll('a'):
						if a_tag!= None and a_tag.find(text=True).strip() != "":
							splunk_var += a_tag.find(text=True)+", "
			return splunk_var[:-2]
		else:
			return "ERROR_404"
	else:
		return "ERROR_404"

def get_stack_password():
	if IS_CW == 0:
		vault = Vault(ANSIBLE_VAULT)
		#try:
		urllib3.contrib.pyopenssl.inject_into_urllib3()
		urllib3.disable_warnings()
		user_agent = {'user-agent': 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) ..'}
		http = urllib3.PoolManager(10, headers=user_agent)
		url = 'https://api.github.com/repos/SplunkStorm/stax/contents/wormhole/secure_vars/tag_Stack_'+STACK+'/secure.yml?access_token='+TOKEN
		result = http.request("GET",url)
		if result.status == 200:
			req = json.loads(result.data)
			content = base64.decodestring(req['content'])
			_pass = vault.load(content)['stack_password']
			return _pass
		else:
			return "ERROR_404" #stack not found
		#except:
		#	return "ERROR"
	else:
		return "ERROR_CW"

PASSWORD = get_stack_password()
print PASSWORD
if "ERROR" in PASSWORD:
	PASSWORD = "###"
	print "Couldn't fetch the stack password - Could be CloudWorks stack"


def check_SF_RF():
	url = "https://internal-c0m1."+STACK+".splunkcloud.com:8089/services/cluster/master/generation?output_mode=json"
	urllib3.contrib.pyopenssl.inject_into_urllib3()
	urllib3.disable_warnings()
	headers = urllib3.util.make_headers(basic_auth=USERNAME+':'+PASSWORD)
	http = urllib3.PoolManager(10, headers=headers)
	result = http.request("GET",url)
	if result.status == 200:
		res = json.loads(result.data)
		idx = ""
		try:
			for i in res[u'entry'][0][u'content'][u'generation_peers']:
				if res[u'entry'][0][u'content'][u'generation_peers'][i][u'status'] == "Up":
					idx = res[u'entry'][0][u'content'][u'generation_peers'][i][u'peer'].split('.')[0]
					SHs['Indexers'] = idx
					break;
		except:
			print "problem with the indexers"
		rf = res[u'entry'][0][u'content'][u'replication_factor_met'].__str__()
		sf = res[u'entry'][0][u'content'][u'search_factor_met'].__str__()
		if sf == '1':
			sf = "True"
		else:
			sf = "False"
		if rf == '1':
			rf = "True"
		else:
			rf = "False"
		return sf,rf
	elif result.status == 401:
		return "ERROR_auth","ERROR_auth"
	else:
		return "ERROR","ERROR"

def get_install_status(folder_name,sh):
	try:
		url = "https://internal-"+sh+"."+STACK+".splunkcloud.com"+":8089/services/apps/local/"+folder_name+"?output_mode=json"
		#print url
		urllib3.contrib.pyopenssl.inject_into_urllib3()
		urllib3.disable_warnings()
		headers = urllib3.util.make_headers(basic_auth=USERNAME+':'+PASSWORD)
		http = urllib3.PoolManager(10, headers=headers)

		result = http.request("GET",url)
		#print result.data
		if result.status == 200:
			res = json.loads(result.data)
			installed = 'yes'
			restart_req = res[u'entry'][0][u'content'][u'state_change_requires_restart'].__str__()
			current_ver = res[u'entry'][0][u'content'][u'version'].__str__()
			return installed,restart_req,current_ver
		elif result.status == 401:
			return "ERROR_auth","ERROR_auth","ERROR_auth"
		elif result.status == 404:
			return "ERROR_404","ERROR_404","ERROR_404"
		else:
			return "ERROR","ERROR","ERROR"
	except:
		print "Internal DNS entry invalid: internal-"+sh+"."+STACK+".splunkcloud.com or 8089 port is not UP"
		return "ERROR","ERROR","ERROR"

def main():
	global IS_CW
	global JIRA_ID
	if APP_IDS != None:
		for APP_ID in APP_IDS.split(','):
			APP_V = get_latest_version(APP_ID)
			if(APP_V == "###"):
				print "Any version of the app",APP_ID,"is not available on 1sot"
			else:
				print "For app:",APP_ID
				print "latest version on 1sot is:",APP_V
				if query_yes_no("Change the version?","yes"):
					sys.stdout.write("Enter the version: ")
					choice = raw_input()
					APP_V = choice
				APP_VS[APP_ID] = APP_V
				print ""
				APP_IDSS.append(APP_ID)



	print "*+Pre-checks for stack+*"
	print " - stack: ",STACK
	content = ""
	try:
		urllib3.contrib.pyopenssl.inject_into_urllib3()
		urllib3.disable_warnings()
		user_agent = {'user-agent': 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) ..'}
		http = urllib3.PoolManager(10, headers=user_agent)

		url = 'https://api.github.com/repos/SplunkStorm/stax/contents/'+STACK+'.json?access_token='+TOKEN
		result = http.request("GET",url)
		if result.status == 200:
			req = json.loads(result.data)
			content = base64.decodestring(req['content'])
			j = json.loads(content)
			print " - Splunk Account: ",j['attributes']['cloud_vendor']['account']
			print " - Splunk Version: ",j['attributes']['splunkwhisper']['splunk_version']
			print " - Is the stack CloudWorks: *No*"
			IS_CW = 0
		elif result.status == 404:
			adhoc_sh = dns.resolver.query(STACK+'.splunkcloud.com', 'CNAME')[0].target[0]
			sh_id = dns.resolver.query(adhoc_sh+'.'+STACK+'.splunkcloud.com', 'CNAME')[0].target.__str__()
			if "sh" in sh_id:
				IS_CW = 1
				print " - Is the stack CloudWorks: *Yes*" 
			else:
				print "*Stack is not available*"
		else:
			print "Github Error with response code :*"+result.status.__str__()+"*"
	except:
		print "Github Error: *Run the script with sudo* or invalid stack name or check the token value in variables.py"

	if PASSWORD != "###":  
		sf,rf = check_SF_RF()
		print " - Search Factor: ",sf
		print " - Replication Factor: ",rf

		if sf == "False" or rf == "False":
			ERROR.append("SF/RF")

	stack_available=1
	try:
		answers = dns.resolver.query(STACK+'.splunkcloud.com', 'CNAME')
		if "shc" not in answers[0].target[0]:
			print " - adhoc sh: ", answers[0].target
			SHs['adhoc SH'] = answers[0].target[0]
		else:
			print "*"+STACK+'.splunkcloud.com '+"is pointing to SHC*"
	except:
		print "*"+STACK+'.splunkcloud.com '+"DNS is not available*"
		ERROR.append("STACK")
		stack_available=0

	if stack_available==1:
		try:
			answers = dns.resolver.query('es-'+STACK+'.splunkcloud.com', 'CNAME')
			print " - es sh: ", answers[0].target
			SHs['es SH'] = answers[0].target[0]
		except:
			print " - es sh: *DNS not available*"

		try:
			answers = dns.resolver.query('itsi-'+STACK+'.splunkcloud.com', 'CNAME')
			print " - itsi sh: ", answers[0].target
			SHs['itsi SH'] = answers[0].target[0]
		except:
			print " - itsi sh: *DNS not available*"

		try:
			answers = dns.resolver.query('vmware-'+STACK+'.splunkcloud.com', 'CNAME')
			print " - vmware sh:", answers[0].target
			SHs['vmware SH'] = answers[0].target[0]
		except:
			print " - vmware sh: *DNS not available*"

		try:
			answers = dns.resolver.query('pci-'+STACK+'.splunkcloud.com', 'CNAME')
			print " - pci sh:", answers[0].target
			SHs['pci SH'] = answers[0].target[0]
		except:
			print " - pci sh: *DNS not available*"

		try:
			answers = dns.resolver.query('exchange-'+STACK+'.splunkcloud.com', 'CNAME')
			print " - exchange sh:", answers[0].target
			SHs['exchange SH'] = answers[0].target[0]
		except:
			print " - exchange sh: *DNS not available*"
	print ""



	if APP_IDS != None:
		appcert_flg = 0
		checked_app_ids = []
		for APP_ID in APP_IDSS:
			APP_V = APP_VS[APP_ID]

			folder_name, _status = self_service_check(APP_ID)

			if PASSWORD != "###":				
				#folder_name = get_app_folder_name(APP_ID+"_"+APP_V+tmp)
				if "ERROR" not in folder_name:
					print " - App directory name: ",folder_name
					for key, value in SHs.iteritems():
						installed,restart_req,current_ver = get_install_status(folder_name,value)
						if installed == "yes":
							print " - *The app "+APP_ID+" is already installed on "+key+" SH with "+current_ver+" version.*"
							#print " - need Splunk restart after upgrade: "+restart_req
						else:
							print " - Is it already installed on "+key+" SH: No"
					print ""
					print ""

print "It's on the way!\n"
page = ""
try:
	if APP_IDS != None:
		page = urllib2.urlopen(ONESOT_URL).read()
except:
	print "Network connectivity check failed. Please ensure that you are connected to splunk VPN"
	exit(1)
#try:
main()
sys.stdout.write("Do you want to add 'Crest' label to the JIRA ticket? (y/n):")
_input = raw_input()
if _input.lower() == 'y':
	if JIRA_ID == "":
		sys.stdout.write("\nEnter the app install JIRA issue id (CO-12345):")
		JIRA_ID = raw_input()
	options = {'server': jira_server, 'verify':False}
	_jira = JIRA(options=options, basic_auth=(jira_user, jira_password))
	_issue = _jira.issue(JIRA_ID)
	labels = _issue.fields.labels
	if u"crest" not in (l.lower() for l in labels):
		_issue.fields.labels.append(u'Crest')
		_issue.update(fields={'labels': _issue.fields.labels})
		print "Label added successfully!"
	else:
		print "Label already avilable!"

print "\nYou are welcome! :)"
#except:
#	print "Some error occured: check the variables in variables.py verify if the Splunk VPN is connected or you have killed it"
