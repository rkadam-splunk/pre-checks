#############################################################################################
#                                                                                           #
# Author:  Sanket R Bhimani @ Crest Data System                                             #
# Date:    4th Mar 2018                                                                     #
# Version: 1.2                                                                              #
# Help:-                                                                                    #
# python app_pre_checks.py --app-ids 1234,5678 --stack abcd                                 #
# python app_pre_checks.py -ids 1234,5678 -s abcd                                           #
# python app_pre_checks.py -h                                                               #
# python app_pre_checks.py --help                                                           #
#                                                                                           #
#############################################################################################

import httplib, urllib2, base64, json, sys, argparse, re, copy, urllib3, warnings

from jira.client import JIRA
import dns.resolver
from confluence import Api
from bs4 import BeautifulSoup
from BeautifulSoup import BeautifulSoup as bs

from variables import *

warnings.filterwarnings("ignore")


jira_server = JIRA_SERVER
jira_user = JIRA_USER
jira_password = JIRA_PASSWORD
TOKEN = GITHUB_PERSONAL_ACCESS_TOKEN

page = ""
try:
	page = urllib2.urlopen(ONESOT_URL).read()
except:
	print "Network connectivity check failed. Please ensure that you are connected to splunk VPN"
	exit(1)


def get_status_code(host, path="/"):
	try:
		conn = httplib.HTTPConnection(host)
		conn.request("HEAD", path)
		return conn.getresponse().status
	except StandardError:
		return None

def query_yes_no(question, default="yes"):
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

def check_on_splunkbase(app_id,app_v):
	page = urllib2.urlopen(SPLUNKBASE_URL+app_id+'/')
	soup = bs(page)
	try:
		if soup.body.find("option", {"value" : app_v}).find(text=True).strip() != "":
			return True
		else:
			return False
	except:
		return False

def check_on_1sot(app_id,app_v):
	

	postfixs = [".zip",".tgz",".tar.gz",".tar",".spl"]
	for postfix in postfixs:
		url="/artifactory/splunk-general/prod/apps/"+app_id+"_"+app_v+postfix
		status_code = get_status_code("1sot.splunkcloud.com",url.encode('utf-8'))
		if status_code==200:
			return postfix
	return "not"
		



parser = argparse.ArgumentParser()
parser.add_argument('-ids','--app-ids', help='App id', required=True)
parser.add_argument('-s','--stack', help='Stack name', required=True)
args = parser.parse_args()
 

APP_IDS=args.app_ids
APP_VS={}
STACK=args.stack
JIRA_ID=""
APP_IDSS = []




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

appcert_flg = 0
print "\n------------------"
for APP_ID in APP_IDSS:
	APP_V = APP_VS[APP_ID]
	print "*+Pre-checks for "+APP_ID+" v"+APP_V+"+*"

	tmp = check_on_1sot(APP_ID,APP_V)
	if tmp != "not":
		print " - 1sot:\t\t",APP_ID+"_"+APP_V+tmp
	else:
		print " - 1sot:\t*Notavailable*"

	appcert_f = 0

	try:

		options = {'server': jira_server, 'verify':False}
		jira = JIRA(options=options, basic_auth=(jira_user, jira_password))
		query = 'project = APPCERT AND status = Closed AND resolution = "Fixed" AND text ~ "'+APP_ID+' v'+APP_V+'"'
		issues = jira.search_issues(query)

		if len(issues) != 0:
			for issue in issues:
				print " - APPCERT:\t\t",issue.__str__()+", status: "+issue.fields.status.__str__()+", resolution: ", issue.fields.resolution.__str__()
				appcert_f = 1

#		query = 'project = APPCERT AND resolution = "Won\'t Fix" AND text ~ "'+APP_ID+' v'+APP_V+'"'
#		issues = jira.search_issues(query)

#		if len(issues) != 0:
#			for issue in issues:
#				print " - APPCERT:\t\t*",issue.__str__()+", status: "+issue.fields.status.__str__()+", resolution: ", issue.fields.resolution.__str__(),"*"
#				appcert_f = 1

		if appcert_f == 0:
			print "*Automation failed to find APPCERT JIRA*"
			appcert_flg = 1

	except:
		print "***Splunk AD credentials are incorrect - unable to connect with Splunk JIRA***"

	if check_on_splunkbase(APP_ID,APP_V):
		print " - Splunk-Base:\t\tavailable"
	else:
		print "***App is not available on Splunk-Base***"


	url = CONFLUENCE_URL
	api = Api(url, jira_user, jira_password)
	text = api.getpagecontent("Splunk Cloud Apps Information List","CLOUDOPS")
	soup = BeautifulSoup(text.encode("utf-8"),"html.parser")
	ids=""

	if len(soup.findAll("span"))!=0:
		for span_tag in soup.findAll("span"):
			if span_tag!= None and span_tag.find(text=True) != None:
				tmp = span_tag.find(text=True)
				span_tag.replace_with(tmp)

	if len(soup.findAll("p"))!=0:
		for span_tag in soup.findAll("p"):
			if span_tag!= None and span_tag.find(text=True) != None:
				tmp = span_tag.find(text=True)
				span_tag.replace_with(tmp)

	if len(soup.findAll("br"))!=0:
		for span_tag in soup.findAll("br"):
			if span_tag!= None and span_tag.find(text=True) != None:
				tmp = span_tag.find(text=True)
				span_tag.replace_with(tmp)




	if len(soup.findAll("td",text=APP_ID))!=0:
		for nodes in soup.findAll("td",text=APP_ID):
			allnodes = nodes.parent.findAll(recursive=False)
			if allnodes[0].find(text=True) == APP_ID:
				print " - APP DETAILS"
				print "\tApp-ID:\t\t",allnodes[0].find(text=True).replace("&nbsp;", "")
				sys.stdout.write("\tcan be intalled on: ")
				if allnodes[4].find(text=True) != None and "true" in allnodes[4].find(text=True).replace("&nbsp;", "").lower():
					sys.stdout.write("sh ")
				if allnodes[5].find(text=True) != None and "true" in allnodes[5].find(text=True).replace("&nbsp;", "").lower():
					sys.stdout.write("c0m1 ")
				if allnodes[6].find(text=True) != None and "true" in allnodes[6].find(text=True).replace("&nbsp;", "").lower():
					sys.stdout.write("hfw ")
				if allnodes[7].find(text=True) != None and "true" in allnodes[7].find(text=True).replace("&nbsp;", "").lower():
					sys.stdout.write("ufw ")
				print ""
				if allnodes[12].find(text=True) != None  and allnodes[12].find(text=True).replace("&nbsp;", "").strip().replace(" ","") != "":
					print "\tdependent apps:\t",allnodes[12].find(text=True).replace("&nbsp;", "")
				if allnodes[12].find(text=True) != None:
					ids = allnodes[12].find(text=True).replace("&nbsp;", "")
	else:
		print "*App is not available on confluence page*"

	ids = ids.split('|')
	for _id in ids:
		_id = ''.join(c for c in _id if c.isdigit())
		if len(soup.findAll("td",text=_id))!=0:
			for nodes in soup.findAll("td",text=_id):
				allnodes = nodes.parent.findAll(recursive=False)
				if allnodes[0].find(text=True) == _id:
					print " - APP DETAILS for dependent app ",_id
					print "\tApp-ID:\t\t",allnodes[0].find(text=True).replace("&nbsp;", "")
					sys.stdout.write("\tcan be intalled on: ")
					if allnodes[4].find(text=True) != None  and "true" in allnodes[4].find(text=True).replace("&nbsp;", "").lower():
						sys.stdout.write("sh ")
					if allnodes[5].find(text=True) != None and "true" in allnodes[5].find(text=True).replace("&nbsp;", "").lower():
						sys.stdout.write("c0m1 ")
					if allnodes[6].find(text=True) != None and "true" in allnodes[6].find(text=True).replace("&nbsp;", "").lower():
						sys.stdout.write("hfw ")
					if allnodes[7].find(text=True) != None and "true" in allnodes[7].find(text=True).replace("&nbsp;", "").lower():
						sys.stdout.write("ufw ")
					print ""
					if allnodes[12].find(text=True) != None and allnodes[12].find(text=True).replace("&nbsp;", "").strip().replace(" ","") != "":
						print "\tdependent apps:\t",allnodes[12].find(text=True).replace("&nbsp;", "")
					_v = get_latest_version(_id)
					print "\tlatest version:\t"+_v
					if check_on_splunkbase(_id,_v):
						print "\tSplunk-Base:\tavailable"
					else:
						print "\tSplunk-Base:\t*Not available*"
					tmp = check_on_1sot(_id,_v)
					if tmp != "not":
						print "\t1sot:\t\t",_id+"_"+_v+"."+tmp
					else:
						print "\t1sot:\t*Not available*"

					appcert_f = 0
					options = {'server': jira_server}
					jira = JIRA(options=options, basic_auth=(jira_user, jira_password))
					query = 'project = APPCERT AND status = Closed AND resolution != "Won\'t Fix" AND text ~ "'+_id+' v'+_v+'"'
					issues = jira.search_issues(query)
					if len(issues) != 0:
						for issue in issues:
							print "\tAPPCERT:\t",issue.__str__()+", status: "+issue.fields.status.__str__()+", resolution: ", issue.fields.resolution.__str__()
							appcert_f = 1
					query = 'project = APPCERT AND resolution = "Won\'t Fix" AND text ~ "'+_id+' v'+_v+'"'
					issues = jira.search_issues(query)
					if len(issues) != 0:
						for issue in issues:
							print "\tAPPCERT:\t",issue.__str__()+", status: "+issue.fields.status+", resolution: ", issue.fields.resolution
							appcert_f = 1
					if appcert_f == 0:
						print "\t*Automation failed to find APPCERT JIRA for dependent app",_id+"*"
		else:
			print "*dependent app is not available on confluence page*"
	print "\n------------------"

print " - stack:\t\t",STACK

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
		print " - Splunk Account:\t",j['attributes']['cloud_vendor']['account']
		print " - Splunk Version:\t",j['attributes']['splunkwhisper']['splunk_version']
	else:
		print "Github Error with response code :",result.status
		print "Check the TOKEN value in app_pre_checks.py file"
except:
	print "***Run the script with sudo or Stack's PO not found on GitHub***"
stack_available=1
try:
	answers = dns.resolver.query(STACK+'.splunkcloud.com', 'CNAME')
	print " - adhoc sh:\t", answers[0].target
except:
	print "***stack is not available***"
	stack_available=0

if stack_available==1:
	try:
		answers = dns.resolver.query('es-'+STACK+'.splunkcloud.com', 'CNAME')
		print " - es sh:\t", answers[0].target
	except:
		print " - es sh: *not available*"

	try:
		answers = dns.resolver.query('itsi-'+STACK+'.splunkcloud.com', 'CNAME')
		print " - itsi sh:\t", answers[0].target
	except:
		print " - itsi sh: *not available*"

	try:
		answers = dns.resolver.query('vmware-'+STACK+'.splunkcloud.com', 'CNAME')
		print " - vmware sh:\t", answers[0].target
	except:
		print " - vmware sh: *not available*"

print ""
print "------------------"

if appcert_flg == 1:
	print "Gone through below JIRA to get the remaining APPCERT JIRA"
	sys.stdout.write("Enter the issue JIRA ID: ")
	JIRA_ID = raw_input()
	issue = jira.issue(JIRA_ID)

	for link in issue.fields.issuelinks:
	#print link.key
		if hasattr(link, "outwardIssue"):
			outwardIssue = link.outwardIssue
			print "\t",outwardIssue.key+" "+outwardIssue.fields.summary
			print "\tstatus: ",outwardIssue.fields.status,"\tresolution: ",jira.issue(outwardIssue.key).fields.resolution
			print ""
		if hasattr(link, "inwardIssue"):
			inwardIssue = link.inwardIssue
			print "\t",inwardIssue.key+" "+inwardIssue.fields.summary
			print "\tstatus: ",inwardIssue.fields.status,"\tresolution: ",jira.issue(inwardIssue.key).fields.resolution
			print ""
