import re #Required for findall function
import requests
import socket
from termcolor import colored
import os
import time
import sys

sys.tracebacklimit=0
os.system('cls' if os.name == 'nt' else 'clear')
print colored('+-+-+-+-+-+-+-+-+-+-+','yellow')
print colored('|E|v|e|r|y|t|h|i|n|g|','yellow')
print colored('+-+-+-+-+-+-+-+-+-+-+','yellow')
domain = raw_input('Enter TLD: ') 
print('')
address = ''
don = ''
try:
	address = socket.gethostbyname(domain) #Converts TLD to IP Address
except socket.gaierror:
	print('')
	don = 'NO A RECORDS FOUND'
	print colored('NO A RECORDS FOUND','red')
numeric = 0 #Counter for page number
params = str(numeric) #Convert integer into string
response = requests.get('https://securitytrails.com/list/ip/'+address+'?page='+params) #Base GET request
regex = 'hostname":"(.*?)",' #Regex that will search the response for hostname and ",
content = response.content #Variable that holds the response of the request
findings = re.findall(regex, content) #This will return only the contents that match the regex pattern
kill = len(findings) #This is used to break the while loop when there are no more pages on Security Trails
subject = ['']
if don == 'NO A RECORDS FOUND':
	pon = 1
else:
	print colored('Calculating Pages for A Records Please Wait...','red')
	while (kill != 1):
		numeric = numeric + 1 #This allows us to go through x amount of pages on Security Trails
		params = str(numeric)
		response = requests.get('https://securitytrails.com/list/ip/'+address+'?page='+params)
		content = response.content
		findings = re.findall(regex, content)
		letter = findings
		subject.append(letter)
		kill = len(findings)
		if kill == 1:
			break
	exp = ('\n'.join(', '.join(elems) for elems in subject))
	y = str(exp)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'A-'+domain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print('Your records have been saved in '+filename)

tdomain = domain 
don = ''
tresponse = requests.get('https://securitytrails.com/domain/'+tdomain+'/dns') #Base GET request
tregex = '"txt":{"v":\["(.*?)"],"time"' #Regex that will search the response for hostname and ",
tcontent = tresponse.content #Variable that holds the response of the request
tfindings = re.findall(tregex, tcontent) #This will return only the contents that match the regex pattern
none = len(tfindings)
dupe = list(set(tfindings)) #Identifies duplicates and removes them from list
if (none == 0):
	print colored('NO TXT RECORDS FOUND','red')
else:
	exp = (", ".join(dupe)) #Removes brackets from list
	y = str(exp)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'TXT-'+tdomain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print colored('Found TXT Records', 'red')
	print('Your records have been saved in '+filename)

tdomain = domain 
don = ''
numeric = 0 #Counter for page number
params = str(numeric) #Convert integer into string
response = requests.get('https://securitytrails.com/list/apex_domain/'+tdomain+'?page='+params) #Base GET request
regexh = '/dns">(.*?)<' #Regex that will search the response for hostname and ",
content = response.content #Variable that holds the response of the request
findingsh = re.findall(regexh, content) #This will return only the contents that match the regex pattern
kill = len(findingsh) #This is used to break the while loop when there are no more pages on Security Trails
subject = ['']
print colored('Calculating Pages for Subdomain Records Please Wait...','red')
while (kill != 1):
	numeric = numeric + 1 #This allows us to go through x amount of pages on Security Trails
	params = str(numeric)
	response = requests.get('https://securitytrails.com/list/apex_domain/'+tdomain+'?page='+params)
	content = response.content
	findingsh = re.findall(regexh, content)
	letter = findingsh
	subject.append(letter)
	kill = len(findingsh)
	if kill == 1:
		break
if numeric != 0:
	exp = ('\n'.join(', '.join(elems) for elems in subject))
	y = str(exp)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'SUBDOMAINS-'+tdomain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print('Your records have been saved in '+filename)
else:
	print colored('NO SUBDOMAIN RECORDS FOUND','red')

tdomain = domain 
don = ''
tresponse = requests.get('https://securitytrails.com/domain/'+tdomain+'/dns') #Base GET request
tregex = 'ttl":(.*?)"}' #Regex that will search the response for hostname and ",
tcontent = tresponse.content #Variable that holds the response of the request
tfindings = re.findall(tregex, tcontent) #This will return only the contents that match the regex pattern
none = len(tfindings)
dupe = list(set(tfindings)) #Identifies duplicates and removes them from list
if (none == 0):
	print colored('NO SOA RECORDS FOUND','red')
else:
	con = (", ".join(dupe)) #Removes brackets from list
	con2 = ('ttl: ' + con)
	y = str(con2)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'SOA-'+tdomain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print colored('Found SOA Records', 'red')
	print('Your records have been saved in '+filename)

tdomain = domain 
don = ''
tresponse = requests.get('https://securitytrails.com/domain/'+tdomain+'/dns') #Base GET request
tregex = 'ns.v:(.*?)":' #Regex that will search the response for hostname and ",
tcontent = tresponse.content #Variable that holds the response of the request
tfindings = re.findall(tregex, tcontent) #This will return only the contents that match the regex pattern
none = len(tfindings)
dupe = list(set(tfindings)) #Identifies duplicates and removes them from list
numeric = 0 #Counter for page number
params = str(numeric) #Convert integer into string
single = ''
try:
	single = str(dupe[0])
except IndexError as error:
	don = 'NO NS RECORDS FOUND'
response = requests.get('https://securitytrails.com/list/ns/'+single+'?page='+params)
content = response.content
regex = 'hostname":"(.*?)",' #Regex that will search the response for hostname and ",
findings = re.findall(regex, content)
kill = len(findings)
if don == 'NO NS RECORDS FOUND':
	pon = 1
	if (none == 0):
		print colored('NO NS RECORDS FOUND','red')
else:
	subject = ['']
	print colored('Calculating Pages for NS Records Please Wait...','red')
	while (kill != 1):
		numeric = numeric + 1 #This allows us to go through x amount of pages on Security Trails
		params = str(numeric)
		response = requests.get('https://securitytrails.com/list/ns/'+single+'?page='+params)
		content = response.content
		findings = re.findall(regex, content)
		letter = findings
		subject.append(letter)
		kill = len(findings)
		if kill == 1:
			break
	exp = ('\n'.join(', '.join(elems) for elems in subject))
	
	y = str(exp)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'NS-'+tdomain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print('Your records have been saved in '+filename)

tdomain = domain 
don = ''
tresponse = requests.get('https://securitytrails.com/domain/'+tdomain+'/dns') #Base GET request
tregex = '"h":"(.*?)"}' #Regex that will search the response for hostname and ",
tcontent = tresponse.content #Variable that holds the response of the request
tfindings = re.findall(tregex, tcontent) #This will return only the contents that match the regex pattern
none = len(tfindings)
dupe = list(set(tfindings)) #Identifies duplicates and removes them from list
numeric = 0 #Counter for page number
params = str(numeric) #Convert integer into string
single = ''
try:
	single = str(dupe[0])
except IndexError as error:
	don = 'NO MX RECORDS FOUND'
response = requests.get('https://securitytrails.com/list/mx/'+single+'?page='+params)
content = response.content
regex = 'hostname":"(.*?)",' #Regex that will search the response for hostname and ",
findings = re.findall(regex, content)
kill = len(findings)
subject = ['']
if don == 'NO MX RECORDS FOUND':
	pon = 1
	if (none == 0):
		print colored('NO MX RECORDS FOUND','red')
else:
	print colored('Calculating Pages for MX Records Please Wait...','red')
	while (kill != 1):
		numeric = numeric + 1 #This allows us to go through x amount of pages on Security Trails
		params = str(numeric)
		response = requests.get('https://securitytrails.com/list/mx/'+single+'?page='+params)
		content = response.content
		findings = re.findall(regex, content)
		letter = findings
		subject.append(letter)
		kill = len(findings)
		if kill == 1:
			break
	exp = ('\n'.join(', '.join(elems) for elems in subject))
	
	y = str(exp)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'MX-'+tdomain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print('Your records have been saved in '+filename)

tdomain = domain 
don = ''
tresponse = requests.get('https://securitytrails.com/domain/'+tdomain+'/dns') #Base GET request
tregex = 'ipv6":"(.*?)",' #Regex that will search the response for hostname and ",
tcontent = tresponse.content #Variable that holds the response of the request
tfindings = re.findall(tregex, tcontent) #This will return only the contents that match the regex pattern
none = len(tfindings)
dupe = list(set(tfindings)) #Identifies duplicates and removes them from list
if (none == 0):
	print colored('NO AAAA RECORDS FOUND','red')
else:
	exp = (", ".join(dupe)) #Removes brackets from list
	y = str(exp)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'AAAA-'+tdomain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print colored('Found AAAA Records', 'red')
	print('Your records have been saved in '+filename)
