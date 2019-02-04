import re #Required for findall function
import requests
from termcolor import colored
import os
import time
import sys

sys.tracebacklimit=0
os.system('cls' if os.name == 'nt' else 'clear')
print colored('+-+-+ +-+-+-+-+-+-+-+','yellow')
print colored('|M|X| |R|e|c|o|r|d|s|','yellow')
print colored('+-+-+ +-+-+-+-+-+-+-+','yellow')
print('')
tdomain = raw_input('Enter TLD: ') 
tresponse = requests.get('https://securitytrails.com/domain/'+tdomain+'/dns') #Base GET request
tregex = '"h":"(.*?)"}' #Regex that will search the response for hostname and ",
tcontent = tresponse.content #Variable that holds the response of the request
tfindings = re.findall(tregex, tcontent) #This will return only the contents that match the regex pattern
none = len(tfindings)
dupe = list(set(tfindings)) #Identifies duplicates and removes them from list
numeric = 0 #Counter for page number
params = str(numeric) #Convert integer into string
try:
	single = str(dupe[0])
except IndexError as error:
	print('')
	print colored('NO RECORDS FOUND','red')
	print('')
	raise
response = requests.get('https://securitytrails.com/list/mx/'+single+'?page='+params)
content = response.content
regex = 'hostname":"(.*?)",' #Regex that will search the response for hostname and ",
findings = re.findall(regex, content)
kill = len(findings)
if (none == 0):
	print('')
	print colored('NO RECORDS FOUND','red')
	print('')
else:
	subject = ['']
	print('Calculating Pages Please Wait...')
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
	if (numeric > 20):
		print ('')
		print('There are '+params+' Pages. A manual review may be necessary to verify the records.')
	else:
		print ('')
		print('There are '+params+' Pages')
	raw_input('Press ENTER to Continue and ^C to Exit')
	print ('')
	exp = ('\n'.join(', '.join(elems) for elems in subject))
	print(exp)
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
