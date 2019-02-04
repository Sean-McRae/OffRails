import re #Required for findall function
import requests #Used to make request to target site
import socket #Used to convert domain entered into an IP address
from termcolor import colored #Used to render graphics
import os #Used to clear screen upon loading the script
import time #Used to create unique file names
import sys #Used to disable debug information upon error

sys.tracebacklimit=0 #will not return debug information upon error
os.system('cls' if os.name == 'nt' else 'clear') #Clears screen upon loading
print colored('+-+ +-+-+-+-+-+-+-+','yellow')
print colored('|A| |R|e|c|o|r|d|s|','yellow')
print colored('+-+ +-+-+-+-+-+-+-+','yellow')
print('')
domain = raw_input('Enter TLD: ') 
address = ''
try:
	address = socket.gethostbyname(domain) #Converts TLD to IP Address
except socket.gaierror: #If an error is thrown, no records found is returned
	print('')
	print colored('NO RECORDS FOUND','red')
	print('')
	raise
numeric = 0 #Counter for page number
params = str(numeric) #Convert integer into string
response = requests.get('https://securitytrails.com/list/ip/'+address+'?page='+params) #Base GET request
regex = 'hostname":"(.*?)",' #Regex that will search the response for hostname 
content = response.content #Variable that holds the response of the request
findings = re.findall(regex, content) #This will return only the contents that match the regex pattern
kill = len(findings) #This is used to break the while loop when there are no more pages on Security Trails
subject = ['']
print('Calculating Pages Please Wait...')
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
filename = path+"/output/"+'A-'+domain+'-'+timestr+'.txt'
saveFile = open(filename,'w')	
saveFile.write(y)
saveFile.close()
print('Your records have been saved in '+filename)
