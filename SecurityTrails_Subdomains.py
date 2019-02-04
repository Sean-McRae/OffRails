import re #Required for findall function
import requests
from termcolor import colored
import os
import time

os.system('cls' if os.name == 'nt' else 'clear')
print colored('+-+-+-+-+-+-+-+-+-+-+', 'yellow')
print colored('|S|u|b|d|o|m|a|i|n|s|','yellow')
print colored('+-+-+-+-+-+-+-+-+-+-+','yellow')
print('')
domain = raw_input('Enter TLD: ') 
numeric = 0 #Counter for page number
params = str(numeric) #Convert integer into string
response = requests.get('https://securitytrails.com/list/apex_domain/'+domain+'?page='+params) #Base GET request
regexh = '/dns">(.*?)<' #Regex that will search the response for hostname and ",
content = response.content #Variable that holds the response of the request
findingsh = re.findall(regexh, content) #This will return only the contents that match the regex pattern
kill = len(findingsh) #This is used to break the while loop when there are no more pages on Security Trails
subject = ['']
print('Calculating Pages Please Wait...')
while (kill != 0):
	numeric = numeric + 1 #This allows us to go through x amount of pages on Security Trails
	print kill
	params = str(numeric)
	response = requests.get('https://securitytrails.com/list/apex_domain/'+domain+'?page='+params)
	content = response.content
	findingsh = re.findall(regexh, content)
	letter = findingsh
	subject.append(letter)
	kill = len(findingsh)
	if kill == 1:
		break
if (numeric > 20):
	print ('')
	print('There are '+params+' Pages. A manual review may be necessary to verify the records.')
else:
	print ('')
	print('There are '+params+' Pages')
if numeric != 0:
	raw_input('Press ENTER to Continue and ^C to Exit')
	print ('')
	exp = ('\n'.join(', '.join(elems) for elems in subject))
	print(exp)
	y = str(exp)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'SUBDOMAINS-'+domain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print('Your records have been saved in '+filename)
else:
	print colored('NO RECORDS FOUND','red')