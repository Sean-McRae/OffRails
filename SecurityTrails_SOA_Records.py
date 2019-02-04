import re #Required for findall function
import requests
from termcolor import colored
import time
import os

os.system('cls' if os.name == 'nt' else 'clear')
print colored('+-+-+-+ +-+-+-+-+-+-+-+','yellow')
print colored('|S|O|A| |R|e|c|o|r|d|s|','yellow')
print colored('+-+-+-+ +-+-+-+-+-+-+-+','yellow')
print('')
tdomain = raw_input('Enter TLD: ')
tresponse = requests.get('https://securitytrails.com/domain/'+tdomain+'/dns') #Base GET request
tregex = 'ttl":(.*?)"}' #Regex that will search the response for hostname and ",
tcontent = tresponse.content #Variable that holds the response of the request
tfindings = re.findall(tregex, tcontent) #This will return only the contents that match the regex pattern
none = len(tfindings)
dupe = list(set(tfindings)) #Identifies duplicates and removes them from list
if (none == 0):
	print('')
	print colored('NO RECORDS FOUND','red')
	print('')
else:
	print('')
	con = (", ".join(dupe)) #Removes brackets from list
	con2 = ('ttl: ' + con)
	print(con2)
	print('')
	y = str(con2)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'SOA-'+tdomain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print('Your records have been saved in '+filename)