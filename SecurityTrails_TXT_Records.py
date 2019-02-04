import re #Required for findall function
import requests
from termcolor import colored
import os
import time

os.system('cls' if os.name == 'nt' else 'clear')
print colored('+-+-+-+ +-+-+-+-+-+-+-+','yellow')
print colored('|T|X|T| |R|e|c|o|r|d|s|','yellow')
print colored('+-+-+-+ +-+-+-+-+-+-+-+','yellow')
print('')
tdomain = raw_input('Enter TLD: ') 
tresponse = requests.get('https://securitytrails.com/domain/'+tdomain+'/dns') #Base GET request
tregex = '"txt":{"v":\["(.*?)"],"time"' #Regex that will search the response for hostname and ",
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
	exp = (", ".join(dupe)) #Removes brackets from list
	print(exp)
	print('')
	y = str(exp)
	path = (os.path.dirname(os.path.realpath(__file__)))
	if not os.path.exists(path+'/output/'):
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'TXT-'+tdomain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print('Your records have been saved in '+filename)