import re #Required for findall function
import requests #Used to make request to securitytrails.com
from termcolor import colored #Required to render graphics in color
import time #Used to create unique file names
import os #Used to clear screen upon loading as well as get path of script

os.system('cls' if os.name == 'nt' else 'clear') #Clears screen upon loading 
print colored('+-+-+-+-+ +-+-+-+-+-+-+-+','yellow')
print colored('|A|A|A|A| |R|e|c|o|r|d|s|','yellow')
print colored('+-+-+-+-+ +-+-+-+-+-+-+-+','yellow')
print('')
tdomain = raw_input('Enter TLD: ') 
tresponse = requests.get('https://securitytrails.com/domain/'+tdomain+'/dns') #Base GET request
tregex = 'ipv6":"(.*?)",' #Regex that will search for IPV6 addresses
tcontent = tresponse.content #Variable that holds the response of the request
tfindings = re.findall(tregex, tcontent) #This will return only the contents that match the regex pattern
none = len(tfindings) #tracker for length of findings. If length is 0 then no records is returned.
dupe = list(set(tfindings)) #Identifies duplicates and removes them from list
if (none == 0): #No records returned if regex finds no patterns
	print('')
	print colored('NO RECORDS FOUND','red')
	print('')
else:
	print('')
	print('WARNING: SecurityTrails will not return any records for AAAA. However, here is the IPV6 address for '+tdomain)
	print('')
	exp = (", ".join(dupe)) #Removes duplicates
	print(exp)
	print('')
	y = str(exp)
	path = (os.path.dirname(os.path.realpath(__file__))) #gets file path of script
	if not os.path.exists(path+'/output/'): #creates folder "output" if it doesn't exist
		os.makedirs(path+'/output/')
	timestr = time.strftime("%Y%m%d-%H%M%S")
	filename = path+"/output/"+'AAAA-'+tdomain+'-'+timestr+'.txt'
	saveFile = open(filename,'w')	
	saveFile.write(y)
	saveFile.close()
	print('Your records have been saved in '+filename)