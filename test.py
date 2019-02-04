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
response = requests.get('https://securitytrails.com/list/apex_domain/'+domain+'?page=600') #Base GET request
regexh = '/dns">(.*?)<' #Regex that will search the response for hostname and ",
content = response.content #Variable that holds the response of the request
findingsh = re.findall(regexh, content) #This will return only the contents that match the regex pattern
kill = len(findingsh) #This is used to break the while loop when there are no more pages on Security Trails
subject = ['']
print(kill)