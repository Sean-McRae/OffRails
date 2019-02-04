import os #Used to run external python scripts
from termcolor import colored #Used to render graphic in color

k = 0 #Used to control "While" loop. Will print menu screen until user enters '10' which will break the loop and exit the program.
print("")
print('Note: All records pulled will be saved in a folder called "output" within the working directory of the script.\n')
print('For your convenience, the full file path will be reflected after pulling a record.')
print('Example: Your records have been saved in /opt/OffRails/output/A-securityriskadvisors.com-20181214-095632.txt\n')
print("The structure of each file will be: Record Type -> Domain -> Date -> Time -> .txt\n")
print colored('This script is used to extract DNS records from SecurityTrails.com','red')
print colored('Any bugs and/or suggestions can be sent here -> Sean.McRae@SecurityRiskAdvisors.com','blue')
print("")
while k == 0:
	print("")
	print colored('______________________   ________       ___________       ','yellow')
	print colored('__  __ \__  __/__  __/   ___  __ \_____ ___(_)__  /_______','yellow')
	print colored('_  / / /_  /_ __  /_     __  /_/ /  __ `/_  /__  /__  ___/','yellow')
	print colored('/ /_/ /_  __/ _  __/     _  _, _// /_/ /_  / _  / _(__  ) ','yellow')
	print colored('\____/ /_/    /_/        /_/ |_| \__,_/ /_/  /_/  /____/  ','yellow')                                                                                                      
	print colored('                             			Made for SRA', 'red')
	print("")
	print("1) Search A Records for Domain")
	print("2) Search Subdomain Records for Domain")
	print("3) Search AAAA Records for Domain (This will only return IPV6 addresses)")
	print("4) Search MX Records for Domain")
	print("5) Search NS Records for Domain")
	print("6) Search SOA Records for Domain")
	print("7) Search TXT Records for Domain")
	print("8) EVERYTHING (Extracts A, AAAA, MX, NS, SOA, TXT & Subdomain Records)")
	print("9) Clear Terminal (Clears terminal)")
	print("10) Exit\n")
	t = raw_input('Enter Selection: ')
	if t == '1':
		os.system('python SecurityTrails_A_Records.py')
	if t == '2':
		os.system('python SecurityTrails_Subdomains.py')
	if t == '3':
		os.system('python SecurityTrails_AAAA_Records.py')
	if t == '4':
		os.system('python SecurityTrails_MX_Records.py')
	if t == '5':
		os.system('python SecurityTrails_NS_Records.py')
	if t == '6':
		os.system('python SecurityTrails_SOA_Records.py')
	if t == '7':
		os.system('python SecurityTrails_TXT_Records.py')
	if t == '8':
		os.system('python SecurityTrails_Everything.py')
	if t == '9':
		os.system('cls' if os.name == 'nt' else 'clear')
	if t == '10':
		k = 1
		print("")
		print("Goodbye")
