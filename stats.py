#!/usr/bin/python

import argparse, re
from collections import Counter
import array as arr
import os.path

#Define list we'll use to hold information
output = []
enabledusers_list = []
enableduniquehashes_list = []
hashcat_list = []
crackedenableduser_list = []
crackedenableduniquehashes_list = []
ntlm_list = []
enabledpasswords = []
basewords = []

groups = []
listgroupmembers = []
privgroupmembers = []


#Open Try/Catch for a minimum of error checking :-)
try:
	#Add Arguments to Argparse
	#Get files to parse from the command line
	parser = argparse.ArgumentParser()
	#Get all hashes
	parser.add_argument("--ntlm", help="ntlm hash list", type=str, required=True)
	#Get hashcat cracked output
	parser.add_argument("--hashcat", help="hashcat cracked hashes with usernames", type=str, required=True)
	#Get list of enabled accounts
	parser.add_argument("--enabled", help="list of enabled user accounts", type=str,  required=True)
	#Add option to be able to output result to csv file
	parser.add_argument("--output", help="save output to csv file", type=str, default="", required=False)
	#Add option to also parse for cracked enabled users who are part of a privileged group
	parser.add_argument("--groupmembers", help="path to adrecon GroupMembers.csv", type=str, default="", required=False)

	args = parser.parse_args()

	#Display banner
	print("\n[*] Password Statistics Generator for Internal Pentest Report - Version 1.0")
	print("[*] Richard Davy, ECSC plc - 2020\n")
	#

	#
	#NTLM Hashses are required, read them all in
	#
	#Read in NTLM Hashes - Contains Everything Enabled/Disabled etc
	with open(args.ntlm) as fp:
		for line in fp:
			#Regex to check that it's a recognised hash
			pwdumpmatch = re.compile('^(.*?):.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::\s*$')
			pwdump = pwdumpmatch.match(line)
			if pwdump:
				if not "$" in str(pwdump):
					#If the username contains the domain, strip it out
					if "\\" in str(pwdump):
						result=line.find("\\")
						ntlm_list.append(line[result+1:].rstrip())
					else:
						ntlm_list.append(line.rstrip())

	#for nt in ntlm_list:
	#	print(nt)


	#
	#Read in hashcat file to parse, hashcat including --show --usernames
	#
	with open(args.hashcat, 'r') as f:
		for line in f:
			#If the username contains the domain, strip it out
			if "\\" in str(line):
				result=line.find("\\")
				hashcat_list.append(line[result+1:].rstrip())
			else:
				hashcat_list.append(line.rstrip())

	#
	#Read in enabled user file to parse
	#
	with open(args.enabled, 'r') as f:
		for line in f:
			enabledusers_list.append(line.rstrip())
			#print(line.rstrip())

	#
	#Generate a list of cracked and enabled users
	#by comparing the list of enabled usernames with the usernames in hashcat all user output
	#
	for username in enabledusers_list:
		for user in hashcat_list:
	
			strippedusername=user[:user.find(":")]
	
			if username == strippedusername:
				crackedenableduser_list.append(user)
				#print(user.rstrip())

	#
	#Generate a list of Enabled User Hashes by taking the list of enabled users and
	#finding them in the all hashes domain dump, get their hash and add to list
	#
	for user in enabledusers_list:
		for ntuser in ntlm_list:
			#print(user)
			#print(ntuser.split(":")[0])
			if user==ntuser.split(":")[0]:
			#Create a list of all enabled user hashes
				#note set command is used when displaying output should probably be done here
				enableduniquehashes_list.append(ntuser.split(":")[3])
				#print(ntuser.split(":")[3])

	#Cracked Enabled Passwords
	for user in crackedenableduser_list:

		upass=user.split(":")[2]
		#print(upass)

		#Create a list of all cracked and enabled user passwords
		enabledpasswords.append(upass)
		#print(upass)


	#Cracked Enabled Unique Hashes
	for user in crackedenableduser_list:

		uhash=user.split(":")[1]
		#print(uhash)
		#note set command is used when displaying output to get unique
		crackedenableduniquehashes_list.append(uhash)


	print ("Total password Hashes Extracted ,"+str(len(ntlm_list)))
	output.append("Total password Hashes Extracted ,"+str(len(ntlm_list)))

	print ("Total 'Enabled' domain user hashes ,"+str(len(enabledusers_list)))
	output.append("Total 'Enabled' domain user hashes ,"+str(len(enabledusers_list)))

	print ("Total Unique 'Enabled' domain user Hashes ,"+str(len(set(enableduniquehashes_list))))
	output.append("Total Unique 'Enabled' domain user Hashes ,"+str(len(set(enableduniquehashes_list))))

	print ("Total password hashes cracked inc. duplicates ,"+str(len(hashcat_list)))
	output.append("Total password hashes cracked inc. duplicates ,"+str(len(hashcat_list)))

	print ("Cracked 'Enabled Hashes' inc. duplicates ,"+str(len(crackedenableduser_list)))
	output.append("Cracked 'Enabled Hashes' inc. duplicates ,"+str(len(crackedenableduser_list)))

	print ("Cracked unique 'Enabled' domain user hashes ,"+str(len(set(crackedenableduniquehashes_list))))
	output.append("Cracked unique 'Enabled' domain user hashes ,"+str(len(set(crackedenableduniquehashes_list))))

	print ("")
	output.append("")

	#
	#Display Top 10 Passwords of Enabled Accounts
	#
	print ("Top 10 Passwords (Enabled Accounts)")
	output.append("Top 10 Passwords (Enabled Accounts)")

	a = Counter(enabledpasswords)
	for letter, count in a.most_common(10):
		#print to screen
		#print (letter, ","+str(count))
		a=list((letter, str(count)))
		print(', '.join(a))
		output.append(', '.join(a))

	print ("")
	output.append("")


	#
	#Password Length for Enabled Accounts
	#
	#Define Array
	a=arr.array('i', [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] )
	
	#Loop enabled passwords and add +1 to array based on password lenth
	for passw in enabledpasswords:
		a[len(passw)-1]=a[len(passw)-1]+1


	print("Password Length (Enabled Accounts)")
	output.append("Password Length (Enabled Accounts)")

	#
	#Display top 20 Password Lenths
	#

	for x in range(0, 20):
		print (str(x+1)+","+str((a[x])))
		output.append(str(x+1)+","+str((a[x])))

	print("")
	output.append("")
	
	
	#Routine here, writes crackedenabled out to file
	#was for use to sanity check against pipal
	#
	#with open("/tmp/crackedenabled.txt",'w') as result_file:
		#Iterate our list
	#	for r in enabledpasswords:
	#		#Write line
	#		result_file.write(r + "\n")
	#	#Close file handle
	#	result_file.close()

	
	#
	#Work out base words
	#Take each enabled password and backwards find the first letter 
	#First letter indicates last character of base word
	#Add to list

	for enPass in enabledpasswords:
		for x in range(len(enPass),-1,-1):
			#print(enPass)
			if (enPass[x:x+1]).isalpha():
				basewords.append(enPass[:x+1].lower())
				break

	print ("Top 10 Base Words")
	output.append("Top 10 Base Words")

	#Display top 10 base words from list
	a = Counter(basewords)
	for letter, count in a.most_common(10):
		#print to screen
		a=list((letter, str(count)))
		print(', '.join(a))
		output.append(', '.join(a))
		
	#Groupmembers is optional commandline, if not "" then proceed.
	if args.groupmembers!="":
		
		#Next bit of code will find what privileged groups cracked enabled users belong to
		#requires a file from AD Recon
		#
		#Read in groups to parse
		#

		if os.path.isfile('groups.txt'):
			with open("groups.txt", 'r') as f:
				for line in f:
					groups.append(line.rstrip().lstrip())
		else:
			print("\n[!] group.txt file not found - defaulting to searching for Domain Admins, Enterprise Admins, Schema Admins only")
			groups.append("Domain Admins")
			groups.append("Enterprise Admins")
			groups.append("Schema Admins")
		
		print("\nCracked Enabled Privileged Users")
		output.append("\nCracked Enabled Privileged Users")
		
		#Read in ADRecon group members data
		if os.path.isfile(args.groupmembers):
			with open(args.groupmembers, 'r') as f:
				for line in f:
					listgroupmembers.append(line.rstrip().lstrip())

			#Get group, if group matches group then get member name, check member name in cracked enabled users
			#crackedenableduser_list
			for user in listgroupmembers:

				#Parse user group
				usernamegroup=user.split(",")[0][1:-1]
				#print(usernamegroup)

				#Parse username
				username=user.split(",")[1][1:-1]
				#print(username)

				#Loop groups.txt defined group names
				for g in groups:
					#If group to search for is in ADRecon group membership file we're in business
					if usernamegroup==g:
						#print (username)
						#privgroupmembers
						#Check then to see if the user is part of cracked and enabled, if so we're in business
						for user in crackedenableduser_list:
							#Get username
							ceuser=user[:user.find(":")]
							#Check usernames match
							if ceuser==username:
				 				#Parse the password value
								passwd=(user.split(":")[2]) 
								#Mask the password with stars, exclusing first and last vals
								maskedpw=(passwd[:1]+("*"*(len(passwd)-2))+passwd[-1:])
								#Create priv group member - usergroup, username,NT Hash, password,masked password
								#privgroupmembers.append(usernamegroup+","+user.split(":")[0]+","+user.split(":")[1]+","+passwd+","+maskedpw)
								#Create priv group member - usergroup, username,password,masked password
								privgroupmembers.append(usernamegroup+","+user.split(":")[0]+","+passwd+","+maskedpw)
								break
			#Sort list of values found
			privgroupmembers.sort()
			#Display list of values found
			for pu in privgroupmembers:
				print(pu)
				output.append(pu)

		else:
			print("[!] Specified Group Members file not found, please check path and re-run")

		
	#
	#Write all collected output to CSV file ready for copy and paste into 
	#spreadsheet for report
	#
	if args.output!="":
		with open(args.output,'w') as result_file:
		#Iterate our list
			for r in output:
				#Write line
				#rint (r)
				result_file.write(str(r)+"\n")
			#Close file handle
			result_file.close()

	print("")


#Friendly Error Handler code
except Exception as e:
	print("[!] Doh... Well that didn't work as expected!")
	print("[!] type error: " + str(e))