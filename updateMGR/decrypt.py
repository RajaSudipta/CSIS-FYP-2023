#!/usr/bin/env python3
from cryptography.fernet import Fernet
import os
import sys
from time import sleep 

command=sys.argv[1]
if command=="1":
	print("Sorry, you have entered several wrong password, deleting all files")
	username=sys.argv[3]
	loc="/home/"+username+"/.config/updateMGR/log_output"
	fd= open(loc,mode='r',encoding='utf8', newline='\n')
	for i, line in enumerate(fd):
		line=line.rstrip("\n")
		if os.path.exists(line+"en") and os.path.isfile(line+"en"):
			os.remove(line+"en")
			print(i, line)
else:
	print()
	print("************* Password matching successfull!*************")
	print()
	print("Decrypting the following files one by one...")
	print()
	argument=sys.argv[2][:43]+'='
	key=bytes(argument, 'utf-8')
	fernet = Fernet(key)
	username=sys.argv[3]
	loc="/home/"+username+"/.config/updateMGR/log_output"
	fd= open(loc,mode='r',encoding='utf8', newline='\n')
	for i, line in enumerate(fd):
		line=line.rstrip("\n")
		if os.path.exists(line+"en") and os.path.isfile(line+"en"):
			with open(line+"en", 'rb') as enc_file:
				encrypted = enc_file.read()
				decrypted = fernet.decrypt(encrypted)
				with open(line, 'wb') as dec_file:
					dec_file.write(decrypted)
				sleep(1.5)
			os.remove(line+"en")
			print(i, line)
