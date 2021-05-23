#!/bin/python3

import paramiko
import os
import time


#try:
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.1.51", username="root", password="root")

ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("date -r /root/.cuckoo/storage/analyses/latest/reports/report.json +%s")
outlines=ssh_stdout.readlines()
resp=''.join(outlines)
date1 = resp
date1 = int(date1)
print(date1)

ftp_client=ssh.open_sftp()
ftp_client.put("/root/Desktop/OmegaVirus/virus_samples/dc030778938b8b6f98236a709d0d18734c325accf44b12a55ecc2d56b8bb9000","/root/cuckoo/file")
ftp_client.close()

ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("source /home/trofa/env/bin/activate && cuckoo submit /root/cuckoo/")
outlines=ssh_stdout.readlines()
resp=''.join(outlines)
print(resp)
analyze_id = resp[-3]
analyze_id += resp[-2]
print(analyze_id)
print("/root/.cuckoo/storage/analyses/"+str(analyze_id)+"/reports/report.json")
date2 = date1
while(date1 == date2):
	ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("date -r /root/.cuckoo/storage/analyses/"+str(analyze_id)+"/reports/report.json +%s")
	outlines=ssh_stdout.readlines()
	resp=''.join(outlines)
	if len(resp) > 0:
		date2 = resp
		date2 = int(date2)
		print(date2)
time.sleep(5)
ftp_client=ssh.open_sftp()
ftp_client.get("/root/.cuckoo/storage/analyses/"+str(analyze_id)+"/reports/report.json","/tmp/report.json")
ftp_client.close()
#except Exception as e:
#    print(e)



