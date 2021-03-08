#!/bin/bash/python3

from virustotal_python import Virustotal
import os
import math
import sys
import hashlib
import tlsh
import ssdeep
import subprocess

path=sys.argv[1]
name=sys.argv[1]


def info_file(path):
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    
    with open(path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
            sha512.update(data)
            SSDEEP = ssdeep.hash(data)
            TLSH = tlsh.hash(data)

    print("MD5: {0}".format(md5.hexdigest()))
    print("SHA1: {0}".format(sha1.hexdigest()))
    print("SHA256: {0}".format(sha256.hexdigest()))
    print("SHA512: {0}".format(sha512.hexdigest()))
    print("SSDEEP: {0}".format(SSDEEP))
    print("TLSH: {0}".format(TLSH))

info_file(path)


def convert_size(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s" % (s, size_name[i])

file = path

size_bytes = os.path.getsize(file)

cmd = "file "+path

proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
(out, err) = proc.communicate()
print("File Type: {0}".format(out))
print("\nTaille: {0}".format(convert_size(size_bytes)))
print("Nom: {0}".format(name))
