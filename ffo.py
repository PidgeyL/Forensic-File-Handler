#!/usr/bin/env python3
#
# Tool to detect a files real file type and act based on it
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import sys
import argparse
import subprocess
import zipfile
import binascii

import magic

# Variables
CONFIGFILE = 'ffo.txt'
ZIPPASSWORD = 'infected'

# Parsing arguments
parser = argparse.ArgumentParser(description='Analyzes a file for its true file type and act accordingly')
parser.add_argument('file', metavar='File',   type=str, help="A file containing the items to check")
parser.add_argument('-c',   metavar="Config",           help='config file to use')
parser.add_argument('-p',   metavar="Pass",             help='optional password for encrypted zip')
args = parser.parse_args()

'''
ASCII Values of the magics

Magic                         - ASCII      - Ident - Extension          |  Magic             - ASCII  - Ident - Extension
52 61 72 21 1A 07 00          - Rar!...    - RAR   - .rar               |  47 49 46 38 37 61 - GIF87a - GIF   - .gif
52 61 72 21 1A 07 01 00       - Rar!....   - RAR   - .rar               |  47 49 46 38 39 61 - GIF89a - GIF   - .gif
50 4B 03 04 0A 00 02 00       - PK......   - EPUB  - .epub              |  25 50 44 46       - %PDF   - PDF   - .pdf
50 4B 03 04 14 00 06 00       - PK......   -       - .docx, pptx, xlsx  |  D0 CF 11 E0       - ....   - OLE   - .doc, .xls, .ppt
50 4B 03 04 14 00 08 00 08 00 - PK........ - JAR   - .jar               |  49 44 33          - ID3    - MP3   - .mp3
50 4B 03 04                   - PK..       - ZIP   - .zip               |  4D 5A             - MZ     - EXE   - .exe
89 50 4E 47 0D 0A 1A 0A       - ‰PNG....   - PNG   - .png
'''

magics={"52 61 72 21 1A 07 00":"RAR",          "52 61 72 21 1A 07 01 00":"RAR", "50 4B 03 04 0A 00 02 00":"EPUB", "50 4B 03 04 14 00 06 00":"*****",
        "50 4B 03 04 14 00 08 00 08 00":"JAR", "50 4B 03 04":"ZIP",             "89 50 4E 47 0D 0A 1A 0A":"PNG",  "47 49 46 38 37 61":"GIF",
        "47 49 46 38 39 61":"GIF",
        "25 50 44 46":"PDF", "D0 CF 11 E0":"OLE", "49 44 33":"MP3", "4D 5A":"EXE"}

# analyze ascii version of the stream to find the magic
def getMagic(f):
  bytes = open(f, "rb").read() if type(f) == str else f
  hexFile=str((binascii.hexlify(bytes).upper())[:16],'utf-8')
  for x in list(magics.keys()):
    if hexFile.startswith(x.replace(" ","")): return x
  return None

# get the command that matches the magic
def getCommandFor(fileType, config=None):
  command=None
  try:
    if not config:
      config=CONFIGFILE
    rules=[x.strip() for x in open(config)]
  except IOError:
    sys.exit("Couldn't open file")
  except Exception as e:
    sys.exit(e)
  for x in rules:
    if fileType==x.split(':')[0]:
      command=':'.join(x.split(':')[1:])
      break
  return command

# analyze the zip file and return the first file if single file
def analyzeZIP(f):
  if not zipfile.is_zipfile(f):
    return f
  fzip = zipfile.ZipFile(f, 'r')
  try:
    if len(fzip.namelist())==1:
      f=fzip.read(fzip.namelist()[0])
  except RuntimeError:
    try:
      password = args.p if args.p else ZIPPASSWORD
      password = password.encode("utf-8")
      f=fzip.read(fzip.namelist()[0], password)
    except RuntimeError:
      print("Password Protected Zip")
  except Exception as e:
    sys.exit(e)
  fzip.close()
  return f

def printAnalysis(f):
  bytes = open(f, "rb").read() if type(f) == str else f
  stmag = getMagic(bytes)
  magic = ' '.join([stmag[i:i+2] for i in range(0,len(stmag),2)]) if getMagic(bytes) else "Not Recognised"
  print("Magic for the file: '%s'"%magic)
  print(bytes[:50])
  sys.exit(0)

# main function
def analyze(f,config=None):
  try:
    mag=getMagic(f)
    if not mag:
      printAnalysis(f)
    if magics[mag]=="ZIP":
      mag=getMagic(analyzeZIP(f))
      if not mag:
        printAnalysis(analyzeZIP(f))
    com=getCommandFor(magics[mag], config=config)
    if com:
      try:
        subprocess.call(com.split(' '))
      except:
        print("The command (%s) for %s (magic: %s) in %s does not work."%(com.split(' ')[0], magics[mag], mag, config))
    else:
      printAnalysis(f)
  except IOError:
    sys.exit("Couldn't open file")
  except Exception as e:
    sys.exit(e)

if __name__ == '__main__':
  analyze(args.file,config=args.c)
