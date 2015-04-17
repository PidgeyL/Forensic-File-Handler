#!/usr/bin/env python3
#
# Tool to detect a files real file type and act based on it
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import re
import os
import sys
import argparse
import subprocess
import zipfile
import binascii

import traceback

# Variables
CONFIGFILE = 'ffh.txt'
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
50 4B 03 04 14 00 06 00       - PK......   - OLE   - .docx, pptx, xlsx  |  D0 CF 11 E0       - ....   - OLE   - .doc, .xls, .ppt
50 4B 03 04 14 00 08 00 08 00 - PK........ - JAR   - .jar               |  49 44 33          - ID3    - MP3   - .mp3
50 4B 03 04                   - PK..       - ZIP   - .zip               |  4D 5A             - MZ     - EXE   - .exe
89 50 4E 47 0D 0A 1A 0A       - .PNG....   - PNG   - .png               |  1A 45 DF A3       - .E..   - WEBM  - .webm
37 7A BC AF 27 1C             - 7z..'.     - 7ZIP  - .7z                |  42 4D             - BM     - BMP   - .bmp
43 44 30 30 31                - CD001      - ISO   - .iso               |  43 57 53          - CWS    - SWF   - .swf
46 4C 56 01                   - FLV.       - FLV   - .flv               |  46 57 53          - FWS    - SWF   - .swf
5F 27 A8 89                   - _'..       - JAR   - .jar               |  5A 57 53          - ZWS    - SWF   - .swf
66 4C 61 43 00 00 00 22       - fLaC..."   - FLAC  - flac               |  7E 74 2C 01       - ~t,.   - IMG   - .img
FF                            - .          - SYS   - .sys               |  ED AB EE DB       - ....   - RPM   - .rpm
FF 4B 45 59 42 20 20 20       - .KEYB      - SYS   - .sys               |  CA FE BA BE       - ....   - CLASS - .class
FF FF FF FF                   - ....       - SYS   - .sys

Magic                                                                   - ASCII                    - Ident - Extension
00 00 00 14 66 74 79 70 71 74 20 20                                     - ....ftypqt               - MOV   - .mov
00 00 00 14 66 74 79 70 69 73 6F 6D                                     - ....ftypisom             - MP4   - .mp4
00 00 00 18 66 74 79 70 33 67 70 35                                     - ....ftyp3gp5             - MP4   - .mp4
00 00 00 1C 66 74 79 70 4D 53 4E 56 01 29 00 46 4D 53 4E 56 6D 70 34 32 - ....ftypMSNV.).FMSNVmp42 - MP4   - .mp4
'''

magics={"52 61 72 21 1A 07 00":"RAR",          "52 61 72 21 1A 07 01 00":"RAR", "50 4B 03 04 0A 00 02 00":"EPUB", "50 4B 03 04 14 00 06 00":"OLE",
        "50 4B 03 04 14 00 08 00 08 00":"JAR", "50 4B 03 04":"ZIP",             "89 50 4E 47 0D 0A 1A 0A":"PNG",  "47 49 46 38 37 61":"GIF",
        "47 49 46 38 39 61":"GIF",  "25 50 44 46":"PDF", "D0 CF 11 E0":"OLE",    "49 44 33":"MP3", "4D 5A":"EXE",    "1A 45 DF A3":"WEBM",
        "37 7A BC AF 27 1C":"7ZIP", "46 4C 56 01":"FLV", "43 44 30 30 31":"ISO", "43 57 53":"SWF", "46 57 53":"SWF", "5A 57 53":"SWF",
        "42 4D":"BMP",              "5F 27 A8 89":"JAR", "7E 74 2C 01":"IMG",    "66 4C 61 43 00 00 00 22":"FLAC",   "CA FE BA BE":"CLASS",
        "ED AB EE DB":"RPM",        "FF":"SYS",          "FF FF FF FF":"SYS",    "FF 4B 45 59 42 20 20 20":"SYS", 
        "00 00 00 14 66 74 79 70 71 74 20 20":"MOV",    "00 00 00 14 66 74 79 70 69 73 6F 6D":"MP4",    "00 00 00 18 66 74 79 70 33 67 70 35":"MP4",
        "00 00 00 1C 66 74 79 70 4D 53 4E 56 01 29 00 46 4D 53 4E 56 6D 70 34 32":"MP4"}

# python2 and 3 compatible functions
def toString(b):
  return str(b) if sys.version_info < (3, 0) else str(b,'utf-8')

def readBinary(f):
  with open(f, "rb") as fIn:
    binary=fIn.read()
  return binary


# analyze ascii version of the stream to find the magic
def getMagic(f):
  bytes = readBinary(f) if type(f) == str else f
  hexFile=toString((binascii.hexlify(bytes).upper())[:16])
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
    raise(e)
    sys.exit(e)
  for x in rules:
    if fileType==x.split(':')[0]:
      command=':'.join(x.split(':')[1:])
      break
  # replace variables
  command=re.compile(re.escape('%name%'), re.IGNORECASE).sub(args.file, command)
  command=re.compile(re.escape('%path%'), re.IGNORECASE).sub(os.path.abspath(args.file), command)
  command=re.compile(re.escape('%ident%'), re.IGNORECASE).sub(magics[unpackIfZip(args.file)], command)
  command=re.compile(re.escape('%magic%'), re.IGNORECASE).sub(unpackIfZip(args.file), command)
  return command

# analyze the zip file and return the first file if single file
def analyzeZIP(f):
  if not zipfile.is_zipfile(f):
    return f
  fzip = zipfile.ZipFile(f, 'r')
  try:
    if len(fzip.namelist())==1:
      f=bytearray(fzip.read(fzip.namelist()[0]))
  except RuntimeError:
    try:
      password = args.p if args.p else ZIPPASSWORD
      password = password.encode("utf-8")
      f=bytearray(fzip.read(fzip.namelist()[0], password))
    except RuntimeError:
      print("Password Protected Zip")
  except Exception as e:
    raise(e)
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

# get the real magic (in case this is a zipped file containing (possible) malware)
def unpackIfZip(f):
  mag=getMagic(f)
  if not mag:
    printAnalysis(f)
  if magics[mag]=="ZIP":
    mag=getMagic(analyzeZIP(f))
    if not mag:
      printAnalysis(analyzeZIP(f))
  return mag

# main function
def analyze(f,config=None):
  try:
    mag=unpackIfZip(f)
    com=getCommandFor(magics[mag], config=config) if mag else None
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
    print(traceback.format_exc())
    raise(e)
    sys.exit(e)

if __name__ == '__main__':
  analyze(args.file,config=args.c)
