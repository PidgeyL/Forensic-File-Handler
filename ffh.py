#!/usr/bin/env python3
#
# Tool to detect a files real file type and act based on it
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import re
import os
import sys
import argparse
import subprocess
import zipfile
import binascii
import traceback
from collections import OrderedDict
from byteAnalysis import byteAnalysis

# Variables
CONFIGFILE = 'ffh.txt'
ZIPPASSWORD = 'infected'
MAGICS={"52 61 72 21 1A 07 00":"RAR",          "52 61 72 21 1A 07 01 00":"RAR", "50 4B 03 04 0A 00 02 00":"EPUB", "50 4B 03 04 14 00 06 00":"OLE",
        "50 4B 03 04 14 00 08 00 08 00":"JAR", "50 4B 03 04":"ZIP",             "89 50 4E 47 0D 0A 1A 0A":"PNG",  "47 49 46 38 37 61":"GIF",
        "47 49 46 38 39 61":"GIF",  "25 50 44 46":"PDF", "D0 CF 11 E0":"OLE",    "49 44 33":"MP3", "4D 5A":"EXE",    "1A 45 DF A3":"WEBM",
        "37 7A BC AF 27 1C":"7ZIP", "46 4C 56 01":"FLV", "43 44 30 30 31":"ISO", "43 57 53":"SWF", "46 57 53":"SWF", "5A 57 53":"SWF",
        "42 4D":"BMP",              "5F 27 A8 89":"JAR", "7E 74 2C 01":"IMG",    "66 4C 61 43 00 00 00 22":"FLAC",   "CA FE BA BE":"CLASS",
        "ED AB EE DB":"RPM",        "FF":"SYS",          "FF FF FF FF":"SYS",    "FF 4B 45 59 42 20 20 20":"SYS", 
        "00 00 00 14 66 74 79 70 71 74 20 20":"MOV",    "00 00 00 14 66 74 79 70 69 73 6F 6D":"MP4",    "00 00 00 18 66 74 79 70 33 67 70 35":"MP4",
        "00 00 00 1C 66 74 79 70 4D 53 4E 56 01 29 00 46 4D 53 4E 56 6D 70 34 32":"MP4",                "[4 bytes] 66 74 79 70 33 67 70 35":"MP4",
        "[4 bytes] 66 74 79 70 4D 34 41 20":"M4A",      "[4 bytes] 66 74 79 70 4D 53 4E 56":"MP4",      "[4 bytes] 66 74 79 70 69 73 6F 6D":"MP4",
        "[4 bytes] 66 74 79 70 6D 70 34 32":"M4A",      "[4 bytes] 66 74 79 70 71 74 20 20":"MOV",      "[4 bytes] 6D 6F 6F 76":"MOV",
        "[30 bytes] 50 4B 4C 49 54 45":"ZIP",           "[512 bytes] 00 6E 1E F0":"PPT",                "[512 bytes] 09 08 10 00 00 06 05 00":"XLS",
        "[512 bytes] 0F 00 E8 03":"PPT",                "[512 bytes] A0 46 1D F0":"PPT",                "[512 bytes] EC A5 C1 00":"DOC",
        "[29152 bytes] 57 69 6E 5A 69 70":"ZIP"}
ASCII_PRINTABLE=list(range(0x20,0x80))+list(range(0x08,0x0B))
# Parsing arguments
parser = argparse.ArgumentParser(description='Analyzes a file for its true file type and act accordingly')
parser.add_argument('file', metavar='File',   type=str, help="A file containing the items to check")
parser.add_argument('-c',   metavar="Config",           help='config file to use')
parser.add_argument('-p',   metavar="Pass",             help='optional password for encrypted zip')
args = parser.parse_args()

# python2 and 3 compatible functions
def toString(b):
  return str(b) if sys.version_info < (3, 0) else str(b,'utf-8')

def readBinary(f):
  with open(f, "rb") as fIn:
    binary=bytes(fIn.read())
  return binary

# this function makes it so that re.sub does not interpret backspaces
def esc(i):
  return i

# analyze ascii version of the stream to find the magic
def getMagic(f):
  bytes = readBinary(f) if type(f) == str else f
  hexFile=toString((binascii.hexlify(bytes).upper()))
  reOffset=re.compile("(\[\s*(\d)+ byte(s)?\s*\](\s*|\d|[A-F]|[a-f])+)")
  for x in sorted(list(MAGICS.keys()),reverse=True):
    result=reOffset.match(x)
    offset=int(result.group(2))*2 if result else 0
    y=(x.split("]"))[1].strip() if result else x
    if hexFile[offset:].startswith(y.replace(" ","")): return x
  return None

# get the command that matches the magic
def getCommandFor(fileType, config=None):
  command=None
  try:
    if not config:
      config=CONFIGFILE
    rules=[x.strip() for x in open(config) if ":" in x]
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
  if command:
    command=re.compile(re.escape('%name%'), re.IGNORECASE).sub(esc(args.file), command)
    command=re.compile(re.escape('%path%'), re.IGNORECASE).sub(esc(os.path.abspath(args.file)), command)
    command=re.compile(re.escape('%ident%'), re.IGNORECASE).sub(esc(MAGICS[unpackIfZip(args.file)]), command)
    command=re.compile(re.escape('%magic%'), re.IGNORECASE).sub(esc(unpackIfZip(args.file)), command)
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
  magic = getMagic(f)
  print("Magic found: '%s'"%magic)
  print("Ident found: '%s'"%(MAGICS[magic] if magic else "None"))
  byteAnalysis(f)
  sys.exit(0)

# get the real magic (in case this is a zipped file containing (possible) malware)
def unpackIfZip(f):
  mag=getMagic(f)
  if not mag:
    printAnalysis(f)
  if MAGICS[mag]=="ZIP":
    mag=getMagic(analyzeZIP(f))
    if not mag:
      printAnalysis(analyzeZIP(f))
  return mag

# main function
def analyze(f,config=None):
  try:
    byteFile=readBinary(f)
    pureText=True
    for x in byteFile:
      if not x in ASCII_PRINTABLE: pureText=False;break
    print("Is pure ascii: %s"%pureText)

    mag=unpackIfZip(f)
    com=getCommandFor(MAGICS[mag], config=config) if mag else None
    if com:
      try:
        subprocess.call(com.split(' '))
      except:
        print("The command (%s) for %s (magic: %s) in %s does not work."%(com.split(' ')[0], MAGICS[mag], mag, config))
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
