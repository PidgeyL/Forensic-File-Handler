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
import string
import zipfile
import binascii
import traceback
from collections import OrderedDict
from byteAnalysis import byteAnalysis

# Variables
CONFIGFILE = 'ffh.txt'
ZIPPASSWORD = 'infected'
MAGICS={"FF":"SYS",                "4D 5A":"EXE",            "42 4D":"BMP",             "FF Ex":"MP3",           "FF Fx":"MP3",
        "1F 9D":"TAR",             "1F A0":"TAR",            "FF FB":"MP3",             "46 57 53":"SWF",        "5A 57 53":"SWF",
        "49 44 33":"MP3",          "43 57 53":"SWF",
        "ED AB EE DB":"RPM",       "FF FF FF FF":"SYS",      "00 00 01 00":"ICO",       "4E 45 53 1A":"NES",     "66 4C 61 43":"FLAC",
        "5F 27 A8 89":"JAR",       "7E 74 2C 01":"IMG",      "46 4C 56 01":"FLV",       "D0 CF 11 E0":"OLE",     "1A 45 DF A3":"WEBM",
        "00 00 01 Bx":"MPG",       "00 00 01 BA":"MPG",      "50 4B 03 04":"ZIP",       "25 50 44 46":"PDF",     "CA FE BA BE":"CLASS",
        "4D 54 68 64":"MIDI",      "4F 67 67 53":"OGG",      "FF D8 FF E0":"JPG",       "4D 4D 00 2A":"TIFF",    "49 49 2A 00":"TIFF",
        "43 44 30 30 31":"ISO",   
        "47 49 46 38 37 61":"GIF",       "47 49 46 38 39 61":"GIF",        "37 7A BC AF 27 1C":"7ZIP",      "50 4B 03 04 0A 00 02 00":"EPUB",
        "50 4B 03 04 14 00 06 00":"OLE", "66 4C 61 43 00 00 00 22":"FLAC", "89 50 4E 47 0D 0A 1A 0A":"PNG", "FF 4B 45 59 42 20 20 20":"SYS",
        "D0 CF 11 E0 A1 B1 1A E1":"OLE", "50 4D 4F 43 43 4D 4F 43":"DAT",  "75 73 74 61 72 00 30 30":"TAR", "75 73 74 61 72 20 20 00":"TAR",
        "50 4B 03 04 14 00 08 00 08 00":"JAR",       
        "00 00 00 xx 66 74 79 70 33 67 70":"3GP",    "FF D8 FF E0 xx xx 4A 46 49 46 00":"JPG",    "FF D8 FF E1 xx xx 45 78 69 66 00":"JPG",
        "FF D8 FF E8 xx xx 53 50 49 46 46 00":"JPG", "00 00 00 14 66 74 79 70 69 73 6F 6D":"MP4", "00 00 00 18 66 74 79 70 33 67 70 35":"MP4",
        "00 00 00 14 66 74 79 70 71 74 20 20":"MOV", "52 49 46 46 xx xx xx xx 57 41 56 45":"WAV", "00 00 00 xx 66 74 79 70 33 67 70 35":"MP4",
        "52 49 46 46 xx xx xx xx 41 56 49 20 4C 49 53 54":"AVI",           "52 49 46 46 xx xx xx xx 57 41 56 45 66 6D 74 20":"WAV",
        "52 61 72 21 1A 07 00":"RAR", "52 61 72 21 1A 07 01 00":"RAR", 
        "00 00 00 1C 66 74 79 70 4D 53 4E 56 01 29 00 46 4D 53 4E 56 6D 70 34 32":"MP4",
        "[4 bytes] 66 74 79 70 33 67 70 35":"MP4",
        "[4 bytes] 66 74 79 70 4D 34 41 20":"M4A",      "[4 bytes] 66 74 79 70 4D 53 4E 56":"MP4",      "[4 bytes] 66 74 79 70 69 73 6F 6D":"MP4",
        "[4 bytes] 66 74 79 70 6D 70 34 32":"M4A",      "[4 bytes] 66 74 79 70 71 74 20 20":"MOV",      "[4 bytes] 6D 6F 6F 76":"MOV",
        "[30 bytes] 50 4B 4C 49 54 45":"ZIP",           "[512 bytes] 00 6E 1E F0":"PPT",                "[512 bytes] 09 08 10 00 00 06 05 00":"XLS",
        "[512 bytes] 0F 00 E8 03":"PPT",                "[512 bytes] A0 46 1D F0":"PPT",                "[512 bytes] EC A5 C1 00":"DOC",
        "[512 byte offset] FD FF FF FF xx xx xx xx xx xx xx xx 04 00 00 00":"DB",
        "[29152 bytes] 57 69 6E 5A 69 70":"ZIP"}

# python2 and 3 compatible functions
def toString(b):
  return str(b) if sys.version_info < (3, 0) else str(b,'utf-8')

def readBinary(f):
  with open(f, "rb") as fIn:
    binary=bytearray(fIn.read())
  return binary

# this function makes it so that re.sub does not interpret backspaces
def esc(i):
  return i

# allows us to work with both strings (the file path) and bytearrays
def readFileIfString(f):
  return readBinary(f) if type(f) == str else f

# analyze ascii version of the stream to find the magic
def getMagic(f):
  bytes = readFileIfString(f)
  hexFile=toString((binascii.hexlify(bytes).upper()))
  reOffset=re.compile("(\[\s*(\d)+ byte(s)?\s*\](\s*|\d|[A-F]|[a-f])+)")
  for x in sorted(list(MAGICS.keys()),reverse=True):
    result=reOffset.match(x)
    offset=int(result.group(2))*2 if result else 0
    y=(x.split("]"))[1].strip() if result else x
    y=y.replace("x",".")
    reg=re.compile("^(%s[\s\dA-Fa-f]+)"%y.replace(" ",""))
    if reg.search(hexFile[offset:]): return x
  return None

# get the command that matches the magic
def getCommandFor(fileType, config=None):
  command=None
  try:
    if not config:
      config=CONFIGFILE
    rules=[x.strip() for x in open(config) if ":" in x and not x.startswith("#")]
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

def isPrintableAscii(f):
  bytes=readFileIfString(f)
  for x in bytes:
    if not x in ([ord(x) for x in string.printable]): return False
  return True

def printAnalysis(f,byteFile):
  if not isPrintableAscii(byteFile):
    magic = getMagic(byteFile)
    ident = MAGICS[magic] if magic else "None"
  else:
    magic = None
    ident = "TXT"
  print("Magic found: '%s'"%magic)
  print("Ident found: '%s'"%ident)
  byteAnalysis(byteFile)
  sys.exit(0)

# get the real magic (in case this is a zipped file containing (possible) malware)
def unpackIfZip(f):
  mag=getMagic(f)
  if mag and MAGICS[mag]=="ZIP":
    mag=getMagic(analyzeZIP(f))
  return mag

# main function
def analyze(f,config=None):
  try:
    byteFile=readBinary(f)
    if not isPrintableAscii(byteFile):
      mag=unpackIfZip(f)
      com=getCommandFor(MAGICS[mag], config=config) if mag else None
    else:
      mag=None
      com=getCommandFor("TXT", config=config)
    if com:
      try:
        subprocess.call(com.split(' '))
      except:
        print("The command (%s) for %s (magic: %s) in %s does not work."%(com.split(' ')[0], MAGICS[mag], mag, config))
    else:
      printAnalysis(f,byteFile)
  except IOError:
    sys.exit("Couldn't open file")
  except Exception as e:
    print(traceback.format_exc())
    raise(e)
    sys.exit(e)

if __name__ == '__main__':
  # Parsing arguments
  parser = argparse.ArgumentParser(description='Analyzes a file for its true file type and act accordingly')
  parser.add_argument('file', metavar='File',   type=str, help="A file containing the items to check")
  parser.add_argument('-c',   metavar="Config", type=str, help='config file to use')
  parser.add_argument('-p',   metavar="Pass",   type=str, help='optional password for encrypted zip')
  parser.add_argument('-m',   metavar="File",   type=str, help="File containing aditional magics")
  parser.add_argument('--override',  action='store_true', help='update the database')
  args = parser.parse_args()

  # Use aditional magics file
  if args.m:
    if args.override:
      MAGICS=[]
    try:
      MAGICS.update({x.split(":")[0].strip():x.split(":")[1].strip() for x in open(args.m) if ":" in x and not x.startswith("#")})
    except IOError:
      sys.exit("Couldn't open the magic file")
    except Exception as e:
      raise(e)

  analyze(args.file,config=args.c)
