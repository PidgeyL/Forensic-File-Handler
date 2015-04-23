#!/usr/bin/env python3
#
# Analyzes a file and print an analysis based on the bytes
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import argparse
import binascii
import hashlib
import math
import sys

# Variables
dumplinelength = 16
dumpbytelength = 256

# python2 and 3 compatible functions
def toString(b):
  return str(b) if sys.version_info < (3, 0) else str(b,'utf-8')

def readBinary(f):
  with open(f, "rb") as fIn:
    binary=bytes(fIn.read())
  return binary

# allows us to work with both strings (the file path) and bytearrays
def readFileIfString(f):
  return readBinary(f) if type(f) == str else f

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

class cDumpStream():
    def __init__(self):
        self.text = ''

    def Addline(self, line):
        if line != '':
            self.text += line + '\n'

    def Content(self):
        return self.text

def HexDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0 and hexDump != '':
            oDumpStream.Addline(hexDump)
            hexDump = ''
        hexDump += IFF(hexDump == '', '', ' ') + '%02X' % ord(b)
    oDumpStream.Addline(hexDump)
    return oDumpStream.Content()

def CombineHexAscii(hexDump, asciiDump):
    if hexDump == '':
        return ''
    return hexDump + '  ' + (' ' * (3 * (dumplinelength - len(asciiDump)))) + asciiDump

def HexAsciiDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    asciiDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0:
            if hexDump != '':
                oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
            hexDump = '%08X:' % i
            asciiDump = ''
        hexDump+= ' %02X' % b
        asciiDump += IFF(b >= 32, chr(b), '.')
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()

# calculate the frequency of each byte value in the file
def getFrequency(byteArr):
  freqList = []
  for b in range(256):
    ctr = 0
    for byte in byteArr:
      if byte == b: ctr += 1
    freqList.append(float(ctr)/len(byteArr))
  return freqList

# Shannon entropy
def entropy(byteFreq):
  ent = 0.0
  for freq in byteFreq:
    if freq > 0: ent = ent + freq * math.log(freq, 2)
  return -ent

# analysis
def byteAnalysis(f):
  # entropy
  binFile=readFileIfString(f)
  filesize=len(binFile)
  if filesize >= 1073741824:
    humanfsize="%.2fGB (%sb)"%(filesize/1073741824,filesize)
  elif filesize >= 1048576:
    humanfsize="%.2fMB (%sb)"%(filesize/1048576,filesize)
  elif filesize >= 1024:
    humanfsize="%.2fKB (%sb)"%(filesize/1024,filesize)
  else:
    humanfsize="%sb"%(filesize)
  print("MD5 hash:    '%s'"%hashlib.md5(binFile).hexdigest())
  print("Entropy:     '%s'"%entropy(getFrequency(binFile)))
  print("File size:   '%s'\n"%humanfsize)
  print(HexAsciiDump(binFile[:dumpbytelength]))


if __name__ == '__main__':
  # Parsing arguments
  parser = argparse.ArgumentParser(description='Analyzes a file and print an analysis based on the bytes')
  parser.add_argument('file', metavar='File',   type=str, help="A file containing the items to check")
  args = parser.parse_args()

  byteAnalysis(args.file)
