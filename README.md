Forensic File Handler
=====================
Forensic File Handler is a tool that uses the **magic bytes** in files to determine the true type of a file, and execute commands accordingly. It is made to be **compatible with both python 2.7 and 3**, on both **Windows** and **Linux** systems.

This download contains:

 * **ffh.py**       the script itself
 * **ffh.txt**      the file that contains the commands to execute when an **ident** is detected (more on idents later). This file contains examples
 * **README.md**    this file
 
Usage
-----
You can specify your commands of choice in ffo.txt (or pass a rules file by appending `-c <rule file>`). The rules file has following format: `<ident>:<command>`.

the command can contain following parameters, which will be parsed by the script, and be replaced with their value:

 * **%name%**   the name of the file
 * **%path%**   the full path of the file
 * **%ident%**  the ident that was recognized
 * **%magic%**  the magic of the file
 
As this script is meant to be used for forensic cases, and if you store malware safely, you can insert it into an encrypted zip, the program will try to open zip files and read its content. If it detects a zip file with multiple files, or encrypted with an unknown password, it will analyze the zip file itself. If the zip file only contains one file, or is encrypted with the password *infected*, it will analyze the first file from the zip. If the password is not *infected*, you can add append `-p <password>` to the script.

**note:** It is not an issue if the command contains colons. The ident, however, cannot contain colons.
**note:** If you want to change the default rules file, you can change the variable `CONFIGFILE` in the script
**note:** If you want to change the default password, you can change the variable `ZIPPASSWORD` in the script

Currently supported magics with their ident
-------------------------------------------

```
Magic                                                                   - ASCII                    - Ident - Extension
-----------------------------------------------------------------------------------------------------------------------
00 00 00 14 66 74 79 70 71 74 20 20                                     - ....ftypqt               - MOV   - .mov
00 00 00 14 66 74 79 70 69 73 6F 6D                                     - ....ftypisom             - MP4   - .mp4
00 00 00 18 66 74 79 70 33 67 70 35                                     - ....ftyp3gp5             - MP4   - .mp4
00 00 00 1C 66 74 79 70 4D 53 4E 56 01 29 00 46 4D 53 4E 56 6D 70 34 32 - ....ftypMSNV.).FMSNVmp42 - MP4   - .mp4
1A 45 DF A3                                                             - .E..                     - WEBM  - .webm
25 50 44 46                                                             - %PDF                     - PDF   - .pdf
37 7A BC AF 27 1C                                                       - 7z..'.                   - 7ZIP  - .7z
42 4D                                                                   - BM                       - BMP   - .bmp
43 44 30 30 31                                                          - CD001                    - ISO   - .iso
46 4C 56 01                                                             - FLV.                     - FLV   - .flv
43 57 53                                                                - CWS                      - SWF   - .swf
46 57 53                                                                - FWS                      - SWF   - .swf
47 49 46 38 37 61                                                       - GIF87a                   - GIF   - .gif
47 49 46 38 39 61                                                       - GIF89a                   - GIF   - .gif
49 44 33                                                                - ID3                      - MP3   - .mp3
4D 5A                                                                   - MZ                       - EXE   - .exe
50 4B 03 04                                                             - PK..                     - ZIP   - .zip
50 4B 03 04 14 00 06 00                                                 - PK......                 - OLE   - .docx, pptx, xlsx
50 4B 03 04 14 00 08 00 08 00                                           - PK........               - JAR   - .jar
50 4B 03 04 0A 00 02 00                                                 - PK......                 - EPUB  - .epub
52 61 72 21 1A 07 00                                                    - Rar!...                  - RAR   - .rar
52 61 72 21 1A 07 01 00                                                 - Rar!....                 - RAR   - .rar
5A 57 53                                                                - ZWS                      - SWF   - .swf
5F 27 A8 89                                                             - _'..                     - JAR   - .jar
66 4C 61 43 00 00 00 22                                                 - fLaC..."                 - FLAC  - flac
7E 74 2C 01                                                             - ~t,.                     - IMG   - .img
89 50 4E 47 0D 0A 1A 0A                                                 - .PNG....                 - PNG   - .png
CA FE BA BE                                                             - ....                     - CLASS - .class
D0 CF 11 E0                                                             - ....                     - OLE   - .doc, .xls, .ppt
ED AB EE DB                                                             - ....                     - RPM   - .rpm
FF                                                                      - .                        - SYS   - .sys
FF 4B 45 59 42 20 20 20                                                 - .KEYB                    - SYS   - .sys
FF FF FF FF                                                             - ....                     - SYS   - .sys
[4 bytes] 66 74 79 70 33 67 70 35                                       - [4 bytes]ftyp3gp5        - MP4   - .mp4
[4 bytes] 66 74 79 70 4D 34 41 20                                       - [4 bytes]ftypM4A         - M4A   - .m4a
[4 bytes] 66 74 79 70 4D 53 4E 56                                       - [4 bytes]ftypMSNV        - MP4   - .mp4
[4 bytes] 66 74 79 70 69 73 6F 6D                                       - [4 bytes]ftypisom        - MP4   - .mp4
[4 bytes] 66 74 79 70 6D 70 34 32                                       - [4 byte]sftypmp42        - M4A   - .m4a
[4 bytes] 66 74 79 70 71 74 20 20                                       - [4 bytes]ftypqt          - MOV   - .mov
[4 bytes] 6D 6F 6F 76                                                   - [4 bytes]moov            - MOV   - .mov
[30 bytes] 50 4B 4C 49 54 45                                            - [30 bytes]PKLITE         - ZIP   - .zip
[512 bytes] 00 6E 1E F0                                                 - [512 bytes].n..          - PPT   - .ppt
[512 bytes] 09 08 10 00 00 06 05 00                                     - [512 bytes]........      - XLS   - .xls
[512 bytes] 0F 00 E8 03                                                 - [512 bytes]..è.          - PPT   - .ppt
[512 bytes] A0 46 1D F0                                                 - [512 bytes].F..          - PPT   - .ppt
[512 bytes] EC A5 C1 00                                                 - [512 bytes]....          - DOC   - .doc
[29152 bytes] 57 69 6E 5A 69 70                                         - [29152 bytes]WinZip      - ZIP   - .zip
```
**note:** If you want to parse two magics with the same ident in a different way, you can change the pairs in the variable `magics` in `ffh.py`<br />
**note:** As for now, the program cannot handle offsets or random bytes in the signature. This will be added in the future.
