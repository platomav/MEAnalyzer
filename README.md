# ME Analyzer
Intel Engine Firmware Analysis Tool

[ME Analyzer News Feed](https://twitter.com/platomaniac)

[ME Analyzer Discussion Topic](https://www.win-raid.com/t840f39-ME-Analyzer-Intel-Engine-Firmware-Analysis-Tool-Discussion.html)

[Intel Engine Firmware Repositories](https://www.win-raid.com/t832f39-Intel-Engine-Firmware-Repositories.html)

[![ME Analyzer Donation](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=DJDZD3PRGCSCL)

![](https://i.imgur.com/VOp78Or.png)

## **A. About ME Analyzer**

ME Analyzer is a tool which parses Intel Engine & PMC firmware images from the Converged Security Management Engine, Converged Security Trusted Execution Engine, Converged Security Server Platform Services, Management Engine, Trusted Execution Engine, Server Platform Services & Power Management Controller families. It can be used by end-users who are looking for all relevant firmware information such as Family, Version, Release, Type, Date, SKU, Platform etc. It is capable of detecting new/unknown firmware, checking firmware health, Updated/Outdated status and many more. ME Analyzer is also a powerful Engine firmware research analysis tool with multiple structures which allow, among others, full parsing and unpacking of Converged Security Engine (CSE) firmware, Flash Partition Table (FPT), Boot Partition Descriptor Table (BPDT/IFWI), CSE Layout Table (LT), advanced Size detection etc. Moreover, with the help of its extensive database, ME Analyzer is capable of uniquely categorizing all supported Engine firmware as well as check for any firmware which have not been stored at the Intel Engine Firmware Repositories yet.

#### **A1. ME Analyzer Features**

- Supports all Engine firmware Families (CS)ME 2-12, (CS)TXE 0-4, (CS)SPS 1-4
- Supports all types of firmware images (Engine Regions, SPI/BIOS etc)
- Detection of Family, Version, SKU, Date, Revision, Platform etc info
- Detection of Production, Pre-Production, ROM-Bypass etc Releases
- Detection of Region (Stock/clean or Extracted/dirty), Update etc Types
- Detection of Security Version Number (SVN), Version Control Number (VCN) & PV
- Detection of Power Management Controller (PMC) firmware Version, SKU etc
- Detection of whether the imported Engine firmware is updated or not
- Detection of unusual Engine firmware (Corrupted, Compressed, OEM etc)
- Ability to fully unpack CSE firmware CSME 11+, CSTXE 3+ and CSSPS 4+
- Ability to validate Engine RSA Signature and Region table checksums
- Advanced detection & validation of Engine region's firmware Size
- Ability to detect & analyze Integrated Firmware Images (IFWI/BPDT)
- Detection of CSME 11+ Flash Image Tool platform configuration by OEM
- Detection of CSME 11 PCH-LP firmware Power Down Mitigation (PDM) erratum
- Ability to analyze multiple files by drag & drop or by input path
- Detection of unique Apple Macintosh Engine firmware "Slim" SKUs
- Detection of multiple Engine regions in input file, number only
- Detection of special Engine firmware BIOS GUIDs via UEFIFind
- Ability to detect & categorize firmware which require attention
- Reports all firmware which are not found at the Engine Firmware Repositories
- Reports any new, unknown, problematic, incomplete etc Engine firmware images
- Features command line parameters to enhance functionality & assist research
- Features user friendly messages & proper handling of unexpected code errors
- Shows colored text to signify the importance of notes, warnings & errors
- Open Source project licensed under GNU GPL v3, comment assisted code

#### **A2. Engine Firmware Repository Database**

ME Analyzer allows end-users and/or researchers to quickly analyze and/or report new firmware versions without the use of special Intel tools (FIT/FITC, FWUpdate) or Hex Editors. To do that effectively, a database had to be built. The [Intel Engine Firmware Repositories](http://www.win-raid.com/t832f39-Intel-Management-amp-Trusted-Execution-Engine-Firmware-Repository.html) is a collection of every (CS)ME, (CS)TXE & (CS)SPS firmware we have found. Its existence is very important for ME Analyzer as it allows us to continue doing research, find new types of firmware, compare same major version releases for similarities, check for updated firmware etc. Bundled with ME Analyzer is a file called MEA.dat which is required for the program to run. It includes entries for all Engine firmware that are available to us. This accommodates primarily three actions: a) Detect each firmware's Family via unique identifier keys, b) Check whether the imported firmware is up to date and c) Help find new Engine firmware sooner by reporting them at the [Intel Management Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t596f39-Intel-Management-Engine-Drivers-Firmware-amp-System-Tools.html) or [Intel Trusted Execution Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t624f39-Intel-Trusted-Execution-Engine-Drivers-Firmware-amp-System-Tools.html) threads respectively.

## **B. How to use ME Analyzer**

There are two ways to use ME Analyzer, MEA executable & Command Prompt. The MEA executable allows you to drag & drop one or more firmware and analyze them one by one or recursively scan entire directories. To manually call ME Analyzer, a Command Prompt can be used with -skip as parameter.

#### **B1. ME Analyzer Executable**

To use ME Analyzer, select one or multiple files and Drag & Drop them to its executable. You can also input certain optional parameters either by running MEA directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter to recursively scan entire directories as explained below.

#### **B2. ME Analyzer Parameters**

There are various parameters which enhance or modify the default behavior of ME Analyzer:

* -?      : Displays help & usage screen
* -skip   : Skips welcome & options screen
* -exit   : Skips Press enter to exit prompt
* -redir  : Enables console redirection support
* -mass   : Scans all files of a given directory
* -enuf   : Enables UEFIFind Engine GUID detection
* -pdb    : Writes input file DB entry to text file
* -dbname : Renames input file based on unique DB name
* -dfpt   : Shows $FPT, BPDT and/or CSE Layout Table headers (Research)
* -unp86  : Unpacks all CSE Converged Security Engine firmware (Research)
* -bug86  : Enables debug/verbose mode during CSE unpacking (Research)
* -ext86  : Prints all Extension info during CSE unpacking (Research)

#### **B3. ME Analyzer Error Control**

During operation, ME Analyzer may encounter issues that can trigger Notes, Warnings and/or Errors. Notes (yellow/green color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected or problematic is encountered.

## **C. Execute/Download ME Analyzer**

ME Analyzer is developed using Python 3.6 and can work under Windows, Linux and macOS operating systems. It consists of two files, the executable (MEA.exe or MEA) and the database (MEA.dat). Regarding the executable, already built/frozen/compiled binaries are provided by me for Windows only (icon designed by [Those Icons](https://thoseicons.com/)). Thus, **you don't need to manually build/freeze/compile ME Analyzer under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/MEAnalyzer/releases) tab, title should be "ME Analyzer v1.X.X". You may need to scroll down a bit if there are DB releases at the top. The latter can be used to update the outdated DB which was bundled with the latest executable release, title should be "DB rXX". For Linux and macOS or courageous Windows users, the build/freeze/compile instructions for all three OS can be found below.

**Note:** To extract the already built/frozen/compiled ME Analyzer archives, you need to use programs which support RAR5 compression!

#### **C1. Compatibility**

ME Analyzer should work at all Windows, Linux or macOS operating systems which have Python 3.6 support. Any latter v3.x releases might work depending on whether MEA's prerequisites are also compatible. Windows users who plan to use the already built/frozen/compiled binaries must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries. Windows users who plan to use console redirection must first "set PYTHONIOENCODING=UTF-8".

#### **C2. Code Prerequisites**

To run ME Analyzer's python script, you need to have the following 3rd party Python modules installed:

* [Colorama](https://pypi.python.org/pypi/colorama/)
* [PTable](https://github.com/platomav/PTable/tree/boxchar)
* [Huffman11](https://github.com/IllegalArgument/Huffman11/)

To build/freeze/compile ME Analyzer's python script, you can use whatever you like. The following are verified to work:

* [Py2exe](https://pypi.python.org/pypi/py2exe/) (Windows)
* [Py2app](https://pypi.python.org/pypi/py2app/) (macOS)
* [PyInstaller](https://github.com/pyinstaller/pyinstaller/tree/master/) (Windows/Linux/macOS)

#### **C3. Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile ME Analyzer at all three supported platforms, it is simple to run and gets updated often.

1. Make sure you have Python 3.6 installed
2. Use pip to install colorama (PyPi)
3. Use pip to install PTable (Github, boxchar branch)
4. Use pip to install PyInstaller (Github, master branch)
5. Place huffman11.py at Huffman11 sub-directory (Github)
6. Open a command prompt and execute:

> pyinstaller --noupx --onefile MEA.py

At dist folder you should find the final MEA executable

## **D. Pictures**

**Note:** Some pictures are outdated and depict older ME Analyzer versions.

![](https://i.imgur.com/VOp78Or.png)

![](https://i.imgur.com/6UNqSe8.png)

![](https://i.imgur.com/9tnZ7lA.png)

![](https://i.imgur.com/4FQlzXU.png)

![](https://i.imgur.com/0fQ9YZF.png)

![](https://i.imgur.com/v46gBmR.png)

![](https://i.imgur.com/WIATngh.png)

![](https://i.imgur.com/OEBpie6.png)

![](https://i.imgur.com/CYNWoiS.png)

![](https://i.imgur.com/dLVMFlg.png)

![](https://i.imgur.com/febB1yM.png)

![](https://i.imgur.com/JGljfRQ.png)

![](https://i.imgur.com/LdYLZrg.png)

![](https://i.imgur.com/XCY7eY6.png)

![](https://i.imgur.com/D012Cpt.png)

![](https://i.imgur.com/cvHhCO2.png)

![](https://i.imgur.com/YEd7frw.png)

![](https://i.imgur.com/QiyR9n8.png)

![](https://i.imgur.com/kSKcpb0.png)

![](https://i.imgur.com/mszfNno.png)