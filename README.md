# ME Analyzer
Intel Engine Firmware Analysis Tool

[ME Analyzer News Feed](https://twitter.com/platomaniac)

[ME Analyzer Discussion Topic](http://www.win-raid.com/t840f39-ME-Analyzer-Intel-Engine-Firmware-Analysis-Tool.html#msg14803)

[![ME Analyzer Donation](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=DJDZD3PRGCSCL)

![](https://i.imgur.com/TZfsR0b.png)

## **A. About ME Analyzer**

ME Analyzer is a tool which can show various details about Intel Engine Firmware (Management Engine, Trusted Execution Engine, Service Platform Services) images. It can be used to identify whether the firmware is updated, healthy, what Release, Type, SKU it is etc.

#### **A1. ME Analyzer Features**

- Supports all Engine firmware generations (ME 1 - 12, TXE 1 - 4 & SPS 1 - 4)
- Supports all types of file images (Engine Regions, SPI/BIOS images etc)
- Detection of Family, Version, SKU, Date, Revision, Platform etc info
- Detection of Production, Pre-Production, ROM-Bypass, MERecovery etc Releases
- Detection of Region (Stock/clean or Extracted/dirty), Update etc Types
- Detection of Security Version Number (SVN), Version Control Number (VCN) & PV
- Detection of firmware's Flash Image Tool platform configuration for ME 11 & up
- Detection of ME 11.x PCH-LP firmware Power Down Mitigation (PDM) erratum
- Detection of Intel SPI Flash Descriptor region's Access Permissions
- Detection of whether the imported Engine firmware is updated
- Detection of unusual Engine firmware (Corrupted, Compressed, OEM etc)
- Detection of multiple Engine regions in input file, number only
- Detection of special Engine firmware BIOS GUIDs via UEFIFind
- Detection of unique mobile Apple Macintosh Engine firmware SKUs
- Advanced detection & validation of Engine region's firmware Size
- Ability to analyze multiple files by drag & drop or by input path
- Ability to unpack Engine x86 firmware (ME >= 11, TXE >= 3, SPS >= 4)
- Ability to detect & analyze Integrated Firmware Image (IFWI)
- Ability to detect & categorize firmware which require attention
- Ability to validate Engine region's $FPT checksums & entries counter
- Ability to detect various important firmware problems and corruptions
- Supports Lordkag's UEFIStrip & CodeRush's UEFIFind utility integration
- Reports all firmware which are not found at the Engine Repository Database
- Reports any new, unknown, problematic, incomplete etc Engine firmware images
- Features command line parameters to enhance functionality & assist research
- Features user friendly messages & proper handling of unexpected code errors
- Shows colored text to signify the importance of notes, warnings & errors
- Open Source project licensed under GNU GPL v3, comment assisted code

#### **A2. Engine Firmware Repository Database**

ME Analyzer's main goal is to allow users to quickly analyze and/or report new firmware versions without the use of special Intel tools (FIT/FITC, FWUpdate) or Hex Editors. To do that effectively, a database had to be built. The [Intel Engine Firmware Repositories](http://www.win-raid.com/t832f39-Intel-Management-amp-Trusted-Execution-Engine-Firmware-Repository.html) is a collection of every ME, TXE & SPS firmware we have found. Its existence is very important for ME Analyzer as it allows us to find new types of firmware, compare same major version releases for similarities, check for updated firmware etc. Bundled with ME Analyzer there's a file called MEA.dat which is required for the program to run. It includes all Engine firmware that are available at the Repository thread. This accommodates two actions: a) Check whether the imported firmware is up to date and b) Help find new Engine firmware releases sooner by reporting them at the [Intel Management Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t596f39-Intel-Management-Engine-Drivers-Firmware-amp-System-Tools.html) or [Intel Trusted Execution Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t624f39-Intel-Trusted-Execution-Engine-Drivers-Firmware-amp-System-Tools.html) threads respectively.

## **B. How to use ME Analyzer**

There are two ways to use ME Analyzer, MEA executable & Command Prompt. The MEA executable allows you to drag & drop one or more firmware and view them one by one. To manually call ME Analyzer, a Command Prompt can be used with -skip as parameter.

#### **B1. ME Analyzer Executable**

To use ME Analyzer, select one or multiple files and Drag & Drop them to its executable. You can also input certain optional parameters either by running MEA directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter as explained below.

#### **B2. ME Analyzer Parameters**

There are various parameters which enhance or modify the default behavior of ME Analyzer.

* -?      : Displays help & usage screen
* -skip   : Skips options intro screen
* -check  : Copies files with messages to check
* -mass   : Scans all files of a given directory
* -enuf   : Enables UEFIFind Engine GUID detection
* -pdb    : Writes input firmware's DB entries to file
* -dbname : Renames input file based on DB name
* -dfpt   : Shows info about the $FPT or IFWI headers (Research)
* -dsku   : Shows verbose detection info for ME 11.x SKU (Research)
* -unp86  : Unpacks all Engine x86 $FPT/IFWI/$CPD firmware (Research)
* -ext86  : Prints all Extension info at Engine x86 unpacking (Research)
* -bug86  : Enables debug/verbose mode at Engine x86 unpacking (Research)

The following are Windows specific:

* -adir   : Sets UEFIFind to the previous directory
* -extr   : Lordkag's UEFIStrip mode
* -msg    : Prints only messages without headers
* -hid    : Displays all firmware even without messages (-msg)

#### **B3. ME Analyzer Error Control**

During operation, ME Analyzer may encounter some issues that can trigger Notes, Warnings or Errors. Notes (yellow color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected or problematic is encountered.

## **C. Download ME Analyzer**

ME Analyzer is developed using Python 3.6 and can work under Windows, Linux and macOS operating systems. It consists of two files, the executable (MEA.exe or MEA) and the database (MEA.dat). Regarding the executable, already built/frozen/compiled binaries are provided by me for Windows only (icon designed by [Those Icons](https://thoseicons.com/)). Thus, **you don't need to manually build/freeze/compile ME Analyzer under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/MEAnalyzer/releases) tab, title should be "ME Analyzer v1.X.X". You may need to scroll down a bit if there are DB releases at the top. The latter can be used to update the outdated DB which was bunled with the latest executable release, title should be "DB rXX". For Linux and macOS or courageous Windows users, the build/freeze/compile instructions for all three OS can be found below.

**Note:** To extract the already built/frozen/compiled ME Analyzer archive, you need to use programs which support RAR5 compression!

#### **C1. Compatibility**

ME Analyzer has been tested to be compatible with Windows Vista-10, Ubuntu 16.04 and macOS Sierra operating systems. It is generally expected to work at all Windows, Linux or macOS operating systems which have Python 3.6 support but feel free to test it. Any latter v3.x releases might work depending on whether MEA's prerequisites are also compatible.

#### **C2. Code Prerequisites**

To run ME Analyzer's python script, you need to have the following 3rd party Python modules installed:

* [Colorama](https://pypi.python.org/pypi/colorama/)
* [PTable](https://github.com/kxxoling/PTable/tree/master/)
* [Huffman11](https://github.com/IllegalArgument/Huffman11/)

To build/freeze/compile ME Analyzer's python script, you can use whatever you like. The following are verified to work:

* [Py2exe](https://pypi.python.org/pypi/py2exe/) (Windows)
* [Py2app](https://pypi.python.org/pypi/py2app/) (macOS)
* [PyInstaller](https://github.com/pyinstaller/pyinstaller/tree/develop/) (Windows/Linux/macOS)

#### **C3. Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile ME Analyzer at all three supported platforms, it is simple to run and gets updated often.

1. Make sure you have Python 3.6 installed
2. Use pip to install colorama (PyPi)
3. Use pip to install PTable (Github, master branch)
4. Use pip to install PyInstaller (Github, develop branch)
5. Place huffman11.py at MEA.py's directory (Github)
6. Open a command prompt and execute:

> pyinstaller --noupx --onefile MEA.py

At dist folder you should find the final MEA executable