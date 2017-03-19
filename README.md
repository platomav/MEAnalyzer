# ME Analyzer
Intel Engine Firmware Analysis Tool

[ME Analyzer Discussion Topic](http://www.win-raid.com/t840f39-ME-Analyzer-Intel-Engine-Firmware-Analysis-Tool.html#msg14803)

![](https://i.imgur.com/M29aJqF.png)

##**A. About ME Analyzer**

ME Analyzer is a tool which can show various details about Intel Engine Firmware (Management Engine, Trusted Execution Engine, Service Platform Services) images. It can be used to identify whether the firmware is updated, healthy, what Release, Type, SKU it is etc.

####**A1. ME Analyzer Features**

- Supports all Engine firmware generations (ME 1 - 11, TXE 1 - 3 & SPS 1 - 4)
- Supports all types of file images (Engine Regions, SPI/BIOS images etc)
- Detection of Family, Version, SKU, Date, Revision, Platform etc info
- Detection of Production, Pre-Production, ROM-Bypass, MERecovery etc Releases
- Detection of Region (Stock/clean or Extracted/dirty), Update etc Types
- Detection of Security Version Number (SVN), Version Control Number (VCN) & PV
- Detection of firmware's Flash Image Tool platform configuration for ME 11 & up
- Detection of Intel SPI Flash Descriptor region's Access Permissions
- Detection of whether the imported Engine firmware is updated
- Detection of unusual Engine firmware (Corrupted, Compressed, OEM etc)
- Detection of multiple Engine regions in input file, number only
- Detection of special Engine firmware BIOS GUIDs via UEFIFind
- Detection of common FWUpdate OEMIDs at Engine region & SPI images
- Detection of unique mobile Apple Macintosh Engine firmware SKUs
- Advanced detection & validation of Engine region's firmware Size
- Ability to analyze multiple files by drag & drop or by input path
- Ability to detect & categorize firmware which require attention
- Ability to validate Engine region's $FPT checksums & entries counter
- Ability to detect various important firmware problems and corruptions
- Supports SoniX/LS_29's UBU, Lordkag's UEFIStrip & CodeRush's UEFIFind
- Reports all firmware which are not found at the Engine Repository Database
- Reports any new, unknown, problematic, incomplete etc Engine firmware images
- Features command line parameters to enhance functionality & assist research
- Features user friendly messages & proper handling of unexpected code errors
- Shows colored text to signify the importance of notes, warnings & errors
- Open Source project licensed under GNU GPL v3, comment assisted code

####**A2. Engine Firmware Repository Database**

ME Analyzer's main goal is to allow users to quickly analyze and/or report new firmware versions without the use of special Intel tools (FIT/FITC, FWUpdate) or Hex Editors. To do that effectively, a database had to be built. The [Intel Engine Firmware Repositories](http://www.win-raid.com/t832f39-Intel-Management-amp-Trusted-Execution-Engine-Firmware-Repository.html) is a collection of every ME, TXE & SPS firmware we have found. Its existence is very important for ME Analyzer as it allows us to find new types of firmware, compare same major version releases for similarities, check for updated firmware etc. Bundled with ME Analyzer there's a file called MEA.dat which is required for the program to run. It includes all Engine firmware that are available at the Repository thread. This accommodates two actions: a) Check whether the imported firmware is up to date and b) Help find new Engine firmware releases sooner by reporting them at the [Intel Management Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t596f39-Intel-Management-Engine-Drivers-Firmware-amp-System-Tools.html) or [Intel Trusted Execution Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t624f39-Intel-Trusted-Execution-Engine-Drivers-Firmware-amp-System-Tools.html) threads respectively.

##**B. How to use ME Analyzer**

There are two ways to use ME Analyzer, MEA executable & Command Prompt. The MEA executable allows you to drag & drop one or more firmware and view them one by one. To manually call ME Analyzer, a Command Prompt can be used with -skip as parameter.

####**B1. ME Analyzer Executable**

To use ME Analyzer, select one or multiple files and Drag & Drop them to its executable. You can also input certain optional parameters either by running MEA directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter as explained below.

####**B2. ME Analyzer Parameters**

There are various parameters which enhance or modify the default behavior of ME Analyzer.

* -?      : Displays help & usage screen
* -skip   : Skips options intro screen
* -multi  : Scans multiple files and copies on messages
* -mass   : Scans all files of a given directory
* -enuf   : Enables UEFIFind Engine GUID detection
* -pdb    : Writes input firmware's DB entries to file
* -dfpt   : Displays details about the $FPT header
* -dbname : Renames input file based on DB name

The following are Windows specific:

* -adir   : Sets UEFIFind to the previous directory
* -ubu    : SoniX/LS_29's UEFI BIOS Updater mode
* -ubupre : SoniX/LS_29's UEFI BIOS Updater Pre-Menu mode
* -extr   : Lordkag's UEFIStrip mode
* -msg    : Prints only messages without headers
* -hid    : Displays all firmware even without messages (-msg)
* -aecho  : Alternative display of empty lines (-msg, -hid)

####**B3. ME Analyzer Error Control**

During operation, ME Analyzer may encounter some issues that can trigger Notes, Warnings or Errors. Notes (yellow color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected or problematic is encountered.

##**C. Download ME Analyzer**

ME Analyzer is developed using Python 3.x and can work under Windows, Linux and macOS operating systems. Pre-built binaries are provided for Windows only with build/freeze instructions for all three OS found below.

####**C1. Compatibility**

ME Analyzer has been tested to be compatible with Windows Vista-10, Ubuntu 16.04 and macOS Sierra operating systems. It is expected to work at all Linux or macOS operating systems which have Python 3.5+ support but feel free to test it. It is executed using Python 3.6 under Windows and the built-in Python 3.5 under Linux and macOS. Any latter v3.x releases might work depending on whether MEA's prerequisites are also compatible.

####**C2. Code Prerequisites**

To run ME Analyzer, you need to have the following 3rd party Python module installed:

* [Colorama](https://pypi.python.org/pypi/colorama)

To freeze ME Analyzer, you can use whatever you like. The following are verified to work:

* [Py2exe](https://pypi.python.org/pypi/py2exe) (Windows)
* [Py2app](https://pypi.python.org/pypi/py2app) (macOS)
* [PyInstaller](https://pypi.python.org/pypi/PyInstaller/) (Windows/Linux/macOS)

####**C3. Freeze with PyInstaller**

PyInstaller can freeze ME Analyzer at all three platforms, it is simple to run and gets updated often.

1. Make sure you have Python 3.5 or 3.6 installed
2. Use pip to install colorama module
3. Use pip to install pyinstaller module
4. Open a command prompt and execute:

> pyinstaller --clean --noconfirm --noupx --onefile --log-level=WARN --name MEA MEA.py

At dist folder you should find the final MEA executable