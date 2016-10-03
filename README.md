# ME Analyzer
Intel Engine Firmware Analysis Tool

[Official ME Analyzer forum thread](http://www.win-raid.com/t840f39-ME-Analyzer-Intel-Engine-Firmware-Analysis-Tool.html#msg14803)

##**A. About ME Analyzer**

ME Analyzer is a tool that can show various details about Intel Engine Firmware (Management Engine, Trusted Execution Engine, Service Platform Services) images. It can be used to identify whether the firmware is updated, what Release, Type, SKU it is etc. 

####**A1. ME Analyzer Features**

- Supports all current & legacy Engine firmware (ME 1.x - 11.x , TXE 1.x - 2.x & SPS 1.x - 4.x)
- All types of firmware files are supported (ME/TXE/SPS Regions, BIOS images etc)
- Partial Firmware Update support for Corporate ME 8-11 enabled platforms
- SoniX/LS_29's UEFI Bios Updater and Lordkag's UEFI Strip integration support
- Firmware Family (ME, TXE or SPS), Date & Version number detection
- Production, Pre-Production & ROM-Bypass firmware release detection
- Region (Stock or Extracted) & Update firmware type detection
- Identification of the platform that the firmware was configured for via FITC
- SKU & target platform detection for all supported firmware releases
- Security Version Number (SVN), Version Control Number (VCN) & PV-bit detection
- Intel SPI Flash Descriptor Access Region detection, Skylake compatible
- Identification of whether the imported Engine firmware is up-to-date
- Proper CPT/PBG SKU & BlackList Table detection for ME 7.x firmware
- Special Apple Macintosh mobile ME firmware SKU support
- FWUpdate OEMID detection at Region & SPI/BIOS images
- Multiple drag & drop & sorting of rare/problematic Engine Firmware
- Multiple Engine Firmware Region detection, number only
- Unidentifiable Engine Firmware Region (ex: Corrupted, Compressed) detection
- Reports unknown firmware not found at the Engine Repository Database
- Reports unknown firmware Major, Minor, SKU, Type etc releases
- Shows colored text to signify the importance of notes, warnings, errors etc
- Open Source project licensed under GNU GPL v3

####**A2. Engine Firmware Repository Database**

ME Analyzer's main goal is to allow users to quickly determine & report new firmware versions without the use of special Intel tools (FIT/FITC, FWUpdate) or Hex Editors. To do that effectively, a database had to be built. The [Intel Engine Firmware Repositories](http://www.win-raid.com/t832f39-Intel-Management-amp-Trusted-Execution-Engine-Firmware-Repository.html) is a collection of every ME, TXE & SPS firmware I have found. It's existence is very important for ME Analyzer as it allows me to find new types of firmware, compare same major version releases for similarities, check for updated firmware etc. Bundled with ME Analyzer there's a file called MEA.dat which is required for the program to run. It includes all Engine firmware that are available at the Repository thread. This accommodates two actions: a) Check whether the imported firmware is up to date and b) Help find new Engine firmware releases sooner by reporting them at the [Intel Management Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t596f39-Intel-Management-Engine-Drivers-Firmware-amp-System-Tools.html) or [Intel Trusted Execution Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t624f39-Intel-Trusted-Execution-Engine-Drivers-Firmware-amp-System-Tools.html) threads respectively.

##**B. How to use ME Analyzer**

There are two ways to use ME Analyzer, MEA.exe & Command Prompt. The MEA executable allows you to drag & drop one or more firmware and view them one by one. To manually call ME Analyzer, a Command Prompt can be used with -skip as parameter.

####**B1. ME Analyzer Executable**

To use ME Analyzer, select one or multiple files and Drag & Drop them to it's executable. You can also input certain optional parameters either by running MEA directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once.

####**B2. ME Analyzer Parameters**

There are various parameters which enhance or modify the default behavior of ME Analyzer.

* -? : Displays MEA's help & usage screen
* -skip : Skips MEA's options intro screen
* -multi : Scans multiple files and renames on messages
* -mass : Scans all files of a given directory
* -ubu : SoniX/LS_29's UEFI BIOS Updater mode
* -ubupre : SoniX/LS_29's UEFI BIOS Updater Pre-Menu mode
* -extr : Lordkag's UEFI Strip mode
* -adir : Sets UEFIFind to the previous directory
* -msg : Prints only messages without headers
* -hid : Displays all firmware even without messages (-msg)
* -aecho : Alternative display of empty lines (-msg, -hid)
* -enuf : Enables UEFIFind Engine GUID detection
* -dbname : Renames input file based on DB name
* -rbume : Extracts Dell HDR RBU ImagME regions
* -pdb : Prints the DB without SHA1 hashes to file
* -prsa : Prints the firmware's SHA-1 hash for DB entry
* -dker : Prints Kernel/FIT analysis for post-SKL firmware
* -eker : Extracts post-SKL FTPR > Kernel region (research)
* -exc : Pauses after unexpected python exceptions (debugging)
* -utf8 : Encodes output to Unicode (only in case of crash)

####**B3. ME Analyzer Error Control**

During operation, ME Analyzer may encounter some issues related to rare firmware circumstances that can trigger Notes, Warnings or Errors. Notes (yellow color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected is encountered like unknown Major/Minor/SKU releases, Failure to find/open/read files etc.

##**C. Download ME Analyzer**

ME Analyzer is developed and tested under Windows and currently Windows XP - Windows 10 operating systems are supported. Since the Engine Firmware Repository Database is updated more frequently compared to the main program, a separate DB release is provided.
