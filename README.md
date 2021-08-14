# ME Analyzer
**Intel Engine & Graphics Firmware Analysis Tool**

[ME Analyzer News Feed](https://twitter.com/platomaniac)

[ME Analyzer Discussion Topic](https://www.win-raid.com/t840f39-ME-Analyzer-Intel-Engine-Firmware-Analysis-Tool-Discussion.html)

[Intel Engine/Graphics/Independent Firmware Introduction](https://www.win-raid.com/t596f39-Intel-Converged-Security-Management-Engine-Drivers-Firmware-and-Tools.html)

[Intel Engine/Graphics/Independent Firmware Repositories](https://www.win-raid.com/t832f39-Intel-CS-ME-CS-TXE-CS-SPS-GSC-PMC-PCHC-PHY-amp-OROM-Firmware-Repositories.html)

<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=DJDZD3PRGCSCL"><img border="0" title="ME Analyzer Donation via Paypal or Debit/Credit Card" alt="ME Analyzer Donation via Paypal or Debit/Credit Card" src="https://user-images.githubusercontent.com/11527726/109392268-e0f68280-7923-11eb-83d8-0a63f0d20783.png"></a>

![](https://i.imgur.com/PoUD96g.png)

## **A. About ME Analyzer**

ME Analyzer is a tool which parses Intel Engine, Intel Graphics and their Independent firmware from the following families:

- (Converged Security) Management Engine - CS(ME)
- (Converged Security) Trusted Execution Engine - (CS)TXE
- (Converged Security) Server Platform Services - (CS)SPS
- Graphics System Controller - GSC
- Power Management Controller - PMC
- Platform Controller Hub Configuration - PCHC
- USB Type C Physical - PHY
- Graphics Option ROM - OROM

It can be used by end-users who are looking for all relevant firmware information such as Family, Version, Release, Type, Date, SKU, Platform, Size, Updated/Outdated, Health Status etc. ME Analyzer is also a powerful Engine / Graphics / Independent firmware research analysis tool with multiple structures which allow, among others, full parsing and unpacking of Converged Security Engine (CSE) & Graphics System Controller (GSC) Code and File Systems such as:

- Flash Partition Table - FPT
- Boot Partition Descriptor Table - BPDT/IFWI
- CSE Layout Table - LT
- CSE File Table - FTBL/EFST
- CSE Virtual File System - VFS
- GSC OROM-PCIR - VBT/EFI

Moreover, with the help of its extensive databases, ME Analyzer is capable of uniquely identifying and categorizing all supported Engine / Graphics / Independent firmware as well as check for any firmware which have not been stored at the equivalent, community supported, Firmware Repositories yet.

#### **A1. ME Analyzer Features**

- Supports all Engine firmware Families (CSE/ME: ME, TXE, SPS etc)
- Supports all Graphics firmware Families (GSC: DG1, DG2, ATS etc)
- Supports CSE/GSC Independent (IUP) firmware Families (PMC, OROM etc)
- Detection of Firmware Details (Family, Version, SKU, Date, Platform etc)
- Detection of Firmware Release (Production, Pre-Production, ROM-Bypass etc)
- Detection of Firmware Type (Region, Extracted, Recovery, Update etc)
- Detection of Firmware Security/Update Version Numbers (SVN, VCN etc)
- Detection of Power Management Controller (PMC) Independent firmware info
- Detection of PCH Configuration (PCHC) Independent firmware info
- Detection of USB Type C Physical (PHY) Independent firmware info
- Detection of Graphics Option ROM (OROM) Independent firmware info
- Detection of imported Engine/Graphics firmware Updated/Outdated Status
- Detection of unusual Engine/Graphics firmware (Corrupted, Compressed etc)
- Ability to fully unpack all supported CSE, GSC and/or IUP/OROM firmware
- Ability to validate Engine/Graphics/IUP RSA Signature and Checksums
- Advanced detection & validation of Engine/Graphics/IUP firmware Size
- Ability to detect & analyze Integrated Firmware Images (IFWI/BPDT)
- Ability to analyze multiple files by drag & drop or by input path
- Ability to detect & categorize any firmware which require attention
- Ability to automatically scan for newer ME Analyzer & Database releases
- Reports firmware which are not found at the Engine/Graphics/IUP Repositories
- Reports new, unknown, problematic, incomplete etc Engine/Graphics/IUP firmware
- Features command line parameters to enhance functionality & assist research
- Features user friendly messages & proper handling of unexpected code errors
- Shows colored text to signify the importance of notes, warnings & errors
- Open Source project under BSD permissive license, comment assisted code

#### **A2. Engine Firmware Repository Database**

ME Analyzer allows end-users and/or researchers to quickly analyze and/or report new firmware versions without the use of special Intel tools (FIT/FITC, FWUpdate) or Hex Editors. To do that effectively, a database had to be built. The [Intel Engine/Graphics/Independent Firmware Repositories](https://www.win-raid.com/t832f39-Intel-CS-ME-CS-TXE-CS-SPS-GSC-PMC-PCHC-PHY-amp-OROM-Firmware-Repositories.html) is a collection of every (CS)ME, (CS)TXE, (CS)SPS, GSC, PMC, PCHC, PHY & OROM firmware we have found. Its existence is very important for ME Analyzer as it allows us to continue doing research, find new types of firmware, compare same major version releases for similarities, check for updated firmware etc. Bundled with ME Analyzer is a file called MEA.dat which is required for the program to run. It includes entries for all Engine / Graphics / Independent firmware that are available to us. This accommodates primarily three actions: a) Detect each firmware's Family via unique identifier keys, b) Check whether the imported firmware is up to date and c) Help find new Engine firmware sooner by reporting them at the [Intel (Converged Security) Management Engine: Drivers, Firmware and Tools](https://www.win-raid.com/t596f39-Intel-Converged-Security-Management-Engine-Drivers-Firmware-and-Tools.html) or [Intel (Converged Security) Trusted Execution Engine: Drivers, Firmware and Tools](https://www.win-raid.com/t624f39-Intel-Trusted-Execution-Engine-Drivers-Firmware-amp-System-Tools.html) threads respectively.

## **B. How to use ME Analyzer**

There are two ways to use ME Analyzer, MEA executable/script & Command Prompt. The MEA executable allows you to drag & drop one or more firmware and analyze them one by one or recursively scan entire directories. To manually call ME Analyzer, a Command Prompt can be used with -skip as parameter.

#### **B1. ME Analyzer Executable**

To use ME Analyzer, select one or multiple files and Drag & Drop them to its executable/script. You can also input certain optional parameters either by running MEA directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter to recursively scan entire directories as explained below.

#### **B2. ME Analyzer Parameters**

There are various parameters which enhance or modify the default behavior of ME Analyzer:

* -?     : Displays help & usage screen
* -skip  : Skips welcome & options screen
* -exit  : Skips Press enter to exit prompt
* -mass  : Scans all files of a given directory
* -pdb   : Writes unique input file DB name to file
* -dbn   : Renames input file based on unique DB name
* -dfpt  : Shows FPT, BPDT, OROM & CSE/GSC Layout Table info
* -unp86 : Unpacks all supported CSE, GSC and/or IUP firmware
* -bug86 : Enables pause on error during CSE/GSC/IUP unpacking
* -ver86 : Enables verbose output during CSE/GSC/IUP unpacking
* -html  : Writes parsable HTML info files during MEA operation
* -json  : Writes parsable JSON info files during MEA operation

#### **B3. ME Analyzer Error Control**

During operation, ME Analyzer may encounter issues that can trigger Notes, Warnings and/or Errors. Notes (yellow/green color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected or problematic is encountered.

## **C. Download ME Analyzer**

ME Analyzer consists of four files, the executable/script (MEA.exe, MEA.py or MEA) and the databases (MEA.dat, Huffman.dat & FileTable.dat). An already built/frozen/compiled binary is provided by me for Windows only (icon designed by [Those Icons](https://thoseicons.com/) under CC BY 3.0 license). Thus, **you don't need to manually build/freeze/compile ME Analyzer under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/MEAnalyzer/releases) tab, title should start with "ME Analyzer v1.X.X". You may need to scroll down a bit if there are DB releases at the top. The latter can be used to update the outdated DB which was bundled with the latest executable release, title should start with "DB rXX". To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression.

#### **C1. Compatibility**

ME Analyzer should work at all Windows, Linux or macOS operating systems which have Python >= 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **C2. Code Prerequisites**

To run ME Analyzer's python script, you need to have the following 3rd party Python modules installed:

* [Colorama](https://pypi.org/project/colorama/)

> pip3 install colorama

* [CRCCheck](https://pypi.org/project/crccheck/)

> pip3 install crccheck

* [PLTable](https://github.com/platomav/PLTable/)

> pip3 install pltable

#### **C3. Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile ME Analyzer at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Use pip to install colorama:

> pip3 install colorama

4. Use pip to install crccheck:

> pip3 install crccheck

5. Use pip to install PLTable:

> pip3 install pltable

6. Build/Freeze/Compile ME Analyzer:

> pyinstaller --noupx --onefile MEA.py

At dist folder you should find the final MEA executable

#### **C4. Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled MEA executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the MEA executable to the exclusions, build/freeze/compile MEA yourself or use the Python script directly.

## **D. Pictures**

**Note:** Some pictures may be outdated and depict older ME Analyzer versions.

![](https://i.imgur.com/PoUD96g.png)

![](https://i.imgur.com/Sns8rtN.png)

![](https://i.imgur.com/xqvD43s.png)

![](https://i.imgur.com/S2I8uRD.png)

![](https://i.imgur.com/aXKKq8j.png)

![](https://i.imgur.com/xY2aWeX.png)

![](https://i.imgur.com/7oLhnMQ.png)

![](https://i.imgur.com/wkcx30U.png)

![](https://i.imgur.com/9d8vAnF.png)

![](https://i.imgur.com/n9u2mnc.png)

![](https://i.imgur.com/an23XZv.png)

![](https://i.imgur.com/fhp16ve.png)

![](https://i.imgur.com/0MD8888.png)

![](https://i.imgur.com/OvIodbo.png)

![](https://i.imgur.com/0DpROxw.png)

![](https://i.imgur.com/DJJPWPX.png)

![](https://i.imgur.com/23PLB1W.png)

![](https://i.imgur.com/TkLvx7O.png)

![](https://i.imgur.com/lmvcleJ.png)

![](https://i.imgur.com/ZYprlQE.png)

![](https://i.imgur.com/d5nzMSE.png)

![](https://i.imgur.com/UlMy3u6.png)

###### _Donate Button Card Image: [Credit and Loan Pack](https://flaticon.com/free-icon/credit-card_3898076) by **Freepik** under Flaticon license_
###### _Donate Button Paypal Image: [Credit Cards Pack](https://flaticon.com/free-icon/paypal_349278) by **Freepik** under Flaticon license_