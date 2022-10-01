# ME Analyzer
**Intel Engine & Graphics Firmware Analysis Tool**

[ME Analyzer News Feed](https://twitter.com/platomaniac)

[ME Analyzer Discussion Topic](https://winraid.level1techs.com/t/me-analyzer-intel-engine-firmware-analysis-tool-discussion/30876)

[Intel Engine/Graphics/Independent Firmware Introduction](https://winraid.level1techs.com/t/intel-converged-security-management-engine-drivers-firmware-and-tools/30719)

[Intel Engine/Graphics/Independent Firmware Repositories](https://winraid.level1techs.com/t/intel-cs-me-cs-txe-cs-sps-gsc-pmc-pchc-phy-orom-firmware-repositories/30869)

![](https://i.imgur.com/PoUD96g.png)

## **A. About ME Analyzer**

ME Analyzer is a tool which parses Intel Engine, Intel Graphics and their Independent firmware from the following families:

- (Converged Security) Management Engine - CS(ME)
    - ME 2-10
    - CSME 11-16.1
- (Converged Security) Trusted Execution Engine - (CS)TXE
    - TXE 0-2
    - CSTXE 3-4
- (Converged Security) Server Platform Services - (CS)SPS
    - SPS 1-3
    - CSSPS 4-6 (BA, HA, ME, PU, TA)
- Graphics System Controller - GSC
    - GSC 100-101
- Power Management Controller - PMC
    - PMC BXT-ADP
- Platform Controller Hub Configuration - PCHC
    - PCHC ICP-ADP
- USB Type C Physical - PHY
    - PHY ICP-ADP
- Graphics Option ROM - OROM
    - OROM 19-20

It can be used by end-users who are looking for all relevant firmware information such as Family, Version, Release, Type, Date, SKU, Platform, Size, Health Status etc. ME Analyzer is also a powerful Engine / Graphics / Independent firmware research analysis tool with multiple structures which allow, among others, full parsing and unpacking of Converged Security Engine (CSE) & Graphics System Controller (GSC) Code and File Systems such as:

- Flash Partition Table - FPT
- Boot Partition Descriptor Table - BPDT/IFWI
- CSE Layout Table - LT
- CSE File Table - FTBL/EFST
- CSE Virtual File System - VFS
- GSC OROM-PCIR - VBT/EFI

Moreover, with the help of its extensive databases, ME Analyzer is capable of uniquely identifying and categorizing all supported Engine / Graphics / Independent firmware as well as check for any firmware which have not been stored at the equivalent, community supported, Firmware Repositories yet.

#### **A1. ME Analyzer Features**

- Supports Engine firmware Families ME 2-16.1, TXE 0-4 and SPS 1-6
- Supports Graphics firmware Families GSC DG1 (100) and DG2 (101)
- Supports CSE/GSC Independent (IUP) firmware Families PMC, PCHC, PHY and OROM
- Detection of Firmware Details (Family, Version, SKU, Date, Platform etc)
- Detection of Firmware Release (Production, Pre-Production, ROM-Bypass etc)
- Detection of Firmware Type (Region, Extracted, Update etc)
- Detection of Firmware Security/Update Version Numbers (SVN, VCN etc)
- Detection of Power Management Controller (PMC) Independent firmware info
- Detection of PCH Configuration (PCHC) Independent firmware info
- Detection of USB Type C Physical (PHY) Independent firmware info
- Detection of Graphics Option ROM (OROM) Independent firmware info
- Ability to fully unpack all supported CSE, GSC and/or IUP firmware
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

ME Analyzer allows end-users and/or researchers to quickly analyze and/or report new firmware versions without the use of special Intel tools (FIT/FITC, FWUpdate) or Hex Editors. To do that effectively, a database had to be built. The [Intel Engine/Graphics/Independent Firmware Repositories](https://winraid.level1techs.com/t/intel-cs-me-cs-txe-cs-sps-gsc-pmc-pchc-phy-orom-firmware-repositories/30869) is a collection of every (CS)ME, (CS)TXE, (CS)SPS, GSC, PMC, PCHC, PHY & OROM firmware we have found. Its existence is very important for ME Analyzer as it allows us to continue doing research, find new types of firmware, compare same major version releases for similarities etc. Bundled with ME Analyzer is a file called MEA.dat which is required for the program to run. It includes entries for all Engine / Graphics / Independent firmware that are available to us. This accommodates primarily two actions: a) Detect each firmware's Family via unique identifier keys and b) Help find new Engine firmware sooner by reporting them at the [Intel (Converged Security) Management Engine: Drivers, Firmware and Tools](https://winraid.level1techs.com/t/intel-converged-security-management-engine-drivers-firmware-and-tools/30719) or [Intel (Converged Security) Trusted Execution Engine: Drivers, Firmware and Tools](https://winraid.level1techs.com/t/intel-converged-security-trusted-execution-engine-drivers-firmware-and-tools/30730) threads respectively.

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
* -duc   : Disables automatic check for MEA & DB updates
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

* [colorama](https://pypi.org/project/colorama/)

> pip3 install colorama

* [crccheck](https://pypi.org/project/crccheck/)

> pip3 install crccheck

* [PLTable](https://pypi.org/project/PLTable/)

> pip3 install PLTable

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

> pip3 install PLTable

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
