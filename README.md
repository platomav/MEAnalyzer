# ME Analyzer
**Intel Engine & Graphics Firmware Analysis Tool**

[ME Analyzer News Feed](https://twitter.com/platomaniac)

[ME Analyzer Discussion Topic](https://winraid.level1techs.com/t/me-analyzer-intel-engine-firmware-analysis-tool-discussion/30876)

[Intel Engine/Graphics/Independent Firmware Introduction](https://winraid.level1techs.com/t/intel-converged-security-management-engine-drivers-firmware-and-tools/30719)

[Intel Engine/Graphics/Independent Firmware Repositories](https://winraid.level1techs.com/t/intel-cs-me-cs-txe-cs-sps-gsc-pmc-pchc-phy-orom-firmware-repositories/30869)

![](https://i.imgur.com/0HRnDAh.png)

## **A. About ME Analyzer**

ME Analyzer is a tool which parses Intel Engine, Intel Graphics and their Independent firmware from the following families:

- (Converged Security) Management Engine - CS(ME)
    - ME 2-10
    - CSME 11-15
- (Converged Security) Trusted Execution Engine - (CS)TXE
    - TXE 0-2
    - CSTXE 3-4
- (Converged Security) Server Platform Services - (CS)SPS
    - SPS 1-3
    - CSSPS 4-5 (BA, HA, ME, PU)
- Graphics System Controller - GSC
    - GSC 100 (DG1)
- Power Management Controller - PMC
    - PMC APL-MCC
- Platform Controller Hub Configuration - PCHC
    - PCHC ICP-MCC
- USB Type C Physical - PHY
    - PHY ICP-TGP
- Graphics Option ROM - OROM
    - OROM DG1

It can be used by end-users who are looking for all relevant firmware information such as Family, Version, Release, Type, Date, SKU, Platform, Size, Health Status etc. ME Analyzer is also a powerful Engine / Graphics / Independent firmware research analysis tool with multiple structures which allow, among others, full parsing and unpacking of Converged Security Engine (CSE) & Graphics System Controller (GSC) Code and File Systems such as:

- Flash Partition Table - FPT
- Boot Partition Descriptor Table - BPDT/IFWI
- CSE Layout Table - LT
- CSE File Table - FTBL/EFST
- CSE Virtual File System - VFS
- GSC OROM-PCIR - VBT/EFI

Moreover, with the help of its extensive databases, ME Analyzer is capable of uniquely identifying and categorizing all supported Engine / Graphics / Independent firmware as well as check for any firmware which have not been stored at the equivalent, community supported, Firmware Repositories yet.

#### **A1. ME Analyzer Features**

- Supports Engine/Graphics firmware Families ME 2-15, TXE 0-4, SPS 1-5 and GSC 100
- Supports CSE/GSC Independent (IUP) firmware Families PMC, PCHC, PHY and OROM/VBT
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

ME Analyzer allows end-users and/or researchers to quickly analyze and/or report new firmware versions without the use of special Intel tools (FIT/FITC, FWUpdate) or Hex Editors. To do that effectively, a database had to be built. The [Intel Engine/Graphics/Independent Firmware Repositories](https://winraid.level1techs.com/t/intel-cs-me-cs-txe-cs-sps-gsc-pmc-pchc-phy-orom-firmware-repositories/30869) is a collection of every (CS)ME, (CS)TXE, (CS)SPS, GSC, PMC, PCHC, PHY & OROM firmware we have found. Its existence is very important for ME Analyzer as it allows us to continue doing research, find new types of firmware, compare same major version releases for similarities etc. Bundled with ME Analyzer is a file called MEA.dat which is required for the program to run. It includes entries for all Engine / Graphics / Independent firmware that are available to us. This accommodates primarily two actions: a) Detect each firmware's Family via unique identifier keys and b) Help find new Engine firmware sooner by reporting them at the [Intel Engine/Graphics/Independent Firmware Repositories](https://winraid.level1techs.com/t/intel-cs-me-cs-txe-cs-sps-gsc-pmc-pchc-phy-orom-firmware-repositories/30869) thread.

#### **A3. Supported Engine Firmware Families/Versions**

|   **(CS)ME**   | **(CS)TXE** |   **(CS)SPS**  | **GSC** | **PMC** | **PCHC** | **PHY** | **OROM** |
|:--------------:|:-----------:|:--------------:|:-------:|:-------:|:--------:|:-------:|:--------:|
|        2       |      0      |        1       |   100   |   APL   |    ICP   |   ICP   |    DG1   |
|        3       |      1      |        2       |    -    |   BXT   |    LKF   |   LKF   |     -    |
|        4       |      2      |        3       |    -    |   GLK   |    JSP   |   CMP   |     -    |
|        5       |      3      | 4 (BA, HA, PU) |    -    |   CNP   |    CMP   |   TGP   |     -    |
|        6       |      4      |     5 (ME)     |    -    |   ICP   |    TGP   |   DG1   |     -    |
|        7       |      -      |        -       |    -    |   LKF   |    MCC   |    -    |     -    |
|        8       |      -      |        -       |    -    |   JSP   |     -    |    -    |     -    |
|        9       |      -      |        -       |    -    |   CMP   |     -    |    -    |     -    |
|       10       |      -      |        -       |    -    |   TGP   |     -    |    -    |     -    |
|       11       |      -      |        -       |    -    |   MCC   |     -    |    -    |     -    |
|       12       |      -      |        -       |    -    |   DG1   |     -    |    -    |     -    |
| 13 (0, 30, 50) |      -      |        -       |    -    |    -    |     -    |    -    |     -    |
|  14 (0, 1, 5)  |      -      |        -       |    -    |    -    |     -    |    -    |     -    |
|   15 (0, 40)   |      -      |        -       |    -    |    -    |     -    |    -    |     -    |

**Any Intel Engine/Graphics/Independent family and/or version which is not listed above, is not supported. There are no plans to add support for other Intel Engine/Graphics/Independent firmware at this point.**

## **B. How to use ME Analyzer**

There are two ways to use ME Analyzer, MEA script & command prompt. The MEA script allows you to input or drag & drop one or more firmware and analyze them one by one or recursively scan entire directories. To manually use ME Analyzer, a command prompt can be used with -skip as parameter.

#### **B1. ME Analyzer Script**

To use ME Analyzer, select one or multiple files and input or Drag & Drop them to its script. You can also input certain optional parameters either by running MEA directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter to recursively scan entire directories, as explained below.

#### **B2. ME Analyzer Parameters**

There are various parameters which enhance or modify the default behavior of ME Analyzer:

* -?     : Displays help & usage screen
* -skip  : Skips welcome & options screen
* -exit  : Skips Press enter to exit prompt
* -mass  : Scans all files of a given directory
* -pdb   : Writes unique input file DB name to file
* -dbn   : Renames input file based on unique DB name
* -duc   : Disables automatic check for MEA & DB updates
* -dcm   : Disables automatic input file copy on messages
* -out   : Defines output directory for all MEA operations
* -dfpt  : Shows FPT, BPDT, OROM & CSE/GSC Layout Table info
* -unp86 : Unpacks all supported CSE, GSC and/or IUP firmware
* -bug86 : Enables pause on error during CSE/GSC/IUP unpacking
* -ver86 : Enables verbose output during CSE/GSC/IUP unpacking
* -html  : Writes parsable HTML info files during MEA operation
* -json  : Writes parsable JSON info files during MEA operation

#### **B3. ME Analyzer Flow Control**

During operation, ME Analyzer may encounter issues that can trigger Notes, Warnings and/or Errors. Notes (yellow/green color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected or problematic is encountered.

## **C. Download ME Analyzer**

ME Analyzer consists of four files: the script (MEA.py) and its databases (MEA.dat, Huffman.dat & FileTable.dat). Download the latest version from the [Releases](https://github.com/platomav/MEAnalyzer/releases) tab, title should start with "ME Analyzer vX.Y.Z". You may need to scroll down a bit if there are DB releases at the top. The latter can be used to update the outdated DB which was bundled with the latest "ME Analyzer vX.Y.Z" release, title should start with "DB rXY".

#### **C1. Compatibility**

ME Analyzer should work at all Windows, Linux or macOS operating systems which have [Python >= 3.7](https://www.python.org/downloads/) support.

#### **C2. Prerequisites**

To run ME Analyzer, you need to install [Python >= 3.7](https://www.python.org/downloads/), followed by these 3rd party Python modules:

* [colorama](https://pypi.org/project/colorama/)
* [crccheck](https://pypi.org/project/crccheck/)
* [pltable](https://pypi.org/project/PLTable/)

> pip3 install colorama crccheck pltable

## **D. Pictures**

**Note:** Some pictures may be outdated and depict older ME Analyzer versions/features.

![](https://i.imgur.com/0HRnDAh.png)

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

![](https://i.imgur.com/UlMy3u6.png)
