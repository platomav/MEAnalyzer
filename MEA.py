#!/usr/bin/env python3

"""
ME Analyzer
Intel Engine Firmware Analysis Tool
Copyright (C) 2014-2018 Plato Mavropoulos
"""

title = 'ME Analyzer v1.61.1'

import os
import re
import sys
import lzma
import zlib
import json
import struct
import ctypes
import shutil
import hashlib
import inspect
import binascii
import colorama
import textwrap
import itertools
import traceback
import prettytable

# Initialize and setup Colorama
colorama.init()
col_r = colorama.Fore.RED + colorama.Style.BRIGHT
col_c = colorama.Fore.CYAN + colorama.Style.BRIGHT
col_b = colorama.Fore.BLUE + colorama.Style.BRIGHT
col_g = colorama.Fore.GREEN + colorama.Style.BRIGHT
col_y = colorama.Fore.YELLOW + colorama.Style.BRIGHT
col_m = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
col_e = colorama.Fore.RESET + colorama.Style.RESET_ALL

# Detect OS platform
mea_os = sys.platform
if mea_os == 'win32' :
	cl_wipe = 'cls'
elif mea_os.startswith('linux') or mea_os == 'darwin' :
	cl_wipe = 'clear'
else :
	print(col_r + '\nError: ' + col_e + 'Unsupported platform "%s"\n' % mea_os)
	if ' -exit' not in sys.argv : input('Press enter to exit')
	colorama.deinit()
	sys.exit(-1)

# Detect Python version
mea_py = sys.version_info
try :
	assert mea_py >= (3,6)
except :
	print(col_r + '\nError: ' + col_e + 'Python >= 3.6 required, not %d.%d!\n' % (mea_py[0],mea_py[1]))
	if ' -exit' not in sys.argv : input('Press enter to exit')
	colorama.deinit()
	sys.exit(-1)
	
# Set ctypes Structure types
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

# Print MEA Help screen
def mea_help() :
	
	text = "\nUsage: MEA [FilePath] {Options}\n\n{Options}\n\n"
	text += "-?      : Displays help & usage screen\n"
	text += "-skip   : Skips welcome & options screen\n"
	text += "-exit   : Skips Press enter to exit prompt\n"
	text += "-redir  : Enables console redirection support\n"
	text += "-mass   : Scans all files of a given directory\n"
	text += "-pdb    : Writes input file DB entry to text file\n"
	text += "-dbname : Renames input file based on unique DB name\n"
	text += "-dfpt   : Shows $FPT, BPDT and/or CSE Layout Table headers\n"
	text += "-unp86  : Unpacks all CSE Converged Security Engine firmware\n"
	text += "-bug86  : Enables debug/verbose mode during CSE unpacking\n"
	text += "-ext86  : Prints all Extension info during CSE unpacking"
	
	print(text)
	mea_exit(0)

# Process MEA Parameters
class MEA_Param :

	def __init__(self, source) :
	
		self.all = ['-?','-skip','-extr','-msg','-hid','-unp86','-ext86','-bug86','-pdb','-dbname','-mass','-dfpt','-exit','-redir']
		self.win = ['-extr','-msg','-hid'] # Windows only
		
		if mea_os == 'win32' : self.val = self.all
		else : self.val = [item for item in self.all if item not in self.win]
		
		self.help_scr = False
		self.skip_intro = False
		self.extr_mea = False
		self.print_msg = False
		self.hid_find = False
		self.me11_mod_extr = False
		self.me11_mod_ext = False
		self.me11_mod_bug = False
		self.fpt_disp = False
		self.db_print_new = False
		self.give_db_name = False
		self.mass_scan = False
		self.skip_pause = False
		self.cli_redirect = False
		
		for i in source :
			if i == '-?' : self.help_scr = True
			if i == '-skip' : self.skip_intro = True
			if i == '-unp86' : self.me11_mod_extr = True
			if i == '-ext86' : self.me11_mod_ext = True
			if i == '-bug86' : self.me11_mod_bug = True
			if i == '-pdb' : self.db_print_new = True
			if i == '-dbname' : self.give_db_name = True
			if i == '-mass' : self.mass_scan = True
			if i == '-dfpt' : self.fpt_disp = True
			if i == '-exit' : self.skip_pause = True
			if i == '-redir' : self.cli_redirect = True
			
			# Windows only options
			if mea_os == 'win32' :
				if i == '-extr' : self.extr_mea = True # Hidden
				if i == '-msg' : self.print_msg = True # Hidden
				if i == '-hid' : self.hid_find = True # Hidden
			
		if self.extr_mea or self.print_msg or self.mass_scan or self.db_print_new or self.cli_redirect : self.skip_intro = True
		if self.extr_mea or self.print_msg : self.cli_redirect = True
		if self.cli_redirect : self.skip_pause = True
		
# Engine Structures
class FPT_Pre_Header(ctypes.LittleEndianStructure) : # (ROM_BYPASS)
	_pack_ = 1
	_fields_ = [
		('ROMB_Instr_0',	uint32_t),		# 0x00
		('ROMB_Instr_1',	uint32_t),		# 0x04
		('ROMB_Instr_2',	uint32_t),		# 0x08
		('ROMB_Instr_3',	uint32_t),		# 0x0C
		# 0x10
	]
	
	def hdr_print_cse(self) :
		NA = [0,0xFFFFFFFF] # Non-ROMB or IFWI EXTR
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table ROM-Bypass' + col_e
		pt.add_row(['Instruction 0', 'N/A' if self.ROMB_Instr_0 in NA else '0x%X' % self.ROMB_Instr_0])
		pt.add_row(['Instruction 1', 'N/A' if self.ROMB_Instr_1 in NA else '0x%X' % self.ROMB_Instr_1])
		pt.add_row(['Instruction 2', 'N/A' if self.ROMB_Instr_2 in NA else '0x%X' % self.ROMB_Instr_2])
		pt.add_row(['Instruction 3', 'N/A' if self.ROMB_Instr_3 in NA else '0x%X' % self.ROMB_Instr_3])
		
		return pt

# noinspection PyTypeChecker
class FPT_Header(ctypes.LittleEndianStructure) : # Flash Partition Table (FPT_HEADER)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('NumPartitions',	uint32_t),		# 0x04
		('HeaderVersion',	uint8_t),		# 0x08
		('EntryVersion',	uint8_t),		# 0x09
		('HeaderLength',	uint8_t),		# 0x0A
		('HeaderChecksum',	uint8_t),		# 0x0B
		('FlashCycleLife',	uint16_t),		# 0x0C TicksToAdd at CSE
		('FlashCycleLimit',	uint16_t),		# 0x0E TokensToAdd at CSE
		('UMASize',			uint32_t),		# 0x10 Reserved at CSE
		('Flags',			uint32_t),		# 0x14 FlashLayout at CSE (FLASH_LAYOUT_TYPES)
		('FitMajor',		uint16_t),		# 0x18
		('FitMinor',		uint16_t),		# 0x1A
		('FitHotfix',		uint16_t),		# 0x1C
		('FitBuild',		uint16_t),		# 0x1E
		# 0x20
	]
	
	def hdr_print_cse(self) :
		NA = 0xFFFFFFFF # IFWI EXTR
		sector_types = {0:'4K', 2:'8K', 4:'64K', 8:'64K-8K Mixed'}
		
		fit_ver = '%d.%d.%d.%d' % (self.FitMajor,self.FitMinor,self.FitHotfix,self.FitBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table 2.0 Header' + col_e
		pt.add_row(['Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Partition Count', '%d' % self.NumPartitions])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['Entry Version', '0x%X' % self.EntryVersion])
		pt.add_row(['Header Size', '0x%X' % self.HeaderLength])
		pt.add_row(['Header Checksum', '0x%X' % self.HeaderChecksum])
		pt.add_row(['Ticks To Add', '0x%X' % self.FlashCycleLife])
		pt.add_row(['Tokens To Add', '0x%X' % self.FlashCycleLimit])
		pt.add_row(['Reserved', 'N/A' if self.UMASize == NA else '0x%X' % self.UMASize])
		pt.add_row(['Flash Layout', 'N/A' if self.Flags == NA else '%s' % sector_types[self.Flags]])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		
		return pt
		
# noinspection PyTypeChecker
class FPT_Header_21(ctypes.LittleEndianStructure) : # Flash Partition Table (FPT_HEADER)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('NumPartitions',	uint32_t),		# 0x04
		('HeaderVersion',	uint8_t),		# 0x08 21
		('EntryVersion',	uint8_t),		# 0x09
		('HeaderLength',	uint8_t),		# 0x0A
		('Flags',			uint8_t),		# 0x0B 0 FPT Backup Present, 1-7 Reserved
		('TicksToAdd',		uint16_t),		# 0x0C
		('TokensToAdd',		uint16_t),		# 0x0E
		('SPSFlags',		uint32_t),		# 0x10 (Unknown/Unused)
		('HeaderChecksum',	uint32_t),		# 0x14 CRC-32
		('FitMajor',		uint16_t),		# 0x18
		('FitMinor',		uint16_t),		# 0x1A
		('FitHotfix',		uint16_t),		# 0x1C
		('FitBuild',		uint16_t),		# 0x1E
		# 0x20
	]
	
	# Used at Lake Field (LKF) IFWI 1.7 platform
	
	def hdr_print(self) :
		f1,f2 = self.get_flags()
		
		fit_ver = '%d.%d.%d.%d' % (self.FitMajor,self.FitMinor,self.FitHotfix,self.FitBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table 2.1 Header' + col_e
		pt.add_row(['Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Partition Count', '%d' % self.NumPartitions])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['Entry Version', '0x%X' % self.EntryVersion])
		pt.add_row(['Header Size', '0x%X' % self.HeaderLength])
		pt.add_row(['Header Backup', ['No','Yes'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Ticks To Add', '0x%X' % self.TicksToAdd])
		pt.add_row(['Tokens To Add', '0x%X' % self.TokensToAdd])
		pt.add_row(['SPS Flags', '0x%X' % self.SPSFlags])
		pt.add_row(['Header Checksum', '0x%X' % self.HeaderChecksum])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		
		return pt
		
	def get_flags(self) :
		flags = FPT_Header_21_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.FPTB, flags.b.Reserved

class FPT_Header_21_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('FPTB', uint8_t, 1),
		('Reserved', uint8_t, 7),
	]

class FPT_Header_21_GetFlags(ctypes.Union):
	_fields_ = [
		('b', FPT_Header_21_Flags),
		('asbytes', uint8_t)
	]

# noinspection PyTypeChecker
class FPT_Entry(ctypes.LittleEndianStructure) : # (FPT_ENTRY)
	_pack_ = 1
	_fields_ = [
		('Name',			char*4),		# 0x00
		('Owner',			char*4),		# 0x04 Reserved at CSE
		('Offset',			uint32_t),		# 0x08
		('Size',			uint32_t),		# 0x0C
		('StartTokens',		uint32_t),		# 0x10 Reserved at CSE
		('MaxTokens',		uint32_t),		# 0x14 Reserved at CSE
		('ScratchSectors',	uint32_t),		# 0x18 Reserved at CSE
		('Flags',			uint32_t),		# 0x1C (FPT_ENTRY_ATTRIBUTES)
		# 0x20
	]
	
	def hdr_print_cse(self) :
		f1,f2,f3,f4,f5,f6 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table Entry' + col_e
		pt.add_row(['Name', '%s' % self.Name.decode('utf-8')])
		pt.add_row(['Reserved 0', '0x%X' % int.from_bytes(self.Owner, 'little')])
		pt.add_row(['Offset', '0x%X' % self.Offset])
		pt.add_row(['Reserved 1', '0x%X' % self.StartTokens])
		pt.add_row(['Reserved 2', '0x%X' % self.MaxTokens])
		pt.add_row(['Reserved 3', '0x%X' % self.ScratchSectors])
		pt.add_row(['Type', ['Code','Data'][f1]])
		pt.add_row(['Reserved 4', '0x%X' % f2])
		pt.add_row(['BWL 0', '0x%X' % f3])
		pt.add_row(['BWL 1', '0x%X' % f4])
		pt.add_row(['Reserved 5', '0x%X' % f5])
		pt.add_row(['Entry Valid', 'No' if f6 == 0xFF else 'Yes'])
		
		return pt
	
	def get_flags(self) :
		flags = FPT_Entry_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.Type, flags.b.Reserved0, flags.b.BWL0, flags.b.BWL1, flags.b.Reserved1, flags.b.EntryValid

class FPT_Entry_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('Type', uint32_t, 7), # (PARTITION_TYPES)
		('Reserved0', uint32_t, 8),
		('BWL0', uint32_t, 1),
		('BWL1', uint32_t, 1),
		('Reserved1', uint32_t, 7),
		('EntryValid', uint32_t, 8)
	]

class FPT_Entry_GetFlags(ctypes.Union):
	_fields_ = [
		('b', FPT_Entry_Flags),
		('asbytes', uint32_t)
	]

class CSE_Layout_Table_16(ctypes.LittleEndianStructure) : # IFWI 1.6 (CseLayoutTable, IfwiRegionData)
	_pack_ = 1
	_fields_ = [
		('ROMBInstr0',		uint32_t),		# 0x00 ROM-Bypass Vector 0
		('ROMBInstr1',		uint32_t),		# 0x04
		('ROMBInstr2',		uint32_t),		# 0x08
		('ROMBInstr3',		uint32_t),		# 0x0C
		('DataOffset',		uint32_t),		# 0x10 Data Partition Base Address
		('DataSize',		uint32_t),		# 0x14 Data Partition Size
		('BP1Offset',		uint32_t),		# 0x18 Boot Partition 1 Base Address
		('BP1Size',			uint32_t),		# 0x1C Boot Partition 1 Size
		('BP2Offset',		uint32_t),		# 0x20
		('BP2Size',			uint32_t),		# 0x24
		('BP3Offset',		uint32_t),		# 0x28
		('BP3Size',			uint32_t),		# 0x2C
		('BP4Offset',		uint32_t),		# 0x30 Reserved
		('BP4Size',			uint32_t),		# 0x34
		('BP5Offset',		uint32_t),		# 0x38 Reserved
		('BP5Size',			uint32_t),		# 0x3C
		('Checksum',		uint64_t),		# 0x40 2's complement Checksum-8 of CSE Layout Table (w/o ROMB ???), sum of the CSE LT + Checksum = 0
		# 0x48
	]
	
	# Used at Cannon Point (CNP) IFWI 1.6 platform
	# Checksum is not used yet (always 0x22), CSE_Layout_Table_16 seems static
	
	def hdr_print(self) :
		NA = [0,0xFFFFFFFF] # Non-ROMB or IFWI EXTR
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'CSE Layout Table 1.6' + col_e
		pt.add_row(['ROMB Instruction 0', 'N/A' if self.ROMBInstr0 in NA else '0x%X' % self.ROMBInstr0])
		pt.add_row(['ROMB Instruction 1', 'N/A' if self.ROMBInstr1 in NA else '0x%X' % self.ROMBInstr1])
		pt.add_row(['ROMB Instruction 2', 'N/A' if self.ROMBInstr2 in NA else '0x%X' % self.ROMBInstr2])
		pt.add_row(['ROMB Instruction 3', 'N/A' if self.ROMBInstr3 in NA else '0x%X' % self.ROMBInstr3])
		pt.add_row(['Data Partition Offset', '0x%X' % self.DataOffset])
		pt.add_row(['Data Partition Size', '0x%X' % self.DataSize])
		pt.add_row(['Boot Partition 1 Offset', '0x%X' % self.BP1Offset])
		pt.add_row(['Boot Partition 1 Size', '0x%X' % self.BP1Size])
		pt.add_row(['Boot Partition 2 Offset', '0x%X' % self.BP2Offset])
		pt.add_row(['Boot Partition 2 Size', '0x%X' % self.BP2Size])
		pt.add_row(['Boot Partition 3 Offset', '0x%X' % self.BP3Offset])
		pt.add_row(['Boot Partition 3 Size', '0x%X' % self.BP3Size])
		pt.add_row(['Boot Partition 4 Offset', '0x%X' % self.BP4Offset])
		pt.add_row(['Boot Partition 4 Size', '0x%X' % self.BP4Size])
		pt.add_row(['Boot Partition 5 Offset', '0x%X' % self.BP5Offset])
		pt.add_row(['Boot Partition 5 Size', '0x%X' % self.BP5Size])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		
		return pt

class CSE_Layout_Table_17(ctypes.LittleEndianStructure) : # IFWI 1.7 (CseLayoutTable, IfwiRegionData)
	_pack_ = 1
	_fields_ = [
		('ROMBInstr0',		uint32_t),		# 0x00 ROM-Bypass Vector 0
		('ROMBInstr1',		uint32_t),		# 0x04
		('ROMBInstr2',		uint32_t),		# 0x08
		('ROMBInstr3',		uint32_t),		# 0x0C
		('Size',			uint16_t),		# 0x10
		('Flags',			uint8_t),		# 0x12 0 CSE Pointer Redundancy, 1-7 Reserved
		('Reserved',		uint8_t),		# 0x13
		('Checksum',		uint32_t),		# 0x14 CRC-32 of CSE LT pointers w/o ROMB (DataOffset - TempPagesSize)
		('DataOffset',		uint32_t),		# 0x18 Data Partition Base Address
		('DataSize',		uint32_t),		# 0x1C Data Partition Size
		('BP1Offset',		uint32_t),		# 0x20 Boot Partition 1 Base Address
		('BP1Size',			uint32_t),		# 0x24 Boot Partition 1 Size
		('BP2Offset',		uint32_t),		# 0x28
		('BP2Size',			uint32_t),		# 0x2C
		('BP3Offset',		uint32_t),		# 0x30
		('BP3Size',			uint32_t),		# 0x34
		('BP4Offset',		uint32_t),		# 0x38
		('BP4Size',			uint32_t),		# 0x3C
		('BP5Offset',		uint32_t),		# 0x40
		('BP5Size',			uint32_t),		# 0x44
		('TempPagesOffset',	uint32_t),		# 0x48 Temporary Pages for DRAM cache, 0 for NVM
		('TempPagesSize',	uint32_t),		# 0x4C
		# 0x50
	]
	
	# Used at Lake Field (LKF) IFWI 1.7 platform
	# When CSE Pointer Redundancy is set, the entire structure is duplicated
	
	def hdr_print(self) :
		f1,f2 = self.get_flags()
		NA = [0,0xFFFFFFFF] # Non-ROMB or IFWI EXTR
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'CSE Layout Table 1.7' + col_e
		pt.add_row(['ROMB Instruction 0', 'N/A' if self.ROMBInstr0 in NA else '0x%X' % self.ROMBInstr0])
		pt.add_row(['ROMB Instruction 1', 'N/A' if self.ROMBInstr1 in NA else '0x%X' % self.ROMBInstr1])
		pt.add_row(['ROMB Instruction 2', 'N/A' if self.ROMBInstr2 in NA else '0x%X' % self.ROMBInstr2])
		pt.add_row(['ROMB Instruction 3', 'N/A' if self.ROMBInstr3 in NA else '0x%X' % self.ROMBInstr3])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['CSE Pointer Redundancy', ['No','Yes'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		pt.add_row(['Data Partition Offset', '0x%X' % self.DataOffset])
		pt.add_row(['Data Partition Size', '0x%X' % self.DataSize])
		pt.add_row(['Boot Partition 1 Offset', '0x%X' % self.BP1Offset])
		pt.add_row(['Boot Partition 1 Size', '0x%X' % self.BP1Size])
		pt.add_row(['Boot Partition 2 Offset', '0x%X' % self.BP2Offset])
		pt.add_row(['Boot Partition 2 Size', '0x%X' % self.BP2Size])
		pt.add_row(['Boot Partition 3 Offset', '0x%X' % self.BP3Offset])
		pt.add_row(['Boot Partition 3 Size', '0x%X' % self.BP3Size])
		pt.add_row(['Boot Partition 4 Offset', '0x%X' % self.BP4Offset])
		pt.add_row(['Boot Partition 4 Size', '0x%X' % self.BP4Size])
		pt.add_row(['Boot Partition 5 Offset', '0x%X' % self.BP5Offset])
		pt.add_row(['Boot Partition 5 Size', '0x%X' % self.BP5Size])
		pt.add_row(['Temporary Pages Offset', '0x%X' % self.TempPagesOffset])
		pt.add_row(['Temporary Pages Size', '0x%X' % self.TempPagesSize])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Layout_Table_17_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.CSE_P_R, flags.b.Reserved
		
class CSE_Layout_Table_17_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('CSE_P_R', uint8_t, 1),
		('Reserved', uint8_t, 7),
	]

class CSE_Layout_Table_17_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Layout_Table_17_Flags),
		('asbytes', uint8_t)
	]

# noinspection PyTypeChecker
class MN2_Manifest(ctypes.LittleEndianStructure) : # Manifest $MAN/$MN2 (MANIFEST_HEADER)
	_pack_ = 1
	_fields_ = [
		("HeaderType",		uint32_t),		# 0x00
		("HeaderLength",	uint32_t),		# 0x04 dwords
		("HeaderVersion",	uint32_t),		# 0x08
		("Flags",			uint32_t),		# 0x0C
		("VEN_ID",			uint32_t),		# 0x10 0x8086
		("Day",				uint8_t),		# 0x14
		("Month",			uint8_t),		# 0x15
		("Year",			uint16_t),		# 0x16
		("Size",			uint32_t),		# 0x18 dwords (0x2000 max)
		("Tag",				char*4),		# 0x1C
		("NumModules",		uint32_t),		# 0x20 Unknown at CSE (some FTPR > Kernel value)
		("Major",			uint16_t),		# 0x24
		("Minor",			uint16_t),		# 0x26
		("Hotfix",			uint16_t),		# 0x28
		("Build",			uint16_t),		# 0x2A
		("SVN",				uint32_t),		# 0x2C ME9+ (LSByte derives keys)
		("SVN_8",			uint32_t),		# 0x30 ME8, Reserved at CSE
		("VCN",				uint32_t),		# 0x34 ME8-10, Reserved at CSE
		("Reserved",		uint32_t*16),	# 0x38
		("ModulusSize",		uint32_t),		# 0x78 dwords (PKCS #1 v1.5)
		("ExponentSize",	uint32_t),		# 0x7C dwords (PKCS #1 v1.5)
		("RSAPublicKey",	uint32_t*64),	# 0x80
		("RSAExponent",		uint32_t),		# 0x180
		("RSASignature",	uint32_t*64),	# 0x184 2048-bit (PKCS #1 v1.5)
		# 0x284
	]
	
	def hdr_print_cse(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4 = self.get_flags()
		
		version = '%d.%d.%d.%d' % (self.Major,self.Minor,self.Hotfix,self.Build)
		
		RSAPublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSAPublicKey))
		RSASignature = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSASignature))
		Reserved3 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Partition Manifest Header' + col_e
		pt.add_row(['Header Type', '%d' % self.HeaderType])
		pt.add_row(['Header Size', '0x%X' % (self.HeaderLength * 4)])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['PV Release', fvalue[f1]])
		pt.add_row(['Flags Reserved', '0x%X' % (f2 + f3)])
		pt.add_row(['Debug Signed', fvalue[f4]])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year,self.Month,self.Day)])
		pt.add_row(['Manifest Size', '0x%X' % (self.Size * 4)])
		pt.add_row(['Manifest Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Unknown', '0x%X' % self.NumModules])
		pt.add_row(['Version', 'N/A' if self.Major in [0,0xFFFF] else version])
		pt.add_row(['Security Version Number', '%d' % self.SVN])
		pt.add_row(['Reserved 0', '0x%X' % self.SVN_8])
		pt.add_row(['Reserved 1', '0x%X' % self.VCN])
		pt.add_row(['Reserved 2', '0x0' if Reserved3 == '00000000' * 16 else Reserved3])
		pt.add_row(['RSA Modulus Size', '0x%X' % (self.ModulusSize * 4)])
		pt.add_row(['RSA Exponent Size', '0x%X' % (self.ExponentSize * 4)])
		pt.add_row(['RSA Public Key', '%s [...]' % RSAPublicKey[:8]])
		pt.add_row(['RSA Exponent', '0x%X' % self.RSAExponent])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		return pt
	
	def get_flags(self) :
		flags = MN2_Manifest_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.PVBit, flags.b.Reserved, flags.b.PreProduction, flags.b.DebugSigned

class MN2_Manifest_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('PVBit', uint32_t, 1), # CSE
		('Reserved', uint32_t, 29),
		('PreProduction', uint32_t, 1), # Reserved at CSE
		('DebugSigned', uint32_t, 1)
	]
	
class MN2_Manifest_GetFlags(ctypes.Union):
	_fields_ = [
		('b', MN2_Manifest_Flags),
		('asbytes', uint32_t)
	]

# noinspection PyTypeChecker
class SKU_Attributes(ctypes.LittleEndianStructure) : # Pre-CSE $SKU
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('Size',			uint32_t),		# 0x04 dwords
		('FWSKUAttrib',		uint64_t),		# 0x08 (uint32_t for ME 2-6 & SPS 1-3)
		# 0x10 (0xC for ME 2-6 & SPS 1-3)
	]
	
	def hdr_print(self) :
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + '$SKU New' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Size', '0x%X' % (self.Size * 4)])
		pt.add_row(['Value 1', '0x%X' % f1])
		pt.add_row(['Value 2', f2])
		pt.add_row(['Value 3', f3])
		pt.add_row(['Value 4', f4])
		pt.add_row(['Value 5', f5])
		pt.add_row(['Value 6', f6])
		pt.add_row(['Value 7', f7])
		pt.add_row(['Value 8', f8])
		pt.add_row(['Value 9', f9])
		pt.add_row(['Patsburg', ['No','Yes'][f10]])
		pt.add_row(['SKU Type', ['Corporate','Consumer','Slim'][f11]])
		pt.add_row(['SKU Size', '%0.1f MB' % (f12 * 0.5)])
		pt.add_row(['Value 10', '0x%X' % f13])
		
		return pt
	
	def get_flags(self) :
		flags = SKU_Attributes_GetFlags()
		flags.asbytes = self.FWSKUAttrib
		
		return flags.b.Value1, flags.b.Value2, flags.b.Value3, flags.b.Value4, flags.b.Value5, flags.b.Value6, \
		flags.b.Value7, flags.b.Value8, flags.b.Value9, flags.b.Patsburg, flags.b.SKUType, flags.b.SKUSize, flags.b.Value10

class SKU_Attributes_Flags(ctypes.BigEndianStructure):
	_fields_ = [
		('Value1', uint64_t, 24),
		('Value2', uint64_t, 1), # Slim (ME 7)
		('Value3', uint64_t, 1),
		('Value4', uint64_t, 1),
		('Value5', uint64_t, 1),
		('Value6', uint64_t, 1),
		('Value7', uint64_t, 1),
		('Value8', uint64_t, 1),
		('Value9', uint64_t, 1),
		('Patsburg', uint64_t, 1), # 0 No, 1 Yes (ME 7-8)
		('SKUType', uint64_t, 3), # 0 Corporate, 1 Consumer, 2 Slim (ME 9-10)
		('SKUSize', uint64_t, 4), # Size * 0.5MB (ME 7-10, TXE 0-2)
		('Value10', uint64_t, 24)
	]
	
class SKU_Attributes_GetFlags(ctypes.Union):
	_fields_ = [
		('b', SKU_Attributes_Flags),
		('asbytes', uint64_t)
	]

# noinspection PyTypeChecker
class MME_Header_Old(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		("Tag",				char*4),		# 0x00
		("Guid",			uint8_t*16),	# 0x04
		("MajorVersion",	uint16_t),		# 0x14
		("MinorVersion",	uint16_t),		# 0x16
		("HotfixVersion",	uint16_t),		# 0x18
		("BuildVersion",	uint16_t),		# 0x1A
		("Name",			char*16),		# 0x1C
		("Hash",			uint8_t*20),	# 0x2C
		("Size",			uint32_t),		# 0x40
		("Flags",			uint32_t),		# 0x44
		("Unk48_4C",		uint32_t),		# 0x48
		("Unk4C_50",		uint32_t),		# 0x4C
		# 0x50
	]

# noinspection PyTypeChecker
class MME_Header_New(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		("Tag",				char*4),		# 0x00
		("Name",			char*16),		# 0x04
		("Hash",			uint8_t*32),	# 0x14
		("ModBase",			uint32_t),		# 0x34
		("Offset_MN2",		uint32_t),		# 0x38 from $MN2
		("SizeUncomp",		uint32_t),		# 0x3C
		("SizeComp",		uint32_t),		# 0x40
		("MemorySize",		uint32_t),		# 0x44
		("PreUmaSize",		uint32_t),		# 0x48
		("EntryPoint",		uint32_t),		# 0x4C
		("Flags",			uint32_t),		# 0x50
		("Unk54",			uint32_t),		# 0x54
		("Unk58",			uint32_t),		# 0x58
		("Unk5C",			uint32_t),		# 0x5C
		# 0x60
	]

# noinspection PyTypeChecker
class MCP_Header(ctypes.LittleEndianStructure) : # Multi Chip Package
	_pack_ = 1
	_fields_ = [
		("Tag",				char*4),		# 0x00
		("HeaderSize",		uint32_t),		# 0x04 dwords
		("CodeSize",		uint32_t),		# 0x08
		("Offset_Code_MN2",	uint32_t),		# 0x0C Code start from $MN2
		("Offset_Part_FPT",	uint32_t),  	# 0x10 Partition start from $FPT
		("Hash",			uint8_t*32),	# 0x14
		("Unknown34_38", 	uint32_t),  	# 0x34
		("Unknown38_3C", 	uint32_t),  	# 0x38 ME8-10
		("Unknown3C_40", 	uint32_t),  	# 0x3C ME8-10
		("Unknown40_44", 	uint32_t),  	# 0x40 ME8-10
		# 0x38 ME7, 0x44 ME8-10
	]

# noinspection PyTypeChecker
class CPD_Header(ctypes.LittleEndianStructure) : # Code Partition Directory Revision 1 (CPD_HEADER)
	_pack_ = 1
	_fields_ = [
		("Tag",				char*4),		# 0x00
		("NumModules",		uint32_t),		# 0x04
		("HeaderVersion",	uint8_t),		# 0x08 1
		("EntryVersion",	uint8_t),		# 0x09
		("HeaderLength",	uint8_t),		# 0x0A
		("Checksum",		uint8_t),		# 0x0B Checksum8
		("PartitionName",	char*4),		# 0x0C
		# 0x10
	]
	
	def hdr_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Code Partition Directory Header' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Module Count', '%d' % self.NumModules])
		pt.add_row(['Header Version', '%d' % self.HeaderVersion])
		pt.add_row(['Entry Version', '%d' % self.EntryVersion])
		pt.add_row(['Header Size', '0x%X' % self.HeaderLength])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		
		return pt

# noinspection PyTypeChecker
class CPD_Header_2(ctypes.LittleEndianStructure) : # Code Partition Directory Revision 2 (CPD_HEADER)
	_pack_ = 1
	_fields_ = [
		("Tag",				char*4),		# 0x00
		("NumModules",		uint32_t),		# 0x04
		("HeaderVersion",	uint8_t),		# 0x08 2
		("EntryVersion",	uint8_t),		# 0x09
		("HeaderLength",	uint8_t),		# 0x0A
		("Reserved",		uint8_t),		# 0x0B
		("PartitionName",	char*4),		# 0x0C
		("Checksum",		uint32_t),		# 0x10 CRC32
		# 0x14
	]
	
	def hdr_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Code Partition Directory Header' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Module Count', '%d' % self.NumModules])
		pt.add_row(['Header Version', '%d' % self.HeaderVersion])
		pt.add_row(['Entry Version', '%d' % self.EntryVersion])
		pt.add_row(['Header Size', '0x%X' % self.HeaderLength])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		
		return pt
		
# noinspection PyTypeChecker
class CPD_Entry(ctypes.LittleEndianStructure) : # (CPD_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("OffsetAttrib",	uint32_t),		# 0x0C
		("Size",			uint32_t),		# 0x10 Uncompressed for LZMA/Huffman, Compressed at CSE_Ext_0A instead
		("Reserved",		uint32_t),		# 0x14
		# 0x18
	]
	
	def hdr_print(self) :
		f1,f2,f3 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Code Partition Directory Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Offset from $CPD', '0x%X' % f1])
		pt.add_row(['Huffman Compression', ['No','Yes'][f2]])
		pt.add_row(['Offset Reserved', '0x%X' % f3])
		pt.add_row(['Size Uncompressed', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
	
	def get_flags(self) :
		flags = CPD_Entry_GetOffsetAttrib()
		flags.asbytes = self.OffsetAttrib
		
		return flags.b.OffsetCPD, flags.b.IsHuffman, flags.b.Reserved

class CPD_Entry_OffsetAttrib(ctypes.LittleEndianStructure):
	_fields_ = [
		('OffsetCPD', uint32_t, 25),
		('IsHuffman', uint32_t, 1),
		('Reserved', uint32_t, 6)
	]
	
class CPD_Entry_GetOffsetAttrib(ctypes.Union):
	_fields_ = [
		('b', CPD_Entry_OffsetAttrib),
		('asbytes', uint32_t)
	]

# noinspection PyTypeChecker
class CSE_Ext_00(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - System Information (SYSTEM_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("MinUMASize",		uint32_t),		# 0x08
		("ChipsetVersion",	uint32_t),		# 0x0C
		("IMGDefaultHash",	uint32_t*8),	# 0x10 FTPR > intl.cfg
		("PageableUMASize",	uint32_t),		# 0x30
		("Reserved0",		uint64_t),		# 0x34
		("Reserved1",		uint32_t),		# 0x3C
		# 0x40
	]
	
	def ext_print(self) :
		IMGDefaultHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.IMGDefaultHash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, System Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minimum UMA Size', '0x%X' % self.MinUMASize])
		pt.add_row(['Chipset Version', '0x%X' % self.ChipsetVersion])
		pt.add_row(['Default Config Hash', '%s' % IMGDefaultHash])
		pt.add_row(['Pageable UMA Size', '0x%X' % self.PageableUMASize])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_00_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4 - (INDEPENDENT_PARTITION_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*4),		# 0x00
		("Version",			uint32_t),		# 0x04
		("UserID",			uint16_t),		# 0x08
		("Reserved",		uint16_t),		# 0x0A
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, Independent Partition' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Version', '0x%X' % self.Version])
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_00_Mod_R2(ctypes.LittleEndianStructure) : # R2 - CSSPS5 - (INDEPENDENT_PARTITION_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*4),		# 0x00
		("Version",			uint32_t),		# 0x04
		("UserID",			uint16_t),		# 0x08
		("Reserved0",		uint16_t),		# 0x0A
		("Reserved1",		uint16_t),		# 0x0C
		("Reserved2",		uint16_t),		# 0x0E
		# 0x10
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, Independent Partition' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Version', '0x%X' % self.Version])
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['Reserved 2', '0x%X' % self.Reserved2])
		
		return pt

class CSE_Ext_01(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Initialization Script (InitScript)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Reserved",		uint32_t),		# 0x08
		("ModuleCount",		uint32_t),		# 0x0C
		# 0x10
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 1, Initialization Script' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Module Count', '%d' % self.ModuleCount])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_01_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (InitScriptEntry)
	_pack_ = 1
	_fields_ = [
		("PartitionName",	char*4),		# 0x00
		("ModuleName",		char*12),		# 0x0C
		("InitFlowFlags",	uint32_t),		# 0x10
		("BootTypeFlags",	uint32_t),		# 0x14
		# 0x18
	]
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 1, Entry' + col_e
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Module Name', self.ModuleName.decode('utf-8')])
		pt.add_row(['IBL', fvalue[f1]])
		pt.add_row(['Removable', fvalue[f2]])
		pt.add_row(['Init Immediately', fvalue[f3]])
		pt.add_row(['Restart Policy', ['Not Allowed','Immediately','On Next Boot'][f4]])
		pt.add_row(['CM0 with UMA', fvalue[f5]])
		pt.add_row(['CM0 without UMA', fvalue[f6]])
		pt.add_row(['CM3', fvalue[f7]])
		pt.add_row(['Init Flow Reserved', '0x%X' % f8])
		pt.add_row(['Normal', fvalue[f9]])
		pt.add_row(['HAP', fvalue[f10]])
		pt.add_row(['HMRFPO', fvalue[f11]])
		pt.add_row(['Temp Disable', fvalue[f12]])
		pt.add_row(['Recovery', fvalue[f13]])
		pt.add_row(['Safe Mode', fvalue[f14]])
		pt.add_row(['FWUpdate', fvalue[f15]])
		pt.add_row(['Boot Type Reserved', '0x%X' % f16])
		
		return pt
	
	def get_flags(self) :
		i_flags = CSE_Ext_01_GetInitFlowFlags()
		b_flags = CSE_Ext_01_GetBootTypeFlags()
		i_flags.asbytes = self.InitFlowFlags
		b_flags.asbytes = self.BootTypeFlags
		
		return i_flags.b.IBL, i_flags.b.Removable, i_flags.b.InitImmediately, i_flags.b.RestartPolicy, i_flags.b.CM0_UMA,\
		       i_flags.b.CM0_NO_UMA, i_flags.b.CM3, i_flags.b.Reserved, b_flags.b.Normal, b_flags.b.HAP, b_flags.b.HMRFPO,\
			   b_flags.b.TempDisable, b_flags.b.Recovery, b_flags.b.SafeMode, b_flags.b.FWUpdate, b_flags.b.Reserved

# noinspection PyTypeChecker
class CSE_Ext_01_Mod_R2(ctypes.LittleEndianStructure) : # R2 - CSME12 - (InitScriptEntry)
	_pack_ = 1
	_fields_ = [
		("PartitionName",	char*4),		# 0x00
		("ModuleName",		char*12),		# 0x0C
		("InitFlowFlags",	uint32_t),		# 0x10
		("BootTypeFlags",	uint32_t),		# 0x14
		("UnknownFlags",	uint32_t),		# 0x18 (Unknown)
		# 0x1C
	]
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16,f17,f18,f19,f20,f21,f22,f23,f24,f25 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 1, Entry' + col_e
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Module Name', self.ModuleName.decode('utf-8')])
		pt.add_row(['IBL', fvalue[f1]])
		pt.add_row(['Removable', fvalue[f2]])
		pt.add_row(['Init Immediately', fvalue[f3]])
		pt.add_row(['Restart Policy', ['Not Allowed','Immediately','On Next Boot'][f4]])
		pt.add_row(['CM0 with UMA', fvalue[f5]])
		pt.add_row(['CM0 without UMA', fvalue[f6]])
		pt.add_row(['CM3', fvalue[f7]])
		pt.add_row(['Init Flow Reserved', '0x%X' % f8])
		pt.add_row(['Normal', fvalue[f9]])
		pt.add_row(['HAP', fvalue[f10]])
		pt.add_row(['HMRFPO', fvalue[f11]])
		pt.add_row(['Temp Disable', fvalue[f12]])
		pt.add_row(['Recovery', fvalue[f13]])
		pt.add_row(['Safe Mode', fvalue[f14]])
		pt.add_row(['FWUpdate', fvalue[f15]])
		pt.add_row(['Boot Type Reserved', '0x%X' % f16])
		pt.add_row(['Unknown Flag 0', fvalue[f17]])
		pt.add_row(['Unknown Flag 1', fvalue[f18]])
		pt.add_row(['Unknown Flag 2', fvalue[f19]])
		pt.add_row(['Unknown Flag 3', fvalue[f20]])
		pt.add_row(['Unknown Flag 4', fvalue[f21]])
		pt.add_row(['Unknown Flag 5', fvalue[f22]])
		pt.add_row(['Unknown Flag 6', fvalue[f23]])
		pt.add_row(['Unknown Flag 7', fvalue[f24]])
		pt.add_row(['Unknown Flag Reserved', '0x%X' % f25])
		
		return pt
	
	def get_flags(self) :
		i_flags = CSE_Ext_01_GetInitFlowFlags()
		b_flags = CSE_Ext_01_GetBootTypeFlags()
		u_flags = CSE_Ext_01_GetUnknownFlags()
		i_flags.asbytes = self.InitFlowFlags
		b_flags.asbytes = self.BootTypeFlags
		u_flags.asbytes = self.UnknownFlags
		
		return i_flags.b.IBL, i_flags.b.Removable, i_flags.b.InitImmediately, i_flags.b.RestartPolicy, i_flags.b.CM0_UMA,\
		       i_flags.b.CM0_NO_UMA, i_flags.b.CM3, i_flags.b.Reserved, b_flags.b.Normal, b_flags.b.HAP, b_flags.b.HMRFPO,\
			   b_flags.b.TempDisable, b_flags.b.Recovery, b_flags.b.SafeMode, b_flags.b.FWUpdate, b_flags.b.Reserved,\
			   u_flags.b.Unknown0, u_flags.b.Unknown1, u_flags.b.Unknown2, u_flags.b.Unknown3, u_flags.b.Unknown4,\
			   u_flags.b.Unknown5, u_flags.b.Unknown6, u_flags.b.Unknown7, u_flags.b.Unknown8
			   
class CSE_Ext_01_InitFlowFlags(ctypes.LittleEndianStructure):
	_fields_ = [
		('IBL', uint32_t, 1),
		('Removable', uint32_t, 1),
		('InitImmediately', uint32_t, 1),
		('RestartPolicy', uint32_t, 1), # (InitScriptRestartPolicy)
		('CM0_UMA', uint32_t, 1),
		('CM0_NO_UMA', uint32_t, 1),
		('CM3', uint32_t, 1),
		('Reserved', uint32_t, 25)
	]
	
class CSE_Ext_01_GetInitFlowFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_01_InitFlowFlags),
		('asbytes', uint32_t)
	]
	
class CSE_Ext_01_BootTypeFlags(ctypes.LittleEndianStructure):
	_fields_ = [
		('Normal', uint32_t, 1),
		('HAP', uint32_t, 1),
		('HMRFPO', uint32_t, 1),
		('TempDisable', uint32_t, 1),
		('Recovery', uint32_t, 1),
		('SafeMode', uint32_t, 1),
		('FWUpdate', uint32_t, 1),
		('Reserved', uint32_t, 25)
	]

class CSE_Ext_01_GetBootTypeFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_01_BootTypeFlags),
		('asbytes', uint32_t)
	]
	
class CSE_Ext_01_UnknownFlags(ctypes.LittleEndianStructure):
	_fields_ = [
		('Unknown0', uint32_t, 1),
		('Unknown1', uint32_t, 1),
		('Unknown2', uint32_t, 1),
		('Unknown3', uint32_t, 1),
		('Unknown4', uint32_t, 1),
		('Unknown5', uint32_t, 1),
		('Unknown6', uint32_t, 1),
		('Unknown7', uint32_t, 1),
		('Unknown8', uint32_t, 24)
	]

class CSE_Ext_01_GetUnknownFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_01_UnknownFlags),
		('asbytes', uint32_t)
	]

class CSE_Ext_02(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Feature Permissions (FEATURE_PERMISSIONS_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("ModuleCount",		uint32_t),		# 0x08
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 2, Feature Permissions' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Feature Count', '%d' % self.ModuleCount])
		
		return pt

class CSE_Ext_02_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (FEATURE_PERMISION_ENTRY)
	_pack_ = 1
	_fields_ = [
		("UserID",			uint16_t),		# 0x00
		("Reserved",		uint16_t),		# 0x02
		# 0x04
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 2, Entry' + col_e
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_03(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Partition Information (MANIFEST_PARTITION_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('Hash',			uint32_t*8),	# 0x10 Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('VCN',				uint32_t),		# 0x30
		('PartitionVer',	uint32_t),  	# 0x34
		('DataFormatMinor',	uint16_t),		# 0x14 dword (0-15 Major, 16-31 Minor)
		('DataFormatMajor',	uint16_t),		# 0x16 dword (0-15 Major, 16-31 Minor)
		('InstanceID', 		uint32_t),  	# 0x3C
		('Flags', 			uint32_t),  	# 0x40 Support multiple instances Y/N (for independently updated WCOD/LOCL partitions with multiple instances)
		('Reserved', 		uint32_t*4),  	# 0x44
		('Unknown', 		uint32_t),  	# 0x54 Unknown (>= 11.6.0.1109, 1 CSSPS, 3 CSME)
		# 0x58
	]
	
	# Used at $FPT size calculation as well, remember to change in case of new Extension Revision!
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 3, Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Hash', '%s' % Hash])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		pt.add_row(['Partition Version', '0x%X' % self.PartitionVer])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		pt.add_row(['Reserved', '0x0' if Reserved in ('00' * 16,'FF' * 16) else Reserved])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_03_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Module Information (MANIFEST_MODULE_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("Type",			uint8_t),		# 0x0C (MODULE_TYPES) (0 Process, 1 Shared Library, 2 Data, 3 OEM/IUP)
		("Compression",		uint8_t),		# 0x0D (0 Uncompressed --> always, 1 Huffman, 2 LZMA)
		("Reserved",		uint16_t),		# 0x0E FFFF
		("MetadataSize",	uint32_t),		# 0x10
		("MetadataHash",	uint32_t*8),	# 0x14
		# 0x34
	]
	
	def ext_print(self) :
		MetadataHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MetadataHash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 3, Module Information' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', ['Process','Shared Library','Data','OEM/IUP'][self.Type]])
		pt.add_row(['Compression', ['Uncompressed','Huffman','LZMA'][self.Compression]])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt

class CSE_Ext_04(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Shared Library (SHARED_LIB_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("ContextSize",		uint32_t),		# 0x08
		("TotAlocVirtSpc",	uint32_t),		# 0x0C
		("CodeBaseAddress",	uint32_t),		# 0x10
		("TLSSize",			uint32_t),		# 0x14
		("Reserved",		uint32_t),		# 0x18
		# 0x1C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 4, Shared Library' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Context Size', '0x%X' % self.ContextSize])
		pt.add_row(['Total Allocated Virtual Space', '0x%X' % self.TotAlocVirtSpc])
		pt.add_row(['Code Base Address', '0x%X' % self.CodeBaseAddress])
		pt.add_row(['TLS Size', '0x%X' % self.TLSSize])
		pt.add_row(['Reserved', '0x0' if self.Reserved == 0 else '0x%X' % self.Reserved])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_05(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Process Manifest (MAN_PROCESS_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Flags",			uint32_t),		# 0x08
		("MainThreadID",	uint32_t),		# 0x0C
		("CodeBaseAddress",	uint32_t),		# 0x10
		("CodeSizeUncomp",	uint32_t),		# 0x14
		("CM0HeapSize",		uint32_t),		# 0x18
		("BSSSize",			uint32_t),		# 0x1C
		("DefaultHeapSize",	uint32_t),		# 0x20
		("MainThreadEntry",	uint32_t),		# 0x24
		("AllowedSysCalls",	uint32_t*3),	# 0x28
		("UserID",			uint16_t),		# 0x34
		("Reserved0",		uint32_t),		# 0x36
		("Reserved1",		uint16_t),		# 0x3A
		("Reserved2",		uint64_t),		# 0x3C
		("GroupID",			uint16_t),	    # 0x44
		# 0x46
	]
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1value = ['Reset System','Terminate Process']
		f1,f2,f3,f4,f5,f6,f7,f8 = self.get_flags()
		AllowedSysCalls = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.AllowedSysCalls))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 5, Process Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Fault Tolerant', f1value[f1]])
		pt.add_row(['Permanent Process', fvalue[f2]])
		pt.add_row(['Single Instance', fvalue[f3]])
		pt.add_row(['Trusted SendReceive Sender', fvalue[f4]])
		pt.add_row(['Trusted Notify Sender', fvalue[f5]])
		pt.add_row(['Public SendReceive Receiver', fvalue[f6]])
		pt.add_row(['Public Notify Receiver', fvalue[f7]])
		pt.add_row(['Reserved', '0x%X' % f8])
		pt.add_row(['Main Thread ID', '0x%0.8X' % self.MainThreadID])
		pt.add_row(['Code Base Address', '0x%X' % self.CodeBaseAddress])
		pt.add_row(['Code Size Uncompressed', '0x%X' % self.CodeSizeUncomp])
		pt.add_row(['CM0 Heap Size', '0x%X' % self.CM0HeapSize])
		pt.add_row(['BSS Size', '0x%X' % self.BSSSize])
		pt.add_row(['Default Heap Size', '0x%X' % self.DefaultHeapSize])
		pt.add_row(['Main Thread Entry', '0x%X' % self.MainThreadEntry])
		pt.add_row(['Allowed System Calls', AllowedSysCalls])
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['Reserved 2', '0x%X' % self.Reserved2])
		pt.add_row(['Group ID', '0x%0.4X' % self.GroupID])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Ext_05_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.FaultTolerant, flags.b.PermanentProcess, flags.b.SingleInstance, flags.b.TrustedSendReceiveSender,\
		       flags.b.TrustedNotifySender, flags.b.PublicSendReceiveReceiver, flags.b.PublicNotifyReceiver, flags.b.Reserved

class CSE_Ext_05_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Group ID (PROCESS_GROUP_ID)
	_pack_ = 1
	_fields_ = [
		('GroupID',			uint16_t),		# 0x00
		# 0x02
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 5, Group ID' + col_e
		pt.add_row(['Data', '0x%0.4X' % self.GroupID])
		
		return pt			   

class CSE_Ext_05_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('FaultTolerant', uint32_t, 1), # (EXCEPTION_HANDLE_TYPES)
		('PermanentProcess', uint32_t, 1),
		('SingleInstance', uint32_t, 1),
		('TrustedSendReceiveSender', uint32_t, 1),
		('TrustedNotifySender', uint32_t, 1),
		('PublicSendReceiveReceiver', uint32_t, 1),
		('PublicNotifyReceiver', uint32_t, 1),
		('Reserved', uint32_t, 25)
	]

class CSE_Ext_05_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_05_Flags),
		('asbytes', uint32_t)
	]

class CSE_Ext_06(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Threads (Threads)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 6, Threads' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_06_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (Thread)
	_pack_ = 1
	_fields_ = [
		("StackSize",		uint32_t),		# 0x00
		("Flags",			uint32_t),		# 0x04
		("SchedulPolicy",	uint32_t),		# 0x08
		("Reserved",		uint32_t),		# 0x0C
		# 0x10
	]
	
	def ext_print(self) :
		f1value = ['Live','CM0 UMA Only']
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 6, Thread' + col_e
		pt.add_row(['Stack Size', '0x%X' % self.StackSize])
		pt.add_row(['Flags Type', f1value[f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Scheduling Policy Fixed Priority', fvalue[f3]])
		pt.add_row(['Scheduling Policy Reserved', '0x%X' % f4])
		pt.add_row(['Scheduling Attributes/Priority', '0x%X' % f5])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
	def get_flags(self) :
		f_flags = CSE_Ext_06_GetFlags()
		s_flags = CSE_Ext_06_GetSchedulPolicy()
		f_flags.asbytes = self.Flags
		s_flags.asbytes = self.SchedulPolicy
		
		return f_flags.b.FlagsType, f_flags.b.FlagsReserved, s_flags.b.PolicyFixedPriority, s_flags.b.PolicyReserved,\
		       s_flags.b.AttributesORPriority
	
class CSE_Ext_06_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('FlagsType', uint32_t, 1),
		('FlagsReserved', uint32_t, 31)
	]

class CSE_Ext_06_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_06_Flags),
		('asbytes', uint32_t)
	]
	
class CSE_Ext_06_SchedulPolicy(ctypes.LittleEndianStructure):
	_fields_ = [
		('PolicyFixedPriority', uint32_t, 1),
		('PolicyReserved', uint32_t, 6),
		('AttributesORPriority', uint32_t, 25)
	]
	
class CSE_Ext_06_GetSchedulPolicy(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_06_SchedulPolicy),
		('asbytes', uint32_t)
	]

class CSE_Ext_07(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Device IDs (DeviceIds)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 7, Device IDs' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_07_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (Device)
	_pack_ = 1
	_fields_ = [
		("DeviceID",		uint32_t),		# 0x00
		("Reserved",		uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 7, Device' + col_e
		pt.add_row(['Device ID', '0x%0.8X' % self.DeviceID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt

class CSE_Ext_08(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - MMIO Ranges (MmioRanges)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x8
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 8, MMIO Ranges' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_08_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (MmioRange)
	_pack_ = 1
	_fields_ = [
		("BaseAddress",		uint32_t),		# 0x00
		("SizeLimit",		uint32_t),		# 0x04
		("Flags",			uint32_t),		# 0x08 (MmioAccess)
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 8, MMIO Range' + col_e
		pt.add_row(['Base Address', '0x%X' % self.BaseAddress])
		pt.add_row(['Size Limit', '0x%X' % self.SizeLimit])
		pt.add_row(['Access', '%s' % ['N/A','Read Only','Write Only','Read & Write'][self.Flags]])
		
		return pt

class CSE_Ext_09(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Special File Producer (SPECIAL_FILE_PRODUCER_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("MajorNumber",		uint16_t),		# 0x08
		("Flags",			uint16_t),		# 0x0A (Unknown/Unused)
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 9, Special File Producer' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Major Number', '%d' % self.MajorNumber])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_09_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (SPECIAL_FILE_DEF)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("AccessMode",		uint16_t),		# 0x0C
		("UserID",			uint16_t),		# 0x0E
		("GroupID",			uint16_t),		# 0x10
		("MinorNumber",		uint8_t),		# 0x12
		("Reserved0",		uint8_t),		# 0x13
		("Reserved1",		uint32_t),		# 0x14
		# 0x18
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 9, Special File Definition' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Access Mode', '0x%X' % self.AccessMode])
		pt.add_row(['User ID', '0x%X' % self.UserID])
		pt.add_row(['Group ID', '0x%X' % self.GroupID])
		pt.add_row(['Minor Number', '%d' % self.MinorNumber])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0A(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Module Attributes (MOD_ATTR_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Compression",		uint8_t),		# 0x08 (0 Uncompressed, 1 Huffman, 2 LZMA)
		("Encryption",		uint8_t),		# 0x09 (0 No, 1 Yes, unknown if LE MSB or entire Byte)
		("Reserved0",		uint8_t),		# 0x0A
		("Reserved1",		uint8_t),		# 0x0B
		("SizeUncomp",		uint32_t),		# 0x0C
		("SizeComp",		uint32_t),		# 0x10 (LZMA & Huffman w/o EOM alignment)
		("DEV_ID",			uint16_t),		# 0x14
		("VEN_ID",			uint16_t),		# 0x16 (0x8086)
		("Hash",			uint32_t*8),	# 0x18 (Compressed for LZMA, Uncompressed for Huffman)
		# 0x38
	]
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 10, Module Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Compression', ['Uncompressed','Huffman','LZMA'][self.Compression]])
		pt.add_row(['Encryption', ['No','Yes'][self.Encryption]])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['Device ID', '0x%0.4X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%0.4X' % self.VEN_ID])
		pt.add_row(['Hash', Hash])
		
		return pt

class CSE_Ext_0B(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Locked Ranges (LockedRanges)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 11, Locked Ranges' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_0B_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (LockedRange)
	_pack_ = 1
	_fields_ = [
		("RangeBase",		uint32_t),		# 0x00
		("RangeSize",		uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 11, Locked Range' + col_e
		pt.add_row(['Range Base', '0x%X' % self.RangeBase])
		pt.add_row(['Range Size', '0x%X' % self.RangeSize])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0C(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Client System Information (CLIENT_SYSTEM_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("FWSKUCaps",		uint32_t),		# 0x08 (System Tools User Guide > NVAR > OEMSkuRule)
		("FWSKUCapsReserv",	uint32_t*7),	# 0x0C
		("FWSKUAttrib",		uint64_t),		# 0x28
		# 0x30
	]
	
	def __init__(self, variant, major, minor, hotfix, build, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.variant = variant
		self.major = major
		self.minor = minor
		self.hotfix = hotfix
		self.build = build
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8 = self.get_flags()
		
		FWSKUCapsReserv = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.FWSKUCapsReserv))
		
		if [self.variant,self.major,self.minor,self.hotfix] == ['CSME',11,0,0] and (self.build < 1205 or self.build == 7101) :
			sku = ['N/A','N/A','Unknown','Unknown']
		else :
			sku = ['H','LP','Unknown','Unknown']
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 12, Client System Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['SKU Capabilities', '0x%0.8X' % self.FWSKUCaps])
		pt.add_row(['SKU Capabilities Reserved', 'FF * 28' if FWSKUCapsReserv == 'FF' * 28 else FWSKUCapsReserv])
		pt.add_row(['CSE Size', '0x%X' % f1])
		pt.add_row(['SKU Type', ['Corporate','Consumer','Slim','SPS'][f2]])
		pt.add_row(['Lewisburg', fvalue[f3]])
		pt.add_row(['M3', fvalue[f4]])
		pt.add_row(['M0', fvalue[f5]])
		pt.add_row(['SKU Platform', sku[f6]])
		pt.add_row(['Si Class', '%d' % f7])
		pt.add_row(['Reserved', '0x0' if f8 == 0 else '0x%X' % f8])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_0C_GetFWSKUAttrib()
		flags.asbytes = self.FWSKUAttrib
		
		return flags.b.CSESize, flags.b.SKUType, flags.b.Lewisburg, flags.b.M3, flags.b.M0,\
		       flags.b.SKUPlatform, flags.b.SiClass, flags.b.Reserved
	
class CSE_Ext_0C_FWSKUAttrib(ctypes.LittleEndianStructure):
	_fields_ = [
		('CSESize', uint64_t, 4), # CSESize * 0.5MB, always 0
		('SKUType', uint64_t, 3), # 0 COR, 1 CON, 2 SLM, 3 LBG (?)
		('Lewisburg', uint64_t, 1), # 0 11.x, 1 11.20
		('M3', uint64_t, 1), # 0 CON & SLM, 1 COR
		('M0', uint64_t, 1), # 1 CON & SLM & COR
		('SKUPlatform', uint64_t, 2), # 0 for H/LP <= 11.0.0.1202, 0 for H >= 11.0.0.1205, 1 for LP >= 11.0.0.1205
		('SiClass', uint64_t, 4), # 2 CON & SLM, 4 COR (maybe Sx Power States, not sure if bitmap or decimal)
		('Reserved', uint64_t, 50) # 0
	]

class CSE_Ext_0C_GetFWSKUAttrib(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_0C_FWSKUAttrib),
		('asbytes', uint64_t)
	]

class CSE_Ext_0D(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - User Information (USER_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x8
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 13, User Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0D_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (USER_INFO_ENTRY)
	_pack_ = 1
	_fields_ = [
		("UserID",			uint16_t),		# 0x00
		("Reserved",		uint16_t),		# 0x02
		("NVStorageQuota",	uint32_t),		# 0x04
		("RAMStorageQuota",	uint32_t),		# 0x08
		("WOPQuota",		uint32_t),		# 0x0C (Wear-out Prevention)
		("WorkingDir",		char*36),		# 0x10
		# 0x34
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 13, Entry' + col_e
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['NV Storage Quota', '0x%X' % self.NVStorageQuota])
		pt.add_row(['RAM Storage Quota', '0x%X' % self.RAMStorageQuota])
		pt.add_row(['WOP Quota', '0x%X' % self.WOPQuota])
		pt.add_row(['Working Directory', self.WorkingDir.decode('utf-8')])
		
		return pt

class CSE_Ext_0D_Mod_R2(ctypes.LittleEndianStructure) : # R2 - CSME12 - (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("UserID",			uint16_t),		# 0x00
		("Reserved",		uint16_t),		# 0x02
		("NVStorageQuota",	uint32_t),		# 0x04
		("RAMStorageQuota",	uint32_t),		# 0x08
		("WOPQuota",		uint32_t),		# 0x0C (Wear-out Prevention)
		# 0x10
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 13, Entry' + col_e
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['NV Storage Quota', '0x%X' % self.NVStorageQuota])
		pt.add_row(['RAM Storage Quota', '0x%X' % self.RAMStorageQuota])
		pt.add_row(['WOP Quota', '0x%X' % self.WOPQuota])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0E(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Key Manifest (KEY_MANIFEST_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("KeyType",			uint32_t),		# 0x08 1 RoT, 2 OEM (KeyManifestTypeValues)
		("KeySVN",			uint32_t),		# 0x0C
		("OEMID",			uint16_t),		# 0x10
		("KeyID",			uint8_t),		# 0x12 Matched against Field Programmable Fuse (FPF)
		("Reserved0",		uint8_t),		# 0x13
		("Reserved1",		uint32_t*4),	# 0x14
		# 0x24
	]
	
	def ext_print(self) :
		Reserved1 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved1))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 14, Key Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Key Type', ['Unknown','RoT','OEM'][self.KeyType]])
		pt.add_row(['Key SVN', '%d' % self.KeySVN])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Key ID', '0x%0.2X' % self.KeyID])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x0' if Reserved1 == '00000000' * 4 else Reserved1])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0E_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (KEY_MANIFEST_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		("UsageBitmap",		uint8_t*16),	# 0x00 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		("Reserved0",		uint32_t*4),	# 0x10
		("Flags",			uint8_t),		# 0x20
		("HashAlgorithm",	uint8_t),		# 0x21
		("HashSize",		uint16_t),		# 0x22
		("Hash",			uint32_t*8),	# 0x24 (Big Endian, PKEY + EXP)
		# 0x44
	]
	
	def ext_print(self) :
		f1,f2 = self.get_flags()
		hash_usages = self.get_usages()
		
		Reserved0 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved0))
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 14, Entry' + col_e
		pt.add_row(['Hash Usages', ', '.join(map(str, hash_usages))])
		pt.add_row(['Reserved 0', '0x0' if Reserved0 == '00000000' * 4 else Reserved0])
		pt.add_row(['IPI Policy', ['OEM or Intel','Intel Only'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Hash Algorithm', ['None','SHA-1','SHA-256'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Public Key & Exponent Hash', Hash])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_0E_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.IPIPolicy, flags.b.Reserved
	
	# Identical code at CSE_Ext_0F
	def get_usages(self) :
		hash_usages = []
		
		usage_bits = list(format(int.from_bytes(self.UsageBitmap, 'little'), '0128b'))
		usage_bits.reverse()
		
		for usage_bit in range(len(usage_bits)) :
			if usage_bits[usage_bit] == '1' :
				hash_usages.append(key_dict[usage_bit] if usage_bit in key_dict else 'Unknown')
				
		return hash_usages
	
class CSE_Ext_0E_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('IPIPolicy', uint8_t, 1), # RoT (Root of Trust) Key Manifest
		('Reserved', uint8_t, 7)
	]

class CSE_Ext_0E_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_0E_Flags),
		('asbytes', uint8_t)
	]

# noinspection PyTypeChecker
class CSE_Ext_0F(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Signed Package Info (SIGNED_PACKAGE_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("PartitionName",	char*4),		# 0x08
		("VCN",				uint32_t),		# 0x0C
		("UsageBitmap",		uint8_t*16),	# 0x10 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		("SVN",				uint32_t),		# 0x20
		("Reserved",		uint32_t*4),  	# 0x24
		# 0x34
	]
	
	def ext_print(self) :
		hash_usages = self.get_usages()
		
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Signed Package Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		pt.add_row(['Hash Usages', ', '.join(map(str, hash_usages))])
		pt.add_row(['Security Version Number', '%d' % self.SVN])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 4 else Reserved])
		
		return pt
	
	# Identical code at CSE_Ext_0E_Mod
	def get_usages(self) :
		hash_usages = []
		
		usage_bits = list(format(int.from_bytes(self.UsageBitmap, 'little'), '0128b'))
		usage_bits.reverse()
		
		for usage_bit in range(len(usage_bits)) :
			if usage_bits[usage_bit] == '1' :
				hash_usages.append(key_dict[usage_bit] if usage_bit in key_dict else 'Unknown')
				
		return hash_usages

# noinspection PyTypeChecker
class CSE_Ext_0F_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (SIGNED_PACKAGE_INFO_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("Type",			uint8_t),		# 0x0C (MODULE_TYPES) (0 Process, 1 Shared Library, 2 Data, 3 OEM/IUP)
		("HashAlgorithm",	uint8_t),		# 0x0D (0 Reserved, 1 SHA1, 2 SHA256)
		("HashSize",		uint16_t),		# 0x0E
		("MetadataSize",	uint32_t),		# 0x10
		("MetadataHash",	uint32_t*8),	# 0x14
		# 0x34
	]
	
	def ext_print(self) :
		MetadataHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MetadataHash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', ['Process','Shared Library','Data','OEM/IUP'][self.Type]])
		pt.add_row(['Hash Algorithm', ['None','SHA-1','SHA-256'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_10(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - iUnit (IUNP) (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Unknown",			uint32_t),		# 0x08 1
		("Reserved0",		uint32_t*4),	# 0x0C
		("SizeComp",		uint32_t),		# 0x1C
		("SizeUncomp",		uint32_t),		# 0x20
		("Day",				uint8_t),		# 0x24
		("Month",			uint8_t),		# 0x25
		("Year",			uint16_t),		# 0x26
		("Hash",			uint32_t*8),	# 0x28 Big Endian
		("Reserved1",		uint32_t*6),	# 0x48
		# 0x60
	]
	
	def ext_print(self) :
		Reserved0 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved0))
		Date = '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		Reserved1 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved1))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 16, Imaging Unit (iUnit/Camera)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		pt.add_row(['Reserved 0', '0x0' if Reserved0 == '00000000' * 4 else Reserved0])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Date', Date])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Reserved 1', '0x0' if Reserved1 == '00000000' * 6 else Reserved1])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_11(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - cAVS (ADSP) (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Unknown",			uint32_t),		# 0x08 3
		("Reserved0",		uint32_t*7),	# 0x0C
		("Hash",			uint32_t*8),	# 0x28 Big Endian
		("SizeUnknown",		uint32_t),		# 0x48 Maybe cache size?
		("SizeUncomp",		uint32_t),		# 0x4C SizeUncomp - SizeUnknown = Actual ($CPD) Size
		("Reserved1",		uint32_t*4),	# 0x50
		# 0x60
	]
	
	def ext_print(self) :
		Reserved0 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved0))
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		Reserved1 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved1))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 17, Clear Audio Video Speech (aDSP)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		pt.add_row(['Reserved 0', '0x0' if Reserved0 == '00000000' * 7 else Reserved0])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Size Unknown', '0x%X' % self.SizeUnknown])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Reserved 1', '0x0' if Reserved1 == '00000000' * 4 else Reserved1])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_12(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Unknown FTPR (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("ModuleCount",		uint32_t),		# 0x08
		("Reserved",		uint32_t*4),	# 0x0C
		# 0x1C
	]
	
	def ext_print(self) :
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 18, Unknown (FTPR)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Module Count', '%d' % self.ModuleCount])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 4 else Reserved])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_12_Mod(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("Unknown00_04",	uint32_t),		# 0x00
		("Unknown04_08",	uint32_t),		# 0x04
		("Unknown08_0C",	uint32_t),		# 0x08
		("Unknown0C_10",	uint32_t),		# 0x0C
		("Unknown10_18",	uint32_t*2),	# 0x10 FFFFFFFFFFFFFFFF
		("Unknown18_1C",	uint32_t),		# 0x18
		("Unknown1C_20",	uint32_t),		# 0x1C
		("Unknown20_28",	uint32_t*2),	# 0x20 FFFFFFFFFFFFFFFF
		("Unknown28_2C",	uint32_t),		# 0x28
		("Unknown2C_30",	uint32_t),		# 0x2C
		("Unknown30_38",	uint32_t*2),	# 0x30 FFFFFFFFFFFFFFFF
		# 0x38
	]
	
	def ext_print(self) :
		Unknown10_18 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown10_18))
		Unknown20_28 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown20_28))
		Unknown30_38 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown30_38))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 18, Entry' + col_e
		pt.add_row(['Unknown 00_04', '0x%X' % self.Unknown00_04])
		pt.add_row(['Unknown 04_08', '0x%X' % self.Unknown04_08])
		pt.add_row(['Unknown 08_0C', '0x%X' % self.Unknown08_0C])
		pt.add_row(['Unknown 0C_10', '0x%X' % self.Unknown0C_10])
		pt.add_row(['Unknown 10_18', '0xFF * 8' if Unknown10_18 == 'FFFFFFFF' * 2 else Unknown10_18])
		pt.add_row(['Unknown 18_1C', '0x%X' % self.Unknown18_1C])
		pt.add_row(['Unknown 1C_20', '0x%X' % self.Unknown1C_20])
		pt.add_row(['Unknown 20_28', '0xFF * 8' if Unknown20_28 == 'FFFFFFFF' * 2 else Unknown20_28])
		pt.add_row(['Unknown 28_2C', '0x%X' % self.Unknown28_2C])
		pt.add_row(['Unknown 2C_30', '0x%X' % self.Unknown2C_30])
		pt.add_row(['Unknown 30_38', '0xFF * 8' if Unknown30_38 == 'FFFFFFFF' * 2 else Unknown30_38])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_13(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Boot Policy (BOOT_POLICY_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("IBBNEMSize",		uint32_t),		# 0x08 in 4K pages (NEM: No Evict Mode or CAR: Cache as RAM)
		("IBBLHashAlg",		uint32_t),		# 0x0C 0 None, 1 SHA1, 2 SHA256
		("IBBLHashSize",	uint32_t),		# 0x10
		("IBBLHash",		uint32_t*8),	# 0x14 Big Endian
		("IBBHashAlg",		uint32_t),		# 0x34 0 None, 1 SHA1, 2 SHA256
		("IBBHashSize",		uint32_t),		# 0x38
		("IBBHash",			uint32_t*8),	# 0x3C Big Endian
		("OBBHashAlg",		uint32_t),		# 0x5C 0 None, 1 SHA1, 2 SHA256
		("OBBHashSize",		uint32_t),		# 0x60
		("OBBHash",			uint32_t*8),	# 0x64 Big Endian
		("IBBFlags",		uint32_t),		# 0x84 Unknown/Unused
		("IBBMCHBar",		uint64_t),		# 0x88
		("IBBVTDBar",		uint64_t),		# 0x90
		("PMRLBase",		uint32_t),		# 0x98
		("PMRLLimit",		uint32_t),		# 0x9C
		("PMRHBase",		uint32_t),		# 0xA0
		("PMRHLimit",		uint32_t),		# 0xA4
		("IBBEntryPoint",	uint32_t),		# 0xA8
		("IBBSegmentCount",	uint32_t),		# 0xAC
		("VendorAttrSize",	uint32_t),		# 0xB0
		# 0xB4
	]
	
	def ext_print(self) :
		hash_alg = ['None','SHA-1','SHA-256']
		
		IBBLHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.IBBLHash)
		IBBHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.IBBHash)
		OBBHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.OBBHash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 19, Boot Policy' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['No Evict Mode Size', '0x%X' % (self.IBBNEMSize * 4096)])
		pt.add_row(['IBBL Hash Algorithm', hash_alg[self.IBBLHashAlg]])
		pt.add_row(['IBBL Hash Size', '0x%X' % self.IBBLHashSize])
		pt.add_row(['IBBL Hash', IBBLHash])
		pt.add_row(['IBB Hash Algorithm', hash_alg[self.IBBHashAlg]])
		pt.add_row(['IBB Hash Size', '0x%X' % self.IBBHashSize])
		pt.add_row(['IBB Hash', IBBHash])
		pt.add_row(['OBB Hash Algorithm', hash_alg[self.OBBHashAlg]])
		pt.add_row(['OBB Hash Size', '0x%X' % self.OBBHashSize])
		pt.add_row(['OBB Hash', OBBHash])
		pt.add_row(['IBB Flags', '0x%X' % self.IBBFlags])
		pt.add_row(['IBB MCH Bar', '0x%X' % self.IBBMCHBar])
		pt.add_row(['IBB VTD Bar', '0x%X' % self.IBBVTDBar])
		pt.add_row(['PMRL Base', '0x%X' % self.PMRLBase])
		pt.add_row(['PMRL Limit', '0x%X' % self.PMRLLimit])
		pt.add_row(['PMRH Base', '0x%X' % self.PMRHBase])
		pt.add_row(['PMRH Limit', '0x%X' % self.PMRHLimit])
		pt.add_row(['IBB Entry Point', '0x%X' % self.IBBEntryPoint])
		pt.add_row(['IBB Segment Count', '%d' % self.IBBSegmentCount])
		pt.add_row(['Vendor Attributes Size', '0x%X' % self.VendorAttrSize])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_14(ctypes.LittleEndianStructure) : # R1 - CSME11/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - DnX Manifest (DnxManifestExtension)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Minor",			uint8_t),		# 0x08
		("Major",			uint8_t),		# 0x09
		("Reserved0",		uint8_t),		# 0x0A
		("Reserved1",		uint8_t),		# 0x0B
		("OEMID",			uint16_t),		# 0x0C
		("PlatformID",		uint16_t),		# 0x0E
		("MachineID",		uint32_t*4),	# 0x10
		("SaltID",			uint32_t),		# 0x20
		("PublicKey",		uint32_t*64),	# 0x24
		("PublicExponent",	uint32_t),		# 0x88
		("IFWIRegionCount",	uint32_t),		# 0x8C Number of eMMC/UFS components (LBPs)
		("Flags",			uint32_t),		# 0x90 Unknown/Unused
		("Reserved2",		uint32_t),		# 0x94
		("Reserved3",		uint32_t),		# 0x98
		("Reserved4",		uint32_t),		# 0x9C
		("Reserved5",		uint32_t),		# 0xA0
		("ChunkSize",		uint32_t),		# 0xA4 0x10000 (64KB)
		("ChunkCount",		uint32_t),		# 0xA8
		# 0xAC
	]
	
	def ext_print(self) :
		MachineID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MachineID))
		PublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.PublicKey))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 20 R1, DnX Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minor', '%d' % self.Minor])
		pt.add_row(['Major', '%d' % self.Major])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Platform ID', '0x%0.4X' % self.PlatformID])
		pt.add_row(['Machine ID', '0x0' if MachineID == '00000000' * 4 else MachineID])
		pt.add_row(['Salt ID', '0x%0.8X' % self.SaltID])
		pt.add_row(['Public Key', '%s [...]' % PublicKey[:7]])
		pt.add_row(['Public Exponent', '0x%X' % self.PublicExponent])
		pt.add_row(['IFWI Region Count', '%d' % self.IFWIRegionCount])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		pt.add_row(['Reserved 2', '0x%X' % self.Reserved2])
		pt.add_row(['Reserved 3', '0x%X' % self.Reserved3])
		pt.add_row(['Reserved 4', '0x%X' % self.Reserved4])
		pt.add_row(['Reserved 5', '0x%X' % self.Reserved5])
		pt.add_row(['IFWI Chunk Data Size', '0x%X' % self.ChunkSize])
		pt.add_row(['IFWI Chunk Count', '%d' % self.ChunkCount])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_14_R2(ctypes.LittleEndianStructure) : # R2 - CSME12 - DnX Manifest (DnxManifestExtension_ver2)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Minor",			uint8_t),		# 0x08
		("Major",			uint8_t),		# 0x09
		("Reserved0",		uint8_t),		# 0x0A
		("Reserved1",		uint8_t),		# 0x0B
		("OEMID",			uint16_t),		# 0x0C
		("PlatformID",		uint16_t),		# 0x0E
		("MachineID",		uint32_t*4),	# 0x10
		("SaltID",			uint32_t),		# 0x20
		("PublicKey",		uint32_t*64),	# 0x24
		("PublicExponent",	uint32_t),		# 0x124
		("IFWIRegionCount",	uint32_t),		# 0x128 Number of eMMC/UFS components (LBPs)
		("Flags",			uint32_t),		# 0x12C Unknown/Unused
		("Reserved2",		uint8_t),		# 0x12D
		("Reserved3",		uint8_t),		# 0x12E
		("Reserved4",		uint8_t),		# 0x12F
		("Reserved5",		uint8_t),		# 0x130
		("HashArrHdrMajor",	uint8_t),		# 0x131
		("HashArrHdrMinor",	uint8_t),		# 0x132
		("HashArrHdrCount",	uint16_t),		# 0x133
		("Reserved6",		uint8_t),		# 0x135
		("HashArrHashAlg",	uint8_t),		# 0x136 0 None, 1 SHA-1, 2 SHA-256
		("HashArrHashSize",	uint16_t),		# 0x137
		("ChunkHashAlg",	uint8_t),		# 0x139 0 None, 1 SHA-1, 2 SHA-256
		("Reserved7",		uint8_t),		# 0x13A
		("Reserved8",		uint8_t),		# 0x13B
		("Reserved9",		uint8_t),		# 0x13C
		("ChunkHashSize",	uint16_t),		# 0x13D
		("Reserved10",		uint8_t),		# 0x13F
		("Reserved11",		uint8_t),		# 0x140
		("ChunkSize",		uint32_t),		# 0x144 0x10000 (64KB)
		# 0x148
	]
	
	def ext_print(self) :
		hash_alg = ['None','SHA-1','SHA-256']
		
		MachineID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MachineID))
		PublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.PublicKey))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 20 R2, DnX Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minor', '%d' % self.Minor])
		pt.add_row(['Major', '%d' % self.Major])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Platform ID', '0x%0.4X' % self.PlatformID])
		pt.add_row(['Machine ID', '0x0' if MachineID == '00000000' * 4 else MachineID])
		pt.add_row(['Salt ID', '0x%0.8X' % self.SaltID])
		pt.add_row(['Public Key', '%s [...]' % PublicKey[:7]])
		pt.add_row(['Public Exponent', '0x%X' % self.PublicExponent])
		pt.add_row(['IFWI Region Count', '%d' % self.IFWIRegionCount])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		pt.add_row(['Reserved 2', '0x%X' % self.Reserved2])
		pt.add_row(['Reserved 3', '0x%X' % self.Reserved3])
		pt.add_row(['Reserved 4', '0x%X' % self.Reserved4])
		pt.add_row(['Reserved 5', '0x%X' % self.Reserved5])
		pt.add_row(['Hashes Array Header Major', '%d' % self.HashArrHdrMajor])
		pt.add_row(['Hashes Array Header Minor', '%d' % self.HashArrHdrMinor])
		pt.add_row(['Hashes Array Header Count', '%d' % self.HashArrHdrCount])
		pt.add_row(['Reserved 6', '0x%X' % self.Reserved6])
		pt.add_row(['Hashes Array Hash Algorithm', hash_alg[self.HashArrHashAlg]])
		pt.add_row(['Hashes Array Hash Size', '0x%X' % self.HashArrHashSize])
		pt.add_row(['IFWI Chunk Hash Algorithm', hash_alg[self.ChunkHashAlg]])
		pt.add_row(['Reserved 7', '0x%X' % self.Reserved7])
		pt.add_row(['Reserved 8', '0x%X' % self.Reserved8])
		pt.add_row(['Reserved 9', '0x%X' % self.Reserved9])
		pt.add_row(['IFWI Chunk Hash Size', '0x%X' % self.ChunkHashSize])
		pt.add_row(['Reserved 10', '0x%X' % self.Reserved10])
		pt.add_row(['Reserved 11', '0x%X' % self.Reserved11])
		pt.add_row(['IFWI Chunk Data Size', '0x%X' % self.ChunkSize])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_14_HashArray(ctypes.LittleEndianStructure) : # DnX 2 Hashes Array (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("HashArrSize",		uint32_t),		# 0x0 dwords
		("HashArrHash",		uint32_t*8),	# 0x4
		# 0x24
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		HashArrHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.HashArrHash))
		
		pt.title = col_y + 'Extension 20 R2, Hashes Array' + col_e
		pt.add_row(['Hashes Array Size', '0x%X' % (self.HashArrSize * 4)])
		pt.add_row(['Hashes Array Hash', HashArrHash])
		
		return pt
		
class CSE_Ext_14_RegionMap(ctypes.LittleEndianStructure) : # DnX R1/R2 Region Map (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Unknown',			uint32_t),		# 0x00 # 0 LBP 1, 1 LBP2, 4 SPI (?)
		('RegionOffset',	uint32_t),		# 0x04 # Start offset from rcipifwi file base
		('RegionSize',		uint32_t),		# 0x08 # Size of region after rcipifwi start offset
		# 0xC
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 20 R1/R2, IFWI Region Map' + col_e
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		pt.add_row(['IFWI Region Start', '0x%X' % self.RegionOffset])
		pt.add_row(['IFWI Region Size', '0x%X' % self.RegionSize])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_15(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - Unlock/Secure Token UTOK/STKN (SECURE_TOKEN_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("ExtVersion",		uint32_t),		# 0x08
		("PayloadVersion",	uint32_t),		# 0x0C
		("PartIDCount",		uint32_t),		# 0x10
		("TokenType",		uint32_t),		# 0x14 (TokenIdValues, tokens_list_broxton)
		("Flags",			uint32_t),		# 0x18
		("ExpirationSec",	uint32_t),		# 0x1C From Time Base
		("ManufLot",		uint32_t),		# 0x20
		("Reserved",		uint32_t*4),	# 0x24
		# 0x34
	]
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		frvalue = ['Yes','No']
		token_ids = {
					1: 'Intel Unlock',
					2: 'IDLM Unlock',
					3: 'OEM Unlock',
					4: 'PAVP Unlock',
					5: 'Visa Override',
					8: 'Change Device Lifecycle'
					}
		f1,f2,f3,f4,f5,f6,f7 = self.get_flags()
		
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Secure Token' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Extension Version', '%d' % self.ExtVersion])
		pt.add_row(['Payload Version', '%d' % self.PayloadVersion])
		pt.add_row(['Part ID Count', '%d' % self.PartIDCount])
		pt.add_row(['Token Type', token_ids[self.TokenType] if self.TokenType in token_ids else 'Unknown'])
		pt.add_row(['Single Boot', fvalue[f1]])
		pt.add_row(['Part Restricted', frvalue[f2]])
		pt.add_row(['Anti-Replay', frvalue[f3]])
		pt.add_row(['Time Limited', frvalue[f4]])
		pt.add_row(['Manufacturing Lot Restrict', fvalue[f5]])
		pt.add_row(['Manufacturing Part ID', fvalue[f6]])
		pt.add_row(['Flags Reserved', '0x%X' % f7])
		pt.add_row(['Expiration Seconds', '%d' % self.ExpirationSec])
		pt.add_row(['Manufacturing Lot', '0x%X' % self.ManufLot])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 4 else Reserved])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_15_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SingleBoot, flags.b.PartRestricted, flags.b.AntiReplay, flags.b.TimeLimited,\
		       flags.b.ManufacturingLotRestrict, flags.b.ManufacturingPartID, flags.b.Reserved
	
class CSE_Ext_15_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('SingleBoot', uint32_t, 1),
		('PartRestricted', uint32_t, 1),
		('AntiReplay', uint32_t, 1),
		('TimeLimited', uint32_t, 1),
		('ManufacturingLotRestrict', uint32_t, 1),
		('ManufacturingPartID', uint32_t, 1),
		('Reserved', uint32_t, 26)
	]

class CSE_Ext_15_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_15_Flags),
		('asbytes', uint32_t)
	]

# noinspection PyTypeChecker
class CSE_Ext_15_PartID(ctypes.LittleEndianStructure) : # After CSE_Ext_15 (SECURE_TOKEN_PARTID)
	_pack_ = 1
	_fields_ = [
		("PartID",			uint32_t*3),	# 0x00
		("Nonce",			uint32_t),		# 0x0C
		("TimeBase",		uint32_t),		# 0x10
		# 0x14
	]
	
	def ext_print(self) :
		PartID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.PartID))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Part ID' + col_e
		pt.add_row(['Part ID', 'N/A' if PartID == '00000000' * 3 else PartID])
		pt.add_row(['Nonce', '0x%X' % self.Nonce])
		pt.add_row(['Time Base', '0x%X' % self.TimeBase])
		
		return pt

class CSE_Ext_15_Payload(ctypes.LittleEndianStructure) : # After CSE_Ext_15_PartID (SECURE_TOKEN_PAYLOAD)
	_pack_ = 1
	_fields_ = [
		("KnobCount",		uint32_t),		# 0x00
		# 0x04
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Payload' + col_e
		pt.add_row(['Knob Count', '%d' % self.KnobCount])
		
		return pt

class CSE_Ext_15_Payload_Knob(ctypes.LittleEndianStructure) : # After CSE_Ext_15_Payload (SECURE_TOKEN_PAYLOAD_KNOB)
	_pack_ = 1
	_fields_ = [
		("ID",			uint32_t),		# 0x00 (KnobIdValues)
		("Data",		uint32_t),		# 0x04
		# 0x08
	]
	
	def __init__(self, variant, major, minor, hotfix, build, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.variant = variant
		self.major = major
		self.minor = minor
		self.hotfix = hotfix
		self.build = build
	
	def ext_print(self) :
		knob_ids = {
			0x80860001 : ['Intel Unlock', ['Disabled', 'Enabled']],
			0x80860002 : ['OEM Unlock', ['Disabled', 'Enabled']],
			0x80860003 : ['PAVP Unlock', ['Disabled', 'Enabled']],
			0x80860010 : ['Allow Visa Override', ['Disabled', 'Enabled']],
			0x80860011 : ['Enable DCI', ['No', 'Yes']],
			0x80860020 : ['ISH GDB Support', ['Disabled', 'Enabled']],
			0x80860030 : ['Boot Guard', ['Reserved', 'Disabled', 'No Enforcement', 'No Timeouts', 'No Enforcement & Timeouts']] \
			if self.variant == 'CSME' and self.major >= 12 else ['BIOS Secure Boot', ['Enforced', 'Allow RnD Keys & Policies', 'Disabled']],
			0x80860031 : ['Audio FW Authentication', ['Enforced', 'Allow RnD Keys', 'Disabled']],
			0x80860032 : ['ISH FW Authentication', ['Enforced', 'Allow RnD Keys', 'Disabled']],
			0x80860033 : ['IUNIT FW Authentication', ['Enforced', 'Allow RnD Keys', 'Disabled']],
			0x80860040 : ['Anti-Rollback', ['Enabled', 'Disabled']], # (BtGuardArbOemKeyManifest)
			0x80860051 : ['ABL Elements', ['Enabled', 'Disabled']], # Guess, not in XML/PFT
			0x80860101 : ['Change Device Lifecycle', ['No', 'Customer Care', 'RnD', 'Refurbish']],
			0x80860201 : ['Co-Signing', ['Enabled', 'Disabled']]
			}
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Payload Knob' + col_e
		pt.add_row(['ID', knob_ids[self.ID][0] if self.ID in knob_ids else 'Unknown: 0x%X' % self.ID])
		pt.add_row(['Data', knob_ids[self.ID][1][self.Data] if self.ID in knob_ids else 'Unknown: 0x%X' % self.Data])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_16(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - IFWI Partition Information (IFWI_PARTITION_MANIFEST_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('PartitionVer',	uint32_t),		# 0x10
		('DataFormatMinor',	uint16_t),		# 0x14 dword (0-15 Major, 16-31 Minor)
		('DataFormatMajor',	uint16_t),		# 0x16 dword (0-15 Major, 16-31 Minor)
		('InstanceID',		uint32_t),		# 0x18
		('Flags',			uint32_t),		# 0x1C Support multiple instances Y/N (for independently updated WCOD/LOCL partitions with multiple instances)
		('HashAlgorithm',	uint8_t),		# 0x20 0 None, 1 SHA-1, 2 SHA-256
		('HashSize',		uint8_t*3),		# 0x21
		('Hash',			uint32_t*8),	# 0x24 Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('Reserved',		uint32_t*5),	# 0x44
		# 0x58
	]
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		HashSize = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.HashSize))
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 22, IFWI Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Partition Version', '0x%X' % self.PartitionVer])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		pt.add_row(['Hash Type', ['None','SHA-1','SHA-256'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % int(HashSize, 16)])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Reserved', '0x%X' % int(Reserved, 16)])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_18(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - USB Type C IO Manageability Metadata (TCSS_METADATA_EXT, TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Reserved',		uint32_t),		# 0x08
		('HashType',		uint32_t),		# 0x0C
		('HashAlgorithm',	uint32_t),		# 0x10 0 SHA-1, 1 SHA-256, 2 MD5
		('HashSize',		uint32_t),		# 0x14
		('Hash',			uint32_t*8),	# 0x18
		# 0x38
	]
	
	# TCCS = USB Type C Sub-System
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 24, USB Type C IO Manageability Metadata' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', ['SHA-1','SHA-256','MD5'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_19(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - USB Type C MG Metadata (TCSS_METADATA_EXT, TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Reserved',		uint32_t),		# 0x08
		('HashType',		uint32_t),		# 0x0C
		('HashAlgorithm',	uint32_t),		# 0x10 0 SHA-1, 1 SHA-256, 2 MD5
		('HashSize',		uint32_t),		# 0x14
		('Hash',			uint32_t*8),	# 0x18
		# 0x38
	]
	
	# TCCS = USB Type C Sub-System
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 25, USB Type C MG Metadata' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', ['SHA-1','SHA-256','MD5'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_1A(ctypes.LittleEndianStructure) : # R1 - CSME11/CSME12/CSTXE3/CSTXE4/CSSPS4/CSSPS5 - USB Type C Thunderbolt Metadata (TCSS_METADATA_EXT, TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Reserved',		uint32_t),		# 0x08
		('HashType',		uint32_t),		# 0x0C
		('HashAlgorithm',	uint32_t),		# 0x10 0 SHA-1, 1 SHA-256, 2 MD5
		('HashSize',		uint32_t),		# 0x14
		('Hash',			uint32_t*8),	# 0x18
		# 0x38
	]
	
	# TCCS = USB Type C Sub-System
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 26, USB Type C Thunerbolt Metadata' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', ['SHA-1','SHA-256','MD5'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_32(ctypes.LittleEndianStructure) : # R1 - CSSPS4/CSSPS5 - SPS Platform ID (MFT_EXT_MANIFEST_PLATFORM_ID)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Type",			char*2),		# 0x08 RC Recovery, OP Operational
		("Platform",		char*2),		# 0x08 GE Greenlow, PU Purley, HA Harrisonville, PE Purley EPO, BA Bakerville
		("Reserved",		uint32_t),		# 0x0C
		# 0x10
	]
	
	def ext_print(self) :
		type_str = self.Type.decode('utf-8')
		platform_str = self.Platform.decode('utf-8')
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 50, SPS Platform ID' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Type', 'Unknown' if type_str not in cssps_type_fw else cssps_type_fw[type_str]])
		pt.add_row(['Platform', 'Unknown' if platform_str not in cssps_platform else cssps_platform[platform_str]])
		pt.add_row(['Reserved', '0x0' if self.Reserved == 0 else '0x%X' % self.Reserved])
		
		return pt

# noinspection PyTypeChecker
class UTFL_Header(ctypes.LittleEndianStructure) : # Unlock Token Flags (DebugTokenSubPartition)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('DelayedAuthMode',	uint8_t),		# 0x04
		('Reserved',		uint8_t*27),	# 0x05
		# 0x20 (End of 8KB UTOK)
	]
	
	def hdr_print(self) :
		Reserved = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Unlock Token Flags' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Delayed Authentication Mode', ['No','Yes'][self.DelayedAuthMode]])
		pt.add_row(['Reserved', '0x0' if Reserved in ('00' * 27,'FF' * 27) else Reserved])
		
		return pt
		
class BPDT_Header(ctypes.LittleEndianStructure) : # Boot Partition Descriptor Table 1.6 & 2.0 (PrimaryBootPartition, SecondaryBootPartition, PrimaryBootPartitionNC, BootPartitionLayout)
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00 AA550000 Boot, AA55AA00 Recovery
		('DescCount',		uint16_t),		# 0x04 Minimum 6 Entries
		('BPDTVersion',		uint16_t),		# 0x06 1 IFWI 1.6 & 2.0, 2 IFWI 1.7
		('Reserved',		uint16_t),		# 0x08
		('Checksum',		uint16_t),		# 0x0A From BPDT up to and including S-BPDT
		('IFWIVersion',		uint32_t),		# 0x0C Unique mark from build server
		('FitMajor',		uint16_t),		# 0x10
		('FitMinor',		uint16_t),		# 0x12
		('FitHotfix',		uint16_t),		# 0x14
		('FitBuild',		uint16_t),		# 0x16
		# 0x18 (0x200 <= Header + Entries <= 0x1000)
	]
	
	# Used at APL/CNP/GLK IFWI 1.6 & 2.0 platforms
	# https://github.com/coreboot/coreboot/blob/master/util/cbfstool/ifwitool.c
	
	def hdr_print(self) :
		bpdt_ver = {1 : '1.6 & 2.0', 2 : '1.7'}
		
		fit_ver = '%d.%d.%d.%d' % (self.FitMajor,self.FitMinor,self.FitHotfix,self.FitBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Boot Partition Descriptor Table 1.6 & 2.0 Header' + col_e
		pt.add_row(['Signature', '0x%0.8X' % self.Signature])
		pt.add_row(['Descriptor Count', '%d' % self.DescCount])
		pt.add_row(['BPDT Version', bpdt_ver[self.BPDTVersion] if self.BPDTVersion in bpdt_ver else 'Unknown'])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		pt.add_row(['IFWI Version', '%d' % self.IFWIVersion])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		
		return pt
		
class BPDT_Header_2(ctypes.LittleEndianStructure) : # Boot Partition Descriptor Table 1.7 (PrimaryBootPartition, PrimaryBootPartitionNC)
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00 AA550000 Boot, AA55AA00 Recovery
		('DescCount',		uint16_t),		# 0x04 Minimum 6 Entries
		('BPDTVersion',		uint8_t),		# 0x06 1 IFWI 1.6 & 2.0, 2 IFWI 1.7
		('BPDTConfig',		uint8_t),		# 0x07 0 BPDT Redundancy Support, 1-7 Reserved
		('Checksum',		uint32_t),		# 0x08 CRC32 of entire BPDT (Header + Entries) without Signature
		('IFWIVersion',		uint32_t),		# 0x0C Unique mark from build server
		('FitMajor',		uint16_t),		# 0x10
		('FitMinor',		uint16_t),		# 0x12
		('FitHotfix',		uint16_t),		# 0x14
		('FitBuild',		uint16_t),		# 0x16
		# 0x18 (0x200 <= Header + Entries <= 0x1000)
	]
	
	# Used at Lake Field (LKF) IFWI 1.7 platform
	
	def hdr_print(self) :
		bpdt_ver = {1 : '1.6 & 2.0', 2 : '1.7'}
		f1,f2 = self.get_flags()
		
		fit_ver = '%d.%d.%d.%d' % (self.FitMajor,self.FitMinor,self.FitHotfix,self.FitBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Boot Partition Descriptor Table 1.7 Header' + col_e
		pt.add_row(['Signature', '0x%0.8X' % self.Signature])
		pt.add_row(['Descriptor Count', '%d' % self.DescCount])
		pt.add_row(['BPDT Version', bpdt_ver[self.BPDTVersion] if self.BPDTVersion in bpdt_ver else 'Unknown'])
		pt.add_row(['BPDT Redundancy', ['No','Yes'][f1]])
		pt.add_row(['BPDT Config Reserved', '0x%X' % f2])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		pt.add_row(['IFWI Version', '0x%X' % self.IFWIVersion])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		
		return pt
		
	def get_flags(self) :
		flags = BPDT_Header_2_GetFlags()
		flags.asbytes = self.BPDTConfig
		
		return flags.b.BPDT_R_S, flags.b.Reserved
	
class BPDT_Header_2_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('BPDT_R_S', uint8_t, 1),
		('Reserved', uint8_t, 7),
	]

class BPDT_Header_2_GetFlags(ctypes.Union):
	_fields_ = [
		('b', BPDT_Header_2_Flags),
		('asbytes', uint8_t)
	]

class BPDT_Entry(ctypes.LittleEndianStructure) : # (BpdtEntry)
	_pack_ = 1
	_fields_ = [
		("Type",			uint16_t),		# 0x00 dword at CNP/GLK IFWI 1.6 & 2.0 (?)
		("Flags",			uint16_t),		# 0x02 only at APL IFWI 2.0 (?)
		("Offset",			uint32_t),		# 0x04
		("Size",			uint32_t),		# 0x08
		# 0xC
	]
	
	# It is probable that Flags field is relevant to APL (IFWI 2.0) platform only
	# At CNP/GLK (IFWI 1.6 & 2.0) and LKF (IFWI 1.7), Type is uint32_t without Flags
	
	def info_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Boot Partition Descriptor Table Entry' + col_e
		pt.add_row(['Type', bpdt_dict[self.Type] if self.Type in bpdt_dict else 'Unknown'])
		pt.add_row(['Split Sub-Partition 1st Part', fvalue[f1]])
		pt.add_row(['Split Sub-Partition 2nd Part', fvalue[f2]])
		pt.add_row(['Code Sub-Partition', fvalue[f3]])
		pt.add_row(['UMA Cachable', fvalue[f4]])
		pt.add_row(['Flags Reserved', '0x%X' % f5])
		pt.add_row(['Offset', '0x%X' % self.Offset])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
	
	def get_flags(self) :
		flags = BPDT_Entry_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SplitSubPartitionFirstPart, flags.b.SplitSubPartitionSecondPart, flags.b.CodeSubPartition,\
		       flags.b.UMACachable, flags.b.Reserved
	
class BPDT_Entry_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('SplitSubPartitionFirstPart', uint16_t, 1), # 1st part in this LBP, 2nd part in other LBP (for up to 1 non-critical Sub-Partition)
		('SplitSubPartitionSecondPart', uint16_t, 1), # 1st part in other LBP, 2nd part in this LBP (for up to 1 non-critical Sub-Partition)
		('CodeSubPartition', uint16_t, 1), # Sub-Partition Contains Directory Structure
		('UMACachable', uint16_t, 1), # Copied to DRAM cache if required for a reset flow (for all Sub-Partition except BIOS-based)
		('Reserved', uint16_t, 12)
	]

class BPDT_Entry_GetFlags(ctypes.Union):
	_fields_ = [
		('b', BPDT_Entry_Flags),
		('asbytes', uint16_t)
	]

# IFWI BPDT Entry Types
# Names from $MN2 Manifest
bpdt_dict = {
			0 : 'SMIP', # OEM-SMIP Partition
			1 : 'RBEP', # ROM Boot Extensions Partition (CSE-RBE)
			2 : 'FTPR', # Fault Tolerant Partition (CSE-BUP)
			3 : 'UCOD', # Microcode Partition
			4 : 'IBBP', # IBB Partition
			5 : 'S-BPDT', # Secondary BPDT
			6 : 'OBBP', # OBB Partition
			7 : 'NFTP', # Non-Fault Tolerant Partition (CSE-MAIN)
			8 : 'ISHC', # ISH Partition
			9 : 'DLMP', # IDLM Partition
			10 : 'UEPB', # IFP Override/Bypass Partition
			11 : 'UTOK', # Debug Tokens Partition
			12 : 'UFS PHY', # UFS PHY Partition
			13 : 'UFS GPP LUN', # UFS GPP LUN Partition
			14 : 'PMCP', # PMC Partition
			15 : 'IUNP', # IUnit Partition
			16 : 'NVM Config', # NVM Configuration
			17 : 'UEP', # Unified Emulation Partition
			18 : 'WCOD', # CSE-WCOD Partition
			19 : 'LOCL', # CSE-LOCL Partition
			20 : 'OEMP', # OEM KM Partition
			23 : 'IOMP', # USB Type C IO Manageability Partition (UIOM)
			24 : 'MGPP', # USB Type C MG Partition
			25 : 'TBTP', # USB Type C Thunerbolt Partition (TBT)
			26 : 'PLTS', # Platform Settings
			}

# CSE Extensions 0x00-0x16, 0x18-0x1A, 0x32
ext_tag_all = list(range(23)) + list(range(24,27)) + [50]

# CSME 12 Revised Extensions
ext_tag_rev_hdr_csme12 = [0x14]

# CSME 12 Revised Extension Modules
ext_tag_rev_mod_csme12 = [0x1,0xD]

# CSSPS 5 Revised Extensions
ext_tag_rev_hdr_cssps5 = []

# CSSPS 5 Revised Extension Modules
ext_tag_rev_mod_cssps5 = [0x0]

# CSE Extensions without Modules
ext_tag_mod_none = [0x4,0xA,0xC,0x10,0x11,0x13,0x16,0x18,0x19,0x1A,0x32]

# CSE Extensions with Module Count
ext_tag_mod_count = [0x1,0x2,0x12,0x14,0x15]

# CSE SPS SKU Type ID
cssps_type_fw = {'RC': 'Recovery', 'OP': 'Operational'}

# CSE SPS SKU Platform ID
cssps_platform = {'GE': 'Greenlow', 'PU': 'Purley', 'HA': 'Harrisonville', 'PE': 'Purley EPO', 'BA': 'Bakerville'}

# CSE Known Bad Partition/Module Hashes
cse_known_bad_hashes = [
('0833D56054E84412DDA84B400D13A13160D4ECEF6ABE407023D0AB502EA2A3EE','2394556989CA959938370811AD3937AAC02354671DB02704404E69CB816AFCF8'), # CSME 11.8.50.3425_SLM_H_D0_PRD > FTPR > FTPR.man
('31B9DB9372F1C20145D84F1F554A207812A4F7832829565B4E3DE8A929139B8B','A16380E901203139AE2534188E54D98210F29DB3FBB21DF16A375F0401837091'), # CSME 11.8.50.3425_SLM_LP_C0_NPDM_PRD > FTPR > FTPR.man
('B42458010144CB5708148C31590637372021FCBF21CE079679772FBD2990CF5F','CFB464D442FB477C1642B3C8F60809F764C727509A2112AB921430E2625ECB9B'), # CSME 11.8.50.3399_COR_H_D0_PRD > WCOD 24FD > mu_init
('89BFFD3CFAA25C0CA3AE4ABBDBFAA06F21566CEE653EF65401A80EAB36EB6F08','3A294E6196783ED22310AA3031706E7F6B774FCAFE479D5AFA1C6433E192652E'), # CSME 11.8.50.3399_COR_H_D0_PRD > WCOD 24FD > mu_d0d3
('B63D75602385A6CFE56EC8B79481E46074B1E39217F191B3C9AB961CE4A03139','3B3866517F1C3B1F07BA9692A8B1599F5DDAA24BFFB3F704C711F30D1E067288'), # CSME 11.8.50.3399_COR_H_D0_PRD > WCOD 24FD > umac_d0
('470A0E018AF18F6477029AFE0207307BCD77991272CF23DA741712DAB109C8F8','B570786DAAA91A9A0119BD6F4143160044B054663FB06317650AE77DD6842401'), # CSME 11.8.50.3399_COR_H_D0_PRD > WCOD 24F3 > mu_init
('35C7D3383E6B380C3B07CB41444448EC63E3F219C77E7D99DA19C5BFB856713B','785F395BC28544253332ACB1C5C65CDA7C24662D55DC8AB8F0E56543B865A4C3'), # CSME 11.8.50.3399_COR_H_D0_PRD > WCOD 24F3 > mu_d0d3
('4DCF921DC0A48D2967063969ED1314CB17AA03E86635A366E2750BE43A219D95','058C09ABE1D1AB2B28D1D06153908EDAE8B420967D54EC4F1F99AC0D0101454C'), # CSME 11.8.50.3399_COR_H_D0_PRD > WCOD 24F3 > umac_d0
('37D7E80D7AA0086DC6F97458C78A6F1C1EDB6E6BF3300BD85272952CD0F26015','6D5988416826AE30DA3D74062582A133B14B4D2E232CC98CBC83C77CD3955DCA'), # CSSPS 05.00.03.107_XX_SKU3_PRD_REC > FTPR > FTPR.man
('4B23027311E2E28EAFA269C507B0A6D1F1BAD5D654CF042212C8F83C53E1D9F9','097ABC45CF6A316F606DE5233B5B1FB18E65BE0D285EA3ABC984E16931EB6CE0'), # CSSPS 05.00.03.107_XX_SKU3_PRD_OPR > OPR > FTPR.man
('592ECB560234A46E6818118A561F2D01F72149203610F4C9D06D2A6F79A7AEF9','97709C6B21B551C35125EF740B183A10ADFD7865E4D5C0BC38220694438E9DE2'), # CSSPS 05.00.03.101_XX_SKU3_PRD_REC > FTPR > FTPR.man
('9869DB38F915FB9FD1D5ACD80A06F166EAF7494D79D8FC42D63DC87CB230AD8C','01AE49D94E580E42BF16065D4773AB73695403DD7C1B560ED76C41770EB9BB4C'), # CSSPS 05.00.03.101_XX_SKU3_PRD_OPR > OPR > FTPR.man
]

# CSE Extension Structures
ext_dict = {
			'CSE_Ext_00' : CSE_Ext_00,
			'CSE_Ext_01' : CSE_Ext_01,
			'CSE_Ext_02' : CSE_Ext_02,
			'CSE_Ext_03' : CSE_Ext_03,
			'CSE_Ext_04' : CSE_Ext_04,
			'CSE_Ext_05' : CSE_Ext_05,
			'CSE_Ext_06' : CSE_Ext_06,
			'CSE_Ext_07' : CSE_Ext_07,
			'CSE_Ext_08' : CSE_Ext_08,
			'CSE_Ext_09' : CSE_Ext_09,
			'CSE_Ext_0A' : CSE_Ext_0A,
			'CSE_Ext_0B' : CSE_Ext_0B,
			'CSE_Ext_0C' : CSE_Ext_0C,
			'CSE_Ext_0D' : CSE_Ext_0D,
			'CSE_Ext_0E' : CSE_Ext_0E,
			'CSE_Ext_0F' : CSE_Ext_0F,
			'CSE_Ext_10' : CSE_Ext_10,
			'CSE_Ext_11' : CSE_Ext_11,
			'CSE_Ext_12' : CSE_Ext_12,
			'CSE_Ext_13' : CSE_Ext_13,
			'CSE_Ext_14' : CSE_Ext_14,
			'CSE_Ext_14_R2' : CSE_Ext_14_R2,
			'CSE_Ext_15' : CSE_Ext_15,
			'CSE_Ext_16' : CSE_Ext_16,
			'CSE_Ext_18' : CSE_Ext_18,
			'CSE_Ext_19' : CSE_Ext_19,
			'CSE_Ext_1A' : CSE_Ext_1A,
			'CSE_Ext_32' : CSE_Ext_32,
			'CSE_Ext_00_Mod' : CSE_Ext_00_Mod,
			'CSE_Ext_00_Mod_R2' : CSE_Ext_00_Mod_R2,
			'CSE_Ext_01_Mod' : CSE_Ext_01_Mod,
			'CSE_Ext_01_Mod_R2' : CSE_Ext_01_Mod_R2,
			'CSE_Ext_02_Mod' : CSE_Ext_02_Mod,
			'CSE_Ext_03_Mod' : CSE_Ext_03_Mod,
			'CSE_Ext_05_Mod' : CSE_Ext_05_Mod,
			'CSE_Ext_06_Mod' : CSE_Ext_06_Mod,
			'CSE_Ext_07_Mod' : CSE_Ext_07_Mod,
			'CSE_Ext_08_Mod' : CSE_Ext_08_Mod,
			'CSE_Ext_09_Mod' : CSE_Ext_09_Mod,
			'CSE_Ext_0B_Mod' : CSE_Ext_0B_Mod,
			'CSE_Ext_0D_Mod' : CSE_Ext_0D_Mod,
			'CSE_Ext_0D_Mod_R2' : CSE_Ext_0D_Mod_R2,
			'CSE_Ext_0E_Mod' : CSE_Ext_0E_Mod,
			'CSE_Ext_0F_Mod' : CSE_Ext_0F_Mod,
			'CSE_Ext_12_Mod' : CSE_Ext_12_Mod,
			'CSE_Ext_14_HashArray' : CSE_Ext_14_HashArray,
			'CSE_Ext_14_RegionMap' : CSE_Ext_14_RegionMap,
			'CSE_Ext_15_PartID' : CSE_Ext_15_PartID,
			'CSE_Ext_15_Payload' : CSE_Ext_15_Payload,
			'CSE_Ext_15_Payload_Knob' : CSE_Ext_15_Payload_Knob,
			}
			
# Key Manifest Hash Usages
key_dict = {
			# Intel (0-31)
			0 : 'CSE BUP', # Fault Tolerant Partition (FTPR)
			1 : 'CSE Main', # Non-Fault Tolerant Partition (NFTP)
			2 : 'PMC', # Power Management Controller
			6 : 'USB Type C IOM', # USB Type C I/O Manageability
			7 : 'USB Type C MG', # # USB Type C Manageability (?)
			8 : 'USB Type C TBT', # USB Type C Thunderbolt
			9 : 'WCOD', # Wireless Microcode
			10 : 'LOCL', # AMT Localization
			11 : 'Unlock Token',
			13 : 'USB Type C D-PHY',
			# OEM (32-127)
			32 : 'Boot Policy',
			33 : 'iUnit Boot Loader', # Imaging Unit (Camera)
			34 : 'iUnit Main Firmware',
			35 : 'cAVS Image 0', # Clear Audio Voice Speech
			36 : 'cAVS Image 1',
			37 : 'IFWI', # Integrated Firmware Image
			38 : 'OS Boot Loader',
			39 : 'OS Kernel',
			40 : 'OEM SMIP', # Signed Master Image Profile
			41 : 'ISH Main', # Integrated Sensor Hub
			42 : 'ISH BUP',
			43 : 'OEM Debug Token',
			44 : 'OEM Life Cycle',
			45 : 'OEM Key',
			46 : 'SilentLake VMM',
			47 : 'OEM Key Attestation',
			48 : 'OEM DAL', # Dynamic Application Loader
			49 : 'OEM DNX IFWI R1', # XML v1.0 (Download and Execute v1)
			53 : 'OEM DNX IFWI R2', # XML v2.4 (Download and Execute v2)
			}

# Unpack Engine CSE firmware
def cse_unpack(fpt_part_all, bpdt_part_all, fw_type, file_end, fpt_start, fpt_chk_fail) :
	print()
	fpt_hdr_0_print = None
	cpd_match_ranges = []
	len_fpt_part_all = len(fpt_part_all)
	len_bpdt_part_all = len(bpdt_part_all)
	ansi_escape = re.compile(r'\x1b[^m]*m') # Generate ANSI Color and Font Escape Character Sequences
	
	# Get Firmware Type DB
	fw_type, type_db = fw_types(fw_type)
	
	# Create firmware extraction folder
	if variant == 'CSSPS' : fw_name = "%0.2d.%0.2d.%0.2d.%0.3d_%s_%s_%s" % (major, minor, hotfix, build, sku_db, rel_db, type_db)
	else : fw_name = "%d.%d.%d.%0.4d_%s_%s_%s" % (major, minor, hotfix, build, sku_db, rel_db, type_db)
	if os.path.isdir(os.path.join(mea_dir, fw_name, '')) : shutil.rmtree(os.path.join(mea_dir, fw_name, ''))
	os.mkdir(os.path.join(mea_dir, fw_name, ''))
	
	# Show & Store CSE Layout Table info
	if cse_lt_exist :
		cse_lt_info = cse_lt.hdr_print()
		cse_lt_fname = os.path.join(mea_dir, fw_name, 'CSE LT [0x%0.6X]' % cse_lt_off)
		
		print('%s\n' % cse_lt_info)
		
		print(col_m + 'CSE Layout Table Checksum is UNKNOWN\n' + col_e) # Not used yet (?)
		
		with open(cse_lt_fname + '.bin', 'w+b') as cse_lt_file : cse_lt_file.write(reading[cse_lt_off:cse_lt_off + cse_lt_size])
		with open(cse_lt_fname + '.txt', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write(ansi_escape.sub('', '\n%s' % cse_lt_info))
		
		pt_dcselt.title = col_y + 'Detected %d Partition(s) at CSE LT [0x%0.6X]' % (len(cse_lt_part_all), cse_lt_off) + col_e
		print('%s\n' % pt_dcselt) # Local copy with different title for cse_unpack function
		
		cse_lt_hdr = ansi_escape.sub('', str(pt_dcselt))
		with open(cse_lt_fname + '.txt', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n%s' % cse_lt_hdr)
		
		print(col_y + '--> Stored CSE Layout Table [0x%0.6X - 0x%0.6X]\n' % (cse_lt_off, cse_lt_off + cse_lt_size) + col_e)
		
		for part in cse_lt_part_all :
			part_name = part[0]
			part_start = part[1]
			#part_size = part[2]
			part_end = part[3]
			part_empty = part[4]
			
			if not part_empty : # Skip Empty Partitions
				file_name = os.path.join(fw_name, 'CSE LT ' + part_name + ' [0x%0.6X].bin' % part_start) # Start offset covers any cases with duplicate name entries (CSE_Layout_Table_17)
				mod_fname = os.path.join(mea_dir, file_name)
				
				with open(mod_fname, 'w+b') as part_file : part_file.write(reading[part_start:part_end])
			
				print(col_y + '--> Stored CSE LT Partition "%s" [0x%0.6X - 0x%0.6X]\n' % (part[0], part_start, part_end) + col_e)
	
	# Parse all Flash Partition Table ($FPT) entries
	if len_fpt_part_all :
		init_fpt_ver = reading[fpt_start + 0x8] # $FPT Version Tag
		if reading[fpt_start:fpt_start + 0x4] == b'$FPT' :
			fpt_romb_exist = False
			if init_fpt_ver == 0x21 : fpt_hdr_1 = get_struct(reading, fpt_start, FPT_Header_21)
			else : fpt_hdr_1 = get_struct(reading, fpt_start, FPT_Header)
		else :
			fpt_romb_exist = True
			if init_fpt_ver == 0x21 : fpt_hdr_1 = get_struct(reading, fpt_start + 0x10, FPT_Header_21)
			else : fpt_hdr_1 = get_struct(reading, fpt_start + 0x10, FPT_Header)
		
		if fpt_romb_exist :
			fpt_hdr_0 = get_struct(reading, fpt_start, FPT_Pre_Header)
			fpt_hdr_0_print = fpt_hdr_0.hdr_print_cse()
			print('%s\n' % fpt_hdr_0_print)
		
		fpt_hdr_1_print = fpt_hdr_1.hdr_print_cse()
		print('%s' % fpt_hdr_1_print)
		
		if not fpt_chk_fail : print(col_g + '\nFlash Partition Table Checksum is VALID\n' + col_e)
		else :
			if param.me11_mod_bug :
				input(col_r + '\nFlash Partition Table Checksum is INVALID\n' + col_e) # Debug
			else :
				print(col_r + '\nFlash Partition Table Checksum is INVALID\n' + col_e)
		
		pt = ext_table([col_y + 'Name' + col_e, col_y + 'Start' + col_e, col_y + 'End' + col_e, col_y + 'ID' + col_e, col_y + 'Type' + col_e,
		                col_y + 'Valid' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt.title = col_y + 'Detected %d Partition(s) at $FPT [0x%0.6X]' % (len_fpt_part_all, fpt_start) + col_e
		
		for part in fpt_part_all :
			pt.add_row([part[0].decode('utf-8'), '0x%0.6X' % part[1], '0x%0.6X' % part[2], '%0.4X' % part[3], part[4], part[5], part[6]]) # Store Partition details
		
		print(pt) # Show Partition details
		
		if cse_lt_exist : fpt_fname = os.path.join(mea_dir, fw_name, 'CSE LT Data [0x%0.6X]' % fpt_start)
		else : fpt_fname = os.path.join(mea_dir, fw_name, 'FPT [0x%0.6X]' % fpt_start)
		
		# Store Flash Partition Table ($FPT) Data
		if not cse_lt_exist : # Stored at CSE LT section too
			with open(fpt_fname + '.bin', 'w+b') as fpt_file : fpt_file.write(reading[fpt_start:fpt_start + 0x1000]) # $FPT size is 4K
			
			print(col_y + '\n--> Stored Flash Partition Table [0x%0.6X - 0x%0.6X]' % (fpt_start, fpt_start + 0x1000) + col_e)
		
		# Store Flash Partition Table ($FPT) Info
		# Ignore Colorama ANSI Escape Character Sequences
		if fpt_romb_exist :
			fpt_hdr_romb = ansi_escape.sub('', str(fpt_hdr_0_print))
			with open(fpt_fname + '.txt', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s' % fpt_hdr_romb)
		
		fpt_hdr_main = ansi_escape.sub('', str(fpt_hdr_1_print))
		fpt_hdr_part = ansi_escape.sub('', str(pt))
		with open(fpt_fname + '.txt', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s\n%s' % (fpt_hdr_main, fpt_hdr_part))
		
		# Charted Partitions include fpt_start, Uncharted do not (RGN only, non-SPI)
		for part in fpt_part_all :
			part_name = part[0].decode('utf-8')
			part_start = part[1]
			part_end = part[2]
			part_inid = part[3]
			part_type = part[4]
			part_empty = part[6]
			
			if not part_empty : # Skip Empty Partitions
				part_name += ' %0.4X' % part_inid
			
				file_name = os.path.join(fw_name, part_name + ' [0x%0.6X].bin' % part_start) # Start offset covers any cases with duplicate name entries (Joule_C0-X64-Release)
				mod_fname = os.path.join(mea_dir, file_name)
				
				with open(mod_fname, 'w+b') as part_file : part_file.write(reading[part_start:part_end])
			
				print(col_y + '\n--> Stored $FPT %s Partition "%s" [0x%0.6X - 0x%0.6X]' % (part_type, part_name, part_start, part_end) + col_e)
				
				if part[0] in [b'UTOK',b'STKN'] :
					ext_print,x1 = key_anl(mod_fname, [], part_name, [variant, major, minor, hotfix, build]) # Retrieve & Store UTOK/STKN Extension Info
					
					# Print Manifest/Metadata/Key Extension Info
					for index in range(0, len(ext_print), 2) : # Only Name (index), skip Info (index + 1)
						if str(ext_print[index]).startswith(part_name) :
							if param.me11_mod_ext : print() # Print Manifest/Metadata/Key Extension Info
							for ext in ext_print[index + 1] :
								ext_str = ansi_escape.sub('', str(ext))
								with open(mod_fname + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
								if param.me11_mod_ext : print(ext) # Print Manifest/Metadata/Key Extension Info
							break
							
				if part[0] == b'MFS' : parse_MFS(mod_fname, part_type, part_name, part_start, part_end)
	
	# Parse all Boot Partition Description Table (BPDT/IFWI) entries
	if len_bpdt_part_all :
		[print('\n%s' % hdr) for hdr in bpdt_hdr_all]
		
		pt = ext_table([col_y + 'Name' + col_e, col_y + 'Type' + col_e, col_y + 'Partition' + col_e, col_y + 'ID' + col_e, col_y + 'Start' + col_e, col_y + 'End' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt.title = col_y + 'Detected %d Partition(s) at %d BPDT(s)' % (len_bpdt_part_all, len(bpdt_hdr_all)) + col_e
		
		for part in bpdt_part_all :
			pt.add_row([part[0], '%0.2d' % part[3], part[5], '%0.4X' % part[6], '0x%0.6X' % part[1], '0x%0.6X' % part[2], part[4]]) # Store Entry details
		
		print('\n%s' % pt) # Show Entry details
		
		if cse_lt_exist : bpdt_fname = os.path.join(mea_dir, fw_name, 'CSE LT Boot x [%d]' % len(bpdt_hdr_all))
		else : bpdt_fname = os.path.join(mea_dir, fw_name, 'BPDT [%d]' % len(bpdt_hdr_all))
		
		# Store Boot Partition Description Table (BPDT/IFWI) Info
		with open(bpdt_fname + '.txt', 'a', encoding = 'utf-8') as bpdt_file :
			for hdr in bpdt_hdr_all : bpdt_file.write('\n%s' % ansi_escape.sub('', str(hdr)))
			bpdt_file.write('\n%s' % ansi_escape.sub('', str(pt)))
		
		# Store Boot Partition Descriptor Table (BPDT/IFWI) Data
		if not cse_lt_exist : # Stored at CSE LT section too
			with open(bpdt_fname + '.bin', 'w+b') as bpdt_file :
				for bpdt in bpdt_data_all : bpdt_file.write(bpdt)
				
			print(col_y + '\n--> Stored Boot Partition Descriptor Table(s) [%d]' % len(bpdt_hdr_all) + col_e)
		
		for part in bpdt_part_all :
			part_name = part[0]
			part_start = part[1]
			part_end = part[2]
			part_empty = part[4]
			part_order = part[5]
			part_inid = part[6]
			
			if not part_empty : # Skip Empty Partitions
				part_name += ' %0.4X' % part_inid
				
				file_name = os.path.join(fw_name, part_name + ' [0x%0.6X].bin' % part_start) # Start offset covers any cases with duplicate name entries ("Unknown" etc)
				mod_fname = os.path.join(mea_dir, file_name)
				
				with open(mod_fname, 'w+b') as part_file : part_file.write(reading[part_start:part_end])
				
				part_data = reading[part_start:part_end]
				with open(os.path.join(mea_dir, file_name), 'w+b') as part_file : part_file.write(part_data)
				
				print(col_y + '\n--> Stored BPDT %s Partition "%s" [0x%0.6X - 0x%0.6X]' % (part_order, part_name, part_start, part_end) + col_e)
				
				if part[0] in ['UTOK'] :
					ext_print,x1 = key_anl(mod_fname, [], part_name, [variant, major, minor, hotfix, build]) # Retrieve & Store UTOK Extension Info
					
					# Print Manifest/Metadata/Key Extension Info
					for index in range(0, len(ext_print), 2) : # Only Name (index), skip Info (index + 1)
						if str(ext_print[index]).startswith(part_name) :
							if param.me11_mod_ext : print() # Print Manifest/Metadata/Key Extension Info
							for ext in ext_print[index + 1] :
								ext_str = ansi_escape.sub('', str(ext))
								with open(mod_fname + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
								if param.me11_mod_ext : print(ext) # Print Manifest/Metadata/Key Extension Info
							break
							
				if part[0] == 'MFS' : parse_MFS(mod_fname, part_order, part_name, part_start, part_end)
	
	# Parse all Code Partition Directory ($CPD) entries
	# Better to separate $CPD from $FPT/BPDT to avoid duplicate FTUP/NFTP ($FPT) issue
	cpd_pat = re.compile(br'\x24\x43\x50\x44.\x00\x00\x00\x01\x01\x10', re.DOTALL) # $CPD detection
	cpd_match_store = list(cpd_pat.finditer(reading))
	
	# Store all Code Partition Directory ranges
	if len(cpd_match_store) :
		for cpd in cpd_match_store : cpd_match_ranges.append(cpd)
	
	# Parse all Code Partition Directory entries
	for cpdrange in cpd_match_ranges :
		(start_cpd_emod, end_cpd_emod) = cpdrange.span()
		
		cpd_offset_e,cpd_mod_attr_e,cpd_ext_attr_e,x3,x4,ext_print,x6,x7,ext_phval,x9,ext_dnx_val,x11,x12,x13 \
		= ext_anl('$CPD', start_cpd_emod, file_end, [variant, major, minor, hotfix, build])
		
		mod_anl(cpd_offset_e, cpd_mod_attr_e, cpd_ext_attr_e, fw_name, ext_print, ext_phval, ext_dnx_val)
	
# Analyze Engine CSE $CPD Offset & Extensions
# noinspection PyUnusedLocal
def ext_anl(input_type, input_offset, file_end, ftpr_var_ver) :
	vcn = -1
	in_id = 0
	cpd_num = -1
	mn2_size = -1
	ext_psize = -1
	mea_phash = -1
	fw_0C_lbg = -1
	fw_0C_sku1 = -1
	fw_0C_sku2 = -1
	cpd_offset = -1
	mn2_offset = -1
	dnx_version = -1
	dnx_rcip_off = -1
	dnx_rcip_len = -1
	start_man_match = -1
	dnx_hash_arr_off = -1
	hash_arr_valid_count = 0
	chunk_hash_valid_count = 0
	mn2_hdr = None
	msg_shown = False
	oem_config = False
	oem_signed = False
	ext_pname = ''
	ibbp_all = []
	ibbp_del = []
	ext_print = []
	ibbp_bpm = ['IBBL', 'IBB', 'OBB']
	cpd_ext_hash = []
	cpd_mod_attr = []
	cpd_ext_attr = []
	ext_err_stor = []
	cpd_mn2_info = []
	cpd_mod_names = []
	cpd_ext_names = []
	ext32_info = ['UNK', 'XX']
	ext12_info = ['00000000', 'NA', 0, 'NA'] # SKU Capabilities, SKU Type, LBG Support, SKU Platform
	ext_dnx_val = [-1, False, False] # [DnXVer, AllHashArrValid, AllChunkValid]
	ext_phval = [False, False, 0, 0]
	mn2_sigs = [False, -1, -1, True, -1, None]
	variant,major,minor,hotfix,build = ftpr_var_ver
	
	if input_type.startswith('$MN2') :
		start_man_match = input_offset
		
		# Scan backwards for $CPD (max $CPD size = 0x2000, .$MN2 Tag starts at 0x1B, works with both RGN --> $FPT & UPD --> 0x0)
		for offset in range(start_man_match + 2, start_man_match + 2 - 0x201D, -4) : # Search from MN2 (no .$) to find CPD (no $) at 1, before loop break at 0
			if b'$CPD' in reading[offset - 1:offset - 1 + 4] :
				cpd_offset = offset - 1 # Adjust $CPD to 0 (offset - 1 = 1 - 1 = 0)
				break # Stop at first detected $CPD
	
	elif input_type.startswith('$CPD') :
		cpd_offset = input_offset
		
		# Scan forward for .$MN2 (max $CPD size = 0x2000, .$MN2 Tag ends at 0x20, works with both RGN --> $FPT & UPD --> 0x0)
		mn2_pat = re.compile(br'\x00\x24\x4D\x4E\x32').search(reading[cpd_offset:cpd_offset + 0x2020]) # .$MN2 detection, 0x00 for extra sanity check
		if mn2_pat is not None :
			(start_man_match, end_man_match) = mn2_pat.span()
			start_man_match += cpd_offset
			end_man_match += cpd_offset
	
	# $MN2 existence not mandatory
	if start_man_match != -1 :
		mn2_hdr = get_struct(reading, start_man_match - 0x1B, MN2_Manifest)
		mn2_offset = start_man_match - 0x1B # $MN2 Manifest Offset
		mn2_size = mn2_hdr.Size * 4 # $MN2 Manifest Size
		mn2_date = '%0.4X-%0.2X-%0.2X' % (mn2_hdr.Year,mn2_hdr.Month,mn2_hdr.Day)
		
		mn2_flags_pvbit,mn2_flags_reserved,mn2_flags_pre,mn2_flags_debug = mn2_hdr.get_flags()
		mn2_rsa_sig = reading[start_man_match - 0x1B + 0x184:start_man_match - 0x1B + 0x284] # Read $MN2 RSA Signature
		mn2_rsa_sig_hash = sha_256(mn2_rsa_sig).upper() # Generate $MN2 RSA Signature SHA-256 hash
		cpd_mn2_info = [mn2_hdr.Major, mn2_hdr.Minor, mn2_hdr.Hotfix, mn2_hdr.Build, ['Production','Debug'][mn2_flags_debug], mn2_rsa_sig_hash, mn2_date]
		
		if param.me11_mod_extr : mn2_sigs = rsa_sig_val(mn2_hdr, reading, start_man_match - 0x1B) # For each Partition
	
	# $CPD detected
	if cpd_offset > -1 :
		cpd_hdr_ver = reading[cpd_offset + 8] # $CPD Version Tag
		if cpd_hdr_ver == 2 : cpd_hdr = get_struct(reading, cpd_offset, CPD_Header_2)
		else : cpd_hdr = get_struct(reading, cpd_offset, CPD_Header)
		cpd_num = cpd_entry_num_fix(reading, cpd_offset, cpd_hdr.NumModules)
		cpd_name = cpd_hdr.PartitionName.decode('utf-8')
		
		cpd_valid,cpd_chk_fw,cpd_chk_exp = cpd_chk(reading[cpd_offset:cpd_offset + 0x10 + cpd_num * 0x18], cpd_hdr_ver) # Validate $CPD Checksum
		
		if not cpd_valid :
			ext_err_stor = cse_anl_err(col_r + 'Error: Wrong $CPD "%s" Checksum 0x%0.2X, expected 0x%0.2X' % (cpd_name, cpd_chk_fw, cpd_chk_exp) + col_e)
		
		# Stage 1: Store $CPD Entry names to detect Partition attributes for MEA
		for entry in range(0, cpd_num) :
			cpd_entry_hdr = get_struct(reading, cpd_offset + 0x10 + entry * 0x18, CPD_Entry)
			cpd_entry_name = cpd_entry_hdr.Name.decode('utf-8')
			cpd_mod_names.append(cpd_entry_name) # Store each $CPD Module name
			cpd_entry_size = cpd_entry_hdr.Size # Uncompressed only
			cpd_entry_offset,cpd_entry_huff,cpd_entry_res = cpd_entry_hdr.get_flags()
		
			# Detect if Partition is FIT/OEM-customized to skip Hash check at Stages 2 & 4
			# At CSTXE RGN there are placeholder OEM modules. At CSME RGN they are missing.
			if cpd_entry_name == 'fitc.cfg' and (cpd_entry_offset,cpd_entry_size) != (0,0) : oem_config = True
			if cpd_entry_name == 'oem.key' and (cpd_entry_offset,cpd_entry_size) != (0,0) : oem_signed = True
			
			# Detect Recovery Image Partition (RCIP)
			if cpd_name == 'RCIP' :
				dnx_entry_off, x1, x2 = cpd_entry_hdr.get_flags()
				
				# Get DNX R1/R2 version
				if cpd_entry_name == 'version' : dnx_version = int.from_bytes(reading[cpd_offset + dnx_entry_off:cpd_offset + dnx_entry_off + 0x4], 'little')
				
				# Get DNX R2 Hash Array offset
				elif cpd_entry_name == 'hash.array' : dnx_hash_arr_off = cpd_offset + dnx_entry_off
				
				# Get DNX R1/R2 RCIP IFWI offset
				elif cpd_entry_name == 'rcipifwi' :
					dnx_rcip_off = cpd_offset + dnx_entry_off
					dnx_rcip_len = cpd_entry_size # RCIP IFWI is uncompressed
		
		# Return only $CPD Module Names for Variant detection (after Stage 1, other Stages omitted)
		if input_type.endswith('_Var') : return cpd_mod_names
		
		# Stage 2: Analyze Manifest & Metadata (must be before Module analysis)
		for entry in range(0, cpd_num) :
			cpd_entry_hdr = get_struct(reading, cpd_offset + 0x10 + entry * 0x18, CPD_Entry)
			cpd_mod_off,cpd_mod_huff,cpd_mod_res = cpd_entry_hdr.get_flags()
			
			cpd_entry_offset = cpd_offset + cpd_mod_off
			cpd_entry_size = cpd_entry_hdr.Size # Uncompressed only
			cpd_entry_name = cpd_entry_hdr.Name
			ext_print_temp = []
			cpd_ext_offset = 0
			loop_break = 0
			entry_empty = 0
			
			if b'.man' in cpd_entry_name or b'.met' in cpd_entry_name :
				
				# Set initial CSE Extension Offset
				if b'.man' in cpd_entry_name and start_man_match != -1 :
					cpd_ext_offset = cpd_entry_offset + mn2_hdr.HeaderLength * 4 # Skip $MN2 at .man
				elif b'.met' in cpd_entry_name :
					cpd_ext_offset = cpd_entry_offset # Metadata is always Uncompressed
				
				# Analyze all Manifest & Metadata Extensions
				# Almost identical code snippet found also at mod_anl > Extraction & Validation > Key
				ext_tag = int.from_bytes(reading[cpd_ext_offset:cpd_ext_offset + 0x4], 'little') # Initial Extension Tag
				
				ext_print.append(cpd_entry_name.decode('utf-8')) # Store Manifest/Metadata name
				
				while True : # Parse all CSE Extensions and break at Manifest/Metadata end
					
					# Break loop just in case it becomes infinite
					loop_break += 1
					if loop_break > 100 :
						ext_err_stor = cse_anl_err(col_r + 'Error: Forced CSE Extension Analysis break after 100 loops at %s > %s!' % (cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
						
						break
					
					# Determine if Entry is Empty/Missing
					entry_data = reading[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
					if entry_data == b'\xFF' * cpd_entry_size or cpd_entry_offset >= file_end : entry_empty = 1
					
					# Determine Extension Size & End Offset
					cpd_ext_size = int.from_bytes(reading[cpd_ext_offset + 0x4:cpd_ext_offset + 0x8], 'little')
					cpd_ext_end = cpd_ext_offset + cpd_ext_size
					
					# Detect unknown CSE Extension & notify user
					if ext_tag not in ext_tag_all :
						ext_err_stor = cse_anl_err(col_r + 'Error: Detected unknown CSE Extension 0x%0.2X at %s > %s!\n       Some modules may not be detected without adding 0x%0.2X support!'
						% (ext_tag, cpd_name, cpd_entry_name.decode('utf-8'), ext_tag) + col_e)
					
					# Detect CSE Extension data overflow & notify user
					if entry_empty == 0 and (cpd_ext_end > cpd_entry_offset + cpd_entry_size) : # Manifest/Metadata Entry overflow
						ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X data overflow at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
					
					hdr_rev_tag = '' # CSE Extension Header Revision Tag
					mod_rev_tag = '' # CSE Extension Module Revision Tag
					
					if ((variant,major) == ('CSME',12) and not ((minor,hotfix) == (0,0) and build >= 7000 and year < 0x2018)) or dnx_version == 2 :
						if ext_tag in ext_tag_rev_hdr_csme12 : hdr_rev_tag = '_R2'
						if ext_tag in ext_tag_rev_mod_csme12 : mod_rev_tag = '_R2'
					elif (variant,major) == ('CSSPS',5) :
						if ext_tag in ext_tag_rev_hdr_cssps5 : hdr_rev_tag = '_R2'
						if ext_tag in ext_tag_rev_mod_cssps5 : mod_rev_tag = '_R2'
					else :
						pass # These CSE use the original Header/Module Structures
					
					ext_dict_name = 'CSE_Ext_%0.2X%s' % (ext_tag, hdr_rev_tag)
					ext_struct_name = ext_dict[ext_dict_name] if ext_dict_name in ext_dict else None
					ext_dict_mod = 'CSE_Ext_%0.2X_Mod%s' % (ext_tag, mod_rev_tag)
					ext_struct_mod = ext_dict[ext_dict_mod] if ext_dict_mod in ext_dict else None
					
					# Analyze Manifest/Metadata Extension Info
					if param.me11_mod_extr :
						if ext_dict_name in ext_dict :
							ext_length = ctypes.sizeof(ext_struct_name)
							
							# Detect CSE Extension without Modules different size & notify user
							if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
								ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
							
							if ext_tag == 0xC : # CSE_Ext_0C requires Variant & Version input
								ext_hdr_p = get_struct(reading, cpd_ext_offset, ext_struct_name, ftpr_var_ver)
							else :
								ext_hdr_p = get_struct(reading, cpd_ext_offset, ext_struct_name)
							
							ext_print_temp.append(ext_hdr_p.ext_print())
							
							if ext_tag == 0x14 and dnx_version == 1 : # CSE_Ext_14 Revision 1 (R1) has a unique structure
								# For CSE_Ext_14_R1, all the processing is done at the Manifest Analysis level. All validation results
								# are transfered to mod_anl via ext_dnx_val list so that they can be displayed in logical -unp86 order.
								
								ext_dnx_val[0] = dnx_version # DnX Version 1 (R1)
								ifwi_rgn_hdr_step = 0 # Step to loop through IFWI Region Maps
								rcip_chunk_size = ext_hdr_p.ChunkSize # RCIP IFWI Chunk Size
								rcip_chunk_count_ext = ext_hdr_p.ChunkCount # RCIP IFWI Chunk Count from Extension
								rcip_chunk_count_mea = int(dnx_rcip_len / rcip_chunk_size) # RCIP IFWI Chunk Count from MEA
								ifwi_rgn_count = ext_hdr_p.IFWIRegionCount # IFWI Region Count (eMMC/UFS)
								
								# Check if RCIP length is divisible by RCIP Chunk length and if RCIP Chunk count from EXT is the same as MEA's
								if (dnx_rcip_len % rcip_chunk_size != 0) or (rcip_chunk_count_ext != rcip_chunk_count_mea) :
									ext_err_stor = cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
								
								# Parse each IFWI Region Map
								for region in range(ifwi_rgn_count) :
									ifwi_rgn_map = get_struct(reading, cpd_ext_offset + ext_length + ifwi_rgn_hdr_step, CSE_Ext_14_RegionMap)
									ext_print_temp.append(ifwi_rgn_map.ext_print())
									
									ifwi_rgn_hdr_step += ctypes.sizeof(CSE_Ext_14_RegionMap)
								
								# Parse each RCIP IFWI Chunk
								for chunk in range(rcip_chunk_count_ext) :
									rcip_chunk_off = dnx_rcip_off + chunk * rcip_chunk_size
									chunk_hash_off = cpd_ext_offset + ext_length + ifwi_rgn_hdr_step + chunk * 0x20
									
									rcip_chunk_hash = sha_256(reading[rcip_chunk_off:rcip_chunk_off + rcip_chunk_size]).upper()
									ext_chunk_hash = format(int.from_bytes(reading[chunk_hash_off:chunk_hash_off + 0x20], 'little'), '064X')
									
									# Check if Extension Chunk Hash is equal to RCIP IFWI Chunk Hash
									if ext_chunk_hash == rcip_chunk_hash : chunk_hash_valid_count += 1
									
									pt_14_R2 = ext_table(['Field', 'Value'], False, 1)
									pt_14_R2.title = col_y + 'Extension 20 R1 Chunk %d/%d' % (chunk + 1, rcip_chunk_count_ext) + col_e
									pt_14_R2.add_row(['Chunk EXT Hash', ext_chunk_hash])
									pt_14_R2.add_row(['Chunk MEA Hash', rcip_chunk_hash])
									
									ext_print_temp.append(pt_14_R2)
									
								# Check if all Extension Chunk Hashes and RCIP IFWI Chunk Hashes are Valid
								if chunk_hash_valid_count == rcip_chunk_count_ext : ext_dnx_val[2] = True
								
							if ext_tag == 0x14 and dnx_version == 2 : # CSE_Ext_14 Revision 2 (R2) has a unique structure
								# For CSE_Ext_14_R2, all the processing is done at the Manifest Analysis level. All validation results
								# are transfered to mod_anl via ext_dnx_val list so that they can be displayed in logical -unp86 order.
								
								ext_dnx_val[0] = dnx_version # DnX Version 2 (R2)
								ifwi_rgn_hdr_step = 0 # Step to loop through IFWI Region Maps
								hash_arr_hdr_step = 0 # Step to loop through Hashes Array Headers
								hash_arr_prev_part_size = 0 # Step to loop through Hashes Array file sections
								hash_arr_hdr_count = ext_hdr_p.HashArrHdrCount # Hashes Array Header Count
								chunk_hash_size = ext_hdr_p.ChunkHashSize # Hashes Array Chunk Hash Size
								rcip_chunk_size = ext_hdr_p.ChunkSize # RCIP IFWI Chunk Size
								rcip_chunk_count = int(dnx_rcip_len / rcip_chunk_size)  # RCIP IFWI Chunk Count
								ifwi_rgn_count = ext_hdr_p.IFWIRegionCount # IFWI Region Count (eMMC/UFS)
								
								# Parse each Hashes Array Header
								for header in range(hash_arr_hdr_count) :
									hash_arr_part_hdr = get_struct(reading, cpd_ext_offset + ext_length + hash_arr_hdr_step, CSE_Ext_14_HashArray)
									hash_arr_part_size = hash_arr_part_hdr.HashArrSize * 4 # Hashes Array file section size
									hash_arr_part_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(hash_arr_part_hdr.HashArrHash)) # Hashes Array file section hash
									hash_arr_part_data_off = dnx_hash_arr_off + hash_arr_prev_part_size # Hashes Array file section data offset
									hash_arr_part_data = reading[hash_arr_part_data_off:hash_arr_part_data_off + hash_arr_part_size] # Hashes Array file section data
									hash_arr_part_data_hash = sha_256(hash_arr_part_data).upper() # Hashes Array file section data hash
									
									# Check if RCIP length is divisible by RCIP Chunk length and if Hashes Array file section length is divisible by its Size
									if (dnx_rcip_len % rcip_chunk_size != 0) or (len(hash_arr_part_data) % hash_arr_part_size != 0) :
										ext_err_stor = cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
									
									# Check if Hashes Array file section Hash is valid to Hashes Array file section Header
									if hash_arr_part_hash == hash_arr_part_data_hash : hash_arr_valid_count += 1
									
									pt_14_R2 = ext_table(['Field', 'Value'], False, 1)
									pt_14_R2.title = col_y + 'Extension 20 R2 Hashes Array %d/%d' % (header + 1, hash_arr_hdr_count) + col_e
									pt_14_R2.add_row(['Hashes Array EXT Hash', hash_arr_part_hash])
									pt_14_R2.add_row(['Hashes Array MEA Hash', hash_arr_part_data_hash])
									
									ext_print_temp.append(pt_14_R2)
									
									# Parse each RCIP IFWI Chunk
									for chunk in range(rcip_chunk_count) :
										rcip_chunk_off = dnx_rcip_off + chunk * rcip_chunk_size
										hash_arr_chunk_off = dnx_hash_arr_off + chunk * chunk_hash_size
										
										rcip_chunk_hash = sha_256(reading[rcip_chunk_off:rcip_chunk_off + rcip_chunk_size]).upper()
										hash_arr_chunk_hash = format(int.from_bytes(reading[hash_arr_chunk_off:hash_arr_chunk_off + chunk_hash_size], 'little'), '064X')
										
										# Check if Hashes Array Chunk Hash is equal to RCIP IFWI Chunk Hash
										if hash_arr_chunk_hash == rcip_chunk_hash : chunk_hash_valid_count += 1
										
										pt_14_R2 = ext_table(['Field', 'Value'], False, 1)
										pt_14_R2.title = col_y + 'Extension 20 R2 Chunk %d/%d' % (chunk + 1, rcip_chunk_count) + col_e
										pt_14_R2.add_row(['Chunk EXT Hash', hash_arr_chunk_hash])
										pt_14_R2.add_row(['Chunk MEA Hash', rcip_chunk_hash])
										
										ext_print_temp.append(pt_14_R2)
									
									hash_arr_prev_part_size += hash_arr_part_size
									hash_arr_hdr_step += ctypes.sizeof(CSE_Ext_14_HashArray)

								# Parse each IFWI Region Map
								for region in range(ifwi_rgn_count) :
									ifwi_rgn_map = get_struct(reading, cpd_ext_offset + ext_length + hash_arr_hdr_step + ifwi_rgn_hdr_step, CSE_Ext_14_RegionMap)
									ext_print_temp.append(ifwi_rgn_map.ext_print())
									
									ifwi_rgn_hdr_step += ctypes.sizeof(CSE_Ext_14_RegionMap)
									
								# Check if all Hashes Array Header Hashes and RCIP IFWI Chunk Hashes are Valid
								if hash_arr_valid_count == hash_arr_hdr_count : ext_dnx_val[1] = True
								if chunk_hash_valid_count == rcip_chunk_count * hash_arr_hdr_count : ext_dnx_val[2] = True
							
							elif ext_tag == 0x15 : # CSE_Ext_15 has a unique structure
								CSE_Ext_15_PartID_length = ctypes.sizeof(CSE_Ext_15_PartID)
								CSE_Ext_15_Payload_length = ctypes.sizeof(CSE_Ext_15_Payload)
								CSE_Ext_15_Payload_Knob_length = ctypes.sizeof(CSE_Ext_15_Payload_Knob)
								
								part_id_count = ext_hdr_p.PartIDCount
								cpd_part_id_offset = cpd_ext_offset + ext_length # CSE_Ext_15 structure size (not entire Extension 15)
								cpd_payload_offset = cpd_part_id_offset + part_id_count * 0x14
								cpd_payload_knob_offset = cpd_payload_offset + 0x4
								
								for _ in range(part_id_count) :
									part_id_struct = get_struct(reading, cpd_part_id_offset, CSE_Ext_15_PartID)
									ext_print_temp.append(part_id_struct.ext_print())
									cpd_part_id_offset += 0x14
								
								payload_struct = get_struct(reading, cpd_payload_offset, CSE_Ext_15_Payload)
								ext_print_temp.append(payload_struct.ext_print())
								payload_knob_count = payload_struct.KnobCount
								payload_knob_area = cpd_ext_end - cpd_payload_knob_offset
								
								# Check Extension full size when Module Counter exists
								if ext_tag in ext_tag_mod_count and (cpd_ext_size != ext_length + part_id_count * CSE_Ext_15_PartID_length + CSE_Ext_15_Payload_length +
								payload_knob_count * CSE_Ext_15_Payload_Knob_length) :
									ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
								
								# Check if Knob data is divisible by Knob size
								if payload_knob_area % CSE_Ext_15_Payload_Knob_length != 0 :
									ext_err_stor = cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
								
								for knob in range(payload_knob_count) :
									payload_knob_struct = get_struct(reading, cpd_payload_knob_offset, CSE_Ext_15_Payload_Knob, ftpr_var_ver)
									ext_print_temp.append(payload_knob_struct.ext_print())
									cpd_payload_knob_offset += 0x08
									
							elif ext_dict_mod in ext_dict :
								mod_length = ctypes.sizeof(ext_struct_mod)
								cpd_mod_offset = cpd_ext_offset + ext_length
								cpd_mod_area = cpd_ext_end - cpd_mod_offset
								
								# Check Extension full size when Module Counter exists
								if ext_tag in ext_tag_mod_count and (cpd_ext_size != ext_length + ext_hdr_p.ModuleCount * mod_length) :
									ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
								
								# Check if Mod data is divisible by Mod size
								if cpd_mod_area % mod_length != 0 :
									ext_err_stor = cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
								
								while cpd_mod_offset < cpd_ext_end :
									mod_hdr_p = get_struct(reading, cpd_mod_offset, ext_struct_mod)
									ext_print_temp.append(mod_hdr_p.ext_print())
							
									cpd_mod_offset += mod_length
					
					if ext_tag == 0x1 :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						CSE_Ext_01_length = ctypes.sizeof(ext_struct_name)
						cpd_mod_offset = cpd_ext_offset + CSE_Ext_01_length
						CSE_Ext_01_Mod_length = ctypes.sizeof(ext_struct_mod)
						
						# Check Extension full size when Module Counter exists
						if ext_tag in ext_tag_mod_count and (cpd_ext_size != CSE_Ext_01_length + ext_hdr.ModuleCount * CSE_Ext_01_Mod_length) :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
					
					elif ext_tag == 0x2 :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						CSE_Ext_02_length = ctypes.sizeof(ext_struct_name)
						cpd_mod_offset = cpd_ext_offset + CSE_Ext_02_length
						CSE_Ext_02_Mod_length = ctypes.sizeof(ext_struct_mod)
						
						# Check Extension full size when Module Counter exists
						if ext_tag in ext_tag_mod_count and (cpd_ext_size != CSE_Ext_02_length + ext_hdr.ModuleCount * CSE_Ext_02_Mod_length) :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
					
					elif ext_tag == 0x3 :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name
						ext_psize = ext_hdr.PartitionSize # Partition Size
						ext_phash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(ext_hdr.Hash)) # Partition Hash
						vcn = ext_hdr.VCN # Version Control Number
						in_id = ext_hdr.InstanceID # LOCL/WCOD identifier
						CSE_Ext_03_length = ctypes.sizeof(ext_struct_name)
						cpd_mod_offset = cpd_ext_offset + CSE_Ext_03_length
						CSE_Ext_03_Mod_length = ctypes.sizeof(ext_struct_mod)
						CSE_Ext_03_Mod_area = cpd_ext_end - cpd_mod_offset
						
						# Verify Partition Hash ($CPD - $MN2 + Data)
						if start_man_match != -1 and not oem_config and not oem_signed :
							mea_pdata = reading[cpd_offset:mn2_offset] + reading[mn2_offset + mn2_size:cpd_offset + ext_psize] # $CPD + Data (no $MN2)
							mea_phash = sha_256(mea_pdata).upper() # SHA-256 for CSE_Ext_03
							
							ext_phval = [True, ext_phash == mea_phash, ext_phash, mea_phash]
							if not ext_phval[1] and int(ext_phval[2], 16) != 0 :
								ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong Partition Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, (ext_phash,mea_phash))
						
						# Check Extension full size when Module Counter exists
						if ext_tag in ext_tag_mod_count and (cpd_ext_size != CSE_Ext_03_length + ext_hdr.ModuleCount * CSE_Ext_03_Mod_length) :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
						
						# Check if Mod data is divisible by Mod size
						if CSE_Ext_03_Mod_area % CSE_Ext_03_Mod_length != 0 :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
							
						while cpd_mod_offset < cpd_ext_end :
							mod_hdr_p = get_struct(reading, cpd_mod_offset, ext_struct_mod)
							met_name = mod_hdr_p.Name.decode('utf-8') + '.met'
							# Some may include 03/0F/16, may have 03/0F/16 MetadataHash mismatch, may have Met name with ".met" included (GREAT WORK INTEL/OEMs...)
							if met_name.endswith('.met.met') : met_name = met_name[:-4]
							met_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(mod_hdr_p.MetadataHash)) # Metadata Hash
							
							cpd_ext_hash.append([cpd_name, met_name, met_hash])
							
							cpd_mod_offset += CSE_Ext_03_Mod_length
						
					elif ext_tag == 0xA :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						ext_length = ctypes.sizeof(ext_struct_name)
						
						# Detect CSE Extension without Modules different size & notify user
						if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
						
						mod_comp_type = ext_hdr.Compression # Metadata's Module Compression Type (0-2)
						mod_encr_type = ext_hdr.Encryption # Metadata's Module Encryption Type (0-1)
						mod_comp_size = ext_hdr.SizeComp # Metadata's Module Compressed Size ($CPD Entry's Module Size is always Uncompressed)
						mod_uncomp_size = ext_hdr.SizeUncomp # Metadata's Module Uncompressed Size (equal to $CPD Entry's Module Size)
						mod_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(ext_hdr.Hash)) # Metadata's Module Hash
						
						cpd_mod_attr.append([cpd_entry_name.decode('utf-8')[:-4], mod_comp_type, mod_encr_type, 0, mod_comp_size, mod_uncomp_size, 0, mod_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
					
					elif ext_tag == 0xC :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name, ftpr_var_ver)
						ext_length = ctypes.sizeof(ext_struct_name)
						
						# Detect CSE Extension without Modules different size & notify user
						if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
						
						fw_0C_cse,fw_0C_sku1,fw_0C_lbg,fw_0C_m3,fw_0C_m0,fw_0C_sku2,fw_0C_sicl,fw_0C_res2 = ext_hdr.get_flags()
						
						ext12_info = ['%0.8X' % ext_hdr.FWSKUCaps, fw_0C_sku1, fw_0C_lbg, fw_0C_sku2]
					
					elif ext_tag == 0xF :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						if ext_pname == '' : ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name (prefer CSE_Ext_03)
						if vcn == -1 : vcn = ext_hdr.VCN # Version Control Number (prefer CSE_Ext_03)
						CSE_Ext_0F_length = ctypes.sizeof(ext_struct_name)
						cpd_mod_offset = cpd_ext_offset + CSE_Ext_0F_length
						CSE_Ext_0F_Mod_length = ctypes.sizeof(ext_struct_mod)
						CSE_Ext_0F_Mod_area = cpd_ext_end - cpd_mod_offset
						
						# Check if Mod data is divisible by Mod size
						if CSE_Ext_0F_Mod_area % CSE_Ext_0F_Mod_length != 0 :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
						
						while cpd_mod_offset < cpd_ext_end :
							mod_hdr_p = get_struct(reading, cpd_mod_offset, ext_struct_mod)
							met_name = mod_hdr_p.Name.decode('utf-8') + '.met'
							# Some may include 03/0F/16, may have 03/0F/16 MetadataHash mismatch, may have Met name with ".met" included (GREAT WORK INTEL/OEMs...)
							if met_name.endswith('.met.met') : met_name = met_name[:-4]
							met_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(mod_hdr_p.MetadataHash)) # Metadata Hash
							
							cpd_ext_hash.append([cpd_name, met_name, met_hash])
							
							cpd_mod_offset += CSE_Ext_0F_Mod_length
					
					elif ext_tag == 0x10 :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						ext_length = ctypes.sizeof(ext_struct_name)
						
						# Detect CSE Extension without Modules different size & notify user
						if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
						
						mod_uncomp_size = ext_hdr.SizeUncomp # Metadata's Module Uncompressed Size (equal to $CPD Entry's Module Size)
						mod_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in ext_hdr.Hash) # Metadata's Module Hash (BE)
						
						cpd_mod_attr.append([cpd_entry_name.decode('utf-8')[:-4], 0, 0, 0, mod_uncomp_size, mod_uncomp_size, 0, mod_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
					
					elif ext_tag == 0x11 :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						ext_length = ctypes.sizeof(ext_struct_name)
						
						# Detect CSE Extension without Modules different size & notify user
						if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
						
						mod_unk_size = ext_hdr.SizeUnknown # Metadata's Module Unknown Size (needs to be subtracted from SizeUncomp)
						mod_uncomp_size = ext_hdr.SizeUncomp # Metadata's Module Uncompressed Size (SizeUnknown + SizeUncomp = $CPD Entry's Module Size)
						mod_cpd_size = mod_uncomp_size - mod_unk_size # Should be the same as $CPD
						mod_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in ext_hdr.Hash) # Metadata's Module Hash (BE)
						
						cpd_mod_attr.append([cpd_entry_name.decode('utf-8')[:-4], 0, 0, 0, mod_cpd_size, mod_cpd_size, 0, mod_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
					
					elif ext_tag == 0x12 :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						CSE_Ext_12_length = ctypes.sizeof(ext_struct_name)
						cpd_mod_offset = cpd_ext_offset + CSE_Ext_12_length
						CSE_Ext_12_Mod_length = ctypes.sizeof(ext_struct_mod)
						
						# Check Extension full size when Module Counter exists
						if ext_tag in ext_tag_mod_count and (cpd_ext_size != CSE_Ext_12_length + ext_hdr.ModuleCount * CSE_Ext_12_Mod_length) :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
					
					elif ext_tag == 0x13 :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						ext_length = ctypes.sizeof(ext_struct_name)
						
						# Detect CSE Extension without Modules different size & notify user
						if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
						
						ibbl_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in ext_hdr.IBBLHash) # IBBL Hash (BE)
						ibb_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in ext_hdr.IBBHash) # IBB Hash (BE)
						obb_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in ext_hdr.OBBHash) # OBB Hash (BE)
						if ibbl_hash not in ['00' * ext_hdr.IBBLHashSize, 'FF' * ext_hdr.IBBLHashSize] : cpd_mod_attr.append(['IBBL', 0, 0, 0, 0, 0, 0, ibbl_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
						if ibb_hash not in ['00' * ext_hdr.IBBHashSize, 'FF' * ext_hdr.IBBHashSize] : cpd_mod_attr.append(['IBB', 0, 0, 0, 0, 0, 0, ibb_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
						if obb_hash not in ['00' * ext_hdr.OBBHashSize, 'FF' * ext_hdr.OBBHashSize] : cpd_mod_attr.append(['OBB', 0, 0, 0, 0, 0, 0, obb_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
						
					elif ext_tag == 0x16 :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						ext_length = ctypes.sizeof(ext_struct_name)
						ext_psize = ext_hdr.PartitionSize # Partition Size
						if ext_pname == '' : ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name (prefer CSE_Ext_03)
						if in_id == 0 : in_id = ext_hdr.InstanceID # LOCL/WCOD identifier (prefer CSE_Ext_03)
						ext_phalg = ext_hdr.HashAlgorithm # Partition Hash Algorithm
						ext_phlen = int(''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(ext_hdr.HashSize)), 16) # Partition Hash Size
						ext_phash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(ext_hdr.Hash)) # Partition Hash
						
						# Verify Partition Hash ($CPD - $MN2 + Data)
						if start_man_match != -1 and not oem_config and not oem_signed :
							mea_pdata = reading[cpd_offset:mn2_offset] + reading[mn2_offset + mn2_size:cpd_offset + ext_psize] # $CPD + Data (no $MN2)
							
							if ext_phalg == 2 and ext_phlen == 0x20 : mea_phash = sha_256(mea_pdata).upper() # SHA-256
							elif ext_phalg == 1 and ext_phlen == 0x14 : mea_phash = sha_1(mea_pdata).upper() # SHA-1
							
							ext_phval = [True, ext_phash == mea_phash, ext_phash, mea_phash]
							if not ext_phval[1] and int(ext_phval[2], 16) != 0 :
								ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong Partition Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, (ext_phash,mea_phash))
						
						# Detect CSE Extension without Modules different size & notify user
						if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
							ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
						
					elif ext_tag == 0x32 :
						ext_hdr = get_struct(reading, cpd_ext_offset, ext_struct_name)
						ext32_type = ext_hdr.Type.decode('utf-8') # OP/RC
						ext32_plat = ext_hdr.Platform.decode('utf-8') # GE/HA/PU/PE
						
						ext32_info = [ext32_type, ext32_plat]
					
					cpd_ext_offset += cpd_ext_size # Next Extension Offset
					
					if cpd_ext_offset + 1 > cpd_entry_offset + cpd_entry_size : # End of Manifest/Metadata Entry reached
						cpd_ext_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, entry_empty, 0, cpd_name, in_id, mn2_sigs, cpd_offset, cpd_valid])
						cpd_ext_names.append(cpd_entry_name.decode('utf-8')[:-4]) # Store Module names which have Manifest/Metadata
						
						break # Stop Extension scanning at the end of Manifest/Metadata Entry
					
					ext_tag = int.from_bytes(reading[cpd_ext_offset:cpd_ext_offset + 0x4], 'little') # Next Extension Tag
				
				if param.me11_mod_extr : ext_print.append(ext_print_temp) # Store Manifest/Metadata Extension Info
			
		# Stage 3: Fill Metadata Hash from Manifest
		for attr in cpd_ext_attr :
			for met_hash in cpd_ext_hash :
				if attr[8] == met_hash[0] and attr[0] == met_hash[1] : # Verify $CPD and Metadata name match
					attr[7] = met_hash[2] # Fill Metadata's Hash Attribute from Manifest Extension 03, 0F or 16
					break # To hopefully avoid some 03/0F/16 MetadataHash mismatch, assuming 1st has correct MetadataHash
		
		# Stage 4: Analyze Modules, Keys, Microcodes & Data (must be after all Manifest & Metadata Extension analysis)
		for entry in range(0, cpd_num) :
			cpd_entry_hdr = get_struct(reading, cpd_offset + 0x10 + entry * 0x18, CPD_Entry)
			cpd_mod_off,cpd_mod_huff,cpd_mod_res = cpd_entry_hdr.get_flags()
			
			cpd_entry_name = cpd_entry_hdr.Name
			cpd_entry_size = cpd_entry_hdr.Size # Uncompressed only
			cpd_entry_offset = cpd_offset + cpd_mod_off
			mod_size = cpd_entry_size # Uncompressed initially, to replace with Compressed for Modules
			mod_empty = 0 # Assume that Module is not empty initially
			
			# Manifest & Metadata Skip
			if b'.man' in cpd_entry_name or b'.met' in cpd_entry_name : continue
			
			# Fill Module Attributes by single unified Metadata
			if cpd_name == 'IBBP' : # IBBP
				ibbp_all.append(cpd_entry_name.decode('utf-8')) # Store all IBBP Module names to exclude those missing but with Hash at .met (GREAT WORK INTEL/OEMs...)
				
				# BPM.met > IBBL, IBB, OBB
				for mod in range(len(cpd_mod_attr)) :
					if cpd_mod_attr[mod][0] == cpd_entry_name.decode('utf-8') :
						cpd_mod_attr[mod][4] = cpd_entry_size # Fill Module Uncompressed Size from $CPD Entry
						cpd_mod_attr[mod][5] = cpd_entry_size # Fill Module Uncompressed Size from $CPD Entry
						cpd_ext_names.append(cpd_entry_name.decode('utf-8')) # To enter "Module with Metadata" section below
						
						break
			
			# Module with Metadata
			if cpd_entry_name.decode('utf-8') in cpd_ext_names :
				for mod in range(len(cpd_mod_attr)) :
					if cpd_mod_attr[mod][0] == cpd_entry_name.decode('utf-8') :
						
						cpd_mod_attr[mod][3] = cpd_entry_offset # Fill Module Starting Offset from $CPD Entry
						cpd_mod_attr[mod][9] = in_id # Fill Module Instance ID from CSE_Ext_03
						
						mod_comp_size = cpd_mod_attr[mod][4] # Store Module Compressed Size for Empty check
						mod_size = mod_comp_size # Store Module Compressed Size for Out of Partition Bounds check
						mod_data = reading[cpd_entry_offset:cpd_entry_offset + mod_comp_size] # Store Module data for Empty check
						if mod_data == b'\xFF' * mod_comp_size or cpd_entry_offset >= file_end : cpd_mod_attr[mod][6] = 1 # Determine if Module is Empty/Missing
						
						break
						
				# Detect $FPT Partition Size mismatch vs CSE_Ext_03/16
				for part in fpt_part_all :
					# Verify that CSE_Ext_03/16.PartitionSize exists and that the same $CPD Partition was found at fpt_part_all
					# by its unique Name, Offset & Instance ID. If $FPT Entry size is smaller than Extension size, error is shown.
					# The check is skipped when Extension size is not found so no problem with OEM/FIT firmware configuration.
					# The check is skipped when IDLM partition (DLMP) is parsed because its $FPT size is wrong by Intel design.
					if not msg_shown and ext_psize != -1 and part[0] == cpd_hdr.PartitionName and part[0] != b'DLMP' \
					and part[1] == cpd_offset and part[3] == in_id and part[2] < (cpd_offset + ext_psize) :
						ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x3/0x16 with smaller $FPT %s Partition Size!' % cpd_name + col_e)
						msg_shown = True # Partition related error, show only once
				
				# Detect BPDT Partition Size mismatch vs CSE_Ext_03/16
				for part in bpdt_part_all :
					# Verify that CSE_Ext_03/16.PartitionSize exists and that the same $CPD Partition was found at bpdt_part_all
					# by its unique Name, Offset & Instance ID. If BPDT Entry size is smaller than Extension size, error is shown.
					# The check is skipped when Extension size is not found so no problem with OEM/FIT firmware configuration.
					# The check is skipped when IDLM partition (DLMP) is parsed because its BPDT size is wrong by Intel design.
					if not msg_shown and ext_psize != -1 and part[0] == cpd_hdr.PartitionName.decode('utf-8') and part[0] != 'DLMP' \
					and part[1] == cpd_offset and part[6] == in_id and part[2] < (cpd_offset + ext_psize) :
						ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x3/0x16 with smaller BPDT %s Partition Size!' % cpd_name + col_e)
						msg_shown = True # Partition related error, show only once
						
			# Key
			elif '.key' in cpd_entry_name.decode('utf-8') :
				mod_data = reading[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
				if mod_data == b'\xFF' * cpd_entry_size or cpd_entry_offset >= file_end : mod_empty = 1 # Determine if Key is Empty/Missing
				
				# Key's RSA Signature is validated at mod_anl via key_anl function
				
				cpd_mod_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, mod_empty, 0, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
			
			# Microcode
			elif 'upatch' in cpd_entry_name.decode('utf-8') :
				mod_data = reading[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
				if mod_data == b'\xFF' * cpd_entry_size or cpd_entry_offset >= file_end : mod_empty = 1 # Determine if Microcode is Empty/Missing
				
				# Detect actual Microcode length
				mc_len = int.from_bytes(mod_data[0x20:0x24], 'little')
				mc_data = reading[cpd_entry_offset:cpd_entry_offset + mc_len]
				
				cpd_mod_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, mod_empty, mc_chk32(mc_data), cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
			
			# Data
			else :
				mod_data = reading[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
				if mod_data == b'\xFF' * cpd_entry_size or cpd_entry_offset >= file_end : mod_empty = 1 # Determine if Module is Empty/Missing
				
				cpd_mod_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, mod_empty, 0, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
			
			# Detect Modules which exceed or are located at/after the end of RGN Partition size (CSE_Ext_03/16.PartitionSize)
			if not oem_config and not oem_signed and ext_psize != -1 and ((cpd_entry_offset >= cpd_offset + ext_psize) or (cpd_entry_offset + mod_size > cpd_offset + ext_psize)) :
				ext_err_stor = cse_anl_err(col_r + 'Error: Detected out of partition bounds Module at %s > %s!' % (cpd_name, cpd_entry_name.decode('utf-8')) + col_e)
			
		# Stage 5: Remove missing APL IBBP Module Attributes
		if len(ibbp_all) :
			for ibbp in ibbp_bpm :
				if ibbp not in ibbp_all : # Module has hash at unified Metadata but is actually missing
					for mod_index in range(len(cpd_mod_attr)) :
						if cpd_mod_attr[mod_index][0] == ibbp : ibbp_del.append(mod_index) # Store missing Module's Attributes
						
			for mod_index in ibbp_del : del cpd_mod_attr[mod_index] # Delete missing Module's Attributes
	
	return cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_err_stor,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info

# Analyze & Store Engine CSE Modules
def mod_anl(cpd_offset, cpd_mod_attr, cpd_ext_attr, fw_name, ext_print, ext_phval, ext_dnx_val) :
	# noinspection PyUnusedLocal
	mea_hash_u = 0
	mea_hash_c = 0
	comp = ['Uncompressed','Huffman','LZMA']
	fext = ['mod','huff','lzma']
	encr_empty = ['No','Yes']
	ansi_escape = re.compile(r'\x1b[^m]*m') # Generate ANSI Color and Font Escape Character Sequences
	
	pt = ext_table([col_y + 'Name' + col_e, col_y + 'Compression' + col_e, col_y + 'Encryption' + col_e, col_y + 'Offset' + col_e, col_y + 'Compressed' + col_e, col_y + 'Uncompressed' + col_e,
					col_y + 'Empty' + col_e], True, 1)
	
	# $CPD validity verified
	if cpd_offset > -1 :
		
		cpd_all_attr = cpd_ext_attr + cpd_mod_attr
		
		# Store Module details
		for mod in cpd_all_attr :
			pt.add_row([mod[0],comp[mod[1]],encr_empty[mod[2]],'0x%0.6X' % mod[3],'0x%0.6X' % mod[4],'0x%0.6X' % mod[5],encr_empty[mod[6]]])
		
		# Parent Partition Attributes (same for all cpd_all_attr list instance entries)
		cpd_pname = cpd_all_attr[0][8] # $CPD Name
		cpd_poffset = cpd_all_attr[0][11] # $CPD Offset, covers any cases with duplicate name entries (Joule_C0-X64-Release)
		cpd_pvalid = cpd_all_attr[0][12] # CPD Checksum Valid
		ext_inid = cpd_all_attr[0][9] # Partition Instance ID
		
		pt.title = col_y + 'Detected %s Module(s) at %s %0.4X [0x%0.6X]' % (len(cpd_all_attr), cpd_pname, ext_inid, cpd_poffset) + col_e
		folder_name = os.path.join(mea_dir, fw_name, '%s %0.4X [0x%0.6X]' % (cpd_pname, ext_inid, cpd_poffset), '')
		info_fname = os.path.join(mea_dir, fw_name, '%s %0.4X [0x%0.6X].txt' % (cpd_pname, ext_inid, cpd_poffset))
		
		cpd_hdr_ver = reading[cpd_poffset + 8] # $CPD Version Tag
		if cpd_hdr_ver == 2 : cpd_phdr = get_struct(reading, cpd_poffset, CPD_Header_2)
		else : cpd_phdr = get_struct(reading, cpd_poffset, CPD_Header)
		if param.me11_mod_extr : print('\n%s' % cpd_phdr.hdr_print())
		
		if cpd_pvalid : print(col_g + '\n$CPD Checksum of partition "%s" is VALID\n' % cpd_pname + col_e)
		else :
			if param.me11_mod_bug :
				input(col_r + '\n$CPD Checksum of partition "%s" is INVALID\n' % cpd_pname + col_e) # Debug
			else :
				print(col_r + '\n$CPD Checksum of partition "%s" is INVALID\n' % cpd_pname + col_e)
			
		print(pt) # Show Module details
		
		os.mkdir(folder_name)
		
		# Store Partition $CPD Header & Entry details
		with open(info_fname, 'a', encoding = 'utf-8') as info_file :
			info_file.write('\n%s\n%s' % (ansi_escape.sub('', str(cpd_phdr.hdr_print())), ansi_escape.sub('', str(pt))))
		
		# Load Huffman Dictionaries for Decompression
		if param.me11_mod_bug : huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, 'error')
		else : huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, 'none')
		
		# Parse all Modules based on their Metadata
		for mod in cpd_all_attr :
			mod_name = mod[0] # Name
			mod_comp = mod[1] # Compression
			mod_encr = mod[2] # Encryption
			mod_start = mod[3] # Starting Offset
			mod_size_comp = mod[4] # Compressed Size
			mod_size_uncomp = mod[5] # Uncompressed Size
			mod_empty = mod[6] # Empty/Missing
			mod_hash = mod[7] # Hash (LZMA --> Compressed + zeroes, Huffman --> Uncompressed)
			mod_end = mod_start + mod_size_comp # Ending Offset
			mn2_valid = mod[10][0] # Check if RSA Signature is valid (rsa_hash == dec_hash)
			# noinspection PyUnusedLocal
			mn2_sig_dec = mod[10][1] # RSA Signature Decrypted Hash
			# noinspection PyUnusedLocal
			mn2_sig_sha = mod[10][2] # RSA Signature Data Hash
			mn2_error = mod[10][3] # Check if RSA validation crashed (try-except)
			# noinspection PyUnusedLocal
			mn2_start = mod[10][4] # Manifest Starting Offset
			mn2_struct = mod[10][5] # Manifest Structure Object
			
			if mod_empty == 1 : continue # Skip Empty/Missing Modules
			
			if '.man' in mod_name or '.met' in mod_name :
				mod_fname = folder_name + mod_name
				mod_type = 'metadata'
			else :
				mod_fname = folder_name + '%s.%s' % (mod_name, fext[mod_comp])
				mod_type = 'module'
				
			mod_data = reading[mod_start:mod_end]

			# Initialization for Module Storing
			if mod_comp == 2 :
				# Calculate LZMA Module SHA256 hash
				mea_hash_c = sha_256(mod_data).upper() # Compressed, Header zeroes included (most LZMA Modules)
				
				# Remove zeroes from LZMA header for decompression (inspired from Igor Skochinsky's me_unpack)
				if mod_data.startswith(b'\x36\x00\x40\x00\x00') and mod_data[0xE:0x11] == b'\x00\x00\x00' :
					mod_data = mod_data[:0xE] + mod_data[0x11:] # Visually, mod_size_comp += -3 for compressed module
			
			# Store Metadata or Module for further actions
			with open(mod_fname, 'w+b') as mod_file : mod_file.write(mod_data)
			
			# Extract & Ignore Encrypted Modules
			if mod_encr == 1 :
				print(col_m + '\n--> Stored Encrypted %s %s "%s" [0x%0.6X - 0x%0.6X]' % (comp[mod_comp], mod_type, mod_name, mod_start, mod_end - 0x1) + col_e)
				
				if param.me11_mod_bug : # Debug
					print('\n    MOD: %s' % mod_hash)
					print(col_m + '\n    Hash of %s %s "%s" cannot be verified' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
				os.rename(mod_fname, mod_fname[:-len(fext[mod_comp])] + 'encr') # Change Module extension to .encr
				
				continue # Module Encryption on top of Compression, skip decompression
			else :
				print(col_y + '\n--> Stored %s %s "%s" [0x%0.6X - 0x%0.6X]' % (comp[mod_comp], mod_type, mod_name, mod_start, mod_end - 0x1) + col_e)
			
			# Extract & Validate Uncompressed Data
			if mod_comp == 0 :
				
				# Manifest
				if '.man' in mod_name :
					if param.me11_mod_bug :
						print('\n    MN2: %s' % mn2_sig_dec) # Debug
						print('    MEA: %s' % mn2_sig_sha) # Debug
					
					if mn2_error :
						if param.me11_mod_bug :
							input(col_m + '\n    RSA Signature of partition "%s" is UNKNOWN' % cpd_pname + col_e) # Debug
						else :
							print(col_m + '\n    RSA Signature of partition "%s" is UNKNOWN' % cpd_pname + col_e)
					elif mn2_valid : print(col_g + '\n    RSA Signature of partition "%s" is VALID' % cpd_pname + col_e)
					else :
						if param.me11_mod_bug :
							input(col_r + '\n    RSA Signature of partition "%s" is INVALID' % cpd_pname + col_e) # Debug
						else :
							print(col_r + '\n    RSA Signature of partition "%s" is INVALID' % cpd_pname + col_e)
							
					mn2_hdr_print = mn2_struct.hdr_print_cse()
					print('\n%s' % mn2_hdr_print) # Show $MN2 details
					
					# Insert $MN2 Manifest details at Extension Info list (ext_print)
					ext_print_cur_len = len(ext_print) # Current length of Extension Info list
					for index in range(0, ext_print_cur_len, 2) : # Only Name (index), skip Info (index + 1)
						if str(ext_print[index]).startswith(mod_name) :
							ext_print[index + 1] = [ansi_escape.sub('', str(mn2_hdr_print))] + (ext_print[index + 1])
							break

					if param.me11_mod_bug and ext_phval[0] :
						print('\n    EXT: %s' % ext_phval[2]) # Debug
						print('    MEA: %s' % ext_phval[3]) # Debug
					
					if ext_phval[0] and int(ext_phval[2], 16) == 0 : # Hash exists but is not used (0)
						print(col_m + '\n    Hash of partition "%s" is UNKNOWN' % cpd_pname + col_e)
					elif ext_phval[0] and ext_phval[1] : # Hash exists and is Valid
						print(col_g + '\n    Hash of partition "%s" is VALID' % cpd_pname + col_e)
					elif ext_phval[0] : # Hash exists but is Invalid
						if param.me11_mod_bug and (ext_phval[2],ext_phval[3]) not in cse_known_bad_hashes :
							input(col_r + '\n    Hash of partition "%s" is INVALID' % cpd_pname + col_e) # Debug
						else :
							print(col_r + '\n    Hash of partition "%s" is INVALID' % cpd_pname + col_e)
				
				# Metadata
				elif '.met' in mod_name :
					mea_hash = sha_256(mod_data).upper()
					
					if param.me11_mod_bug :
						print('\n    MOD: %s' % mod_hash) # Debug
						print('    MEA: %s' % mea_hash) # Debug
				
					if mod_hash == mea_hash : print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.me11_mod_bug and (mod_hash,mea_hash) not in cse_known_bad_hashes :
							input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
				# Key
				elif '.key' in mod_name :
					os.rename(mod_fname, mod_fname[:-4]) # Change Key extension from .mod to .key
					
					mod_fname = mod_fname[:-4] # To save Key Extension info file
					
					ext_print,x1 = key_anl(mod_fname, ext_print, mod_name, [variant, major, minor, hotfix, build]) # Retrieve & Store Key Extension Info
				
				# Microcode
				elif 'upatch' in mod_name :
					if mod_hash == 0 : print(col_g + '\n    Checksum of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.me11_mod_bug :
							input(col_r + '\n    Checksum of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						else :
							print(col_r + '\n    Checksum of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						
					os.rename(mod_fname, mod_fname[:-4] + '.bin') # Change Microcode extension from .mod to .bin
				
				# Data
				elif mod_hash == 0 :
					
					# CSE_Ext_14 R1/R2 has a unique structure
					if cpd_pname == 'RCIP' :
						if (mod_name,ext_dnx_val[1]) == ('hash.array',True) or (mod_name,ext_dnx_val[2]) == ('rcipifwi',True) :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						elif mod_name == 'version' :
							print(col_m + '\n    Hash of %s %s "%s" is UNKNOWN' % (comp[mod_comp], mod_type, mod_name) + col_e)
						elif param.me11_mod_bug :
							input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						print(col_m + '\n    Hash of %s %s "%s" is UNKNOWN' % (comp[mod_comp], mod_type, mod_name) + col_e)
					
					os.rename(mod_fname, mod_fname[:-4]) # Change Data extension from .mod to default
				
				# Module
				else :
					mea_hash = sha_256(mod_data).upper()
					
					if param.me11_mod_bug :
						print('\n    MOD: %s' % mod_hash) # Debug
						print('    MEA: %s' % mea_hash) # Debug
				
					if mod_hash == mea_hash : print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.me11_mod_bug and (mod_hash,mea_hash) not in cse_known_bad_hashes :
							input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
			# Extract LZMA Modules & Decompress
			if mod_comp == 2 :
				try :
					# noinspection PyArgumentList
					mod_data = lzma.LZMADecompressor().decompress(mod_data)
					
					# Add missing EOF Padding when needed (usually at NFTP.ptt Module)
					data_size_uncomp = len(mod_data)
					if data_size_uncomp != mod_size_uncomp :
						mod_last_byte = struct.pack('B', mod_data[data_size_uncomp - 1]) # Determine padding type (0xFF or 0x00)
						mod_miss_padd = mod_size_uncomp - data_size_uncomp # Determine missing padding size
						mod_data += mod_last_byte * mod_miss_padd # Fill module with missing padding
					
					mod_dname = mod_fname[:-5] + '.mod'
					with open(mod_dname, 'w+b') as mod_file : mod_file.write(mod_data)
					print(col_c + '\n    Decompressed %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
					
					mea_hash_u = sha_256(mod_data).upper() # Uncompressed (few LZMA Modules)
					
					if param.me11_mod_bug :
						print('\n    MOD  : %s' % mod_hash) # Debug
						print('    MEA C: %s' % mea_hash_c) # Debug
						print('    MEA U: %s' % mea_hash_u) # Debug
						
					if mod_hash in [mea_hash_c,mea_hash_u] :
						print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						os.remove(mod_fname) # Decompression complete, remove stored LZMA module (.lzma)
					else :
						if param.me11_mod_bug and (mod_hash,mea_hash_c) not in cse_known_bad_hashes :
							input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
				except :
					if param.me11_mod_bug :
						input(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
					else :
						print(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
			
			# Extract Huffman Modules & Decompress
			if mod_comp == 1 :
				try :
					mod_dname = mod_fname[:-5] + '.mod'
					
					with open(mod_fname, 'r+b') as mod_cfile :
						if param.me11_mod_bug :
							mod_ddata = cse_huffman_decompress(mod_cfile.read(), mod_size_comp, mod_size_uncomp, huff_shape, huff_sym, huff_unk, 'error') # Debug
						else :
							mod_ddata = cse_huffman_decompress(mod_cfile.read(), mod_size_comp, mod_size_uncomp, huff_shape, huff_sym, huff_unk, 'none')
							
						if mod_ddata != b'' :
							with open(mod_dname, 'w+b') as mod_dfile: mod_dfile.write(mod_ddata)
					
					if os.path.isfile(mod_dname) :
						print(col_c + '\n    Decompressed %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
						
						# Open decompressed Huffman module for hash validation
						with open(mod_dname, 'r+b') as mod_dfile :
							mea_hash = sha_256(mod_dfile.read()).upper()
							
							if param.me11_mod_bug :
								print('\n    MOD: %s' % mod_hash) # Debug
								print('    MEA: %s' % mea_hash) # Debug
								
							if mod_hash == mea_hash :
								print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
								os.remove(mod_fname) # Decompression complete, remove stored Huffman module (.huff)
							else :
								if param.me11_mod_bug and (mod_hash,mea_hash) not in cse_known_bad_hashes :
									input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
								else :
									print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						raise Exception('Decompressed file not found!')
				
				except :
					if param.me11_mod_bug :
						input(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
					else :
						print(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
			# Print Manifest/Metadata/Key Extension Info
			ext_print_len = len(ext_print) # Final length of Extension Info list (must be after Manifest & Key extraction)
			if mod_type == 'metadata' or '.key' in mod_name :
				for index in range(0, ext_print_len, 2) : # Only Name (index), skip Info (index + 1)
					if str(ext_print[index]).startswith(mod_name) :
						if param.me11_mod_ext : print() # Print Manifest/Metadata/Key Extension Info
						for ext in ext_print[index + 1] :
							ext_str = ansi_escape.sub('', str(ext)) # Ignore Colorama ANSI Escape Character Sequences
							with open(mod_fname + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
							if param.me11_mod_ext : print(ext) # Print Manifest/Metadata/Key Extension Info
						break

# Analyze Key Manifests (Signature & Metadata within .key Module or $FPT/IFWI Partition)
# Almost identical parent code at ext_anl > Manifest & Metadata Analysis > Extensions
def key_anl(mod_fname, ext_print, mod_name, ftpr_var_ver) :
	ext_err_stor = []
	mn2_hdr_print = []
	ext_print_temp = []
	loop_break = 0 # To trigger break at infinite loop
	
	with open(mod_fname, 'r+b') as key_file : key_data = key_file.read() # Key data stream
	key_size = len(key_data)
	
	mn2_key_hdr = get_struct(key_data, 0, MN2_Manifest)
	if mn2_key_hdr.Tag == b'$MN2' : # Sanity check
		
		cpd_ext_offset = mn2_key_hdr.HeaderLength * 4 # End of Key $MN2 Header
		
		mn2_hdr_print = mn2_key_hdr.hdr_print_cse()
		print('\n%s' % mn2_hdr_print) # Show $MN2 details
		
		ext_tag = int.from_bytes(key_data[cpd_ext_offset:cpd_ext_offset + 0x4], 'little') # Initial Key Extension Tag
		
		# Validate Key's RSA Signature
		mn2_key_sigs = rsa_sig_val(mn2_key_hdr, key_data, 0)
		
		mn2_valid = mn2_key_sigs[0] # RSA Signature Validation
		mn2_sig_dec = mn2_key_sigs[1] # RSA Signature Decrypted
		mn2_sig_sha = mn2_key_sigs[2] # RSA Signature Data Hash
		mn2_error = mn2_key_sigs[3] # RSA Signature Validation Error
		# noinspection PyUnusedLocal
		mn2_start = mn2_key_sigs[4] # Manifest Starting Offset
		# noinspection PyUnusedLocal
		mn2_struct = mn2_key_sigs[5] # Manifest Structure
		
		if param.me11_mod_bug :
			print('\nMN2: %s' % mn2_sig_dec) # Debug
			print('MEA: %s' % mn2_sig_sha) # Debug
			
		if mn2_error :
			if param.me11_mod_bug :
				input(col_m + '\nRSA Signature of key "%s" is UNKNOWN' % mod_name + col_e) # Debug
			else :
				print(col_m + '\nRSA Signature of key "%s" is UNKNOWN' % mod_name + col_e)
		elif mn2_valid : print(col_g + '\nRSA Signature of key "%s" is VALID' % mod_name + col_e)
		else :
			if param.me11_mod_bug :
				input(col_r + '\nRSA Signature of key "%s" is INVALID' % mod_name + col_e) # Debug
			else :
				print(col_r + '\nRSA Signature of key "%s" is INVALID' % mod_name + col_e)
		
		while True :
			
			# Break loop just in case it becomes infinite
			loop_break += 1
			if loop_break > 100 :
				ext_err_stor = cse_anl_err(col_r + 'Error: Forced CSE Extension Analysis break after 100 loops at FTPR/UTOK > %s!' % mod_name + col_e)
				
				break
			
			cpd_ext_size = int.from_bytes(key_data[cpd_ext_offset + 0x4:cpd_ext_offset + 0x8], 'little')
			cpd_ext_end = cpd_ext_offset + cpd_ext_size
			
			# Detect unknown CSE Extension & notify user
			if ext_tag not in ext_tag_all :
				ext_err_stor = cse_anl_err(col_r + 'Error: Detected unknown CSE Extension 0x%0.2X at FTPR/UTOK > %s!\n       Some modules may not be detected without adding 0x%0.2X support!'
				% (ext_tag, mod_name, ext_tag) + col_e)
			
			# Detect CSE Extension data overflow & notify user
			if cpd_ext_end > cpd_ext_end : # Key Entry overflow
				ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X data overflow at FTPR/UTOK > %s!' % (ext_tag, mod_name) + col_e)
			
			hdr_rev_tag = '' # CSE Extension Header Revision Tag
			mod_rev_tag = '' # CSE Extension Module Revision Tag
			
			if (variant,major) == ('CSME',12) and not ((minor,hotfix) == (0,0) and build >= 7000) :
				if ext_tag in ext_tag_rev_hdr_csme12 : hdr_rev_tag = '_R2'
				if ext_tag in ext_tag_rev_mod_csme12 : mod_rev_tag = '_R2'
			elif (variant,major) == ('CSSPS',5) :
				if ext_tag in ext_tag_rev_hdr_cssps5 : hdr_rev_tag = '_R2'
				if ext_tag in ext_tag_rev_mod_cssps5 : mod_rev_tag = '_R2'
			else :
				pass # These CSE use the original Header/Module Structures
			
			ext_dict_name = 'CSE_Ext_%0.2X%s' % (ext_tag, hdr_rev_tag)
			ext_struct_name = ext_dict[ext_dict_name] if ext_dict_name in ext_dict else None
			ext_dict_mod = 'CSE_Ext_%0.2X_Mod%s' % (ext_tag, mod_rev_tag)
			ext_struct_mod = ext_dict[ext_dict_mod] if ext_dict_mod in ext_dict else None
			
			if ext_dict_name in ext_dict :
				ext_length = ctypes.sizeof(ext_struct_name)
				
				# Detect CSE Extension without Modules different size & notify user
				if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
					ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at FTPR/UTOK > %s!' % (ext_tag, mod_name) + col_e)
				
				ext_hdr_p = get_struct(key_data, cpd_ext_offset, ext_struct_name)
				ext_print_temp.append(ext_hdr_p.ext_print())
				
				if ext_tag == 0x15 : # CSE_Ext_15 has a unique structure
					CSE_Ext_15_PartID_length = ctypes.sizeof(CSE_Ext_15_PartID)
					CSE_Ext_15_Payload_length = ctypes.sizeof(CSE_Ext_15_Payload)
					CSE_Ext_15_Payload_Knob_length = ctypes.sizeof(CSE_Ext_15_Payload_Knob)
					
					part_id_count = ext_hdr_p.PartIDCount
					cpd_part_id_offset = cpd_ext_offset + ext_length # CSE_Ext_15 structure size (not entire Extension 15)
					cpd_payload_offset = cpd_part_id_offset + part_id_count * 0x14
					cpd_payload_knob_offset = cpd_payload_offset + 0x4
					
					for _ in range(part_id_count) :
						part_id_struct = get_struct(key_data, cpd_part_id_offset, CSE_Ext_15_PartID)
						ext_print_temp.append(part_id_struct.ext_print())
						cpd_part_id_offset += 0x14
								
					payload_struct = get_struct(key_data, cpd_payload_offset, CSE_Ext_15_Payload)
					ext_print_temp.append(payload_struct.ext_print())
					payload_knob_count = payload_struct.KnobCount
					payload_knob_area = cpd_ext_end - cpd_payload_knob_offset
					
					# Check Extension full size when Module Counter exists
					if ext_tag in ext_tag_mod_count and (cpd_ext_size != ext_length + part_id_count * CSE_Ext_15_PartID_length + CSE_Ext_15_Payload_length +
					payload_knob_count * CSE_Ext_15_Payload_Knob_length) :
						ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at FTPR/UTOK > %s!' % (ext_tag, mod_name) + col_e)
					
					# Check if Knob data is divisible by Knob size
					if payload_knob_area % CSE_Ext_15_Payload_Knob_length != 0 :
						ext_err_stor = cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at FTPR/UTOK > %s!' % (ext_tag, mod_name) + col_e)
					
					for knob in range(payload_knob_count) :
						payload_knob_struct = get_struct(key_data, cpd_payload_knob_offset, CSE_Ext_15_Payload_Knob, ftpr_var_ver)
						ext_print_temp.append(payload_knob_struct.ext_print())
						cpd_payload_knob_offset += 0x08
				
				elif ext_dict_mod in ext_dict :
					mod_length = ctypes.sizeof(ext_struct_mod)
					cpd_mod_offset = cpd_ext_offset + ext_length
					cpd_mod_area = cpd_ext_end - cpd_mod_offset
					
					# Check Extension full size when Module Counter exists
					if ext_tag in ext_tag_mod_count and (cpd_ext_size != ext_length + ext_hdr_p.ModuleCount * mod_length) :
						ext_err_stor = cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at FTPR/UTOK > %s!' % (ext_tag, mod_name) + col_e)
					
					# Check if Mod data is divisible by Mod size
					if cpd_mod_area % mod_length != 0 :
						ext_err_stor = cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at FTPR/UTOK > %s!' % (ext_tag, mod_name) + col_e)
					
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr_p = get_struct(key_data, cpd_mod_offset, ext_struct_mod)
						ext_print_temp.append(mod_hdr_p.ext_print())
						
						cpd_mod_offset += mod_length
						
			cpd_ext_offset += cpd_ext_size
			
			if cpd_ext_offset + 1 > cpd_ext_end : break # End of Key data reached
			
			ext_tag = int.from_bytes(key_data[cpd_ext_offset:cpd_ext_offset + 0x4], 'little') # Next Key Extension Tag
	
	# Detect last 0x20 of UTOK/STKN for UTFL structure
	if key_data[key_size - 0x20:key_size - 0x1C] == b'UTFL' :
		utfl_hdr = get_struct(key_data, key_size - 0x20, UTFL_Header)
		ext_print_temp.append(utfl_hdr.hdr_print())
	
	if not mn2_hdr_print : ext_print_temp = mn2_hdr_print + ext_print_temp # UTFL info only w/o Key
	else : ext_print_temp = [mn2_hdr_print] + ext_print_temp # $MN2 followed by Key Extension and optional UTFL info
	
	ext_print.append(mod_name) # Store Key name
	ext_print.append(ext_print_temp) # Store Key Extension $MN2 + Info
	
	return ext_print, ext_err_stor
	
# Analyze CSE PMC firmware
def pmc_anl(mn2_info) :
	pmc_pch_sku = 'N/A'
	pmc_pch_rev = 'N/A'
	pmc_platform = 'Unknown'
	pmcp_upd_found = False
	pmcp_not_in_db = False
	pch_sku_val = {1: 'LP', 2: 'H'}
	pch_sku_old = {0: 'H', 2: 'LP'}
	pch_rev_val = {0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E', 5: 'F', 6: 'G', 7: 'H', 8: 'I', 9: 'J'}
	
	# mn2_info = [Major/PCH, Minor/SKU, Hotfix/Compatibility-Maintenance, Build, Release, RSA Sig Hash]
	
	pmc_fw_ver = '%s.%s.%s.%s' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
	pmc_mn2_signed = 'Pre-Production' if mn2_info[4] == 'Debug' else 'Production'
	
	# Search DB for PMC firmware
	fw_db = db_open()
	for line in fw_db :
		if mn2_info[5] in line :
			break # Break loop at 1st hash match
	else :
		pmcp_not_in_db = True
	fw_db.close()
	
	if variant == 'PMCCNP' or (variant,major) in [('CSME',12),('CSSPS',5)] :
		pmc_platform = 'CNP'
		
		if mn2_info[0] == 300 :
			# CSME 12.0.0.1033 - 12.0.5.1117 --> 300.2.01.1012 = CNP + H + PCH Stepping A1 + PMC Revision 1012 (POR)
			# CSME >= 12.0.6.1120 --> 300.2.11.1014 = CNP + H + PCH Compatibility B + PMC Maintenance 1 + PMC Revision 1014 (POR)
			if mn2_info[1] in pch_sku_val : pmc_pch_sku = pch_sku_val[mn2_info[1]] # 1 LP, 2 H
			pmc_pch_rev = '%s%d' % (pch_rev_val[mn2_info[2] // 10], mn2_info[2] % 10) # 21 = PCH C PMC 1 (>= 12.0.6.1120) or PCH C1 (<= 12.0.0.1033)
		else :
			# CSME < 12.0.0.1033 --> 01.7.0.1022 = PCH Stepping A1 + PMC Hotfix 7 + PCH-H + PMC Build 1022 (Guess)
			# CSME < 12.0.0.1033 --> 10.0.2.1021 = PCH Stepping B0 + PMC Hotfix 0 + PCH-LP + PMC Build 1021 (Guess)
			if mn2_info[2] in pch_sku_old : pmc_pch_sku = pch_sku_old[mn2_info[2]] # 0 H, 2 LP
			pmc_pch_rev = '%s%d' % (pch_rev_val[mn2_info[0] // 10], mn2_info[0] % 10) # 00 = PCH A0, 10 = PCH B0, 21 = PCH C1 etc
		
		# Check if PMCCNP firmware is the latest
		db_pch,db_sku,db_rev,db_rel = check_upd(('Latest_PMCCNP_%s_%s' % (pmc_pch_sku, pch_rev_val[mn2_info[2] // 10])))
		if mn2_info[2] < db_rev or (mn2_info[2] == db_rev and mn2_info[3] < db_rel) : pmcp_upd_found = True
			
	elif variant.startswith('PMCAPL') or (variant == 'CSTXE' and major == 3 and minor in [0,1]) :
		pmc_platform = 'APL'
		pmc_pch_rev = sku_stp if variant == 'CSTXE' else variant[-1]
	elif variant.startswith('PMCBXT') or (variant == 'CSTXE' and major == 3 and minor == 2) :
		pmc_platform = 'BXT'
		pmc_pch_rev = sku_stp if variant == 'CSTXE' else variant[-1]
	elif variant.startswith('PMCGLK') or (variant == 'CSTXE' and major == 4) :
		pmc_platform = 'GLK'
		pmc_pch_rev = sku_stp if variant == 'CSTXE' else variant[-1]
	
	return pmc_fw_ver, mn2_info[0], pmc_pch_sku, pmc_pch_rev, mn2_info[3], pmc_mn2_signed, pmcp_upd_found, pmcp_not_in_db, pmc_platform, mn2_info[6]

# CSE Huffman Dictionary Loader by IllegalArgument
# Dictionaries by Dmitry Sklyarov & IllegalArgument
# Message Verbosity: All | Error | None
def cse_huffman_dictionary_load(cse_variant, cse_major, verbosity) :
	HUFFMAN_SHAPE = []
	HUFFMAN_SYMBOLS = {}
	HUFFMAN_UNKNOWNS = {}
	mapping_types = {'code' : 0x20, 'data' : 0x60}
	huffman_dict = os.path.join(mea_dir, 'Huffman.dat')
	
	# Check if Huffman dictionary version is supported
	if (cse_variant, cse_major) in [('CSME', 11), ('CSSPS', 4)] : dict_version = 11
	elif (cse_variant, cse_major) in [('CSME', 12), ('CSSPS', 5)] : dict_version = 12
	else :
		# CSTXE 3-4 do not use Huffman compression, skip error message
		if (cse_variant,cse_major) not in [('CSTXE', 3), ('CSTXE', 4)] and verbosity in ['all','error'] :
			print(col_r + '\nNo Huffman dictionary for {0} {1}'.format(cse_variant, cse_major) + col_e)
		
		return HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS
	
	# Check if supported Huffman dictionary file exists
	if not os.path.isfile(huffman_dict) :
		if verbosity in ['all','error'] : print(col_r + '\nHuffman dictionary file is missing!' + col_e)
		
		return HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS
	
	with open(huffman_dict, 'r') as dict_file :
		dict_json = json.load(dict_file)
		
		dict_mappings = dict_json[str(dict_version)]
		mapping_codeword_ranges = {}
		
		for mapping_type_string, mapping in dict_mappings.items() :
			mapping_type = mapping_types[mapping_type_string]
			grouped_codeword_strings = itertools.groupby(sorted(list(mapping.keys()), key=len), key=len)
			# noinspection PyTypeChecker
			grouped_codewords = { codeword_len : [int(codeword, 2) for codeword in codewords] for codeword_len, codewords in grouped_codeword_strings}
			mapping_codeword_ranges[mapping_type] = {codeword_len : (min(codewords), max(codewords)) for codeword_len, codewords in grouped_codewords.items()}
		
		if len(set([frozenset(x.items()) for x in mapping_codeword_ranges.values()])) > 1 and verbosity in ['all','error'] :
			print(col_r + '\n    Mismatched mappings in the same dictionary' + col_e)
		
		codeword_ranges = list(mapping_codeword_ranges.values())[0]
		
		for i, j in zip(list(codeword_ranges.keys())[:-1], list(codeword_ranges.keys())[1:]) :
			if 2 * codeword_ranges[i][0] - 1 != codeword_ranges[j][1] and verbosity in ['all','error'] :
				print(col_r + '\n    Discontinuity between codeword lengths {0} and {1}'.format(i, j) + col_e)
				
		HUFFMAN_SHAPE = [(codeword_len, codeword_min << (32 - codeword_len), codeword_max) for codeword_len, (codeword_min, codeword_max) in codeword_ranges.items()]
			
		for mapping_type_string, mapping in dict_mappings.items() :
			mapping_type = mapping_types[mapping_type_string]
			
			HUFFMAN_SYMBOLS[mapping_type] = {}
			HUFFMAN_UNKNOWNS[mapping_type] = {}
			
			for codeword_len, (codeword_min, codeword_max) in codeword_ranges.items() :
				HUFFMAN_UNKNOWNS[mapping_type][codeword_len] = set()
				
				def parse_symbol(codeword) :
					codeword_binary = format(codeword, '0' + str(codeword_len) + 'b')
					symbol = mapping[codeword_binary].strip()
					if symbol == '' :
						HUFFMAN_UNKNOWNS[mapping_type][codeword_len].add(codeword)
						return [0x7F]
					elif re.match('^(\?\?)+$', symbol) :
						HUFFMAN_UNKNOWNS[mapping_type][codeword_len].add(codeword)
						return list(itertools.repeat(0x7F, int(len(symbol) / 2)))
					else :
						return [x for x in bytes.fromhex(symbol)]
				
				HUFFMAN_SYMBOLS[mapping_type][codeword_len] = [parse_symbol(codeword) for codeword in range(codeword_max, codeword_min - 1, -1)]
			
	return HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS
	
# CSE Huffman Decompressor by IllegalArgument
# Message Verbosity: All | Error | None
def cse_huffman_decompress(module_contents, compressed_size, decompressed_size, HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS, verbosity) :
	CHUNK_SIZE = 0x1000
	decompressed_array = []
	
	if not HUFFMAN_SHAPE : return b'' # Failed to load required Huffman dictionary
	
	chunk_count = int(decompressed_size / CHUNK_SIZE)
	header_size = chunk_count * 0x4
	
	module_buffer = bytearray(module_contents)
	header_buffer = module_buffer[0:header_size]
	compressed_buffer = module_buffer[header_size:compressed_size]
	
	header_entries = struct.unpack('<{:d}I'.format(chunk_count), header_buffer)
	start_offsets, flags = zip(*[(x & 0x1FFFFFF, (x >> 25) & 0x7F) for x in header_entries])
	end_offsets = itertools.chain(start_offsets[1:], [compressed_size - header_size])
	
	for index, dictionary_type, compressed_position, compressed_limit in zip(range(chunk_count), flags, start_offsets, end_offsets) :
		if verbosity == 'all' :
			print(col_r + '\n    ==Processing chunk 0x{:X} at compressed offset 0x{:X} with dictionary 0x{:X}=='.format(index, compressed_position, dictionary_type) + col_e)
			
		dictionary = HUFFMAN_SYMBOLS[dictionary_type]
		unknowns = HUFFMAN_UNKNOWNS[dictionary_type]
		
		decompressed_position, decompressed_limit = index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE
		
		bit_buffer = 0
		available_bits = 0
		
		while decompressed_position < decompressed_limit :
			while available_bits <= 24 and compressed_position < compressed_limit :
				bit_buffer = bit_buffer | compressed_buffer[compressed_position] << (24 - available_bits)
				compressed_position = compressed_position + 1
				available_bits = available_bits + 8
			
			codeword_length, base_codeword = 0, 0
			for length, shape, base in HUFFMAN_SHAPE :
				if bit_buffer >= shape :
					codeword_length, base_codeword = length, base
					break
			
			if available_bits >= codeword_length :
				codeword = bit_buffer >> (32 - codeword_length)
				bit_buffer = (bit_buffer << codeword_length) & 0xFFFFFFFF
				available_bits = available_bits - codeword_length
				
				symbol = dictionary[codeword_length][base_codeword - codeword]
				symbol_length = len(symbol)
				
				if decompressed_limit - decompressed_position >= symbol_length :
					if codeword in unknowns[codeword_length] and verbosity in ['all','error'] :
						print(col_r + '\n    Unknown codeword {: <15s} (dictionary 0x{:X}, codeword length {: >2d}, codeword {: >5s}, symbol length {:d}) at decompressed offset 0x{:X}'.format(
							('{:0>' + str(codeword_length) + 'b}').format(codeword), dictionary_type, codeword_length, "0x{:X}".format(codeword), symbol_length, decompressed_position) + col_e)
					decompressed_array.extend(symbol)
					decompressed_position = decompressed_position + symbol_length
				else :
					if verbosity in ['all','error'] :
						print(col_r + '\n    Skipping overflowing codeword {: <15s} (dictionary 0x{:X}, codeword length {: >2d}, codeword {: >5s}, symbol length {:d}) at decompressed offset 0x{:X}'.format(
							('{:0>' + str(codeword_length) + 'b}').format(codeword), dictionary_type, codeword_length, '0x{:X}'.format(codeword), symbol_length, decompressed_position) + col_e)
					filler = itertools.repeat(0x7F, decompressed_limit - decompressed_position)
					decompressed_array.extend(filler)
					decompressed_position = decompressed_limit
			else :
				if verbosity in ['all','error'] :
					print(col_r + '\n    Reached end of compressed stream early at decompressed offset 0x{:X}'.format(decompressed_position) + col_e)
				filler = itertools.repeat(0x7F, decompressed_limit - decompressed_position)
				decompressed_array.extend(filler)
				decompressed_position = decompressed_limit
				
	return bytearray(decompressed_array)

# Intel ME File System Explorer by Dmitry Sklyarov
# Python 2.7 executable path must be adjusted manually
# Temporary until native MEA MFS unpacker is implemented
def parse_MFS(mod_fname, part_type, part_name, part_start, part_end) :
	try :
		import subprocess, zipfile
		subprocess.Popen('C:\Python\Python27\python.exe parseMFS.py "%s"' % mod_fname, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).communicate()
		if os.path.isfile(mod_fname + '.zip') :
			os.mkdir(mod_fname[:-4])
			with zipfile.ZipFile(mod_fname + '.zip') as mfs_zip : mfs_zip.extractall(mod_fname[:-4])
			os.remove(mod_fname + '.zip')
			print(col_c + '\n    Unpacked $FPT %s Partition "%s" [0x%0.6X - 0x%0.6X] via parseMFS' % (part_type, part_name, part_start, part_end) + col_e)
	except:
		pass
	
# Store and show CSE analysis errors
def cse_anl_err(ext_err_msg, checked_hashes = None) :
	if checked_hashes is None : checked_hashes = ['','']
	
	ext_err_stor.append(ext_err_msg)
	copy_file = False if checked_hashes in cse_known_bad_hashes else True
	err_stor.append([ext_err_msg, copy_file])
	if param.me11_mod_extr or param.me11_mod_bug :
		gen_msg(err_stor, ext_err_msg, 'unp', copy_file)
		if copy_file : input('Press enter to continue...') # Debug
		
	return ext_err_stor
	
# Detect CSE Partition Instance Identifier
def cse_part_inid(buffer, cpd_offset, ext_dictionary) :
	cpd_hdr_ver = reading[cpd_offset + 8] # $CPD Version Tag
	if cpd_hdr_ver == 2 : cpd_hdr = get_struct(buffer, cpd_offset, CPD_Header_2)
	else : cpd_hdr = get_struct(buffer, cpd_offset, CPD_Header)
	cse_in_id = 0
	in_id_step = 0
	in_id_stop = 0
	cse_part_size = 0
	cse_part_name = ''
	
	if cpd_hdr.Tag == b'$CPD' : # Sanity check
		mn2_start = cpd_offset + 0x10 + cpd_entry_num_fix(buffer, cpd_offset, cpd_hdr.NumModules) * 0x18 # $CPD entries start at $CPD + 0x10, size = 0x18
		
		mn2_hdr = get_struct(buffer, mn2_start, MN2_Manifest)
		
		if mn2_hdr.Tag == b'$MN2' : # Sanity check
			mn2_size = mn2_hdr.HeaderLength * 4
			
			# Detected $CPD + $MN2, search for Instance ID at CSE_Ext_03 or CSE_Ext_16
			while int.from_bytes(buffer[mn2_start + mn2_size + in_id_step:mn2_start + mn2_size + in_id_step + 0x4], 'little') not in [0x3,0x16] :
				in_id_stop += 1
				if in_id_stop > 10 : break
				in_id_step += int.from_bytes(buffer[mn2_start + mn2_size + in_id_step + 0x4:mn2_start + mn2_size + in_id_step + 0x8], 'little')
			else :
				in_id_ext = 'CSE_Ext_%0.2X' % int.from_bytes(buffer[mn2_start + mn2_size + in_id_step:mn2_start + mn2_size + in_id_step + 0x4], 'little')
				if in_id_ext in ext_dictionary :
					cse_ext_hdr = get_struct(buffer, mn2_start + mn2_size + in_id_step, ext_dictionary[in_id_ext])
					cse_in_id = cse_ext_hdr.InstanceID # Partition Instance Identifier
					cse_part_name = cse_ext_hdr.PartitionName # Partition Name (for uncharted $FPT code, no need for almost duplicate function)
					cse_part_size = cse_ext_hdr.PartitionSize # Partition Size (for uncharted $FPT code, no need for almost duplicate function)
								
	return cse_in_id, cse_part_name, cse_part_size
	
# Get correct $CPD Entry Counter for end offset detection
def cpd_entry_num_fix(buffer, cpd_offset, cpd_entry_count) :
	cpd_entry_empty = 0
	cpd_entry_end = cpd_offset + 0x10 + cpd_entry_count * 0x18 # $CPD entries start at $CPD + 0x10, size = 0x18
	
	# Some $CPD may have X entries + empty Y. Try to adjust counter a maximum of 5 times (GREAT WORK INTEL/OEMs...)
	while int.from_bytes(buffer[cpd_entry_end:cpd_entry_end + 0x18], 'little') == 0 :
		cpd_entry_end += 0x18
		cpd_entry_empty += 1
		if cpd_entry_empty > 5 :
			gen_msg(err_stor, col_r + 'Error: Failed to fix $CPD entry counter at 0x%X!' % cpd_offset + col_e, 'unp', True)
			break
		
	return cpd_entry_count + cpd_entry_empty
	
# Calculate $CPD Partition size via its Entries
def cpd_size_calc(buffer, cpd_offset, align_size) :
	cpd_fw_end = 0
	cpd_offset_last = 0
	
	cpd_hdr_ver = buffer[cpd_offset + 8] # $CPD Version Tag
	if cpd_hdr_ver == 2 : cpd_hdr = get_struct(buffer, cpd_offset, CPD_Header_2)
	else : cpd_hdr = get_struct(buffer, cpd_offset, CPD_Header)
	cpd_num = cpd_entry_num_fix(buffer, cpd_offset, cpd_hdr.NumModules)
	
	for entry in range(1, cpd_num, 2) : # Skip 1st .man module, check only .met
		cpd_entry_hdr = get_struct(buffer, cpd_offset + 0x10 + entry * 0x18, CPD_Entry)
		cpd_mod_off,cpd_mod_huff,cpd_mod_res = cpd_entry_hdr.get_flags()
		
		cpd_entry_name = cpd_entry_hdr.Name
		
		if b'.met' not in cpd_entry_name and b'.man' not in cpd_entry_name : # Sanity check
			cpd_entry_offset = cpd_mod_off
			cpd_entry_size = cpd_entry_hdr.Size
			
			# Store last entry (max $CPD offset)
			if cpd_entry_offset > cpd_offset_last :
				cpd_offset_last = cpd_entry_offset
				cpd_fw_end = cpd_entry_offset + cpd_entry_size
		else :
			break # nested "for" loop
		
	cpd_align = (cpd_fw_end - cpd_offset) % align_size
	cpd_fw_end = cpd_fw_end + align_size - cpd_align
	
	return cpd_fw_end
	
# Process ctypes Structure Classes
def get_struct(input_stream, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = input_stream[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= file_end) or (fit_len < struct_len) :
		err_stor.append([col_r + 'Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name) + col_e, True])
		
		for error in err_stor : print(error[0])
		
		if not param.extr_mea : copy_on_msg() # Close input and copy it in case of messages
		
		mea_exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure

# Initialize PrettyTable
def ext_table(row_col_names,header,padd) :
	pt = prettytable.PrettyTable(row_col_names)
	if not param.cli_redirect : pt.set_style(prettytable.BOX_CHARS)
	pt.header = header # Boolean
	pt.left_padding_width = padd
	pt.right_padding_width = padd
	pt.hrules = prettytable.ALL
	pt.vrules = prettytable.ALL
	
	return pt
	
# Detect DB Revision
def mea_hdr_init() :
	db_rev = col_r + 'Unknown' + col_e
	
	try :
		fw_db = db_open()
		for line in fw_db :
			if 'Revision' in line :
				db_line = line.split()
				db_rev = col_y + db_line[2] + col_e
		fw_db.close()
	except :
		pass
	
	return db_rev

# Print MEA Header
def mea_hdr(db_rev) :
	hdr_pt = ext_table([], False, 1)
	hdr_pt.add_row([col_y + '        %s' % title + col_e + ' %s        ' % db_rev])
	print(hdr_pt)

# https://stackoverflow.com/a/22881871
def get_script_dir(follow_symlinks=True) :
	if getattr(sys, 'frozen', False) :
		path = os.path.abspath(sys.executable)
	else :
		path = inspect.getabsfile(get_script_dir)
	if follow_symlinks :
		path = os.path.realpath(path)

	return os.path.dirname(path)

# https://stackoverflow.com/a/781074
def show_exception_and_exit(exc_type, exc_value, tb) :
	print(col_r + '\nError: MEA just crashed, please report the following:\n')
	traceback.print_exception(exc_type, exc_value, tb)
	if not param.skip_pause : input(col_e + "\nPress enter to exit")
	colorama.deinit() # Stop Colorama
	sys.exit(-1)

# Execute final actions
def mea_exit(code=0) :
	colorama.deinit() # Stop Colorama
	if param.extr_mea or param.print_msg : sys.exit(code)
	if not param.skip_pause : input("\nPress enter to exit")
	sys.exit(code)

# Calculate SHA-1 hash of data
def sha_1(data) :
	return hashlib.sha1(data).hexdigest()
	
# Calculate SHA-256 hash of data
def sha_256(data) :
	return hashlib.sha256(data).hexdigest()

# Validate UCODE checksum
def mc_chk32(data) :
	chk32 = 0
	
	for idx in range(0, len(data), 4) : # Move 4 bytes at a time
		chkbt = int.from_bytes(data[idx:idx + 4], 'little') # Convert to int, MSB at the end (LE)
		chk32 = chk32 + chkbt
	
	return -chk32 & 0xFFFFFFFF # Return 0
	
# Close input file and copy it if there are worthy Notes, Warnings or Errors
# Must be called at the end of analysis to gather any generated messages
def copy_on_msg() :
	f.close()
	copy = False
	
	# Detect if any copy-worthy generated message exists
	for message in (err_stor + warn_stor + note_stor) :
		if message[1] : copy = True
	
	#if err_stor or warn_stor or note_stor : copy = True # Copy on any message (Debug)
	
	# At least one message needs a file copy
	if copy :
		file_name = os.path.basename(file_in)
		check_dir = os.path.join(mea_dir, '__CHECK__', '')
		
		if not os.path.isdir(check_dir) : os.mkdir(check_dir)
		
		suffix = 0
		while os.path.exists(check_dir + file_name) :
			suffix += 1
			file_name += '_%s' % suffix
		
		shutil.copyfile(file_in, check_dir + file_name)

# Open MEA database
def db_open() :
	fw_db = open(db_path, 'r', encoding = 'utf-8')
	return fw_db

# Check DB for latest version
def check_upd(key) :
	upd_key_found = False
	vlp = [0]*4
	fw_db = db_open()
	for line in fw_db :
		if key in line :
			upd_key_found = True
			wlp = line.strip().split('__') # whole line parts
			vlp = wlp[1].strip().split('.') # version line parts
			for i in range(len(vlp)) :
				# noinspection PyTypeChecker
				vlp[i] = int(vlp[i])
			break
	fw_db.close()
	if upd_key_found : return vlp[0],vlp[1],vlp[2],vlp[3]
	else : return 0,0,0,0

# Generate general MEA messages
def gen_msg(msg_type, msg, command, copy_file) :
	if not param.print_msg and param.me11_mod_extr and command == 'unp' : print('\n' + msg + '\n')
	elif not param.print_msg and command == 'unp' : print(msg + '\n')
	elif not param.print_msg : print('\n' + msg)
	
	if (not err_stor) and (not warn_stor) and (not note_stor): msg_type.append([msg, copy_file])
	else: msg_type.append(['\n' + msg, copy_file])

# Detect Intel Flash Descriptor
def spi_fd_init() :
	# Search for Flash Descriptor pattern (PCH/ICH)
	fd_match = list(re.compile(br'\x5A\xA5\xF0\x0F.{172}\xFF{16}', re.DOTALL).finditer(reading)) # Z¥π. + [0xAC] + 0xFF * 16 detection
	
	# Detected Flash Descriptor, use first but notify if more exist
	if fd_match :
		# Platform Controller Hub (PCH)
		if (fd_match[0].start() == 0x10 or reading[fd_match[0].start() - 0x4:fd_match[0].start()] == b'\xFF' * 4) \
		and reading[fd_match[0].start() + 0x4] in [3,2] and reading[fd_match[0].start() + 0x6] == 4 :
			start_substruct = 0x10
			end_substruct = 0xBC # 0xBC for [0xAC] + 0xFF * 16 sanity check
		# I/O Controller Hub (ICH)
		else :
			start_substruct = 0x0
			end_substruct = 0xBC - 0x10 # 0xBC for [0xAC] + 0xFF * 16 sanity check, 0x10 extra before ICH FD Regions
		
		return True, fd_match[0].start() - start_substruct, fd_match[0].end() - end_substruct, len(fd_match)
	
	else :
		return False, 0, 0, 0

# Analyze Intel Flash Descriptor (FD)
def spi_fd(action,start_fd_match,end_fd_match) :
	fd_reg_exist = [] # BIOS/IAFW + Engine
	
	if action == 'region' :
		bios_fd_base = int.from_bytes(reading[end_fd_match + 0x30:end_fd_match + 0x32], 'little')
		bios_fd_limit = int.from_bytes(reading[end_fd_match + 0x32:end_fd_match + 0x34], 'little')
		me_fd_base = int.from_bytes(reading[end_fd_match + 0x34:end_fd_match + 0x36], 'little')
		me_fd_limit = int.from_bytes(reading[end_fd_match + 0x36:end_fd_match + 0x38], 'little')
		devexp_fd_base = int.from_bytes(reading[end_fd_match + 0x40:end_fd_match + 0x42], 'little')
		devexp_fd_limit = int.from_bytes(reading[end_fd_match + 0x42:end_fd_match + 0x44], 'little')
		
		if bios_fd_limit != 0 :
			bios_fd_start = bios_fd_base * 0x1000 + start_fd_match # fd_match required in case FD is not at the start of image
			bios_fd_size = (bios_fd_limit + 1 - bios_fd_base) * 0x1000 # The +1 is required to include last Region byte
			fd_reg_exist.extend((True,bios_fd_start,bios_fd_size)) # BIOS/IAFW Region exists
		else :
			fd_reg_exist.extend((False,0,0)) # BIOS/IAFW Region missing
			
		if me_fd_limit != 0 :
			me_fd_start = me_fd_base * 0x1000 + start_fd_match
			me_fd_size = (me_fd_limit + 1 - me_fd_base) * 0x1000
			fd_reg_exist.extend((True,me_fd_start,me_fd_size)) # Engine Region exists
		else :
			fd_reg_exist.extend((False,0,0)) # Engine Region missing
			
		if devexp_fd_limit != 0 :
			devexp_fd_start = devexp_fd_base * 0x1000 + start_fd_match
			devexp_fd_size = (devexp_fd_limit + 1 - devexp_fd_base) * 0x1000
			fd_reg_exist.extend((True,devexp_fd_start,devexp_fd_size)) # Device Expansion Region exists
		else :
			fd_reg_exist.extend((False,0,0)) # Device Expansion Region missing
			
		return fd_reg_exist
	
# Format firmware version
def fw_ver(major,minor,hotfix,build) :
	if variant in ['SPS','CSSPS'] :
		version = '%s.%s.%s.%s' % ('{0:02d}'.format(major), '{0:02d}'.format(minor), '{0:02d}'.format(hotfix), '{0:03d}'.format(build)) # xx.xx.xx.xxx
	else :
		version = '%s.%s.%s.%s' % (major, minor, hotfix, build)
	
	return version

# Detect Fujitsu Compressed ME Region
def fuj_umem_ver(me_fd_start) :
	version = 'NaN'
	
	if reading[me_fd_start:me_fd_start + 0x4] == b'\x55\x4D\xC9\x4D' : # UMEM
		major = int.from_bytes(reading[me_fd_start + 0xB:me_fd_start + 0xD], 'little')
		minor = int.from_bytes(reading[me_fd_start + 0xD:me_fd_start + 0xF], 'little')
		hotfix = int.from_bytes(reading[me_fd_start + 0xF:me_fd_start + 0x11], 'little')
		build = int.from_bytes(reading[me_fd_start + 0x11:me_fd_start + 0x13], 'little')
		version = '%s.%s.%s.%s' % (major, minor, hotfix, build)
	
	return version
	
# Check if Fixed Offset Variables (FOVD/NVKR) partition is dirty
def fovd_clean(fovdtype) :
	fovd_start = -1
	fovd_empty = 'N/A'
	
	for part in fpt_part_all :
		if (fovdtype,part[0]) in [('new',b'FOVD'),('old',b'NVKR')] :
			fovd_start = part[1]
			fovd_empty = part[6]
	
	if (fovd_start,fovd_empty) != (-1,'N/A') :
		if fovdtype == 'new' :
			return fovd_empty # Empty = Clean
		elif fovdtype == 'old' :
			if fovd_empty :
				return True
			else :
				nvkr_size = int.from_bytes(reading[fovd_start + 0x19:fovd_start + 0x1C], 'little')
				nvkr_data = reading[fovd_start + 0x1C:fovd_start + 0x1C + nvkr_size]
				
				if nvkr_data == b'\xFF' * nvkr_size : return True
				else : return False
	else :
		return True

# Create Firmware Type Database Entry
def fw_types(fw_type) :
	type_db = 'NaN'
	
	if variant in ['SPS','CSSPS'] and fw_type in ['Region','Region, Stock','Region, Extracted'] : # SPS --> Region (EXTR at DB)
		fw_type = 'Region'
		type_db = 'EXTR'
	elif fw_type == 'Region, Extracted' : type_db = 'EXTR'
	elif fw_type == 'Region, Stock' or fw_type == 'Region' : type_db = 'RGN'
	elif fw_type == 'Update' : type_db = 'UPD'
	elif fw_type == 'Operational' : type_db = 'OPR'
	elif fw_type == 'Recovery' : type_db = 'REC'
	elif fw_type == 'Independent' and variant.startswith('PMC') : type_db = 'PMC'
	elif fw_type == 'Unknown' : type_db = 'UNK'
	
	return fw_type, type_db

# Validate $CPD Checksum
def cpd_chk(cpd_data, cpd_ver) :
	if cpd_ver == 2 :
		cpd_chk_file = int.from_bytes(cpd_data[0x10:0x14], 'little')
		cpd_chk_calc = zlib.crc32(cpd_data) & 0xFFFFFFFF
	else :
		cpd_chk_file = cpd_data[0xB]
		cpd_sum = sum(cpd_data) - cpd_chk_file
		cpd_chk_calc = (0x100 - cpd_sum & 0xFF) & 0xFF
	
	return cpd_chk_file == cpd_chk_calc, cpd_chk_file, cpd_chk_calc
	
# Validate Manifest RSA Signature
def rsa_sig_val(man_hdr_struct, input_stream, check_start) :
	man_hdr = man_hdr_struct.HeaderLength * 4
	man_size = man_hdr_struct.Size * 4
	man_pexp = man_hdr_struct.RSAExponent
	man_pkey = int((''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(man_hdr_struct.RSAPublicKey))), 16)
	man_sign = int((''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(man_hdr_struct.RSASignature))), 16)
	
	# return [RSA Sig isValid, RSA Sig Decr Hash, RSA Sig Data Hash, RSA Validation isCrashed, $MN2 Offset, $MN2 Struct Object]
	
	try :
		dec_sign = '%X' % pow(man_sign, man_pexp, man_pkey) # Decrypted Signature
	
		if (variant == 'ME' and major < 6) or (variant == 'SPS' and major < 2) : # SHA-1
			rsa_hash = hashlib.sha1()
			dec_hash = dec_sign[-40:] # 160-bit
		else : # SHA-256
			rsa_hash = hashlib.sha256()
			dec_hash = dec_sign[-64:] # 256-bit
	
		rsa_hash.update(input_stream[check_start:check_start + 0x80]) # First 0x80 before RSA area
		rsa_hash.update(input_stream[check_start + man_hdr:check_start + man_size]) # Manifest protected data
		rsa_hash = rsa_hash.hexdigest().upper() # Data SHA-1 or SHA-256 Hash
		
		return [dec_hash == rsa_hash, dec_hash, rsa_hash, False, check_start, man_hdr_struct] # RSA block validation check OK
	except :
		if (man_pexp,man_pkey,man_sign) == (0,0,0) :
			return [True, 0, 0, False, check_start, man_hdr_struct] # "Valid"/Empty RSA block, no validation crash
		else :
			return [False, 0, 0, True, check_start, man_hdr_struct] # RSA block validation check crashed, debugging required
	
# Search DB for manual CSE values
def db_skl(variant) :
	fw_db = db_open()

	db_sku_chk = 'NaN'
	sku = 'NaN'
	sku_stp = 'NaN'
	sku_pdm = 'UPDM'
	
	for line in fw_db :
		if rsa_sig_hash in line :
			line_parts = line.strip().split('_')
			if variant == 'CSME' :
				db_sku_chk = line_parts[2] # Store the SKU from DB for latter use
				sku = sku_init + " " + line_parts[2] # Cell 2 is SKU
				if line_parts[3] not in ('X','XX') : sku_stp = line_parts[3] # Cell 3 is PCH Stepping
				if 'YPDM' in line_parts[4] or 'NPDM' in line_parts[4] or 'UPDM' in line_parts[4] : sku_pdm = line_parts[4] # Cell 4 is PDM
			elif variant == 'CSTXE' :
				if line_parts[1] not in ('X','XX') : sku_stp = line_parts[1] # Cell 1 is SoC Stepping
			break # Break loop at 1st rsa_sig_hash match
	fw_db.close()

	return db_sku_chk, sku, sku_stp, sku_pdm

# Store CSE DB SKU and check Latest version
def sku_db_upd_cse(sku_type, sku_plat, sku_stp, upd_found, stp_only = False) :
	if sku_stp == 'NaN' : sku_db = '%s%sX' % (sku_type if stp_only else sku_type + '_', sku_plat if stp_only else sku_plat + '_')
	else : sku_db = '%s%s' % (sku_type if stp_only else sku_type + '_', sku_plat if stp_only else sku_plat + '_') + sku_stp
	
	db_maj,db_min,db_hot,db_bld = check_upd(('Latest_%s_%s%s_%s%s' % (variant, major, minor, sku_type, sku_plat)))
	if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
	
	return sku_db, upd_found

# Detect Variant/Family
def get_variant() :
	variant = 'Unknown'
	variant_p = 'Unknown'
	var_rsa_db = True
	
	# Detect Variant by unique DB RSA Public Key
	fw_db = db_open()
	for line in fw_db :
		if rsa_key_hash in line :
			line_parts = line.strip().split('_')
			variant = line_parts[1] # Store the Variant
			break # Break loop at 1st match
	fw_db.close()
	
	# Variant DB RSA Public Key not found, manual known correction
	if variant == 'TBD3' and major == 12 : variant = 'CSME'
	elif variant == 'TBD3' and major == 300 : variant = 'PMCCNP'
	elif variant == 'TBD3' and major in (3,4) : variant = 'CSTXE'
	elif variant == 'TBD1' and major == 11 : variant = 'CSME'
	elif variant == 'TBD1' and 6 <= major <= 10 : variant = 'ME'
	elif variant == 'TBD1' and 0 <= major <= 2 : variant = 'TXE'
	
	# Manual known variant correction failed, targeted detection
	if variant in ['Unknown','TBD1','TBD2','TBD3'] :
		if variant == 'Unknown' : var_rsa_db = False # TBDx are multi-platform RSA Public Keys
		
		cpd_mod_names = ext_anl('$MN2_Var', start_man_match, file_end, [variant, major, minor, hotfix, build]) # Get CSE $CPD Module Names only
		
		if cpd_mod_names :
			for mod in cpd_mod_names :
				if mod == 'fwupdate' :
					variant = 'CSME'
					break
				elif mod in ['bup_rcv', 'sku_mgr'] :
					variant = 'CSSPS'
					break
				elif mod == 'PMCC000' : # 0 CNP A/B
					variant = 'PMCCNP'
					break
				elif mod == 'PMCC002' : # 2 APL A
					variant = 'PMCAPLA'
					break
				elif mod == 'PMCC003' : # 3 APL B
					variant = 'PMCAPLB'
					break
				elif mod == 'PMCC004' : # 4 GLK A
					variant = 'PMCGLKA'
					break
				elif mod == 'PMCC005' : # 5 BXT C (Joule)
					variant = 'PMCBXTC'
					break
				elif mod == 'PMCC006' : # 6 GLK B
					variant = 'PMCGLKB'
					break
				else :
					variant = 'CSTXE' # CSE fallback, no CSME/CSSPS/PMC detected
		
		elif reading[end_man_match + 0x270 + 0x80:end_man_match + 0x270 + 0x84].decode('utf-8', 'ignore') == '$MME' :
			# $MME: ME2-5/SPS1 = 0x50, ME6-10/SPS2-3 = 0x60, TXE1-2 = 0x80
			variant = 'TXE'
		
		elif re.compile(br'\x24\x53\x4B\x55\x03\x00\x00\x00\x2F\xE4\x01\x00').search(reading) or \
		re.compile(br'\x24\x53\x4B\x55\x03\x00\x00\x00\x08\x00\x00\x00').search(reading) :
			variant = 'SPS'
		
		else :
			variant = 'ME' # Default fallback, no CSE/TXE/SPS/PMC detected
	
	# Create Variant display-friendly text
	if variant == 'CSME' : variant_p = 'CSE ME'
	elif variant == 'CSTXE' : variant_p = 'CSE TXE'
	elif variant == 'CSSPS' : variant_p = 'CSE SPS'
	elif variant.startswith('PMC') : variant_p = 'PMC'
	elif variant in ['ME','TXE','SPS'] : variant_p = variant
	
	return variant, variant_p, var_rsa_db

# Print all Errors, Warnings & Notes (must be Errors > Warnings > Notes)
# Rule 1: If -msg -hid or -msg only: none at the beginning & one empty line at the end (only when messages exist)
def msg_rep(name_db) :
	if param.hid_find : # Parameter -hid always prints a message whether the error/warning/note arrays are empty or not
		print(col_y + 'MEA: Found Intel %s firmware %s in file!' % (variant, name_db) + col_e)
		
		if err_stor or warn_stor or note_stor : print('') # Separates -hid from -msg output (only when messages exist, Rule 1 compliant)
		
	for i in range(len(err_stor)) : print(err_stor[i][0])
	for i in range(len(warn_stor)) : print(warn_stor[i][0])
	for i in range(len(note_stor)) : print(note_stor[i][0])
	
	if (err_stor or warn_stor or note_stor) or param.hid_find : print('') # Rule 1

# Scan all files of a given directory
def mass_scan(f_path) :
	mass_files = []
	for root, dirs, files in os.walk(f_path):
		for name in files :
			mass_files.append(os.path.join(root, name))
			
	input('\nFound %s file(s)\n\nPress enter to start' % len(mass_files))
	
	return mass_files
	
# Get script location
mea_dir = get_script_dir()

# Get MEA Parameters from input
param = MEA_Param(sys.argv)

# Enumerate parameter input
arg_num = len(sys.argv)

# Set dependencies paths
db_path = os.path.join(mea_dir, 'MEA.dat')

# Check if dependencies exist
depend_db = os.path.isfile(db_path)

db_rev = mea_hdr_init() # Get DB Revision
	
if not param.skip_intro :
	mea_hdr(db_rev)

	print("\nWelcome to Intel Engine Firmware Analysis Tool\n")
	
	if arg_num == 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFile:       " + col_g + "%s" % os.path.basename(sys.argv[1]) + col_e)
	elif arg_num > 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFiles:       " + col_y + "Multiple" + col_e)
	else :
		print('Input a file name/path or press Enter to list options\n')
		print("\nFile:       " + col_m + "None" + col_e)

	input_var = input('\nOption(s):  ')
	
	# Anything quoted ("") is taken as one (file paths etc)
	input_var = re.split(''' (?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', input_var.strip())
	
	# Get MEA Parameters based on given Options
	param = MEA_Param(input_var)
	
	# Non valid parameters are treated as files
	if input_var[0] != "" :
		for i in input_var:
			if i not in param.val :
				sys.argv.append(i.strip('"'))
	
	# Re-enumerate parameter input
	arg_num = len(sys.argv)
	
	os.system(cl_wipe)
	
	mea_hdr(db_rev)
	
elif not param.extr_mea and not param.print_msg :
	mea_hdr(db_rev)
	
if (arg_num < 2 and not param.help_scr and not param.mass_scan) or param.help_scr :
	mea_help()
	mea_exit(5)

# Actions for MEA but not UEFIStrip
if param.extr_mea or param.print_msg :
	pass
else :
	sys.excepthook = show_exception_and_exit # Pause after any unexpected python exception
	if mea_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(title) # Set console window title

if param.mass_scan :
	in_path = input('\nEnter the full folder path : ')
	source = mass_scan(in_path)
else :
	source = sys.argv[1:] # Skip script/executable

# Connect to DB, if it exists
if depend_db :
	pass
else :
	print(col_r + "\nError: MEA.dat file is missing!" + col_e)
	mea_exit(1)

# Initialize file input
in_count = len(source)
cur_count = 0

for file_in in source :
	
	# Variable Initialization
	sku_me = ''
	fw_type = ''
	upd_rslt = ''
	me2_type_fix = ''
	me2_type_exp = ''
	name_db_hash = ''
	sku = 'NaN'
	sku_db = 'NaN'
	rel_db = 'NaN'
	type_db = 'NaN'
	sku_stp = 'NaN'
	txe_sub = 'NaN'
	platform = 'NaN'
	sku_init = 'NaN'
	pdm_status = 'NaN'
	txe_sub_db = 'NaN'
	fuj_version = 'NaN'
	no_man_text = 'NaN'
	pmc_date = 'Unknown'
	me7_blist_1 = 'Empty'
	me7_blist_2 = 'Empty'
	cse_in_id_str = '0000'
	pos_sku_ker = 'Invalid'
	pos_sku_ext = 'Unknown'
	pmc_pch_sku = 'Unknown'
	pmc_pch_rev = 'Unknown'
	pmc_platform = 'Unknown'
	pmc_mn2_signed = 'Unknown'
	pt_dfpt = None
	fpt_hdr = None
	bpdt_hdr = None
	byp_match = None
	pmc_mn2_ver = None
	fpt_pre_hdr = None
	me11_vcn_match = None
	upd_found = False
	rgn_exist = False
	pmcp_found = False
	ifwi_exist = False
	utok_found = False
	oemp_found = False
	wcod_found = False
	rec_missing = False
	fw_type_fix = False
	is_patsburg = False
	can_search_db = True
	fpt_chk_null = False
	fpt_chk_fail = False
	fpt_num_fail = False
	cse_lt_exist = False
	pmc_not_comp = False
	sps3_chk_fail = False
	fuj_rgn_exist = False
	sps_opr_found = False
	fpt_romb_found = False
	fitc_ver_found = False
	pmcp_fwu_found = False
	pmcp_upd_found = False
	pmcp_not_in_db = False
	fw_in_db_found = False
	fd_me_rgn_exist = False
	fd_bios_rgn_exist = False
	fd_devexp_rgn_exist = False
	rgn_over_extr_found = False
	eng_size_text = ['', False]
	err_stor = []
	note_stor = []
	warn_stor = []
	s_bpdt_all = []
	fpt_ranges = []
	fpt_matches = []
	p_store_all = []
	fpt_part_all = []
	bpdt_matches = []
	bpdt_hdr_all = []
	ext_err_stor = []
	err_fpt_stor = []
	bpdt_data_all = []
	bpdt_part_all = []
	cse_lt_part_all = []
	me11_vcn_ranges = []
	cse_lt_hdr_info = []
	man_match_ranges = []
	vcn = -1
	svn = -1
	pvbit = -1
	mod_size = 0
	fw_0C_lbg = 0
	sku_type = -1
	sku_size = -1
	sku_slim = 0
	fd_count = 0
	fpt_count = 0
	mod_align = 0
	cse_in_id = 0
	fpt_start = -1
	oem_config = 0
	oem_signed = 0
	fpt_length = -1
	fpt_version = -1
	pmc_fw_ver = -1
	fitc_major = -1
	fitc_minor = -1
	fitc_build = -1
	fitc_hotfix = -1
	p_end_last = 0
	mod_end_max = 0
	cse_lt_off = -1
	cse_lt_size = 0
	fpt_num_diff = 0
	mod_size_all = 0
	cpd_end_last = 0
	fpt_chk_file = 0
	fpt_chk_calc = 0
	fpt_num_file = 0
	fpt_num_calc = 0
	me_fd_start = -1
	me_fd_size = -1
	fpt_part_num = -1
	fpt_chk_byte = -1
	fpt_chk_start = -1
	p_offset_last = 0
	rec_rgn_start = 0
	sps3_chk16_file = 0
	sps3_chk16_calc = 0
	cpd_offset_last = 0
	p_end_last_cont = 0
	devexp_fd_start = -1
	mod_end = 0xFFFFFFFF
	p_max_size = 0xFFFFFFFF
	eng_fw_end = 0xFFFFFFFF
	cur_count += 1
	
	if not os.path.isfile(file_in) :
		if any(p in file_in for p in param.val) : continue # Next input file
		
		print(col_r + "\nError" + col_e + ": file %s was not found!" % file_in)
		
		if not param.mass_scan : mea_exit(0)
		else : continue
	
	f = open(file_in, 'rb')
	file_end = f.seek(0,2)
	file_start = f.seek(0,0)
	reading = f.read()
	
	# Detect if file has Engine firmware
	man_pat = re.compile(br'\x86\x80.........\x00\x24\x4D((\x4E\x32)|(\x41\x4E))', re.DOTALL) # .$MN2 or .$MAN detection, 0x00 adds old ME RGN support
	
	for man_range in list(man_pat.finditer(reading)) :
		(start_man_match, end_man_match) = man_range.span()
		start_man_match += 0xB # Add 8680.{9} sanity check before .$MN2 or .$MAN
		
		pr_man_1 = (reading[end_man_match + 0x274:end_man_match + 0x278]) # FTPR,OPR (ME 11+, TXE 3+, SPS 4+)
		pr_man_2 = (reading[end_man_match + 0x264:end_man_match + 0x266]) # FT,OP (ME 6-10 Part 1, TXE 0-2 Part 1, SPS 2-3 Part 1)
		pr_man_3 = (reading[end_man_match + 0x266:end_man_match + 0x268]) # PR,xx (ME 6-10 Part 2, TXE 0-2 Part 2)
		pr_man_4 = (reading[end_man_match + 0x28C:end_man_match + 0x293]) # BRINGUP (ME 2-5)
		pr_man_5 = (reading[end_man_match + 0x2DC:end_man_match + 0x2E7]) # EpsRecovery,EpsFirmware (SPS 1)
		pr_man_6 = (reading[end_man_match + 0x270:end_man_match + 0x277]) # $MMEBUP (ME 6 BYP Part 1, SPS 2-3 Part 2)
		pr_man_7 = (reading[end_man_match + 0x33C:end_man_match + 0x340]) # $MMX (ME 6 BYP Part 2)
		pr_man_8 = (re.compile(br'\x24\x43\x50\x44.\x00\x00\x00\x01\x01\x10.\x4C\x4F\x43\x4C', re.DOTALL)).search(reading[:0x10]) # $CPD LOCL detection
		pr_man_9 = (re.compile(br'\x24\x4D\x4D\x45\x57\x43\x4F\x44\x5F')).search(reading[0x290:0x299]) # $MMEWCOD_ detection
		pr_man_10 = (re.compile(br'\x24\x43\x50\x44.\x00\x00\x00\x01\x01\x10.\x50\x4D\x43\x50', re.DOTALL)).search(reading[:0x10]) # $CPD PMCP detection
		
		#break # Force MEA to accept any $MAN/$MN2 (Debug)
		
		if any(p in (pr_man_1, pr_man_2 + pr_man_3, pr_man_2 + pr_man_6 + pr_man_7, pr_man_4, pr_man_5, pr_man_6 + pr_man_7) \
		for p in (b'\x46\x54\x50\x52', b'\x4F\x50\x52\x00', b'\x42\x52\x49\x4E\x47\x55\x50',
		b'\x45\x70\x73\x52\x65\x63\x6F\x76\x65\x72\x79', b'\x45\x70\x73\x46\x69\x72\x6D\x77\x61\x72\x65',
		b'\x4F\x50\x24\x4D\x4D\x45\x42\x55\x50\x00\x00\x00\x00', b'\x24\x4D\x4D\x45\x42\x55\x50\x24\x4D\x4D\x58')) \
		or pr_man_8 or pr_man_9 or pr_man_10 :
			# Recovery Manifest found
			break
	else :
		# Recovery Manifest not found (for > finish)
		
		# Determine if FD exists and if Engine Region is present
		fd_exist,start_fd_match,end_fd_match,fd_count = spi_fd_init()
		if fd_exist :
			fd_bios_rgn_exist,bios_fd_start,bios_fd_size,fd_me_rgn_exist,me_fd_start,me_fd_size,fd_devexp_rgn_exist,devexp_fd_start,devexp_fd_size \
			= spi_fd('region',start_fd_match,end_fd_match)
		
		# Engine Region exists but cannot be identified
		if fd_me_rgn_exist :
			fuj_version = fuj_umem_ver(me_fd_start) # Check if ME Region is Fujitsu UMEM compressed
			
			# ME Region is Fujitsu UMEM compressed
			if fuj_version != 'NaN' :
				no_man_text = 'Found' + col_y + ' Fujitsu Compressed ' + col_e + ('Intel Engine firmware v%s' % fuj_version)
				
				if param.extr_mea : no_man_text = 'NaN %s_NaN_UMEM %s NaN NaN' % (fuj_version, fuj_version)
			
			# ME Region is X58 ROMB Test
			elif reading[me_fd_start:me_fd_start + 0x8] == b'\xD0\x3F\xDA\x00\xC8\xB9\xB2\x00' :
				no_man_text = 'Found' + col_y + ' X58 ROMB Test ' + col_e + 'Intel Engine firmware'
				
				if param.extr_mea : no_man_text = 'NaN NaN_NaN_X58 NaN NaN NaN'
			
			# ME Region is Unknown
			else :
				no_man_text = 'Found' + col_y + ' unidentifiable ' + col_e + 'Intel Engine firmware'
				
				if param.extr_mea : no_man_text = 'NaN NaN_NaN_UNK NaN NaN NaN' # For UEFI Strip (-extr)
		
		# Engine Region does not exist
		else :
			fuj_version = fuj_umem_ver(0) # Check if ME Region is Fujitsu UMEM compressed (me_fd_start is 0x0, no SPI FD)
			fw_start_match = (re.compile(br'\x24\x46\x50\x54.\x00\x00\x00', re.DOTALL)).search(reading) # $FPT detection
			
			# Image is ME Fujitsu UMEM compressed
			if fuj_version != 'NaN' :
				no_man_text = 'Found' + col_y + ' Fujitsu Compressed ' + col_e + ('Intel Engine firmware v%s' % fuj_version)
				
				if param.extr_mea : no_man_text = 'NaN %s_NaN_UMEM %s NaN NaN' % (fuj_version, fuj_version)
			
			# Image is X58 ROMB Test
			elif reading[:0x8] == b'\xD0\x3F\xDA\x00\xC8\xB9\xB2\x00' :
				no_man_text = 'Found' + col_y + ' X58 ROMB Test ' + col_e + 'Intel Engine firmware'
				
				if param.extr_mea : no_man_text = "NaN NaN_NaN_X58 NaN NaN NaN"
			
			# Image contains some Engine Flash Partition Table ($FPT)
			elif fw_start_match is not None :
				(start_fw_start_match, end_fw_start_match) = fw_start_match.span()
				init_fpt_ver = reading[start_fw_start_match + 0x8] # $FPT Version Tag
				if init_fpt_ver == 0x21 : fpt_hdr = get_struct(reading, start_fw_start_match, FPT_Header_21)
				else : fpt_hdr = get_struct(reading, start_fw_start_match, FPT_Header)
				
				if fpt_hdr.FitBuild != 0 and fpt_hdr.FitBuild != 65535 :
					fitc_ver = '%s.%s.%s.%s' % (fpt_hdr.FitMajor, fpt_hdr.FitMinor, fpt_hdr.FitHotfix, fpt_hdr.FitBuild)
					no_man_text = 'Found' + col_y + ' Unknown ' + col_e + ('Intel Engine Flash Partition Table v%s' % fitc_ver)
					
					if param.extr_mea : no_man_text = 'NaN %s_NaN_FPT %s NaN NaN' % (fitc_ver, fitc_ver) # For UEFI Strip (-extr)
				
				else :
					no_man_text = 'Found' + col_y + ' Unknown ' + col_e + 'Intel Engine Flash Partition Table'
					
					if param.extr_mea : no_man_text = 'NaN NaN_NaN_FPT NaN NaN NaN' # For UEFI Strip (-extr)
				
			# Image does not contain any kind of Intel Engine firmware
			else :
				no_man_text = 'File does not contain Intel Engine firmware'

		# Print filename when not in UEFIStrip mode
		if not param.extr_mea and not param.print_msg :
			print()
			msg_pt = ext_table([], False, 1)
			msg_pt.add_row([col_c + '%s (%d/%d)' % (textwrap.wrap(os.path.basename(file_in), width=45)[0], cur_count, in_count) + col_e])
			print(msg_pt)
		
		if param.extr_mea :
			if no_man_text != 'NaN' : print(no_man_text)
			else : pass
		elif param.print_msg :
			print('MEA: %s\n' % no_man_text) # Rule 1, one empty line at the beginning
		else :
			print('\n%s' % no_man_text)
			
		if not param.extr_mea : copy_on_msg() # Close input and copy it in case of messages
		
		continue # Next input file

	# Engine firmware found (for > break), Manifest analysis
	
	# Detect Intel Flash Descriptor
	fd_exist,start_fd_match,end_fd_match,fd_count = spi_fd_init()
	if fd_exist :
		fd_bios_rgn_exist,bios_fd_start,bios_fd_size,fd_me_rgn_exist,me_fd_start,me_fd_size,fd_devexp_rgn_exist,devexp_fd_start,devexp_fd_size \
		= spi_fd('region',start_fd_match,end_fd_match)
	
	# Detect all $FPT and/or BPDT starting offsets (both allowed/needed)
	if fd_me_rgn_exist :
		# $FPT detection based on FD with Engine region (limits false positives from IE or CSTXE Engine/ROMB & DevExp1/Init)
		fpt_matches = list((re.compile(br'\x24\x46\x50\x54.\x00\x00\x00', re.DOTALL)).finditer(reading[me_fd_start:me_fd_start + me_fd_size]))
	else :
		# FD with Engine region not found or multiple FD detected, scan entire file (could lead to false positives)
		fpt_matches = list((re.compile(br'\x24\x46\x50\x54.\x00\x00\x00', re.DOTALL)).finditer(reading))
	
	# Detect $FPT Firmware Starting Offset
	if len(fpt_matches) :
		rgn_exist = True # Set $FPT detection boolean
		
		for r in fpt_matches:
			fpt_ranges.append(r.span()) # Store all $FPT ranges
			fpt_count += 1 # Count $FPT ranges
		
		# Store ranges and start from 1st $FPT by default
		(start_fw_start_match, end_fw_start_match) = fpt_ranges[0]
		
		# Adjust $FPT offset if FD with Engine region exists
		if fd_me_rgn_exist :
			start_fw_start_match += me_fd_start
			end_fw_start_match += me_fd_start
		
		# Detect if $FPT is proceeded by CSE Layout Table
		cse_lt_off = start_fw_start_match - 0x1000 # CSE LT size is 0x1000
		cse_lt_test_fpt = cse_lt_off + int.from_bytes(reading[cse_lt_off + 0x10:cse_lt_off + 0x14], 'little') # Is Data ($FPT)
		cse_lt_test_bp1 = cse_lt_off + int.from_bytes(reading[cse_lt_off + 0x18:cse_lt_off + 0x1C], 'little') # Is BP1 (BPDT)
		cse_lt_test_bp2 = cse_lt_off + int.from_bytes(reading[cse_lt_off + 0x20:cse_lt_off + 0x24], 'little') # Is BP2 (BPDT)
		if start_fw_start_match == cse_lt_test_fpt and reading[cse_lt_test_bp1:cse_lt_test_bp1 + 0x4] in [b'\xAA\x55\x00\x00',b'\xAA\x55\xAA\x00'] \
		and reading[cse_lt_test_bp2:cse_lt_test_bp2 + 0x4] in [b'\xAA\x55\x00\x00',b'\xAA\x55\xAA\x00'] :
			# Analyze CSE Layout Table
			cse_lt_exist = True
			cse_lt_size = 0x1000
			NA = [0,0xFFFFFFFF]
			
			cse_lt = get_struct(reading, cse_lt_off, CSE_Layout_Table_16) # No IFWI 1.6 vs 1.7 distinction yet
			cse_lt_hdr_info = [['Data',cse_lt.DataOffset,cse_lt.DataSize],['Boot 1',cse_lt.BP1Offset,cse_lt.BP1Size],['Boot 2',cse_lt.BP2Offset,cse_lt.BP2Size],
								['Boot 3',cse_lt.BP3Offset,cse_lt.BP3Size],['Boot 4',cse_lt.BP4Offset,cse_lt.BP4Size],['Boot 5',cse_lt.BP5Offset,cse_lt.BP5Size]]	
			
			# Store CSE LT partition details
			for entry in cse_lt_hdr_info :
				cse_lt_entry_name = entry[0]
				cse_lt_entry_off = entry[1]
				cse_lt_entry_size = entry[2]
				cse_lt_entry_spi = cse_lt_off + cse_lt_entry_off
				cse_lt_entry_end = cse_lt_entry_spi + cse_lt_entry_size
				cse_lt_entry_data = reading[cse_lt_entry_spi:cse_lt_entry_end]
				cse_lt_entry_empty = True if (cse_lt_entry_off in NA or cse_lt_entry_size in NA or cse_lt_entry_data in [b'\x00' * cse_lt_entry_size,b'\xFF' * cse_lt_entry_size]) else False
				cse_lt_part_all.append([cse_lt_entry_name,cse_lt_entry_spi,cse_lt_entry_size,cse_lt_entry_end,cse_lt_entry_empty])

			pt_dcselt = ext_table([col_y + 'Name' + col_e, col_y + 'Start' + col_e, col_y + 'Size' + col_e, col_y + 'End' + col_e, col_y + 'Empty' + col_e], True, 1)
			pt_dcselt.title = col_y + 'CSE Partition Layout Table' + col_e		
			
			# Detect CSE LT partition overlaps
			for part in cse_lt_part_all :
				pt_dcselt.add_row([part[0],'0x%0.6X' % part[1],'0x%0.6X' % part[2],'0x%0.6X' % part[3],part[4]]) # For -dfpt
				for all_part in cse_lt_part_all :
					# Partition A starts before B but ends after B start
					# Ignore partitions which have empty offset or size
					if not part[4] and not all_part[4] and not any(s in [0,0xFFFFFFFF] for s in (part[1],part[2],all_part[1],all_part[2])) and (part[1] < all_part[1] < part[2]) :
						err_fpt_msg = col_r + 'Error: CSE LT partition %s (0x%0.6X - 0x%0.6X) overlaps with %s (0x%0.6X - 0x%0.6X)' % \
									(part[0],part[1],part[2],all_part[0],all_part[1],all_part[2]) + col_e
						err_fpt_stor.append(err_fpt_msg)
						err_stor.append([err_fpt_msg, True])
						
			# Show CSE LT partition info on demand (-dfpt)
			if param.fpt_disp : print('%s\n' % pt_dcselt)
		
		# Analyze $FPT header
		pt_dfpt = ext_table([col_y + 'Name' + col_e, col_y + 'Owner' + col_e, col_y + 'Start' + col_e, col_y + 'Size' + col_e, col_y + 'End' + col_e,
				  col_y + 'Type' + col_e, col_y + 'ID' + col_e, col_y + 'Valid' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt_dfpt.title = col_y + 'Flash Partition Table' + col_e
		
		init_fpt_ver = reading[start_fw_start_match + 0x8] # $FPT Version Tag
		if init_fpt_ver == 0x21 : fpt_hdr = get_struct(reading, start_fw_start_match, FPT_Header_21)
		else : fpt_hdr = get_struct(reading, start_fw_start_match, FPT_Header)
		
		fpt_part_num = fpt_hdr.NumPartitions
		fpt_version = fpt_hdr.HeaderVersion
		fpt_length = fpt_hdr.HeaderLength
		
		fpt_pre_hdr = None
		fpt_chk_start = 0x0
		fpt_start = start_fw_start_match - 0x10
		fpt_chk_byte = reading[start_fw_start_match + 0xB]
		
		if (cse_lt_exist or (fd_devexp_rgn_exist and reading[devexp_fd_start:devexp_fd_start + 0x4] == b'$FPT')) \
		and fpt_version in [0x20,0x21] and fpt_length == 0x20 :
			fpt_start = start_fw_start_match
		elif fpt_version in [0x20,0x21] and fpt_length == 0x30 :
			fpt_pre_hdr = get_struct(reading, fpt_start, FPT_Pre_Header)
		elif fpt_version in [0x20,0x21] and fpt_length == 0x20 :
			fpt_chk_start = 0x10 # ROMB instructions excluded
			fpt_pre_hdr = get_struct(reading, fpt_start, FPT_Pre_Header)
		elif fpt_version == 0x10 and fpt_length == 0x20 :
			fpt_start = start_fw_start_match
		
		fpt_step = start_fw_start_match + 0x20 # 0x20 $FPT entry size
		
		for i in range(0, fpt_part_num):
			cse_in_id = 0
			cse_in_id_str = '0000'
			
			fpt_entry = get_struct(reading, fpt_step, FPT_Entry)
			
			p_type,p_reserved0,p_bwl0,p_bwl1,p_reserved1,p_valid = fpt_entry.get_flags()
			
			p_name = fpt_entry.Name
			p_owner = fpt_entry.Owner
			p_offset = fpt_entry.Offset
			p_offset_spi = fpt_start + fpt_entry.Offset
			p_size = fpt_entry.Size
			p_valid_print = False if p_valid == 0xFF else True
			p_type_values = {0: 'Code', 1: 'Data', 2: 'NVRAM', 3: 'Generic', 4: 'EFFS', 5: 'ROM'} # Only 0 & 1 for CSE
			p_type_print = p_type_values[p_type] if p_type in p_type_values else 'Unknown'
			
			if p_offset in [4294967295, 0] or p_size == 0 or (
			p_size != 4294967295 and reading[p_offset_spi:p_offset_spi + p_size] == p_size * b'\xFF') :
				p_empty = True
			else :
				p_empty = False
			
			if not p_empty and p_offset_spi < file_end :
				# Get CSE Partition Instance ID
				cse_in_id,x1,x2 = cse_part_inid(reading, p_offset_spi, ext_dict)
				cse_in_id_str = '%0.4X' % cse_in_id
				
				# Get ME LOCL/WCOD Partition Instance ID
				mn2_hdr = get_struct(reading, p_offset_spi, MN2_Manifest)
				if mn2_hdr.Tag in [b'$MN2',b'$MAN'] : # Sanity check
					mn2_len = mn2_hdr.HeaderLength * 4
					mod_name = reading[p_offset_spi + mn2_len:p_offset_spi + mn2_len + 0x8].strip(b'\x00').decode('utf-8')
					if mod_name in ['LOCL','WCOD'] :
						cse_in_id = reading[p_offset_spi + mn2_len + 0x15:p_offset_spi + mn2_len + 0x15 + 0xB].strip(b'\x00').decode('utf-8')
						cse_in_id_str = cse_in_id
			
			fpt_part_all.append([p_name, p_offset_spi, p_offset_spi + p_size, cse_in_id, p_type_print, p_valid_print, p_empty])
			
			if p_name in [b'\xFF\xFF\xFF\xFF', b''] :
				p_name = '' # If appears, wrong NumPartitions
				fpt_num_diff -= 1 # Check for less $FPT Entries
			elif p_name == b'\xE0\x15' : p_name = '' # ME8 (E0150020)
			else : p_name = p_name.decode('utf-8', 'ignore')
			
			# Store $FPT Partition info for -dfpt
			if param.fpt_disp :
				if p_owner in [b'\xFF\xFF\xFF\xFF', b''] : p_owner = '' # Missing
				else : p_owner = p_owner.decode('utf-8', 'ignore')
				
				if p_offset in [4294967295, 0] : p_offset_print = ''
				else : p_offset_print = '0x%0.6X' % p_offset_spi
				
				if p_size in [4294967295, 0] : p_size_print = ''
				else : p_size_print = '0x%0.6X' % p_size
				
				if p_offset_print == '' or p_size_print == '' : p_end_print = ''
				else : p_end_print = '0x%0.6X' % (p_offset_spi + p_size)
				
				pt_dfpt.add_row([p_name,p_owner,p_offset_print,p_size_print,p_end_print,p_type_print,cse_in_id_str,p_valid_print,p_empty])
			
			p_store_all.append([p_name, p_offset_spi, p_size]) # For $FPT Recovery/Operational adjustment
			
			# Detect if firmware has ROM-Bypass (ROMB) partition 
			if p_name == 'ROMB' and not p_empty : fpt_romb_found = True
			
			# Detect if firmware has Operational (OPRx) partition
			if p_name.startswith('OPR') and not p_empty : sps_opr_found = True
			
			# Detect if firmware has Power Management Controller (PMCP) partition
			if p_name == 'PMCP' and not p_empty :
				pmcp_found = True
				pmcp_fwu_found = True # CSME12+ FWUpdate tool requires PMC
				
				x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,pmc_mn2_ver = ext_anl('$CPD', p_offset_spi, file_end, ['NaN', -1, -1, -1, -1])
			
			# Detect if firmware has OEM Unlock Token (UTOK/STKN)
			if p_name in ('UTOK','STKN') and p_offset_spi < file_end and reading[p_offset_spi:p_offset_spi + 0x10] != b'\xFF' * 0x10 : utok_found = True
			
			# Detect if CSE firmware has OEM Key Manager Partition (OEMP)
			if p_name == 'OEMP' and p_offset_spi < file_end and reading[p_offset_spi:p_offset_spi + 0x10] != b'\xFF' * 0x10 : oemp_found = True
			
			if 0 < p_offset_spi < p_max_size and 0 < p_size < p_max_size : eng_fw_end = p_offset_spi + p_size
			else : eng_fw_end = p_max_size
			
			# Store last partition (max offset)
			if p_offset_last < p_offset_spi < p_max_size:
				p_offset_last = p_offset_spi
				p_size_last = p_size
				p_end_last = eng_fw_end
			
			fpt_step += 0x20 # Next $FPT entry
		
		# Adjust Manifest to Recovery (ME/TXE) or Operational (SPS) partition based on $FPT
		if fpt_count <= 2 :
			# This does not work with Intel Engine Capsule images because they have multiple $FPT and Engine CODE
			# regions. It cannot be removed because MEA needs to jump to COD1/OPR1 for (CS)SPS parsing. The Intel
			# POR is to have at most two $FPT at normal CS(SPS) images, Main ($FPT) and Backup (FPTB), so MEA skips
			# this adjustment for images with more than two $FPT hits. The drawback is that MEA detects FTPR instead
			# of COD1/OPR1 at these Intel Capsule images. A proper detection/extractor could be added in the future.
			for p_rec_fix in p_store_all :
				# For ME 2-5 & SPS 1, pick CODE if RCVY or COD1 are not present
				# For SPS, pick Operational (COD1/OPR1) instead of Recovery (CODE/FTPR)
				if p_rec_fix[0] in ['FTPR', 'RCVY', 'OPR1', 'COD1'] or (p_rec_fix[0] == 'CODE' and not any(p in ('RCVY', 'COD1') for p in p_store_all)) :
					# Only if partition exists at file (counter-example: sole $FPT etc)
					# noinspection PyTypeChecker
					if p_rec_fix[1] + p_rec_fix[2] <= file_end :
						rec_man_match = man_pat.search(reading[p_rec_fix[1]:p_rec_fix[1] + p_rec_fix[2]])
						
						if rec_man_match :
							(start_man_match, end_man_match) = rec_man_match.span()
							start_man_match += p_rec_fix[1] + 0xB # Add Recovery/Operational offset and 8680.{9} sanity check before .$MN2 or .$MAN
							end_man_match += p_rec_fix[1]
		
		# Check for extra $FPT Entries, wrong NumPartitions (0x2+ for SPS3 Checksum)
		while reading[fpt_step + 0x2:fpt_step + 0xC] not in [b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'] :
			fpt_num_diff += 1
			fpt_step += 0x20
	
		# Check $FPT NumPartitions validity
		if fpt_num_diff != 0 :
			fpt_num_fail = True
			fpt_num_file = '0x%0.2X' % fpt_hdr.NumPartitions
			fpt_num_calc = '0x%0.2X' % (fpt_hdr.NumPartitions + fpt_num_diff)
	
	# Scan for IFWI/BPDT Ranges
	if cse_lt_exist :
		# Search Boot Partitions only when CSE LT exists (fast & robust)
		for part in cse_lt_part_all :
			if part[0].startswith('Boot') and not part[4] : # Non-Empty CSE LT Boot Partition (skip Data)
				bpdt_match = (re.compile(br'\xAA\x55[\x00\xAA]\x00.\x00[\x01-\x03]\x00', re.DOTALL)).search(reading[part[1]:part[3]]) # BPDT detection
				bpdt_matches.append((bpdt_match.start() + part[1], bpdt_match.end() + part[1])) # Store BPDT range, relative to 0x0
	else :
		# Search entire image when no CSE LT exists (slower & false positive prone)
		bpdt_match = list((re.compile(br'\xAA\x55[\x00\xAA]\x00.\x00[\x01-\x03]\x00', re.DOTALL)).finditer(reading)) # BPDT detection
		for match in bpdt_match : bpdt_matches.append(match.span()) # Store all BPDT ranges, already relative to 0x0
	
	# Parse IFWI/BPDT Ranges
	for ifwi_bpdt in range(len(bpdt_matches)):
		
		ifwi_exist = True # Set IFWI/BPDT detection boolean
		
		(start_fw_start_match, end_fw_start_match) = bpdt_matches[ifwi_bpdt] # Get BPDT range via bpdt_matches index
		
		if start_fw_start_match in s_bpdt_all : continue # Skip already parsed S-BPDT (Type 5)
		
		init_bpdt_ver = int.from_bytes(reading[start_fw_start_match + 0x6:start_fw_start_match + 0x8], 'little') # BPDT Version
		if init_bpdt_ver == 2 : bpdt_hdr = get_struct(reading, start_fw_start_match, BPDT_Header_2)
		else : bpdt_hdr = get_struct(reading, start_fw_start_match, BPDT_Header)
		
		# Store Primary BPDT info to show at CSE unpacking
		if param.me11_mod_extr :
			bpdt_hdr_all.append(bpdt_hdr.hdr_print())
			bpdt_data_all.append(reading[start_fw_start_match:start_fw_start_match + 0x200]) # Min size 0x200 (no size at Header, min is enough though)
		
		# Analyze BPDT header
		bpdt_step = start_fw_start_match + 0x18 # 0x18 BPDT Header size
		bpdt_part_num = bpdt_hdr.DescCount
		
		pt_dbpdt = ext_table([col_y + 'Name' + col_e, col_y + 'Type' + col_e, col_y + 'Partition' + col_e, col_y + 'Start' + col_e,
				  col_y + 'Size' + col_e, col_y + 'End' + col_e, col_y + 'ID' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt_dbpdt.title = col_y + 'Boot Partition Descriptor Table' + col_e
		
		for i in range(0, bpdt_part_num):
			cse_in_id = 0
			
			bpdt_entry = get_struct(reading, bpdt_step, BPDT_Entry)
			
			p_type = bpdt_entry.Type
			p_offset = bpdt_entry.Offset
			p_offset_spi = start_fw_start_match + p_offset
			p_size = bpdt_entry.Size
			
			if reading[p_offset_spi:p_offset_spi + p_size] == p_size * b'\xFF' : p_empty = True
			else : p_empty = False
			
			if p_type in bpdt_dict : p_name = bpdt_dict[p_type]
			else : p_name = 'Unknown'
			
			if not p_empty and p_offset_spi < file_end :
				# Get CSE Partition Instance ID
				cse_in_id,x1,x2 = cse_part_inid(reading, p_offset_spi, ext_dict)
			
			# Store BPDT Partition info for -dfpt
			if param.fpt_disp :
				if p_offset in [4294967295, 0] : p_offset_print = ''
				else : p_offset_print = '0x%0.6X' % p_offset_spi
				
				if p_size in [4294967295, 0] : p_size_print = ''
				else : p_size_print = '0x%0.6X' % p_size
				
				if p_offset_print == '' or p_size_print == '' : p_end_print = ''
				else : p_end_print = '0x%0.6X' % (p_offset_spi + p_size)
				
				pt_dbpdt.add_row([p_name,'%0.2d' % p_type,'Primary',p_offset_print,p_size_print,p_end_print,'%0.4X' % cse_in_id,p_empty])
				
			# Detect if IFWI Primary includes PMC firmware (PMCP)
			if p_name == 'PMCP' and not p_empty :
				pmcp_found = True
				pmcp_fwu_found = False # CSME12+ FWUpdate tool requires PMC
				
				x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,pmc_mn2_ver = ext_anl('$CPD', p_offset_spi, file_end, ['NaN', -1, -1, -1, -1])
			
			if p_type == 5 and not p_empty and p_offset_spi < file_end and reading[p_offset_spi:p_offset_spi + 0x2] == b'\xAA\x55' : # Secondary BPDT (S-BPDT)
				init_s_bpdt_ver = int.from_bytes(reading[start_fw_start_match + 0x6:start_fw_start_match + 0x8], 'little') # BPDT Version
				if init_s_bpdt_ver == 2 : s_bpdt_hdr = get_struct(reading, p_offset_spi, BPDT_Header_2)
				else : s_bpdt_hdr = get_struct(reading, p_offset_spi, BPDT_Header)
				
				# Store Secondary BPDT info to show at CSE unpacking
				if param.me11_mod_extr :
					bpdt_hdr_all.append(s_bpdt_hdr.hdr_print())
					bpdt_data_all.append(reading[start_fw_start_match:start_fw_start_match + 0x200]) # Min size 0x200 (no size at Header, min is enough though)
				
				s_bpdt_all.append(p_offset_spi) # Store parsed S-BPDT offset to skip at IFWI/BPDT Starting Offsets
				
				s_bpdt_step = p_offset_spi + 0x18 # 0x18 S-BPDT Header size
				s_bpdt_part_num = s_bpdt_hdr.DescCount
				
				for j in range(0, s_bpdt_part_num):
					cse_in_id = 0
					
					s_bpdt_entry = get_struct(reading, s_bpdt_step, BPDT_Entry)
					
					s_p_type = s_bpdt_entry.Type
					s_p_offset = s_bpdt_entry.Offset
					s_p_offset_spi = start_fw_start_match + s_p_offset
					s_p_size = s_bpdt_entry.Size
					
					if s_p_offset in [4294967295, 0] or s_p_size in [4294967295, 0] or reading[s_p_offset_spi:s_p_offset_spi + s_p_size] == s_p_size * b'\xFF' :
						s_p_empty = True
					else :
						s_p_empty = False
					
					if s_p_type in bpdt_dict : s_p_name = bpdt_dict[s_p_type]
					else : s_p_name = 'Unknown'
					
					if not s_p_empty and s_p_offset_spi < file_end :
						cse_in_id,x1,x2 = cse_part_inid(reading, s_p_offset_spi, ext_dict)
					
					# Store BPDT Partition info for -dfpt
					if param.fpt_disp :
						if s_p_offset in [4294967295, 0] : s_p_offset_print = ''
						else : s_p_offset_print = '0x%0.6X' % s_p_offset_spi
						
						if s_p_size in [4294967295, 0] : s_p_size_print = ''
						else : s_p_size_print = '0x%0.6X' % s_p_size
						
						if s_p_offset_print == '' or s_p_size_print == '' : s_p_end_print = ''
						else : s_p_end_print = '0x%0.6X' % (s_p_offset_spi + s_p_size)
						
						pt_dbpdt.add_row([s_p_name,'%0.2d' % s_p_type,'Secondary',s_p_offset_print,s_p_size_print,s_p_end_print,'%0.4X' % cse_in_id,s_p_empty])
						
					# Detect if IFWI Secondary includes PMC firmware (PMCP)
					if p_name == 'PMCP' and not p_empty :
						pmcp_found = True
						pmcp_fwu_found = False # CSME12+ FWUpdate tool requires PMC
						
						x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,pmc_mn2_ver = ext_anl('$CPD', p_offset_spi, file_end, ['NaN', -1, -1, -1, -1])
					
					# Store all Secondary BPDT entries for extraction
					bpdt_part_all.append([s_p_name,s_p_offset_spi,s_p_offset_spi + s_p_size,s_p_type,s_p_empty,'Secondary',cse_in_id])
						
					s_bpdt_step += 0xC # 0xC BPDT Entry size
			
			# Store all Primary BPDT entries for extraction
			bpdt_part_all.append([p_name,p_offset_spi,p_offset_spi + p_size,p_type,p_empty,'Primary',cse_in_id])
			
			# Adjust Manifest Header to Recovery section based on BPDT
			if p_type == 2 and not p_empty and p_offset_spi < file_end : # CSE_BUP
				# Only if partition exists at file (counter-example: sole IFWI etc)
				# noinspection PyTypeChecker
				if p_offset_spi + p_size <= file_end :
					rec_man_match = man_pat.search(reading[p_offset_spi:p_offset_spi + p_size])
					
					if rec_man_match :
						(start_man_match, end_man_match) = rec_man_match.span()
						start_man_match += p_offset_spi + 0xB # Add CSE_BUP offset and 8680.{9} sanity check before .$MN2 or .$MAN
						end_man_match += p_offset_spi
			
			bpdt_step += 0xC # 0xC BPDT Entry size
		
		# Show BPDT Partition info on demand (-dfpt)
		if param.fpt_disp : print('%s\n' % pt_dbpdt)
	
	# Detect if CSE firmware has OEM Unlock Token (UTOK/STKN)
	for part in bpdt_part_all :
		if part[0] in ('UTOK','STKN') and reading[part[1]:part[1] + 0x10] != b'\xFF' * 0x10 : utok_found = True
		if part[0] == 'OEMP' and reading[part[1]:part[1] + 0x10] != b'\xFF' * 0x10 : oemp_found = True
	
	# Detect BPDT partition overlaps
	for part in bpdt_part_all :
		for all_part in bpdt_part_all :
			# Partition A starts before B but ends after B start
			# Ignore partitions which have empty offset or size
			# Ignore DLMP partition which overlaps by Intel design
			if not part[4] and not all_part[4] and not any(s in [0,0xFFFFFFFF] for s in (part[1],part[2],all_part[1],all_part[2])) \
			and part[0] not in ['S-BPDT','DLMP'] and all_part[0] not in ['S-BPDT','DLMP'] and (part[1] < all_part[1] < part[2]) :
				err_fpt_msg = col_r + 'Error: BPDT partition %s (0x%0.6X - 0x%0.6X) overlaps with %s (0x%0.6X - 0x%0.6X)' % \
				              (part[0],part[1],part[2],all_part[0],all_part[1],all_part[2]) + col_e
				err_fpt_stor.append(err_fpt_msg)
				err_stor.append([err_fpt_msg, True])
	
	# Ignore Flash Descriptor OEM backup at BPDT > OBBP > NvCommon (HP)
	for part in bpdt_part_all :
		if part[0] == 'OBBP' and not part[4] and re.compile(br'\x5A\xA5\xF0\x0F.{172}\xFF{16}', re.DOTALL).search(reading[part[1]:part[2]]) :
			fd_count -= 1
	
	# Scan $MAN/$MN2 manifest
	mn2_ftpr_hdr = get_struct(reading, start_man_match - 0x1B, MN2_Manifest)
	
	major = mn2_ftpr_hdr.Major
	minor = mn2_ftpr_hdr.Minor
	hotfix = mn2_ftpr_hdr.Hotfix
	build = mn2_ftpr_hdr.Build
	svn = mn2_ftpr_hdr.SVN
	vcn = mn2_ftpr_hdr.VCN
	day = mn2_ftpr_hdr.Day
	month = mn2_ftpr_hdr.Month
	year = mn2_ftpr_hdr.Year
	date = '%0.4X-%0.2X-%0.2X' % (year, month, day)
	
	# Read & Hash RSA Public Key and Signature
	rsa_key = reading[end_man_match + 0x60:end_man_match + 0x160] # Read FTPR RSA Public Key
	rsa_key_hash = sha_256(rsa_key).upper() # Generate FTPR RSA Public Key SHA-256 hash
	rsa_sig = reading[end_man_match + 0x164:end_man_match + 0x264] # Read FTPR RSA Signature
	rsa_sig_hash = sha_256(rsa_sig).upper() # Generate FTPR RSA Signature SHA-256 hash
	
	variant, variant_p, var_rsa_db = get_variant() # Detect Variant/Family
	
	# Detect FTPR RSA Signature Validity
	man_valid = rsa_sig_val(mn2_ftpr_hdr, reading, start_man_match - 0x1B)
	if not man_valid[0] :
		err_stor.append([col_r + "Error" + col_e + ", invalid FTPR RSA Signature!", True])
	
	if rgn_exist :
		
		# Multiple Backup $FPT header bypass at SPS1/SPS4 (DFLT/FPTB)
		if variant == 'CSSPS' or (variant,major) == ('SPS',1) and fpt_count % 2 == 0 : fpt_count /= 2
		
		# Check $FPT Checksum validity
		fpt_chk_file = '0x%0.2X' % fpt_hdr.HeaderChecksum
		chk_sum = sum(reading[fpt_start + fpt_chk_start:fpt_start + fpt_chk_start + fpt_length]) - fpt_chk_byte
		fpt_chk_calc = '0x%0.2X' % ((0x100 - chk_sum & 0xFF) & 0xFF)
		if fpt_chk_calc != fpt_chk_file: fpt_chk_fail = True
		
		# CSME12+ & CSTXE EXTR checksum from FIT is a placeholder (0x00), ignore
		if ((variant == 'CSME' and major >= 12) or variant == 'CSTXE') and fpt_chk_file == '0x00' :
			fpt_chk_null = True
			fpt_chk_fail = False
		
		# Check SPS3 $FPT Checksum validity (from Lordkag's UEFIStrip)
		if variant == 'SPS' and major == 3 :
			sps3_chk_start = fpt_start + 0x30
			sps3_chk_end = sps3_chk_start + fpt_part_num * 0x20
			fpt_chk16 = sum(bytearray(reading[sps3_chk_start:sps3_chk_end])) & 0xFFFF
			sps3_chk16 = ~fpt_chk16 & 0xFFFF
			sps3_chk16_file = '0x%0.4X' % (int(binascii.b2a_hex( (reading[sps3_chk_end:sps3_chk_end + 0x2])[::-1] ), 16))
			sps3_chk16_calc = '0x%0.4X' % sps3_chk16
			if sps3_chk16_calc != sps3_chk16_file: sps3_chk_fail = True
		
		# Last/Uncharted partition scanning inspired by Lordkag's UEFIStrip
		# ME2-ME6 don't have size for last partition, scan its submodules
		if p_end_last == p_max_size :
			
			mn2_hdr = get_struct(reading, p_offset_last, MN2_Manifest)
			man_tag = mn2_hdr.Tag
			man_num = mn2_hdr.NumModules
			man_len = mn2_hdr.HeaderLength * 4
			mod_start = p_offset_last + man_len + 0xC
			
			# ME6
			if man_tag == b'$MN2' :

				for _ in range(0, man_num) :
					mme_mod = get_struct(reading, mod_start, MME_Header_New)
					
					mod_code_start = mme_mod.Offset_MN2
					mod_size_comp = mme_mod.SizeComp
					mod_size_uncomp = mme_mod.SizeUncomp
					
					if mod_size_comp > 0 : mod_size = mod_size_comp
					elif mod_size_comp == 0 : mod_size = mod_size_uncomp
					
					mod_end = p_offset_last + mod_code_start + mod_size
					
					if mod_end > mod_end_max : mod_end_max = mod_end # In case modules are not offset sorted
					
					mod_start += 0x60
			
			# ME2-5
			elif man_tag == b'$MAN' :
				
				for _ in range(0, man_num) :
					mme_mod = get_struct(reading, mod_start, MME_Header_Old)
					mme_tag = mme_mod.Tag
					
					if mme_tag == b'$MME' : # Sanity check
						mod_size_all += mme_mod.Size # Append all $MOD ($MME Code) sizes
						mod_end_max = mod_start + 0x50 + 0xC + mod_size_all # Last $MME + $MME size + $SKU + all $MOD sizes
						mod_end = mod_end_max
					
						mod_start += 0x50
			
			# For Engine alignment & size, remove fpt_start (included in mod_end_max < mod_end < p_offset_last)
			mod_align = (mod_end_max - fpt_start) % 0x1000 # 4K alignment on Engine size only
			
			if mod_align > 0 : eng_fw_end = mod_end + 0x1000 - mod_align - fpt_start
			else : eng_fw_end = mod_end
		
		# Last $FPT entry has size, scan for uncharted partitions
		else :
			
			# TXE3+ uncharted DNXP starts 0x1000 after last $FPT entry for some reason
			if variant == 'CSTXE' and reading[p_end_last:p_end_last + 0x4] != b'$CPD' :
				if reading[p_end_last + 0x1000:p_end_last + 0x1004] == b'$CPD' : p_end_last += 0x1000
			
			# ME8-10 WCOD/LOCL but works for ME7, TXE1-2, SPS2-3 even though these end at last $FPT entry
			while reading[p_end_last + 0x1C:p_end_last + 0x20] == b'$MN2' :
				mod_in_id = '0000'
				
				mn2_hdr = get_struct(reading, p_end_last, MN2_Manifest)
				man_ven = '%X' % mn2_hdr.VEN_ID
				
				if man_ven == '8086' : # Sanity check
					man_num = mn2_hdr.NumModules
					man_len = mn2_hdr.HeaderLength * 4
					mod_start = p_end_last + man_len + 0xC
					mod_name = reading[p_end_last + man_len:p_end_last + man_len + 0x8].strip(b'\x00').decode('utf-8')
					mod_in_id = reading[p_end_last + man_len + 0x15:p_end_last + man_len + 0x15 + 0xB].strip(b'\x00').decode('utf-8')
					if variant == 'TXE' : mme_size = 0x80
					else : mme_size = 0x60 # ME & SPS
					mcp_start = mod_start + man_num * mme_size + mme_size # (each $MME = mme_size, mme_size padding after last $MME)
					
					mcp_mod = get_struct(reading, mcp_start, MCP_Header) # $MCP holds total partition size
					
					if mcp_mod.Tag == b'$MCP' : # Sanity check
						fpt_part_all.append([mod_name,p_end_last,p_end_last + mcp_mod.Offset_Code_MN2 + mcp_mod.CodeSize,mod_in_id,'Code',True,False])
						
						# Store $FPT Partition info for -dfpt
						if param.fpt_disp : # No Owner, Type Code, Valid, Not Empty
							pt_dfpt.add_row([mod_name,'','0x%0.6X' % p_end_last,'0x%0.6X' % mcp_mod.CodeSize,
							        '0x%0.6X' % (p_end_last + mcp_mod.Offset_Code_MN2 + mcp_mod.CodeSize),'Code',mod_in_id,True,False])
									
						p_end_last += mcp_mod.Offset_Code_MN2 + mcp_mod.CodeSize
					else :
						break # main "while" loop
				else :
					break # main "while" loop
				
			# SPS1, should not be run but works even though it ends at last $FPT entry
			while reading[p_end_last + 0x1C:p_end_last + 0x20] == b'$MAN' :
				
				mn2_hdr = get_struct(reading, p_end_last, MN2_Manifest)
				man_ven = '%X' % mn2_hdr.VEN_ID
				
				if man_ven == '8086': # Sanity check
					man_num = mn2_hdr.NumModules
					man_len = mn2_hdr.HeaderLength * 4
					mod_start = p_end_last + man_len + 0xC
					mod_size_all = 0
					
					for _ in range(0, man_num) :
						mme_mod = get_struct(reading, mod_start, MME_Header_Old)
						mme_tag = mme_mod.Tag
						
						if mme_tag == b'$MME': # Sanity check
							mod_size_all += mme_mod.Size # Append all $MOD ($MME Code) sizes
							p_end_last = mod_start + 0x50 + 0xC + mod_size_all # Last $MME + $MME size + $SKU + all $MOD sizes
						
							mod_start += 0x50
						else :
							p_end_last += 10 # to break main "while" loop
							break # nested "for" loop
				else :
					break # main "while" loop
			
			# ME11+ WCOD/LOCL, TXE3+ DNXP
			while reading[p_end_last:p_end_last + 0x4] == b'$CPD' :
				cse_in_id = 0
				
				cpd_hdr_ver = reading[p_end_last + 8] # $CPD Version Tag
				if cpd_hdr_ver == 2 : cpd_hdr = get_struct(reading, p_end_last, CPD_Header_2)
				else : cpd_hdr = get_struct(reading, p_end_last, CPD_Header)
				cpd_num = cpd_entry_num_fix(reading, p_end_last, cpd_hdr.NumModules)
				cpd_tag = cpd_hdr.PartitionName
				
				# Calculate partition size by the CSE Extension 03 or 16 (CSE_Ext_03 or CSE_Ext_16)
				# PartitionSize of CSE_Ext_03/16 is always 0x0A at TXE3+ so check $CPD entries instead
				cse_in_id,cse_ext_part_name,cse_ext_part_size = cse_part_inid(reading, p_end_last, ext_dict)
					
				# Last charted $FPT region size can be larger than CSE_Ext_03/16.PartitionSize because of 4K pre-alignment by Intel
				if cse_ext_part_name == cpd_hdr.PartitionName : # Sanity check
					p_end_last_cont = cse_ext_part_size
				
				# Calculate partition size by the $CPD entries (TXE3+, 2nd check for ME11+)
				for entry in range(1, cpd_num, 2) : # Skip 1st .man module, check only .met
					cpd_entry_hdr = get_struct(reading, p_end_last + 0x10 + entry * 0x18, CPD_Entry)
					cpd_mod_off,cpd_mod_huff,cpd_mod_res = cpd_entry_hdr.get_flags()
					
					cpd_entry_name = cpd_entry_hdr.Name
					
					if b'.met' not in cpd_entry_name and b'.man' not in cpd_entry_name : # Sanity check
						cpd_entry_offset = cpd_mod_off
						cpd_entry_size = cpd_entry_hdr.Size
						
						# Store last entry (max $CPD offset)
						if cpd_entry_offset > cpd_offset_last :
							cpd_offset_last = cpd_entry_offset
							cpd_end_last = cpd_entry_offset + cpd_entry_size
					else :
						break # nested "for" loop
				
				fpt_off_start = p_end_last # Store starting offset of current $FPT Partition for fpt_part_all
				
				# Take the largest partition size from the two checks
				# Add previous $CPD start for next size calculation
				p_end_last += max(p_end_last_cont,cpd_end_last)
				
				# Store all $FPT Partitions, uncharted (Type Code, Valid, Not Empty)
				fpt_part_all.append([cpd_tag,fpt_off_start,p_end_last,cse_in_id,'Code',True,False])
				
				# Store $FPT Partition info for -dfpt
				if param.fpt_disp :
					pt_dfpt.add_row([cpd_tag.decode('utf-8'),'','0x%0.6X' % fpt_off_start,'0x%0.6X' % (p_end_last - fpt_off_start),
					        '0x%0.6X' % p_end_last,'Code','%0.4X' % cse_in_id,True,False])
			
			# CSME 12+ consists of Layout Table (0x1000) + Data (MEA or LT size) + BPx (LT size)
			if cse_lt_exist :
				p_end_last = cse_lt_size + max(p_end_last,cse_lt_hdr_info[0][2]) + cse_lt_hdr_info[1][2] + cse_lt_hdr_info[2][2] + \
				             cse_lt_hdr_info[3][2] + cse_lt_hdr_info[4][2] + cse_lt_hdr_info[5][2]
			
			# For Engine alignment & size, remove fpt_start (included in p_end_last < eng_fw_end < p_offset_spi)
			mod_align = (p_end_last - fpt_start) % 0x1000 # 4K alignment on Engine size only
			
			if mod_align > 0 : eng_fw_end = p_end_last + 0x1000 - mod_align - fpt_start
			else : eng_fw_end = p_end_last - fpt_start
		
		# Show $FPT Partition info on demand (-dfpt)
		if param.fpt_disp : print('%s\n' % pt_dfpt)
		
		# Detect $FPT partition overlaps
		for part in fpt_part_all :
			for all_part in fpt_part_all :
				# Partition A starts before B but ends after B start
				# Ignore partitions which have empty offset or size
				# Ignore FTUP combo partition (NFTP + WCOD + LOCL)
				# Ignore DLMP partition which overlaps by Intel design
				if not part[6] and not all_part[6] and not any(s in [0,0xFFFFFFFF] for s in (part[1],part[2],all_part[1],all_part[2])) \
				and part[0] not in [b'FTUP',b'DLMP'] and all_part[0] not in [b'FTUP',b'DLMP'] and (part[1] < all_part[1] < part[2]) :
					err_fpt_msg = col_r + 'Error: $FPT partition %s (0x%0.6X - 0x%0.6X) overlaps with %s (0x%0.6X - 0x%0.6X)' % \
					              (part[0].decode('utf-8'),part[1],part[2],all_part[0].decode('utf-8'),all_part[1],all_part[2]) + col_e
					err_fpt_stor.append(err_fpt_msg)
					err_stor.append([err_fpt_msg, True])
		
		# Detect CSSPS 4 sometimes uncharted/empty $BIS partition
		if variant == 'CSSPS' : sps4_bis_match = (re.compile(br'\x24\x42\x49\x53\x00')).search(reading)
		else : sps4_bis_match = None
		
		# SPI image with FD
		if fd_me_rgn_exist :
			if eng_fw_end > me_fd_size :
				eng_size_text = [col_m + 'Warning: Firmware size exceeds Engine region, possible data loss!' + col_e, False]
			elif eng_fw_end < me_fd_size :
				# Extra data at Engine FD region padding
				padd_size_fd = me_fd_size - eng_fw_end
				padd_start_fd = fpt_start - cse_lt_size + eng_fw_end
				padd_end_fd = fpt_start - cse_lt_size + eng_fw_end + padd_size_fd
				if reading[padd_start_fd:padd_end_fd] != padd_size_fd * b'\xFF' :
					if sps4_bis_match is not None : eng_size_text = ['', False]
					else : eng_size_text = [col_m + 'Warning: Data in Engine region padding, possible data corruption!' + col_e, True]
		
		# Bare Engine Region
		elif fpt_start == 0 or (cse_lt_exist and cse_lt_off == 0) :
			# noinspection PyTypeChecker
			padd_size_file = file_end - eng_fw_end
			
			# noinspection PyTypeChecker
			if eng_fw_end > file_end :
				if eng_fw_end == file_end + 0x1000 - mod_align :
					pass # Firmware ends at last $FPT entry but is not 4K aligned, can be ignored (CSME12+)
				else :
					eng_size_text = [col_m + 'Warning: Firmware size exceeds file, possible data loss!' + col_e, False]
			elif eng_fw_end < file_end :
				if reading[eng_fw_end:eng_fw_end + padd_size_file] == padd_size_file * b'\xFF' :
					# Extra padding is clear
					eng_size_text = [col_y + 'Note: File size exceeds firmware, unneeded padding!' + col_e, False] # warn_stor
				else :
					# Extra padding has data
					if sps4_bis_match is not None : eng_size_text = ['', False]
					else : eng_size_text = [col_m + 'Warning: File size exceeds firmware, data in padding!' + col_e, True]
	
	# Firmware Type detection (Stock, Extracted, Update)
	if ifwi_exist : # IFWI
		fitc_ver_found = True
		fw_type = 'Region, Extracted'
		fitc_major = bpdt_hdr.FitMajor
		fitc_minor = bpdt_hdr.FitMinor
		fitc_hotfix = bpdt_hdr.FitHotfix
		fitc_build = bpdt_hdr.FitBuild
	elif rgn_exist : # SPS 1-3 have their own firmware Types
		if variant == 'SPS' : fw_type = 'Region' # SPS is built manually so EXTR
		elif variant == 'ME' and (2 <= major <= 7) :
			# Check 1, FOVD partition
			if (major >= 3 and not fovd_clean('new')) or (major == 2 and not fovd_clean('old')) : fw_type = 'Region, Extracted'
			else :
				# Check 2, EFFS/NVKR strings
				fitc_match = re.compile(br'\x4B\x52\x4E\x44\x00').search(reading) # KRND. detection = FITC, 0x00 adds old ME RGN support
				if fitc_match is not None :
					if major == 4 : fw_type_fix = True # ME4-Only Fix 3
					else : fw_type = 'Region, Extracted'
				elif major in [2,3] : fw_type_fix = True # ME2-Only Fix 1, ME3-Only Fix 1
				else : fw_type = 'Region, Stock'
		elif (variant == 'ME' and major >= 8) or variant in ['CSME','CSTXE','CSSPS','TXE'] :
			# Check 1, FITC Version
			if fpt_hdr.FitBuild in [0,65535] : # 0000/FFFF --> clean CS(ME)/CS(TXE)
				fw_type = 'Region, Stock'
				
				# Check 2, FOVD partition
				if not fovd_clean('new') : fw_type = 'Region, Extracted'
				
				# Check 3, CSTXE FIT temporarily/placeholder $FPT Header and Checksum
				if reading[fpt_start:fpt_start + 0x10] + reading[fpt_start + 0x1C:fpt_start + 0x30] == b'\xFF' * 0x24 : fw_type = 'Region, Extracted'
			else :
				# Get FIT/FITC version used to build the image
				fitc_ver_found = True
				fw_type = 'Region, Extracted'
				fitc_major = fpt_hdr.FitMajor
				fitc_minor = fpt_hdr.FitMinor
				fitc_hotfix = fpt_hdr.FitHotfix
				fitc_build = fpt_hdr.FitBuild
				
	else :
		fw_type = 'Update' # No Region detected, Update
	
	# Check for Fujitsu UMEM ME Region (RGN/$FPT or UPD/$MN2)
	if fd_me_rgn_exist and reading[me_fd_start:me_fd_start + 0x4] == b'\x55\x4D\xC9\x4D' : fuj_rgn_exist = True
	elif reading[:0x4] == b'\x55\x4D\xC9\x4D' : fuj_rgn_exist = True
	
	# Detect Firmware Release (Production, Pre-Production, ROM-Bypass, Other)
	mn2_flags_pvbit,mn2_flags_reserved,mn2_flags_pre,mn2_flags_debug = mn2_ftpr_hdr.get_flags()
	rel_signed = ['Production', 'Debug'][mn2_flags_debug]
	
	# Production PRD, Pre-Production PRE, ROM-Bypass BYP
	if fpt_romb_found :
		release = 'ROM-Bypass'
		rel_db = 'BYP'
	elif rel_signed == 'Production' :
		release = 'Production'
		rel_db = 'PRD'
	else :
		release = 'Pre-Production' # rel_signed = Debug
		rel_db = 'PRE'
	
	# Detect PV/PC bit (0 or 1)
	if (variant == 'ME' and major >= 8) or variant == 'TXE' :
		pvbit_match = (re.compile(br'\x24\x44\x41\x54....................\x49\x46\x52\x50', re.DOTALL)).search(reading) # $DAT + [0x14] + IFRP detection
		if pvbit_match is not None :
			(start_pvbit_match, end_pvbit_match) = pvbit_match.span()
			pvbit = int(binascii.b2a_hex( (reading[start_pvbit_match + 0x10:start_pvbit_match + 0x11]) ), 16)
	elif variant in ['CSME','CSTXE','CSSPS'] :
		pvbit = mn2_flags_pvbit
	
	if variant == 'ME' : # Management Engine
		
		# Detect SKU Attributes
		sku_match = re.compile(br'\x24\x53\x4B\x55[\x03-\x04]\x00\x00\x00').search(reading[start_man_match:]) # $SKU detection
		if sku_match is not None :
			(start_sku_match, end_sku_match) = sku_match.span()
			start_sku_match += start_man_match
			end_sku_match += start_man_match
			
			if 2 <= major <= 6 :
				# https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/WordDocuments/instanceidandversionstringformats.htm
				# https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/WordDocuments/vproverificationtableparameterdefinitions.htm
				sku_me = reading[start_sku_match + 8:start_sku_match + 0xC]
				sku_me = binascii.b2a_hex(sku_me).decode('utf-8').upper()
			elif 7 <= major <= 10 :
				sku_attrib = get_struct(reading, start_sku_match, SKU_Attributes)
				x1,sku_slim,x3,x4,x5,x6,x7,x8,x9,is_patsburg,sku_type,sku_size,x13 = sku_attrib.get_flags()
		
		if major == 2 : # ICH8 2.0 - 2.2 or ICH8M 2.5 - 2.6
			sku_byte = {0: 'AMT + ASF + QST', 1: 'ASF + QST', 2: 'QST'}
			
			if sku_me == '00000000' : # AMT + ASF + QST
				sku = 'AMT'
				sku_db = 'AMT'
				if minor <= 2 : sku_db_check = 'AMTD'
				else : sku_db_check = 'AMTM'
			elif sku_me == '02000000' : # QST
				sku = 'QST'
				sku_db = 'QST'
				sku_db_check = 'QST'
			else :
				sku = col_r + 'Unknown *' + col_e
				sku_db_check = 'UNK'
				err_stor.append([sku, True])
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_2_%s' % sku_db_check)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME2-Only Fix 1 : The usual method to detect EXTR vs RGN does not work for ME2
			if fw_type_fix :
				if sku == 'QST' or (sku == 'AMT' and minor >= 5) :
					nvkr_match = (re.compile(br'\x4E\x56\x4B\x52\x4B\x52\x49\x44')).search(reading) # NVKRKRID detection
					if nvkr_match is not None :
						(start_nvkr_match, end_nvkr_match) = nvkr_match.span()
						nvkr_start = int.from_bytes(reading[end_nvkr_match:end_nvkr_match + 0x4], 'little')
						nvkr_size = int.from_bytes(reading[end_nvkr_match + 0x4:end_nvkr_match + 0x8], 'little')
						nvkr_data = reading[fpt_start + nvkr_start:fpt_start + nvkr_start + nvkr_size]
						# NVKR sections : Name[0xC] + Size[0x3] + Data[Size]
						prat_match = (re.compile(br'\x50\x72\x61\x20\x54\x61\x62\x6C\x65\xFF\xFF\xFF')).search(nvkr_data) # "Pra Table" detection (2.5/2.6)
						maxk_match = (re.compile(br'\x4D\x61\x78\x55\x73\x65\x64\x4B\x65\x72\x4D\x65\x6D\xFF\xFF\xFF')).search(nvkr_data) # "MaxUsedKerMem" detection
						if prat_match is not None :
							(start_prat_match, end_prat_match) = prat_match.span()
							prat_start = fpt_start + nvkr_start + end_prat_match + 0x3
							prat_end = fpt_start + nvkr_start + end_prat_match + 0x13
							me2_type_fix = (binascii.b2a_hex(reading[prat_start:prat_end])).decode('utf-8').upper()
							me2_type_exp = '7F45DBA3E65424458CB09A6E608812B1'
						elif maxk_match is not None :
							(start_maxk_match, end_maxk_match) = maxk_match.span()
							qstpat_start = fpt_start + nvkr_start + end_maxk_match + 0x68
							qstpat_end = fpt_start + nvkr_start + end_maxk_match + 0x78
							me2_type_fix = (binascii.b2a_hex(reading[qstpat_start:qstpat_end])).decode('utf-8').upper()
							me2_type_exp = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
				elif sku == 'AMT' and minor < 5 :
					nvsh_match = (re.compile(br'\x4E\x56\x53\x48\x4F\x53\x49\x44')).search(reading) # NVSHOSID detection
					if nvsh_match is not None :
						(start_nvsh_match, end_nvsh_match) = nvsh_match.span()
						nvsh_start = int.from_bytes(reading[end_nvsh_match:end_nvsh_match + 0x4], 'little')
						nvsh_size = int.from_bytes(reading[end_nvsh_match + 0x4:end_nvsh_match + 0x8], 'little')
						nvsh_data = reading[fpt_start + nvsh_start:fpt_start + nvsh_start + nvsh_size]
						netip_match = (re.compile(br'\x6E\x65\x74\x2E\x69\x70\xFF\xFF\xFF')).search(reading) # "net.ip" detection (2.0-2.2)
						if netip_match is not None :
							(start_netip_match, end_netip_match) = netip_match.span()
							netip_size = int.from_bytes(reading[end_netip_match + 0x0:end_netip_match + 0x3], 'little')
							netip_start = fpt_start + end_netip_match + 0x4 # 0x4 always 03 so after that byte for 00 search
							netip_end = fpt_start + end_netip_match + netip_size + 0x3 # (+ 0x4 - 0x1)
							me2_type_fix = (binascii.b2a_hex(reading[netip_start:netip_end])).decode('utf-8').upper()
							me2_type_exp = (binascii.b2a_hex(b'\x00' * (netip_size - 0x1))).decode('utf-8').upper()
							
				if me2_type_fix != me2_type_exp : fw_type = 'Region, Extracted'
				else : fw_type = 'Region, Stock'
			
			# ME2-Only Fix 2 : Identify ICH Revision B0 firmware SKUs
			me2_sku_fix = ['FF4DAEACF679A7A82269C1C722669D473F7D76AD3DFDE12B082A0860E212CD93',
			'345F39266670F432FCFF3B6DA899C7B7E0137ED3A8A6ABAD4B44FB403E9BB3BB',
			'8310BA06D7B9687FC18847991F9B1D747B55EF30E5E0E5C7B48E1A13A5BEE5FA']
			if rsa_sig_hash in me2_sku_fix :
				sku = 'AMT B0'
				sku_db = 'AMT_B0'
			
			# ME2-Only Fix 3 : Detect ROMB RGN/EXTR image correctly (at $FPT v1 ROMB was before $FPT)
			if rgn_exist and release == 'Pre-Production' :
				byp_pat = re.compile(br'\x24\x56\x45\x52\x02\x00\x00\x00') # $VER2... detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				
				if byp_match is not None :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
					(byp_start, byp_end) = byp_match.span()
					byp_size = fpt_start - (byp_start - 0x80)
					eng_fw_end += byp_size
					if 'Data in Engine region padding' in eng_size_text[0] : eng_size_text = ['', False]
					
			if minor >= 5 : platform = 'ICH8M'
			else : platform = 'ICH8'
	
		elif major == 3 : # ICH9 or ICH9DO
			sku_bits = {1: 'IDT', 2: 'TPM', 3: 'AMT Lite', 4: 'AMT', 5: 'ASF', 6: 'QST'}
			
			if sku_me in ['0E000000','00000000'] : # AMT + ASF + QST (00000000 for Pre-Alpha ROMB)
				sku = 'AMT' # Q35 only
				sku_db = 'AMT'
			elif sku_me == '06000000' : # ASF + QST
				sku = 'ASF' # Q33 (HP dc5800)
				sku_db = 'ASF'
			elif sku_me == '02000000' : # QST
				sku = 'QST'
				sku_db = 'QST'
			else :
				sku = col_r + 'Unknown *' + col_e
				err_stor.append([sku, True])
				
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_3_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True

			# ME3-Only Fix 1 : The usual method to detect EXTR vs RGN does not work for ME3
			if fw_type_fix :
				me3_type_fix1 = []
				me3_type_fix2a = 0x10 * 'FF'
				me3_type_fix2b = 0x10 * 'FF'
				me3_type_fix3 = 0x10 * 'FF'
				effs_match = (re.compile(br'\x45\x46\x46\x53\x4F\x53\x49\x44')).search(reading) # EFFSOSID detection
				if effs_match is not None :
					(start_effs_match, end_effs_match) = effs_match.span()
					effs_start = int.from_bytes(reading[end_effs_match:end_effs_match + 0x4], 'little')
					effs_size = int.from_bytes(reading[end_effs_match + 0x4:end_effs_match + 0x8], 'little')
					effs_data = reading[fpt_start + effs_start:fpt_start + effs_start + effs_size]
					
					me3_type_fix1 = (re.compile(br'\x4D\x45\x5F\x43\x46\x47\x5F\x44\x45\x46\x04\x4E\x56\x4B\x52')).findall(effs_data) # ME_CFG_DEF.NVKR detection (RGN have <= 2)
					me3_type_fix2 = (re.compile(br'\x4D\x61\x78\x55\x73\x65\x64\x4B\x65\x72\x4D\x65\x6D\x04\x4E\x56\x4B\x52\x7F\x78\x01')).search(effs_data) # MaxUsedKerMem.NVKR.x. detection
					me3_type_fix3 = (binascii.b2a_hex(reading[fpt_start + effs_start + effs_size - 0x20:fpt_start + effs_start + effs_size - 0x10])).decode('utf-8').upper()
					
					if me3_type_fix2 is not None :
						(start_me3f2_match, end_me3f2_match) = me3_type_fix2.span()
						me3_type_fix2a = (binascii.b2a_hex(reading[fpt_start + effs_start + end_me3f2_match - 0x30:fpt_start + effs_start + end_me3f2_match - 0x20])).decode('utf-8').upper()
						me3_type_fix2b = (binascii.b2a_hex(reading[fpt_start + effs_start + end_me3f2_match + 0x30:fpt_start + effs_start + end_me3f2_match + 0x40])).decode('utf-8').upper()

				if len(me3_type_fix1) > 2 or (0x10 * 'FF') not in me3_type_fix3 or (0x10 * 'FF') not in me3_type_fix2a or (0x10 * 'FF') not in me3_type_fix2b : fw_type = 'Region, Extracted'
				else : fw_type = 'Region, Stock'
			
			# ME3-Only Fix 2 : Detect AMT ROMB UPD image correctly (very vague, may not always work)
			if fw_type == 'Update' and release == 'Pre-Production' : # Debug Flag detected at $MAN but PRE vs BYP is needed for UPD (not RGN)
				# It seems that ROMB UPD is smaller than equivalent PRE UPD
				# min size(ASF, UPD) is 0xB0904 so 0x100000 safe min AMT ROMB
				# min size(AMT, UPD) is 0x190904 so 0x185000 safe max AMT ROMB
				# min size(QST, UPD) is 0x2B8CC so 0x40000 safe min for ASF ROMB
				# min size(ASF, UPD) is 0xB0904 so 0xAF000 safe max for ASF ROMB
				# min size(QST, UPD) is 0x2B8CC so 0x2B000 safe max for QST ROMB
				# noinspection PyTypeChecker
				if (sku == 'AMT' and int(0x100000) < file_end < int(0x185000)) or (sku == 'ASF' and int(0x40000) < file_end < int(0xAF000)) \
				or (sku == 'QST' and file_end < int(0x2B000)) :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			# ME3-Only Fix 3 : Detect Pre-Alpha ($FPT v1) ROMB RGN/EXTR image correctly
			if rgn_exist and fpt_version == 16 and release == 'Pre-Production' :
				byp_pat = re.compile(br'\x24\x56\x45\x52\x03\x00\x00\x00') # $VER3... detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				
				if byp_match is not None :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
					(byp_start, byp_end) = byp_match.span()
					byp_size = fpt_start - (byp_start - 0x80)
					eng_fw_end += byp_size
					if 'Data in Engine region padding' in eng_size_text[0] : eng_size_text = ['', False]
			
			platform = 'ICH9'
	
		elif major == 4 : # ICH9M or ICH9M-E (AMT or TPM+AMT): 4.0 - 4.2 , xx00xx --> 4.0 , xx20xx --> 4.1 or 4.2
			sku_bits = {0: 'Reserved', 1: 'IDT', 2: 'TPM', 3: 'AMT Lite', 4: 'AMT', 5: 'ASF', 6: 'QST', 7: 'Reserved'}
			
			if sku_me in ['AC200000','AC000000','04000000'] : # 040000 for Pre-Alpha ROMB
				sku = 'AMT + TPM' # CA_ICH9_REL_ALL_SKUs_ (TPM + AMT)
				sku_db = 'ALL'
			elif sku_me in ['8C200000','8C000000','0C000000'] : # 0C000000 for Pre-Alpha ROMB
				sku = 'AMT' # CA_ICH9_REL_IAMT_ (AMT)
				sku_db = 'AMT'
			elif sku_me in ['A0200000','A0000000'] :
				sku = 'TPM' # CA_ICH9_REL_NOAMT_ (TPM)
				sku_db = 'TPM'
			else :
				sku = col_r + 'Unknown *' + col_e
				err_stor.append([sku, True])
			
			# ME4-Only Fix 1 : Detect ROMB UPD image correctly
			if fw_type == "Update" :
				byp_pat = re.compile(br'\x52\x4F\x4D\x42') # ROMB detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				if byp_match is not None :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			# ME4-Only Fix 2 : Detect SKUs correctly, only for Pre-Alpha firmware
			if minor == 0 and hotfix == 0 :
				if fw_type == 'Update' :
					tpm_tag = (re.compile(br'\x24\x4D\x4D\x45........................\x54\x50\x4D', re.DOTALL)).search(reading) # $MME + [0x18] + TPM
					amt_tag = (re.compile(br'\x24\x4D\x4D\x45........................\x4D\x4F\x46\x46\x4D\x31\x5F\x4F\x56\x4C', re.DOTALL)).search(reading) # $MME + [0x18] + MOFFM1_OVL
				else :
					tpm_tag = (re.compile(br'\x4E\x56\x54\x50\x54\x50\x49\x44')).search(reading) # NVTPTPID partition found at ALL or TPM
					amt_tag = (re.compile(br'\x4E\x56\x43\x4D\x41\x4D\x54\x43')).search(reading) # NVCMAMTC partition found at ALL or AMT
				
				if tpm_tag is not None and amt_tag is not None :
					sku = 'AMT + TPM' # CA_ICH9_REL_ALL_SKUs_
					sku_db = 'ALL'
				elif tpm_tag is not None :
					sku = 'TPM' # CA_ICH9_REL_NOAMT_
					sku_db = 'TPM'
				else :
					sku = 'AMT' # CA_ICH9_REL_IAMT_
					sku_db = 'AMT'
			
			# ME4-Only Fix 3 : The usual method to detect EXTR vs RGN does not work for ME4, KRND. not enough
			if fw_type_fix :
				effs_match = (re.compile(br'\x45\x46\x46\x53\x4F\x53\x49\x44')).search(reading) # EFFSOSID detection
				if effs_match is not None :
					(start_effs_match, end_effs_match) = effs_match.span()
					effs_start = int.from_bytes(reading[end_effs_match:end_effs_match + 0x4], 'little')
					effs_size = int.from_bytes(reading[end_effs_match + 0x4:end_effs_match + 0x8], 'little')
					effs_data = reading[fpt_start + effs_start:fpt_start + effs_start + effs_size]
				
					me4_type_fix1 = (re.compile(br'\x4D\x45\x5F\x43\x46\x47\x5F\x44\x45\x46')).findall(effs_data) # ME_CFG_DEF detection (RGN have 2-4)
					me4_type_fix2 = (re.compile(br'\x47\x50\x49\x4F\x31\x30\x4F\x77\x6E\x65\x72')).search(effs_data) # GPIO10Owner detection
					me4_type_fix3 = (re.compile(br'\x41\x70\x70\x52\x75\x6C\x65\x2E\x30\x33\x2E\x30\x30\x30\x30\x30\x30')).search(effs_data) # AppRule.03.000000 detection
				
					if len(me4_type_fix1) > 5 or me4_type_fix2 is not None or me4_type_fix3 is not None : fw_type = "Region, Extracted"
					else : fw_type = 'Region, Stock'
			
			# Placed here in order to comply with Fix 2 above in case it is triggered
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_4_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				
			platform = 'ICH9M'
			
		elif major == 5 : # ICH10D or ICH10DO
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 5: 'ASF', 6: 'QST', 8: 'Level III Manageability Upgrade', 9: 'Corporate', 10: 'Anti-Theft', 15: 'Remote PC Assist'}
			
			if sku_me == '3E080000' : # EL_ICH10_SKU1
				sku = 'Digital Office' # AMT
				sku_db = 'DO'
			elif sku_me == '060D0000' : # EL_ICH10_SKU4
				sku = 'Base Consumer' # NoAMT
				sku_db = 'BC'
			elif sku_me == '06080000' : # EL_ICH10_SKU2 or EL_ICH10_SKU3
				sku = 'Digital Home or Base Corporate (?)'
				sku_db = 'DHBC'
			else :
				sku = col_r + 'Unknown *' + col_e
				err_stor.append([sku, True])
				
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_5_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				
			# ME5-Only Fix : Detect ROMB UPD image correctly
			if fw_type == 'Update' :
				byp_pat = re.compile(br'\x52\x4F\x4D\x42') # ROMB detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				if byp_match is not None :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			platform = 'ICH10'
	
		elif major == 6 :
			platform = 'IBX'
			
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 6: 'QST', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist'}
			
			if sku_me == '00000000' : # Ignition (128KB, 2MB)
				if hotfix == 50 : # 89xx (Cave/Coleto Creek)
					ign_pch = 'CCK'
					platform = 'CCK'
				else : # P55, PM55, 34xx (Ibex Peak)
					ign_pch = 'IBX'
				sku_db = 'IGN_' + ign_pch
				sku = 'Ignition ' + ign_pch
			elif sku_me == '701C0000' : # Home IT (1.5MB, 4MB)
				sku = '1.5MB'
				sku_db = '1.5MB'
			# xxDCxx = 6.x, xxFCxx = 6.0, xxxxEE = Mobile, xxxx6E = Desktop, F7xxxx = Old Alpha/Beta Releases
			elif sku_me in ['77DCEE00','77FCEE00','F7FEFE00'] : # vPro (5MB, 8MB)
				sku = '5MB MB'
				sku_db = '5MB_MB'
			elif sku_me in ['77DC6E00','77FC6E00','F7FE7E00'] : # vPro (5MB, 8MB)
				sku = '5MB DT'
				sku_db = '5MB_DT'
			else :
				sku = col_r + 'Unknown *' + col_e
				err_stor.append([sku, True])
				
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_6_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME6-Only Fix 1 : ME6 Ignition does not work with KRND
			if 'Ignition' in sku and rgn_exist :
				ign_pat = (re.compile(br'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6D\x3C\x75\x6D')).findall(reading) # Clean $MINIFAD checksum
				if len(ign_pat) < 2 : fw_type = "Region, Extracted" # 2 before NFTP & IGRT
				else : fw_type = "Region, Stock"
			
			# ME6-Only Fix 2 : Ignore errors at ROMB (Region present, FTPR tag & size missing)
			if release == "ROM-Bypass" :
				rec_missing = False
				if 'Firmware size exceeds file' in eng_size_text[0] : eng_size_text = ['', False]
			
		elif major == 7 :
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist'}
			
			if sku_slim == 1 :
				sku = 'Slim'
				sku_db = 'SLM'
			elif sku_size * 0.5 == 1.5 :
				sku = '1.5MB'
				sku_db = '1.5MB'
			elif sku_size * 0.5 == 5 or (build,hotfix,minor,sku_size) == (1041,0,0,1) :
				sku = '5MB'
				sku_db = '5MB'
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_7_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME7-Only Fix: ROMB UPD detection
			if fw_type == 'Update' :
				me7_mn2_hdr_len = mn2_ftpr_hdr.HeaderLength * 4
				me7_mn2_mod_len = (mn2_ftpr_hdr.NumModules + 1) * 0x60
				me7_mcp = get_struct(reading, start_man_match - 0x1B + me7_mn2_hdr_len + 0xC + me7_mn2_mod_len, MCP_Header) # Goto $MCP
				
				if me7_mcp.CodeSize == 374928 or me7_mcp.CodeSize == 419984 : # 1.5/5MB ROMB Code Sizes
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			# ME7 Blacklist Table Detection
			me7_blist_1_minor  = int(binascii.b2a_hex( (reading[start_man_match + 0x6DF:start_man_match + 0x6E1]) [::-1]), 16)
			me7_blist_1_hotfix = int(binascii.b2a_hex( (reading[start_man_match + 0x6E1:start_man_match + 0x6E3]) [::-1]), 16)
			me7_blist_1_build  = int(binascii.b2a_hex( (reading[start_man_match + 0x6E3:start_man_match + 0x6E5]) [::-1]), 16)
			if me7_blist_1_build != 0 : me7_blist_1 = '<= 7.%d.%d.%d' % (me7_blist_1_minor, me7_blist_1_hotfix, me7_blist_1_build)
			me7_blist_2_minor  = int(binascii.b2a_hex( (reading[start_man_match + 0x6EB:start_man_match + 0x6ED]) [::-1]), 16)
			me7_blist_2_hotfix = int(binascii.b2a_hex( (reading[start_man_match + 0x6ED:start_man_match + 0x6EF]) [::-1]), 16)
			me7_blist_2_build  = int(binascii.b2a_hex( (reading[start_man_match + 0x6EF:start_man_match + 0x6F1]) [::-1]), 16)
			if me7_blist_2_build != 0 : me7_blist_2 = '<= 7.%d.%d.%d' % (me7_blist_2_minor, me7_blist_2_hotfix, me7_blist_2_build)
			
			platform = ['CPT','CPT/PBG'][is_patsburg]
			
		elif major == 8 :
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist', 23: 'Small Business'}
			
			if sku_size * 0.5 == 1.5 :
				sku = '1.5MB'
				sku_db = '1.5MB'
			elif sku_size * 0.5 == 5 :
				sku = '5MB'
				sku_db = '5MB'
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_8_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				
			# ME8-Only Fix: SVN location
			svn = mn2_ftpr_hdr.SVN_8
			
			platform = 'CPT/PBG/PPT'
		
		elif major == 9 :
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist', 23: 'Small Business'}
			
			if sku_type == 0 :
				sku = '5MB'
				sku_db = '5MB'
			elif sku_type == 1 :
				sku = '1.5MB'
				sku_db = '1.5MB'
			elif sku_type == 2 :
				sku = 'Slim'
				sku_db = 'SLM'
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_9%d_%s' % (minor, sku_db))
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			if minor == 0 : platform = 'LPT'
			elif minor == 1 : platform = 'LPT/WPT'
			elif minor in [5,6] : platform = 'LPT-LP'
				
			# 9.6 --> Intel Harris Beach Ultrabook, HSW developer preview (https://bugs.freedesktop.org/show_bug.cgi?id=90002)
			
		elif major == 10 :
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist', 23: 'Small Business'}
			
			if sku_type == 0 :
				sku = '5MB'
				sku_db = '5MB'
			elif sku_type == 1 :
				sku = '1.5MB'
				sku_db = '1.5MB'
			elif sku_type == 2 :
				sku = 'Slim'
				sku_db = 'SLM'
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_10%d_%s' % (minor, sku_db))
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			if minor == 0 : platform = 'WPT-LP'
	
	elif variant == 'CSME' : # Converged Security Management Engine
		
		# Chipset Initialization: Platform.Stepping.Version
		# 211.10 = D3.A = D.3.A --> CNP-H Stepping D Version 10
		# 0x0 = LBG (???)
		# 0x3 = ICP-LP (POR)
		# 0x4 = ICP-N (POR)
		# 0x5 = ICP-H (POR)
		# 0x6 = TGP-LP (POR)
		# 0x7 = TGP-H (POR)
		# 0x8 = SPT/KBP-LP (???)
		# 0x9 = SPT-H (???)
		# 0xB = KBP-H/BSF (???)
		# 0xC = CNP-LP (POR)
		# 0xD = CNP-H (POR)
		# 0xE = LKF (POR)
		
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_err_stor,ext_dnx_val,\
		oem_config,oem_signed,cpd_mn2_info = ext_anl('$MN2', start_man_match, file_end, [variant, major, minor, hotfix, build]) # Detect CSE Attributes
		
		fw_0C_sku0,fw_0C_sku1,fw_0C_lbg,fw_0C_sku2 = ext12_info # SKU Capabilities, SKU Type, HEDT Support, SKU Platform
		
		# Set SKU Type via Extension 0C Attributes
		if fw_0C_sku1 == 0 : # 0 Corporate/Intel (1272K MFS)
			sku_init = 'Corporate'
			sku_init_db = 'COR'
		elif fw_0C_sku1 == 1 : # 1 Consumer/Intel (400K MFS)
			sku_init = 'Consumer'
			sku_init_db = 'CON'
		elif fw_0C_sku1 == 2 : # 2 Slim/Apple (256K MFS)
			sku_init = 'Slim'
			sku_init_db = 'SLM'
		else :
			sku_init = 'Unknown'
			sku_init_db = 'UNK'
		
		# Set SKU Platform via Extension 0C Attributes
		if fw_0C_sku2 == 0 : pos_sku_ext = 'H' # Halo
		elif fw_0C_sku2 == 1 : pos_sku_ext = 'LP' # Low Power
		elif fw_0C_sku2 == 2 : pos_sku_ext = 'N' # ???
		
		db_sku_chk,sku,sku_stp,sku_pdm = db_skl(variant) # Retrieve SKU & Rev from DB
		
		# Early firmware are reported as PRD even though they are PRE
		if release == 'Production' and \
		rsa_key_hash in ['86C0E5EF0CFEFF6D810D68D83D8C6ECB68306A644C03C0446B646A3971D37894','C3416BFF2A9A85414F584263CE6BC0083979DC90FC702FCB671EA497994BA1A7'] :
			release = 'Pre-Production'
			rel_db = 'PRE'
		
		if major == 11 :
			
			# Set SKU Platform via Extension 0C Attributes
			if minor > 0 or (minor == 0 and (hotfix > 0 or (hotfix == 0 and build >= 1205 and build != 7101))) :
				pass # Use the already set general CSME pos_sku_ext
			else :
				pos_sku_ext = 'Invalid' # Only for CSME >= 11.0.0.1205
			
			# SKU not in Extension 0C and not in DB, scan decompressed Huffman module FTPR > kernel
			if pos_sku_ext == 'Invalid' and sku == 'NaN' :
				for mod in cpd_mod_attr :
					if mod[0] == 'kernel' :
						huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, 'none')
						ker_decomp = cse_huffman_decompress(reading[mod[3]:mod[3] + mod[4]], mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none')
						
						# 0F22D88D65F85B5E5DC355B8 (56 & AA for H, 60 & A0 for LP)
						sku_pat = re.compile(br'\x0F\x22\xD8\x8D\x65\xF8\x5B\x5E\x5D\xC3\x55\xB8').search(ker_decomp)
						
						if sku_pat :
							sku_byte_1 = ker_decomp[sku_pat.end():sku_pat.end() + 0x1]
							sku_byte_2 = ker_decomp[sku_pat.end() + 0x17:sku_pat.end() + 0x18]
							sku_bytes = binascii.b2a_hex(sku_byte_1 + sku_byte_2).decode('utf-8').upper()
							if sku_bytes == '56AA' : pos_sku_ker = 'H'
							elif sku_bytes == '60A0' : pos_sku_ker = 'LP'
						
						break # Skip rest of FTPR modules
			
			if pos_sku_ext in ['Unknown','Invalid'] : # SKU not retrieved from Extension 0C
				if pos_sku_ker == 'Invalid' : # SKU not retrieved from Kernel
					if sku == 'NaN' : # SKU not retrieved from manual MEA DB entry
						sku = col_r + 'Unknown *' + col_e
						err_stor.append([sku, True])
					else :
						pass # SKU retrieved from manual MEA DB entry
				else :
					sku = sku_init + ' ' + pos_sku_ker # SKU retrieved from Kernel
			else :
				sku = sku_init + ' ' + pos_sku_ext # SKU retrieved from Extension 0C
			
			# Store final SKU result (CSME 11 only)
			if ' LP' in sku : sku_result = 'LP'
			elif ' H' in sku : sku_result = 'H'
			else : sku_result = 'UNK'
			
			# Adjust Production PCH Stepping, if not found at DB
			if sku_stp == 'NaN' :
				if (release == 'Production' and (minor == 0 and (hotfix > 0 or (hotfix == 0 and build >= 1158)))) or 20 > minor > 0 :
					if sku_result == 'LP' : sku_stp = 'C0'
					elif sku_result == 'H' : sku_stp = 'D0'
				elif release == 'Production' and minor in [20,21] and ' H' in sku : sku_stp = 'B0' # PRD Bx (C620 Datasheet, 1.6 PCH Markings)
			
			sku_db, upd_found = sku_db_upd_cse(sku_init_db, sku_result, sku_stp, upd_found, False) # Store DB SKU and check Latest version
			
			if minor == 0 : platform = 'SPT' # Skylake, Sunrise Point
			elif minor in [5,6,7,8] : platform = 'SPT/KBP' # Skylake/Kabylake(R)/Coffeelake, Sunrise/Union Point
			elif minor in [10,11] : platform = 'BSF' # Skylake-X/Kabylake-X, Basin Falls
			elif minor in [20,21] : platform = 'LBG' # Skylake-SP, Lewisburg
			
			if minor in [0,5,6,7,10,20] : upd_found = True # INTEL-SA-00086
			
			# Power Down Mitigation (PDM) is a SPT-LP C0 erratum, first fixed at ~11.0.0.1183
			# Hardcoded in FTPR > BUP, Huffman decompression required to detect NPDM or YPDM
			# Hardfixed at KBP-LP A0 but 11.5-8 have PDM firmware for SPT-LP C0 with KBL(R)
			if sku_result == 'LP' :
				# PDM not in DB, scan decompressed Huffman module FTPR > bup
				if sku_pdm not in ['NPDM','YPDM'] :
					for mod in cpd_mod_attr :
						if mod[0] == 'bup' :
							huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, 'none')
							bup_decomp = cse_huffman_decompress(reading[mod[3]:mod[3] + mod[4]], mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none')
							
							if bup_decomp != b'' :
								# C355B00189E55D (FFFF8D65F45B5E5F5DC355B00189E55DC3)
								pdm_pat = re.compile(br'\xFF\xFF\x8D\x65\xF4\x5B\x5E\x5F\x5D\xC3\x55\xB0\x01\x89\xE5\x5D\xC3').search(bup_decomp)
							
								if pdm_pat : sku_pdm = 'YPDM'
								else : sku_pdm = 'NPDM'
							
							break # Skip rest of FTPR modules
				
				if sku_pdm == 'YPDM' : pdm_status = 'Yes'
				elif sku_pdm == 'NPDM' : pdm_status = 'No'
				elif sku_pdm == 'UPDM1' : pdm_status = 'Unknown 1'
				elif sku_pdm == 'UPDM2' : pdm_status = 'Unknown 2'
				else : pdm_status = 'Unknown'
				
				sku_db += '_%s' % sku_pdm
		
		elif major == 12 :
			
			# Detect SKU Platform, prefer DB over Extension
			if sku != 'NaN' :
				sku_result = db_sku_chk # SKU Platform retrieved from DB
			else :
				sku_result = pos_sku_ext # SKU Platform retrieved from Extension 12
				
				# Early firmware are reported as H even though they are LP
				if sku_result == 'H' and fw_0C_sku0 in ('3111BED0','7DF7FFDF','11009A40') : sku_result = 'LP' # CON 0x3111BED0, COR 0x7DF7FFDF, SLM 0x11009A40
				elif sku_result == 'LP' and fw_0C_sku0 in ('3111BDD0','7DF7FDDF','11009940') : sku_result = 'H' # CON 0x3111BDD0, COR 0x7DF7FDDF, SLM 0x11009940
			
			sku = sku_init + ' ' + sku_result
			
			# Set PCH/SoC Stepping, if not found at DB
			if sku_stp == 'NaN' :
				
				# Adjust Production PCH/SoC Stepping from known values
				if sku_result == 'H' and (minor > 0 or (minor == 0 and hotfix > 0 or (hotfix == 0 and build >= 1062))) : sku_stp = 'B'
				#elif sku_result == 'H' : sku_stp = 'A' # <= 12.0.0.xxxx
			
			# Detected stitched PMC firmware
			if pmcp_found :
				pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmcp_upd_found,pmcp_not_in_db,pmc_platform,pmc_date = pmc_anl(pmc_mn2_ver)
				
				# Verify FTPR & PMC compatibility (PCH & SKU)
				if pmc_pch_gen < 300 or pmc_fw_rel == 0 :
					pass # Old CNP 300-series PMC versioning
				elif pmc_mn2_signed != release or pmc_pch_gen != 300 or pmc_pch_sku != sku_result or (sku_stp != 'NaN' and pmc_pch_rev[0] != sku_stp) :
					pmc_not_comp = True
			
			sku_db,upd_found = sku_db_upd_cse(sku_init_db, sku_result, sku_stp, upd_found, False) # Store DB SKU and check Latest version
			
			# 12.0 : Cannonlake, Cannon Point
			if minor == 0 : platform = 'CNP'
			
		# Module Extraction for all CSME
		if param.me11_mod_extr :
			cse_unpack(fpt_part_all, bpdt_part_all, fw_type, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail)
			continue # Next input file
	
	elif variant == 'TXE' : # Trusted Execution Engine
		
		# Detect SKU Attributes
		sku_match = re.compile(br'\x24\x53\x4B\x55[\x03-\x04]\x00\x00\x00').search(reading[start_man_match:]) # $SKU detection
		if sku_match is not None :
			(start_sku_match, end_sku_match) = sku_match.span()
			start_sku_match += start_man_match
			end_sku_match += start_man_match
			
			sku_attrib = get_struct(reading, start_sku_match, SKU_Attributes)
			x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,sku_size,x13 = sku_attrib.get_flags()
			
		if major in [0,1] :
			if sku_size * 0.5 == 1.5 :
				if minor == 0 :
					sku = '1.25MB'
					sku_db = '1.25MB'
				else :
					sku = '1.375MB'
					sku_db = '1.375MB'
			elif sku_size * 0.5 in [2.5,3] :
				sku = '3MB'
				sku_db = '3MB'
			
			if rsa_key_hash in ['6B8B10107E20DFD45F6C521100B950B78969B4AC9245D90DE3833E0A082DF374','86C0E5EF0CFEFF6D810D68D83D8C6ECB68306A644C03C0446B646A3971D37894'] :
				sku += ' M/D'
				sku_db += '_MD'
			elif rsa_key_hash in ['613421A156443F1C038DDE342FF6564513A1818E8CC23B0E1D7D7FB0612E04AC','86C0E5EF0CFEFF6D810D68D83D8C6ECB68306A644C03C0446B646A3971D37894'] :
				sku += ' I/T'
				sku_db += '_IT'
			
			platform = 'BYT'
				
		elif major == 2 :
			if sku_size * 0.5 == 1.5 :
				sku = '1.375MB'
				sku_db = '1.375MB'
			
			platform = 'BSW/CHT'
			
		db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_%d%d_%s' % (major, minor, sku_db))
		if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
	
	elif variant == 'CSTXE' : # Converged Security Trusted Execution Engine
		
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_err_stor,ext_dnx_val,\
		oem_config,oem_signed,cpd_mn2_info = ext_anl('$MN2', start_man_match, file_end, [variant, major, minor, hotfix, build]) # Detect CSE Attributes
		
		fw_0C_sku0,fw_0C_sku1,fw_0C_lbg,fw_0C_sku2 = ext12_info # SKU Capabilities, SKU Type, HEDT Support, SKU Platform
		
		db_sku_chk,sku,sku_stp,sku_pdm = db_skl(variant) # Retrieve SKU & Rev from DB
		
		# Early firmware are reported as PRD even though they are PRE
		if release == 'Production' and rsa_key_hash == 'C3416BFF2A9A85414F584263CE6BC0083979DC90FC702FCB671EA497994BA1A7' :
			release = 'Pre-Production'
			rel_db = 'PRE'
			
		if major == 3 :
			
			if minor in [0,1] :
				
				# Adjust SoC Stepping if not from DB
				if sku_stp == 'NaN' :
					if release == 'Production' : sku_stp = 'B' # PRD
					else : sku_stp = 'A' # PRE, BYP
					
				platform = 'APL'
				
			elif minor in [2,3] :
				
				# Adjust SoC Stepping if not from DB
				if sku_stp == 'NaN' :
					if release == 'Production' : sku_stp = 'C' # PRD (Joule_C0-X64-Release)
					else : sku_stp = 'A' # PRE, BYP
					
				platform = 'BXT' # Joule (Broxton)
					
			if minor in [0,2] : upd_found = True # INTEL-SA-00086
			
		elif major == 4 :
			
			if minor == 0 :
				
				# Adjust SoC Stepping if not from DB
				if sku_stp == 'NaN' :
					if release == 'Production' : sku_stp = 'B' # PRD
					else : sku_stp = 'A' # PRE, BYP
			
				platform = 'GLK'
		
		# Detected stitched PMC firmware
		if pmcp_found :				
			pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmcp_upd_found,pmcp_not_in_db,pmc_platform,pmc_date = pmc_anl(pmc_mn2_ver)
			
			if pmc_mn2_signed != release or pmc_platform != platform or (sku_stp != 'NaN' and pmc_pch_rev != sku_stp) : pmc_not_comp = True
			
		sku_db, upd_found = sku_db_upd_cse('', '', sku_stp, upd_found, True) # Store DB SKU and check Latest version
		
		# Module Extraction for all CSTXE
		if param.me11_mod_extr :
			cse_unpack(fpt_part_all, bpdt_part_all, fw_type, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail)
			continue # Next input file
			
	elif variant == 'SPS' : # Server Platform Services
		
		if major == 1 and not rgn_exist :
			sps1_rec_match = re.compile(br'\x45\x70\x73\x52\x65\x63\x6F\x76\x65\x72\x79').search(reading[start_man_match:]) # EpsRecovery detection
			if sps1_rec_match : fw_type = 'Recovery'
			else : fw_type = 'Operational'
		
		elif major in [2,3] :
			sps_platform = {'GR':'Grantley', 'GP':'Grantley-EP', 'GV':'Grangeville', 'DE':'Denlow', 'BR':'Bromolow', 'RO':'Romley', 'BK':'Brickland'}
			sps_type = (reading[end_man_match + 0x264:end_man_match + 0x266]).decode('utf-8') # FT (Recovery) or OP (Operational)
			
			if sps_type == 'OP' :
				if not rgn_exist : fw_type = 'Operational'
				sku = (reading[end_man_match + 0x266:end_man_match + 0x268]).decode('utf-8') # OPxx (example: OPGR --> Operational Grantley)
				sku_db = sku
				platform = sps_platform[sku] if sku in sps_platform else 'Unknown ' + sku
			
			elif sps_type == 'FT' :
				if not rgn_exist : fw_type = 'Recovery'
				rec_sku_match = re.compile(br'\x52\x32\x4F\x50......\x4F\x50', re.DOTALL).search(reading[start_man_match:start_man_match + 0x2000]) # R2OP.{6}OP detection
				if rec_sku_match :
					(start_rec_sku, end_rec_sku) = rec_sku_match.span()
					sku = (reading[start_man_match + start_rec_sku + 0x8:start_man_match + start_rec_sku + 0xA]).decode('utf-8')
					sku_db = sku
					platform = sps_platform[sku] if sku in sps_platform else 'Unknown ' + sku

	elif variant == 'CSSPS' : # Converged Security Server Platform Services
		
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_err_stor,ext_dnx_val,\
		oem_config,oem_signed,cpd_mn2_info = ext_anl('$MN2', start_man_match, file_end, [variant, major, minor, hotfix, build]) # Detect CSE Attributes
		
		fw_0C_sku0,fw_0C_sku1,fw_0C_lbg,fw_0C_sku2 = ext12_info # SKU Capabilities, SKU Type, HEDT Support, SKU Platform
		
		# Set Recovery or Operational Region Type
		if not rgn_exist :
			# Intel releases OPR as partition ($CPD) but REC as region ($FPT)
			if ext_pname == 'FTPR' : fw_type = 'Recovery' # Non-Intel POR for REC
			elif ext_pname == 'OPR' : fw_type = 'Operational' # Intel POR for OPR
		elif not ifwi_exist and not sps_opr_found :
			fw_type = 'Recovery' # Intel POR for REC ($FPT + FTPR)
			
		sku = '%d' % fw_0C_sku1
		sku_db = ext32_info[1] + '_SKU' + sku
		sku_plat = ext32_info[1]
		platform = cssps_platform[sku_plat] if sku_plat in cssps_platform else 'Unknown'
		
		if major == 4 :
			pass
		
		elif major == 5 :
			
			# Detected stitched PMC firmware
			if pmcp_found :
				pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmcp_upd_found,pmcp_not_in_db,pmc_platform,pmc_date = pmc_anl(pmc_mn2_ver)
				
				# Verify OPR & PMC compatibility
				if pmc_mn2_signed != release or pmc_pch_gen != 300 or pmc_pch_sku != 'H' : pmc_not_comp = True
	
		# Module Extraction for all CSSPS
		if param.me11_mod_extr :
			cse_unpack(fpt_part_all, bpdt_part_all, fw_type, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail)
			continue # Next input file
	
	elif variant.startswith('PMC') : # Power Management Controller
		
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_err_stor,ext_dnx_val,\
		oem_config,oem_signed,cpd_mn2_info = ext_anl('$CPD', 0, file_end, ['NaN', -1, -1, -1, -1]) # Detect CSE Attributes
		
		pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,upd_found,pmcp_not_in_db,pmc_platform,pmc_date = pmc_anl(cpd_mn2_info)
		
		sku = pmc_pch_sku
		sku_stp = pmc_pch_rev[0]
		sku_db = '%s_%s' % (sku, sku_stp)
		platform = pmc_platform
		fw_type = 'Independent'
		
		eng_fw_end = cpd_size_calc(reading, 0, 0x1000) # Get PMC firmware size
		
		# Check PMC firmware size
		if eng_fw_end > file_end :
			eng_size_text = [col_m + 'Warning: PMC %s firmware size exceeds file, possible data loss!' % pmc_platform + col_e, True]
		elif eng_fw_end < file_end :
			padd_size_pmc = file_end - eng_fw_end
			if reading[eng_fw_end:file_end] == padd_size_pmc * b'\xFF' :
				eng_size_text = [col_y + 'Note: File size exceeds PMC %s firmware, unneeded padding!' % pmc_platform + col_e, False] # warn_stor
			else :
				eng_size_text = [col_m + 'Warning: File size exceeds PMC %s firmware, data in padding!' % pmc_platform + col_e, True]
		
		# Module Extraction for PMC
		if param.me11_mod_extr :
			cse_unpack(fpt_part_all, bpdt_part_all, fw_type, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail)
			continue # Next input file
	
	# Partial Firmware Update adjustments
	if pr_man_8 or pr_man_9 :
		wcod_found = True
		fw_type = 'Partial Update'
		del err_stor[:]
	
	# Create Firmware Type DB entry
	fw_type, type_db = fw_types(fw_type)
	
	# Create firmware DB names
	if variant in ['CSSPS','SPS'] and sku != 'NaN' :
		name_db = '%s.%s.%s.%s_%s_%s_%s' % ('{0:02d}'.format(major), '{0:02d}'.format(minor), '{0:02d}'.format(hotfix), '{0:03d}'.format(build), sku_db, rel_db, type_db)
		name_db_extr = '%s.%s.%s.%s_%s_%s_EXTR_%s' % ('{0:02d}'.format(major), '{0:02d}'.format(minor), '{0:02d}'.format(hotfix), '{0:03d}'.format(build), sku_db, rel_db, rsa_sig_hash)
		name_db_rgn = 'N/A'
	elif variant == 'SPS' :
		name_db = '%s.%s.%s.%s_%s_%s' % ('{0:02d}'.format(major), '{0:02d}'.format(minor), '{0:02d}'.format(hotfix), '{0:03d}'.format(build), rel_db, type_db)
		name_db_extr = '%s.%s.%s.%s_%s_EXTR_%s' % ('{0:02d}'.format(major), '{0:02d}'.format(minor), '{0:02d}'.format(hotfix), '{0:03d}'.format(build), rel_db, rsa_sig_hash)
		name_db_rgn = 'N/A'
	elif (variant,major) == ('PMCCNP',300) : # PMC CNP A/B
		name_db = '%s_%s.%s.%s.%s_%s_%s' % (pmc_platform, major, minor, hotfix, build, sku_db, rel_db)
		name_db_rgn,name_db_extr = 'N/A','N/A'
	elif variant.startswith('PMC') : # PMC APL A/B, BXT C, GLK A/B, CNP A
		name_db = '%s_%s.%s.%s.%s_%s_%s_%s' % (pmc_platform, major, minor, hotfix, build, pmc_pch_rev, date, rel_db)
		name_db_rgn,name_db_extr = 'N/A','N/A'
	else : # CS(ME) & (CS)TXE
		name_db = '%s.%s.%s.%s_%s_%s_%s' % (major, minor, hotfix, build, sku_db, rel_db, type_db) # Filename
		name_db_rgn = '%s.%s.%s.%s_%s_%s_RGN_%s' % (major, minor, hotfix, build, sku_db, rel_db, rsa_sig_hash) # Equivalent RGN filename
		name_db_extr = '%s.%s.%s.%s_%s_%s_EXTR_%s' % (major, minor, hotfix, build, sku_db, rel_db, rsa_sig_hash) # Equivalent EXTR filename
		
	name_db_hash = '%s_%s' % (name_db, rsa_sig_hash)
	
	if param.db_print_new :
		with open(os.path.join(mea_dir, 'MEA_DB_NEW.txt'), 'a', encoding = 'utf-8') as db_file : db_file.write(name_db_hash + '\n')
		continue # Next input file
	
	# Search Database for firmware
	if not variant.startswith('PMC') and not wcod_found : # Not PMC or Partial Update
		fw_db = db_open()
		for line in fw_db :
			# Search the re-created file name without extension at the database
			if name_db_hash in line : fw_in_db_found = True # Known firmware, nothing new
			if type_db == 'EXTR' and name_db_rgn in line :
				rgn_over_extr_found = True # Same firmware found but of preferred type (RGN > EXTR), nothing new
				fw_in_db_found = True
			# For ME 6.0 IGN, (CS)ME 7+, (CS)TXE
			if type_db == 'UPD' and ((variant in ['ME','CSME'] and (major >= 7 or
			(major == 6 and 'Ignition' in sku))) or variant in ['TXE','CSTXE']) and (name_db_rgn in line or name_db_extr in line) :
				rgn_over_extr_found = True # Same RGN/EXTR firmware found at database, UPD disregarded
			if type_db in ['REC','OPR'] and name_db_extr in line :
				rgn_over_extr_found = True # Same EXTR found at DB, OPR/REC disregarded
		fw_db.close()
	else :
		can_search_db = False # Do not search DB for PMC or Partial Update
	
	# Check if firmware is updated, Production only
	if release == 'Production' and not wcod_found : # Does not display if firmware is non-Production or Partial Update
		if variant in ['ME','CSME','TXE','CSTXE','PMCCNP'] : # CS(SPS) excluded
			if upd_found : upd_rslt = col_r + 'No' + col_e
			elif not upd_found : upd_rslt = col_g + 'Yes' + col_e
	
	# Rename input file based on the DB structured name
	if param.give_db_name :
		file_name = file_in
		new_dir_name = os.path.join(os.path.dirname(file_in), name_db + '.bin')
		f.close()
		if not os.path.exists(new_dir_name) : os.rename(file_name, new_dir_name)
		elif os.path.basename(file_in) == name_db + '.bin' : pass
		else : print(col_r + 'Error: ' + col_e + 'A file with the same name already exists!')
		
		continue # Next input file
	
	# UEFI Strip Integration (must be after Printed Messages)
	if param.extr_mea :
		if variant == 'CSME' and sku not in ['Consumer H','Consumer LP','Corporate H','Corporate LP','Slim H','Slim LP'] :
			if sku_init == 'Consumer' : sku_db = 'CON_X'
			elif sku_init == 'Corporate' : sku_db = 'COR_X'
			elif sku_init == 'Slim' : sku_db = 'SLM_X'
			else : sku_db = 'UNK_X'
		
		if not fw_in_db_found and not rgn_over_extr_found and not wcod_found :
			if variant not in ['SPS','CSSPS'] : name_db = '%s_%s_%s_%s_%s' % (fw_ver(major,minor,hotfix,build), sku_db, rel_db, type_db, rsa_sig_hash)
			else : name_db = '%s_%s_%s_%s' % (fw_ver(major,minor,hotfix,build), rel_db, type_db, rsa_sig_hash) # No SKU for SPS
			
		if fuj_rgn_exist : name_db = '%s_UMEM' % name_db
		
		print('%s %s %s %s %s' % (variant, name_db, fw_ver(major,minor,hotfix,build), sku_db, date))
		
		mea_exit(0)
	
	# Print MEA Messages
	elif not param.print_msg :
		print()
		msg_pt = ext_table(['Field', 'Value'], False, 1)
		msg_pt.title = col_c + '%s (%d/%d)' % (textwrap.wrap(os.path.basename(file_in), width=45)[0], cur_count, in_count) + col_e
		
		msg_pt.add_row(['Firmware Family', variant_p])
		msg_pt.add_row(['Firmware Version', fw_ver(major,minor,hotfix,build)])
		msg_pt.add_row(['Firmware Release', release])
		msg_pt.add_row(['Firmware Type', fw_type])
		
		if (variant == 'CSTXE' and 'Unknown' not in sku) or ((variant,sku) == ('SPS','NaN')) or (variant.startswith('PMC')
		and variant != 'PMCCNP') or wcod_found :
			pass
		else :
			msg_pt.add_row(['Firmware SKU', sku])
		
		if (variant in ('CSME','CSTXE') or variant.startswith('PMC')) and not wcod_found :
			if sku_stp != 'NaN' : msg_pt.add_row(['Chipset Stepping', sku_stp])
			else : msg_pt.add_row(['Chipset Stepping', 'Unknown'])
		
		if ((variant in ['ME','CSME'] and major >= 8) or variant in ['TXE','CSTXE','CSSPS']) and not wcod_found :
			msg_pt.add_row(['Security Version Number', svn])
			msg_pt.add_row(['Version Control Number', vcn])
		
		if [variant,major,wcod_found] == ['CSME',11,False] :
			if pdm_status != 'NaN' : msg_pt.add_row(['Power Down Mitigation', pdm_status])
			msg_pt.add_row(['Lewisburg PCH Support', ['No','Yes'][fw_0C_lbg]])
		
		if variant == 'ME' and major == 7 : msg_pt.add_row(['Patsburg PCH Support', ['No','Yes'][is_patsburg]])
		
		if pvbit in [0,1] and wcod_found is False : msg_pt.add_row(['Production Version', ['No','Yes'][pvbit]])
		
		if pmcp_found :
			msg_pt.add_row(['PMC Version', pmc_fw_ver])
			msg_pt.add_row(['PMC Release', pmc_mn2_signed])
			if variant == 'PMCCNP' or (variant == 'CSME' and major >= 12) or (variant == 'CSSPS' and major >= 5) :
				msg_pt.add_row(['PMC SKU', pmc_pch_sku])
			msg_pt.add_row(['PMC Stepping', pmc_pch_rev[0]])
			msg_pt.add_row(['PMC Date', pmc_date])
			if pmc_mn2_signed == 'Production' and (variant == 'CSME' and major >= 12) :
				msg_pt.add_row(['PMC Latest', [col_g + 'Yes' + col_e, col_r + 'No' + col_e][pmcp_upd_found]])
		
		if ((variant == 'CSME' and major >= 12) or (variant == 'CSTXE' and major >= 3)) and not wcod_found :
			msg_pt.add_row(['OEM Configuration', ['No','Yes'][int(oem_config)]])
			msg_pt.add_row(['OEM RSA Signature', ['No','Yes'][int(oem_signed or oemp_found)]])
			
		if (rgn_exist or ifwi_exist) and variant in ('CSME','CSTXE','CSSPS','TXE') : msg_pt.add_row(['OEM Unlock Token', ['No','Yes'][int(utok_found)]])
		
		if variant == 'CSME' and major >= 12 and not wcod_found : msg_pt.add_row(['FWUpdate Support', ['No','Yes'][int(pmcp_fwu_found)]])
		
		msg_pt.add_row(['Firmware Date', date])

		if rgn_exist or variant.startswith('PMC') :
			if (variant,major,release) == ('ME',6,'ROM-Bypass') : msg_pt.add_row(['Firmware Size', 'Unknown'])
			elif (variant,fd_devexp_rgn_exist) == ('CSTXE',True) : pass
			else : msg_pt.add_row(['Firmware Size', '0x%X' % eng_fw_end])
		
		if fitc_ver_found :
			msg_pt.add_row(['Flash Image Tool', fw_ver(fitc_major,fitc_minor,fitc_hotfix,fitc_build)])
		
		if (variant,major) == ('ME',7) :
			msg_pt.add_row(['Downgrade Blacklist 7.0', me7_blist_1])
			msg_pt.add_row(['Downgrade Blacklist 7.1', me7_blist_2])
		
		if platform != 'NaN' : msg_pt.add_row(['Chipset Support', platform])
		
		if variant not in ['SPS','CSSPS'] and upd_rslt != '' : msg_pt.add_row(['Firmware Latest', upd_rslt])
		
		print(msg_pt)
		
	# General MEA Messages (must be Errors > Warnings > Notes)
	if not var_rsa_db : gen_msg(err_stor, col_r + 'Error: Unknown RSA Public Key! *' + col_e, '', True)
	
	if rec_missing and fw_type != 'Partial Update' : gen_msg(err_stor, col_r + 'Error: Recovery missing, Manifest not found! *' + col_e, '', True)
	
	if not man_valid[0] : gen_msg(err_stor, col_r + 'Error: Invalid RSA Signature! *' + col_e, '', True)
	
	for fpt_error in err_fpt_stor : print('\n%s' % fpt_error)
	
	for ext_error in ext_err_stor : print('\n%s' % ext_error)
	
	if eng_size_text != ['', False] : gen_msg(warn_stor, '%s' % eng_size_text[0], '', eng_size_text[1])
	
	if fpt_chk_fail : gen_msg(warn_stor, col_m + 'Warning: Wrong $FPT Checksum %s, expected %s!' % (fpt_chk_file,fpt_chk_calc) + col_e, '', True)
	
	if sps3_chk_fail : gen_msg(warn_stor, col_m + 'Warning: Wrong $FPT SPS3 Checksum %s, expected %s!' % (sps3_chk16_file,sps3_chk16_calc) + col_e, '', True)
	
	if fpt_num_fail : gen_msg(warn_stor, col_m + 'Warning: Wrong $FPT entry count %s, expected %s!' % (fpt_num_file,fpt_num_calc) + col_e, '', True)
	
	if pmc_not_comp : gen_msg(warn_stor, col_m + 'Warning: Incompatible PMC %s firmware detected!' % pmc_platform + col_e, '', True)
	
	if fuj_rgn_exist : gen_msg(warn_stor, col_m + 'Warning: Fujitsu Intel Engine firmware detected!' + col_e, '', False)
	
	if fpt_count > 1 : gen_msg(note_stor, col_y + 'Note: Multiple (%d) Intel Engine firmware detected in file!' % fpt_count + col_e, '', True)
	
	if fd_count > 1 : gen_msg(note_stor, col_y + 'Note: Multiple (%d) Intel Flash Descriptors detected in file!' % fd_count + col_e, '', True)
	
	if can_search_db and not rgn_over_extr_found and not fw_in_db_found : gen_msg(note_stor, col_g + 'Note: This %s firmware was not found at the database, please report it!' % variant_p + col_e, '', True)
	
	if pmcp_not_in_db : gen_msg(note_stor, col_g + 'Note: This PMC %s firmware was not found at the database, please report it!' % pmc_platform + col_e, '', True)
	
	# Print Error/Warning/Note Messages
	if param.print_msg : msg_rep(name_db)
	
	if not param.extr_mea : copy_on_msg() # Close input and copy it in case of messages
		
	if param.help_scr : mea_exit(0) # Only once for -?
	
mea_exit(0)
