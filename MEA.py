#!/usr/bin/env python3
#coding=utf-8

"""
ME Analyzer
Intel Engine & Graphics Firmware Analysis Tool
Copyright (C) 2014-2022 Plato Mavropoulos
"""

title = 'ME Analyzer v1.273.1'

import sys

# Detect Python version
sys_py = sys.version_info
if sys_py < (3,7) :
	sys.stdout.write('%s\n\nError: Python >= 3.7 required, not %d.%d!\n' % (title, sys_py[0], sys_py[1]))
	if '-exit' not in sys.argv : (raw_input if sys_py[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
	sys.exit(1)

# Detect OS platform
sys_os = sys.platform
if sys_os == 'win32' :
	cl_wipe = 'cls'
	sys.stdout.reconfigure(encoding='utf-8') # Fix Windows Unicode console redirection
elif sys_os.startswith('linux') or sys_os == 'darwin' or sys_os.find('bsd') != -1 :
	cl_wipe = 'clear'
else :
	print('%s\n\nError: Unsupported platform "%s"!\n' % (title, sys_os))
	if '-exit' not in sys.argv : input('Press enter to exit')
	sys.exit(1)

import os
import re
import lzma
import json
import struct
import ctypes
import shutil
import hashlib
import inspect
import threading
import itertools
import traceback
import subprocess
import urllib.request
import importlib.util

# Check code dependency installation
for depend in ['colorama','crccheck','pltable'] :
	if not importlib.util.find_spec(depend) :
		print('%s\n\nError: Dependency "%s" is missing!\n       Install via "pip3 install %s"\n' % (title, depend, depend))
		if '-exit' not in sys.argv : input('Press enter to exit')
		sys.exit(1)

import pltable
import colorama
import crccheck

# Initialize and setup Colorama
colorama.init()
col_r = colorama.Fore.RED + colorama.Style.BRIGHT
col_c = colorama.Fore.CYAN + colorama.Style.BRIGHT
col_b = colorama.Fore.BLUE + colorama.Style.BRIGHT
col_g = colorama.Fore.GREEN + colorama.Style.BRIGHT
col_y = colorama.Fore.YELLOW + colorama.Style.BRIGHT
col_m = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
col_e = colorama.Fore.RESET + colorama.Style.RESET_ALL

# Set ctypes Structure types
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

# Print MEA Help screen
def mea_help() :
	print(
		  '\nUsage: MEA [FilePath] {Options}\n\n{Options}\n\n'
		  '-?     : Displays help & usage screen\n'
		  '-skip  : Skips welcome & options screen\n'
		  '-exit  : Skips Press enter to exit prompt\n'
		  '-mass  : Scans all files of a given directory\n'
		  '-pdb   : Writes unique input file DB name to file\n'
		  '-dbn   : Renames input file based on unique DB name\n'
		  '-duc   : Disables automatic check for MEA & DB updates\n'
		  '-dfpt  : Shows FPT, BPDT, OROM & CSE/GSC Layout Table info\n'
		  '-unp86 : Unpacks all supported CSE, GSC and/or IUP firmware\n'
		  '-bug86 : Enables pause on error during CSE/GSC/IUP unpacking\n'
		  '-ver86 : Enables verbose output during CSE/GSC/IUP unpacking\n'
		  '-html  : Writes parsable HTML info files during MEA operation\n'
		  '-json  : Writes parsable JSON info files during MEA operation'
		  )
	
	print(col_g + '\nCopyright (C) 2014-2022 Plato Mavropoulos' + col_e)
	
	if getattr(sys, 'frozen', False) : print(col_c + '\nIcon by Those Icons (thoseicons.com, CC BY 3.0)' + col_e)
	
	mea_exit(0)

# Process MEA Parameters
class MEA_Param :

	def __init__(self, source) :
	
		self.val = ['-?','-skip','-unp86','-ver86','-bug86','-html','-json','-pdb','-dbn',
					'-mass','-dfpt','-exit','-ftbl','-rcfg','-chk','-byp','-duc']
		
		self.help_scr = False
		self.skip_intro = False
		self.cse_unpack = False
		self.cse_verbose = False
		self.cse_pause = False
		self.fpt_disp = False
		self.db_print_new = False
		self.give_db_name = False
		self.mass_scan = False
		self.skip_pause = False
		self.write_html = False
		self.write_json = False
		self.mfs_ftbl = False
		self.mfs_rcfg = False
		self.check = False
		self.bypass = False
		self.upd_dis = False
		
		if '-?' in source : self.help_scr = True
		if '-skip' in source : self.skip_intro = True
		if '-unp86' in source : self.cse_unpack = True
		if '-ver86' in source : self.cse_verbose = True
		if '-bug86' in source : self.cse_pause = True
		if '-pdb' in source : self.db_print_new = True
		if '-dbn' in source : self.give_db_name = True
		if '-mass' in source : self.mass_scan = True
		if '-dfpt' in source : self.fpt_disp = True
		if '-exit' in source : self.skip_pause = True
		if '-html' in source : self.write_html = True
		if '-json' in source : self.write_json = True
		if '-ftbl' in source : self.mfs_ftbl = True # Hidden
		if '-rcfg' in source : self.mfs_rcfg = True # Hidden
		if '-chk' in source : self.check = True # Hidden
		if '-byp' in source : self.bypass = True # Hidden
		if '-duc' in source : self.upd_dis = True
			
		if self.mass_scan or self.db_print_new : self.skip_intro = True

# https://stackoverflow.com/a/65447493 by Shail-Shouryya
class Thread_With_Result(threading.Thread) :
	def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None) :
		self.result = None
		if kwargs is None : kwargs = {}

		def function() :
			self.result = target(*args, **kwargs)

		super().__init__(group=group, target=function, name=name, daemon=daemon)
		
# Engine/Graphics/Independent Structures
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
		pt.add_row(['Instruction 0', 'N/A' if self.ROMB_Instr_0 in NA else '0x%0.8X' % self.ROMB_Instr_0])
		pt.add_row(['Instruction 1', 'N/A' if self.ROMB_Instr_1 in NA else '0x%0.8X' % self.ROMB_Instr_1])
		pt.add_row(['Instruction 2', 'N/A' if self.ROMB_Instr_2 in NA else '0x%0.8X' % self.ROMB_Instr_2])
		pt.add_row(['Instruction 3', 'N/A' if self.ROMB_Instr_3 in NA else '0x%0.8X' % self.ROMB_Instr_3])
		
		return pt

class FPT_Header(ctypes.LittleEndianStructure) : # Flash Partition Table v1.0 & v2.0 (FPT_HEADER)
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
		pt.add_row(['Flash Layout', 'N/A' if self.Flags == NA else sector_types[self.Flags]])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		
		return pt
		
class FPT_Header_21(ctypes.LittleEndianStructure) : # Flash Partition Table v2.1 (FPT_HEADER)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('NumPartitions',	uint32_t),		# 0x04
		('HeaderVersion',	uint8_t),		# 0x08 21
		('EntryVersion',	uint8_t),		# 0x09
		('HeaderLength',	uint8_t),		# 0x0A
		('Flags',			uint8_t),		# 0x0B 0 $FPT Redundancy, 1-7 Reserved
		('TicksToAdd',		uint16_t),		# 0x0C
		('TokensToAdd',		uint16_t),		# 0x0E
		('SPSFlags',		uint32_t),		# 0x10 Unknown/Unused
		('HeaderChecksum',	uint32_t),		# 0x14 CRC-32 (Header + Entries, Checksum = 0)
		('FitMajor',		uint16_t),		# 0x18
		('FitMinor',		uint16_t),		# 0x1A
		('FitHotfix',		uint16_t),		# 0x1C
		('FitBuild',		uint16_t),		# 0x1E
		# 0x20
	]
	
	# When $FPT Redundancy is set, a backup of $FPT is kept at 0x1000
	
	def hdr_print_cse(self) :
		f1,f2 = self.get_flags()
		
		fit_ver = '%d.%d.%d.%d' % (self.FitMajor,self.FitMinor,self.FitHotfix,self.FitBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table 2.1 Header' + col_e
		pt.add_row(['Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Partition Count', '%d' % self.NumPartitions])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['Entry Version', '0x%X' % self.EntryVersion])
		pt.add_row(['Header Size', '0x%X' % self.HeaderLength])
		pt.add_row(['FPT Redundancy', ['No','Yes'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Ticks To Add', '0x%X' % self.TicksToAdd])
		pt.add_row(['Tokens To Add', '0x%X' % self.TokensToAdd])
		pt.add_row(['SPS Flags', '0x%X' % self.SPSFlags])
		pt.add_row(['Checksum', '0x%X' % self.HeaderChecksum])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		
		return pt
		
	def get_flags(self) :
		flags = FPT_Header_21_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.Redundancy, flags.b.Reserved

class FPT_Header_21_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('Redundancy', uint8_t, 1),
		('Reserved', uint8_t, 7),
	]

class FPT_Header_21_GetFlags(ctypes.Union):
	_fields_ = [
		('b', FPT_Header_21_Flags),
		('asbytes', uint8_t)
	]

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
		f1,f2,f3,f4,f5,f6,f7 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table Entry' + col_e
		pt.add_row(['Name', '%s' % self.Name.decode('utf-8')])
		pt.add_row(['Reserved 0', '0x%X' % int.from_bytes(self.Owner, 'little')])
		pt.add_row(['Offset', '0x%X' % self.Offset])
		pt.add_row(['Reserved 1', '0x%X' % self.StartTokens])
		pt.add_row(['Reserved 2', '0x%X' % self.MaxTokens])
		pt.add_row(['Reserved 3', '0x%X' % self.ScratchSectors])
		pt.add_row(['Type', ['Code','Data'][f1]])
		pt.add_row(['Copy To DRAM Cache', ['No','Yes'][f2]])
		pt.add_row(['Reserved 4', '0x%X' % f3])
		pt.add_row(['Built With Length 1', '0x%X' % f4])
		pt.add_row(['Built With Length 2', '0x%X' % f5])
		pt.add_row(['Reserved 5', '0x%X' % f6])
		pt.add_row(['Entry Valid', 'No' if f7 == 0xFF else 'Yes'])
		
		return pt
	
	def get_flags(self) :
		flags = FPT_Entry_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.Type, flags.b.CopyToDramCache, flags.b.Reserved0, flags.b.BuiltWithLength1, flags.b.BuiltWithLength2, \
			   flags.b.Reserved1, flags.b.EntryValid

class FPT_Entry_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('Type', uint32_t, 7), # (PARTITION_TYPES)
		('CopyToDramCache', uint32_t, 1), # Partition should be copied to persistent DRAM cache
		('Reserved0', uint32_t, 7),
		('BuiltWithLength1', uint32_t, 1), # Indication to Flash Building Tool
		('BuiltWithLength2', uint32_t, 1), # Indication to Flash Building Tool
		('Reserved1', uint32_t, 7),
		('EntryValid', uint32_t, 8)
	]

class FPT_Entry_GetFlags(ctypes.Union):
	_fields_ = [
		('b', FPT_Entry_Flags),
		('asbytes', uint32_t)
	]
	
class GSC_Info_FWI(ctypes.LittleEndianStructure) : # GSC Firmware Image Info (igsc_system.h > gsc_fwu_fw_image_data)
	_pack_ = 1
	_fields_ = [
		('Project',			char*4),		# 0x00 (gsc_fwu_external_version)
		('Hotfix',			uint16_t),		# 0x04
		('Build',			uint16_t),		# 0x06
		('GSCMajor',		uint16_t),		# 0x08
		('GSCMinor',		uint16_t),		# 0x0A
		('GSCHotfix',		uint16_t),		# 0x0C
		('GSCBuild',		uint16_t),		# 0x0E
		('Flags',			uint16_t),		# 0x10 Unknown
		('FWType',			uint8_t),		# 0x12
		('FWSKU',			uint8_t),		# 0x13
		('ARBSVN',			uint32_t),		# 0x14
		('TCBSVN',			uint32_t),		# 0x18
		('VCN',				uint32_t),		# 0x1C
		# 0x20
	]
	
	# FWType & FWSKU are also used by CSE_Ext_0F_R2 & CSE_Ext_23, remember to change them as well!
	
	def get_flags(self) :
		fw_type = CSE_Ext_0F_R2_GetFWType()
		fw_type.asbytes = self.FWType
		fw_sub_type = CSE_Ext_0F_R2_GetFWSKU()
		fw_sub_type.asbytes = self.FWSKU
		
		return fw_type.b.FWType, fw_type.b.Reserved, fw_sub_type.b.FWSKU, fw_sub_type.b.Reserved
	
	def gsc_print(self) :
		f1,f2,f3,f4 = self.get_flags()
		
		gsc_ver = '%d.%d.%d.%d' % (self.GSCMajor,self.GSCMinor,self.GSCHotfix,self.GSCBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'GSC Firmware Image Info' + col_e
		pt.add_row(['Project Name', self.Project.decode('utf-8')])
		pt.add_row(['Project Hotfix', self.Hotfix])
		pt.add_row(['Project Build', self.Build])
		pt.add_row(['Version', 'N/A' if self.GSCMajor in [0,0xFFFF] else gsc_ver])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		pt.add_row(['Type', ext15_fw_type[f1] if f1 in ext15_fw_type else 'Unknown (%d)' % f1])
		pt.add_row(['Type Reserved', '0x%X' % f2])
		pt.add_row(['SKU', ext15_fw_sku[f3][0] if f3 in ext15_fw_sku else 'Unknown (%d)' % f3])
		pt.add_row(['SKU Reserved', '0x%X' % f4])
		pt.add_row(['ARB SVN', self.ARBSVN])
		pt.add_row(['TCB SVN', self.TCBSVN])
		pt.add_row(['VCN', self.VCN])
		
		return pt
		
class GSC_Info_IUP(ctypes.LittleEndianStructure) : # GSC Independent Update Partition Info (igsc_system.h > gsc_fwu_iup_data)
	_pack_ = 1
	_fields_ = [
		('Name',			char*4),		# 0x00
		('Flags',			uint16_t),		# 0x04 Unknown
		('Reserved',		uint16_t),		# 0x06
		('SVN',				uint32_t),		# 0x08
		('VCN',				uint32_t),		# 0x0C
		# 0x10
	]
	
	def gsc_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'GSC Independent Update Partition Info' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['SVN', self.SVN])
		pt.add_row(['VCN', self.VCN])
		
		return pt
		
class GSC_OROM_Header(ctypes.LittleEndianStructure) : # GSC Option ROM Image Header (igsc_oprom.h > oprom_header_ext_v2)
	_pack_ = 1
	_fields_ = [
		('Signature',		uint16_t),		# 0x00 AA55
		('ImageSize',		uint16_t),		# 0x02 Multiple of 512, includes Headers
		('InitFuncEntrPnt',	uint32_t),		# 0x04
		('SubSystem',		uint16_t),		# 0x08
		('MachineType',		uint16_t),		# 0x0A
		('CompressionType',	uint16_t),		# 0x0C
		('Reserved',		uint64_t),		# 0x0E
		('EFIImageOffset',	uint16_t),		# 0x16
		('PCIDataHdrOff',	uint16_t),		# 0x18
		('OROMPayloadOff',	uint16_t),		# 0x1A
		# 0x1C
	]
	
	def gsc_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'GSC Option ROM Image Header' + col_e
		pt.add_row(['Signature', '%0.4X' % self.Signature])
		pt.add_row(['Image Size', '0x%X' % (self.ImageSize * 512)])
		pt.add_row(['Init Function Entry Point', '0x%X' % self.InitFuncEntrPnt])
		pt.add_row(['Sub System', '0x%X' % self.SubSystem])
		pt.add_row(['Machine Type', '0x%X' % self.MachineType])
		pt.add_row(['Compression Type', '0x%X' % self.CompressionType])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['EFI Image Offset', '0x%X' % self.EFIImageOffset])
		pt.add_row(['PCI Data Header Offset', '0x%X' % self.PCIDataHdrOff])
		pt.add_row(['OROM Payload Offset', '0x%X' % self.OROMPayloadOff])
		
		return pt
		
class GSC_OROM_PCI_Data(ctypes.LittleEndianStructure) : # GSC Option ROM Image Data Header (igsc_oprom.h > oprom_pci_data)
	_pack_ = 1
	_fields_ = [
		('Signature',		char*4),		# 0x00 PCIR
		('VEN_ID',			uint16_t),		# 0x04
		('DEV_ID',			uint16_t),		# 0x06
		('DevListPointer',	uint16_t),		# 0x08
		('PCIDataHdrLen',	uint16_t),		# 0x0A
		('PCIDataHdrRev',	uint8_t),		# 0x0C
		('ClassCode',		uint8_t*3),		# 0x0D
		('ImageSize',		uint16_t),		# 0x10 Multiple of 512, includes Headers
		('RevisionLevel',	uint16_t),		# 0x12
		('CodeType',		uint8_t),		# 0x14
		('LastImageMark',	uint8_t),		# 0x15
		('MaxRuntimeImgLen',uint16_t),		# 0x16
		('ConfUtlCodHdrPtr',uint16_t),		# 0x18 Config Utility Code Header Pointer
		('DMTFCLPEntPntPtr',uint16_t),		# 0x1A DMTF CLP Entry Point Pointer
		# 0x1C
	]
	
	def gsc_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'GSC Option ROM Image Data' + col_e
		pt.add_row(['Signature', self.Signature.decode('utf-8')])
		pt.add_row(['Vendor ID', '%0.4X' % self.VEN_ID])
		pt.add_row(['Device ID', '%0.4X' % self.DEV_ID])
		pt.add_row(['Device List Pointer', '0x%X' % self.DevListPointer])
		pt.add_row(['Header Size', '0x%X' % self.PCIDataHdrLen])
		pt.add_row(['Header Revision', self.PCIDataHdrRev])
		pt.add_row(['Class Code', '0x%X' % int.from_bytes(self.ClassCode, 'little')])
		pt.add_row(['Image Size', '0x%X' % (self.ImageSize * 512)])
		pt.add_row(['Revision Level', '0x%X' % self.RevisionLevel])
		pt.add_row(['Code Type', pcir_code_types[self.CodeType] if self.CodeType in pcir_code_types else 'Unknown (0x%X)' % self.CodeType])
		pt.add_row(['Last Image', ['No','Yes'][self.LastImageMark >> 7]])
		pt.add_row(['Maximum Runtime Image Size', '0x%X' % self.MaxRuntimeImgLen])
		pt.add_row(['Config Utility Code Header Pointer', '0x%X' % self.ConfUtlCodHdrPtr])
		pt.add_row(['DMTF CLP Entry Point Pointer', '0x%X' % self.DMTFCLPEntPntPtr])
		
		return pt

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
		('BP4Offset',		uint32_t),		# 0x30
		('BP4Size',			uint32_t),		# 0x34
		('BP5Offset',		uint32_t),		# 0x38
		('BP5Size',			uint32_t),		# 0x3C
		('Checksum',		uint64_t),		# 0x40 2's complement of CSE Layout Table (w/o ROMB), sum of the CSE LT + Checksum = 0
		# 0x48
	]
	
	def hdr_print(self) :
		NA = [0,0xFFFFFFFF] # Non-ROMB or IFWI EXTR
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'CSE Layout Table 1.6 & 2.0' + col_e
		pt.add_row(['ROMB Instruction 0', 'N/A' if self.ROMBInstr0 in NA else '0x%0.8X' % self.ROMBInstr0])
		pt.add_row(['ROMB Instruction 1', 'N/A' if self.ROMBInstr1 in NA else '0x%0.8X' % self.ROMBInstr1])
		pt.add_row(['ROMB Instruction 2', 'N/A' if self.ROMBInstr2 in NA else '0x%0.8X' % self.ROMBInstr2])
		pt.add_row(['ROMB Instruction 3', 'N/A' if self.ROMBInstr3 in NA else '0x%0.8X' % self.ROMBInstr3])
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
		('Size',			uint16_t),		# 0x10 0x40 w/o ELOG, 0x48 w/ ELOG
		('Flags',			uint8_t),		# 0x12 0 CSE Redundancy, 1-7 Reserved
		('Reserved',		uint8_t),		# 0x13
		('Checksum',		uint32_t),		# 0x14 CRC-32 of CSE LT pointers w/o ROMB (DataOffset - TempPagesSize, Checksum = 0)
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
		('ELogOffset',		uint32_t),		# 0x50 External Fatal Error Log
		('ELogSize',		uint32_t),		# 0x54
		# 0x58
	]
	
	# When CSE Redundancy is set, a backup of BP1 is stored in (the otherwise empty) BP2
	
	def hdr_print(self) :
		f1,f2 = self.get_flags()
		NA = [0,0xFFFFFFFF] # Non-ROMB or IFWI EXTR
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'CSE Layout Table 1.7' + col_e
		pt.add_row(['ROMB Instruction 0', 'N/A' if self.ROMBInstr0 in NA else '0x%0.8X' % self.ROMBInstr0])
		pt.add_row(['ROMB Instruction 1', 'N/A' if self.ROMBInstr1 in NA else '0x%0.8X' % self.ROMBInstr1])
		pt.add_row(['ROMB Instruction 2', 'N/A' if self.ROMBInstr2 in NA else '0x%0.8X' % self.ROMBInstr2])
		pt.add_row(['ROMB Instruction 3', 'N/A' if self.ROMBInstr3 in NA else '0x%0.8X' % self.ROMBInstr3])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['CSE Redundancy', ['No','Yes'][f1]])
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
		if self.Size >= 0x48 : pt.add_row(['External Fatal Error Log Offset', '0x%X' % self.ELogOffset])
		if self.Size >= 0x48 : pt.add_row(['External Fatal Error Log Size', '0x%X' % self.ELogSize])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Layout_Table_17_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.Redundancy, flags.b.Reserved
		
class CSE_Layout_Table_17_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('Redundancy', uint8_t, 1),
		('Reserved', uint8_t, 7),
	]

class CSE_Layout_Table_17_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Layout_Table_17_Flags),
		('asbytes', uint8_t)
	]
	
class BPDT_Header_1(ctypes.LittleEndianStructure) : # Boot Partition Descriptor Table 1.6 & 2.0 (PrimaryBootPartition, SecondaryBootPartition, PrimaryBootPartitionNC, BootPartitionLayout)
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00 AA550000 Boot/Green, AA55AA00 Recovery/Yellow
		('DescCount',		uint16_t),		# 0x04 Minimum 6 Entries
		('BPDTVersion',		uint16_t),		# 0x06 1 IFWI 1.6 & 2.0, 2 IFWI 1.7
		('Reserved',		uint16_t),		# 0x08
		('Checksum',		uint16_t),		# 0x0A
		('IFWIVersion',		uint32_t),		# 0x0C Unique mark from build server
		('FitMajor',		uint16_t),		# 0x10
		('FitMinor',		uint16_t),		# 0x12
		('FitHotfix',		uint16_t),		# 0x14
		('FitBuild',		uint16_t),		# 0x16
		# 0x18 (0x200 <= Header + Entries <= 0x1000)
	]
	
	# Used at IFWI 1.6 & 2.0 platforms
	
	# XOR Checksum of the redundant block (from the beginning of the BPDT structure, up to and including the S-BPDT) such that
	# the XOR Checksum of the redundant block including Checksum field is 0. If no redundancy is supported, Checksum field is 0
	
	# https://github.com/coreboot/coreboot/blob/master/util/cbfstool/ifwitool.c by coreboot
	
	# Remember to also update bpdt_match
	
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
		('Signature',		uint32_t),		# 0x00 AA550000 Boot/Green, AA55AA00 Recovery/Yellow
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
	
	# Used at IFWI 1.7 platform
	
	# Remember to also update bpdt_match
	
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
		("Type",			uint16_t),		# 0x00 dword at non-APL IFWI 1.6, 1.7 & 2.0
		("Flags",			uint16_t),		# 0x02 only at APL IFWI 2.0
		("Offset",			uint32_t),		# 0x04
		("Size",			uint32_t),		# 0x08
		# 0xC
	]
	
	# It is probable that Flags field is relevant to APL IFWI 2.0 platform only
	# At the rest of IFWI 1.6, 2.0 & 1.7, Type is uint32_t without Flags
	
	def hdr_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Boot Partition Descriptor Table Entry' + col_e
		pt.add_row(['Type', bpdt_dict[self.Type] if self.Type in bpdt_dict else 'Unknown'])
		pt.add_row(['Split Sub-Partition 1st Part', fvalue[f1]])
		pt.add_row(['Split Sub-Partition 2nd Part', fvalue[f2]])
		pt.add_row(['Code Sub-Partition', fvalue[f3]])
		pt.add_row(['UMA Cacheable', fvalue[f4]])
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

class MN2_Manifest_R0(ctypes.LittleEndianStructure) : # Manifest $MAN/$MN2 Pre-CSE R0 (MANIFEST_HEADER)
	_pack_ = 1
	_fields_ = [
		("HeaderType",		uint32_t),		# 0x00
		("HeaderLength",	uint32_t),		# 0x04 dwords
		("HeaderVersion",	uint32_t),		# 0x08 0x10000
		("Flags",			uint32_t),		# 0x0C
		("VEN_ID",			uint32_t),		# 0x10 0x8086
		("Day",				uint8_t),		# 0x14
		("Month",			uint8_t),		# 0x15
		("Year",			uint16_t),		# 0x16
		("Size",			uint32_t),		# 0x18 dwords (0x2000 max)
		("Tag",				char*4),		# 0x1C
		("NumModules",		uint32_t),		# 0x20
		("Major",			uint16_t),		# 0x24
		("Minor",			uint16_t),		# 0x26
		("Hotfix",			uint16_t),		# 0x28
		("Build",			uint16_t),		# 0x2A
		("SVN",				uint32_t),		# 0x2C ME9+ (LSByte derives keys)
		("SVN_8",			uint32_t),		# 0x30 ME8
		("VCN",				uint32_t),		# 0x34 ME8-10
		("Reserved",		uint32_t*16),	# 0x38
		("PublicKeySize",	uint32_t),		# 0x78 dwords
		("ExponentSize",	uint32_t),		# 0x7C dwords
		("RSAPublicKey",	uint32_t*64),	# 0x80
		("RSAExponent",		uint32_t),		# 0x180
		("RSASignature",	uint32_t*64),	# 0x184 2048-bit (PKCS #1 v1.5)
		# 0x284
	]
	
	def get_flags(self) :
		flags = MN2_Manifest_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.PVBit, flags.b.Reserved, flags.b.PIDBound, flags.b.IntelOwned, flags.b.DebugSigned
	
	@staticmethod
	def hdr_print_cse() :
		pass # Placeholder for test ext_anl calls
	
class MN2_Manifest_R1(ctypes.LittleEndianStructure) : # Manifest $MN2 CSE R1 (MANIFEST_HEADER)
	_pack_ = 1
	_fields_ = [
		('HeaderType',		uint16_t),		# 0x00
		('HeaderSubType',	uint16_t),		# 0x02
		('HeaderLength',	uint32_t),		# 0x04 dwords
		('HeaderVersion',	uint32_t),		# 0x08 0x10000
		('Flags',			uint32_t),		# 0x0C
		('VEN_ID',			uint32_t),		# 0x10 0x8086
		('Day',				uint8_t),		# 0x14
		('Month',			uint8_t),		# 0x15
		('Year',			uint16_t),		# 0x16
		('Size',			uint32_t),		# 0x18 dwords (0x2000 max)
		('Tag',				char*4),		# 0x1C
		('BuildTag',		uint32_t),		# 0x20 Internal Info of FTPR > kernel or IGMF
		('Major',			uint16_t),		# 0x24
		('Minor',			uint16_t),		# 0x26
		('Hotfix',			uint16_t),		# 0x28
		('Build',			uint16_t),		# 0x2A
		('SVN',				uint32_t),		# 0x2C LS Byte derives keys
		('MEU_Major',		uint16_t),		# 0x30
		('MEU_Minor',		uint16_t),		# 0x32
		('MEU_Hotfix',		uint16_t),		# 0x34
		('MEU_Build',		uint16_t),		# 0x36
		('MEU_Man_Ver',		uint16_t),		# 0x38
		('MEU_Man_Res',		uint16_t),		# 0x3A
		('GeneralData',		uint32_t),		# 0x3C General Data of RBE
		('IPSpecific0',		uint32_t),		# 0x40 IP Specific Data
		('IPSpecific1',		uint32_t),		# 0x44
		('IPSpecific2',		uint32_t),		# 0x48
		('IPSpecific3',		uint32_t),		# 0x4C
		('IPSpecific4',		uint32_t),		# 0x50
		('IPSpecific5',		uint32_t),		# 0x54
		('Reserved',		uint32_t*8),	# 0x58
		('PublicKeySize',	uint32_t),		# 0x78 dwords
		('ExponentSize',	uint32_t),		# 0x7C dwords
		('RSAPublicKey',	uint32_t*64),	# 0x80
		('RSAExponent',		uint32_t),		# 0x180
		('RSASignature',	uint32_t*64),	# 0x184 2048-bit (PKCS #1 v1.5)
		# 0x284
	]
	
	def hdr_print_cse(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		version = '%d.%d.%d.%d' % (self.Major,self.Minor,self.Hotfix,self.Build)
		meu_version = '%d.%d.%d.%d' % (self.MEU_Major,self.MEU_Minor,self.MEU_Hotfix,self.MEU_Build)
		
		PublicKeySize = self.PublicKeySize * 4
		RSAPublicKey = '%0.*X' % (PublicKeySize * 2, int.from_bytes(self.RSAPublicKey, 'little'))
		RSASignature = '%0.*X' % (PublicKeySize * 2, int.from_bytes(self.RSASignature, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Manifest Header' + col_e
		pt.add_row(['Header Type', '%d' % self.HeaderType])
		pt.add_row(['Header Sub Type', '%d' % self.HeaderSubType])
		pt.add_row(['Header Size', '0x%X' % (self.HeaderLength * 4)])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['Production Ready', fvalue[f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['PID Bound', fvalue[f3]])
		pt.add_row(['Intel Owned', fvalue[f4]])
		pt.add_row(['Debug Signed', fvalue[f5]])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year,self.Month,self.Day)])
		pt.add_row(['Manifest Size', '0x%X' % (self.Size * 4)])
		pt.add_row(['Manifest Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Unique Build Tag', '0x%X' % self.BuildTag])
		pt.add_row(['Version', 'N/A' if self.Major in [0,0xFFFF] else version])
		pt.add_row(['TCB Security Version Number', '%d' % self.SVN])
		pt.add_row(['MEU Version', 'N/A' if self.MEU_Major in [0,0xFFFF] else meu_version])
		pt.add_row(['MEU Manifest Version', '%d' % self.MEU_Man_Ver])
		pt.add_row(['MEU Manifest Reserved', '0x%X' % self.MEU_Man_Res])
		pt.add_row(['General Data', '0x%0.8X' % self.GeneralData])
		pt.add_row(['IP Specific Data 0', '0x%0.8X' % self.IPSpecific0])
		pt.add_row(['IP Specific Data 1', '0x%0.8X' % self.IPSpecific1])
		pt.add_row(['IP Specific Data 2', '0x%0.8X' % self.IPSpecific2])
		pt.add_row(['IP Specific Data 3', '0x%0.8X' % self.IPSpecific3])
		pt.add_row(['IP Specific Data 4', '0x%0.8X' % self.IPSpecific4])
		pt.add_row(['IP Specific Data 5', '0x%0.8X' % self.IPSpecific5])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		pt.add_row(['RSA Public Key Size', '0x%X' % PublicKeySize])
		pt.add_row(['RSA Exponent Size', '0x%X' % (self.ExponentSize * 4)])
		pt.add_row(['RSA Public Key', '%s [...]' % RSAPublicKey[:8]])
		pt.add_row(['RSA Exponent', '0x%X' % self.RSAExponent])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		return pt
	
	def get_flags(self) :
		flags = MN2_Manifest_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.PVBit, flags.b.Reserved, flags.b.PIDBound, flags.b.IntelOwned, flags.b.DebugSigned

class MN2_Manifest_R2(ctypes.LittleEndianStructure) : # Manifest $MN2 CSE R2 (MANIFEST_HEADER)
	_pack_ = 1
	_fields_ = [
		('HeaderType',		uint16_t),		# 0x00
		('HeaderSubType',	uint16_t),		# 0x02
		('HeaderLength',	uint32_t),		# 0x04 dwords
		('HeaderVersion',	uint32_t),		# 0x08 0x21000
		('Flags',			uint32_t),		# 0x0C
		('VEN_ID',			uint32_t),		# 0x10 0x8086
		('Day',				uint8_t),		# 0x14
		('Month',			uint8_t),		# 0x15
		('Year',			uint16_t),		# 0x16
		('Size',			uint32_t),		# 0x18 dwords (max 2K, 4K for MTP+)
		('Tag',				char*4),		# 0x1C
		('BuildTag',		uint32_t),		# 0x20 Internal Info of FTPR > kernel or IGMF
		('Major',			uint16_t),		# 0x24
		('Minor',			uint16_t),		# 0x26
		('Hotfix',			uint16_t),		# 0x28
		('Build',			uint16_t),		# 0x2A
		('SVN',				uint32_t),		# 0x2C LS Byte derives keys
		('MEU_Major',		uint16_t),		# 0x30
		('MEU_Minor',		uint16_t),		# 0x32
		('MEU_Hotfix',		uint16_t),		# 0x34
		('MEU_Build',		uint16_t),		# 0x36
		('MEU_Man_Ver',		uint16_t),		# 0x38
		('MEU_Man_Res',		uint16_t),		# 0x3A
		('GeneralData',		uint32_t),		# 0x3C General Data of RBE
		('IPSpecific0',		uint32_t),		# 0x40 IP Specific Data
		('IPSpecific1',		uint32_t),		# 0x44
		('IPSpecific2',		uint32_t),		# 0x48
		('IPSpecific3',		uint32_t),		# 0x4C
		('IPSpecific4',		uint32_t),		# 0x50
		('IPSpecific5',		uint32_t),		# 0x54
		('Reserved',		uint32_t*8),	# 0x58
		('PublicKeySize',	uint32_t),		# 0x78 dwords
		('ExponentSize',	uint32_t),		# 0x7C dwords
		('RSAPublicKey',	uint32_t*96),	# 0x80
		('RSAExponent',		uint32_t),		# 0x200
		('RSASignature',	uint32_t*96),	# 0x204 3072-bit (SSA-PSS)
		# 0x384
	]
	
	def hdr_print_cse(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		version = '%d.%d.%d.%d' % (self.Major,self.Minor,self.Hotfix,self.Build)
		meu_version = '%d.%d.%d.%d' % (self.MEU_Major,self.MEU_Minor,self.MEU_Hotfix,self.MEU_Build)
		
		PublicKeySize = self.PublicKeySize * 4
		RSAPublicKey = '%0.*X' % (PublicKeySize * 2, int.from_bytes(self.RSAPublicKey, 'little'))
		RSASignature = '%0.*X' % (PublicKeySize * 2, int.from_bytes(self.RSASignature, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Manifest Header' + col_e
		pt.add_row(['Header Type', '%d' % self.HeaderType])
		pt.add_row(['Header Sub Type', '%d' % self.HeaderSubType])
		pt.add_row(['Header Size', '0x%X' % (self.HeaderLength * 4)])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['Production Ready', fvalue[f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['PID Bound', fvalue[f3]])
		pt.add_row(['Intel Owned', fvalue[f4]])
		pt.add_row(['Debug Signed', fvalue[f5]])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year,self.Month,self.Day)])
		pt.add_row(['Manifest Size', '0x%X' % (self.Size * 4)])
		pt.add_row(['Manifest Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Unique Build Tag', '0x%X' % self.BuildTag])
		pt.add_row(['Version', 'N/A' if self.Major in [0,0xFFFF] else version])
		pt.add_row(['TCB Security Version Number', '%d' % self.SVN])
		pt.add_row(['MEU Version', 'N/A' if self.MEU_Major in [0,0xFFFF] else meu_version])
		pt.add_row(['MEU Manifest Version', '%d' % self.MEU_Man_Ver])
		pt.add_row(['MEU Manifest Reserved', '0x%X' % self.MEU_Man_Res])
		pt.add_row(['General Data', '0x%0.8X' % self.GeneralData])
		pt.add_row(['IP Specific Data 0', '0x%0.8X' % self.IPSpecific0])
		pt.add_row(['IP Specific Data 1', '0x%0.8X' % self.IPSpecific1])
		pt.add_row(['IP Specific Data 2', '0x%0.8X' % self.IPSpecific2])
		pt.add_row(['IP Specific Data 3', '0x%0.8X' % self.IPSpecific3])
		pt.add_row(['IP Specific Data 4', '0x%0.8X' % self.IPSpecific4])
		pt.add_row(['IP Specific Data 5', '0x%0.8X' % self.IPSpecific5])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		pt.add_row(['RSA Public Key Size', '0x%X' % PublicKeySize])
		pt.add_row(['RSA Exponent Size', '0x%X' % (self.ExponentSize * 4)])
		pt.add_row(['RSA Public Key', '%s [...]' % RSAPublicKey[:8]])
		pt.add_row(['RSA Exponent', '0x%X' % self.RSAExponent])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		return pt
	
	def get_flags(self) :
		flags = MN2_Manifest_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.PVBit, flags.b.Reserved, flags.b.PIDBound, flags.b.IntelOwned, flags.b.DebugSigned
		
class MN2_Manifest_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('PVBit', uint32_t, 1), # CSE
		('Reserved', uint32_t, 28),
		('PIDBound', uint32_t, 1), # CSE
		('IntelOwned', uint32_t, 1), # ME 9 - 10
		('DebugSigned', uint32_t, 1)
	]
	
class MN2_Manifest_GetFlags(ctypes.Union):
	_fields_ = [
		('b', MN2_Manifest_Flags),
		('asbytes', uint32_t)
	]
	
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

class CPD_Header_R1(ctypes.LittleEndianStructure) : # Code Partition Directory R1 (CPD_HEADER)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('NumModules',		uint32_t),		# 0x04
		('HeaderVersion',	uint8_t),		# 0x08 1
		('EntryVersion',	uint8_t),		# 0x09
		('HeaderLength',	uint8_t),		# 0x0A
		('Checksum',		uint8_t),		# 0x0B Checksum-8 of Header + Entries with Checksum field = 0
		('PartitionName',	char*4),		# 0x0C
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

class CPD_Header_R2(ctypes.LittleEndianStructure) : # Code Partition Directory R2 (CPD_HEADER)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('NumModules',		uint32_t),		# 0x04
		('HeaderVersion',	uint8_t),		# 0x08 2
		('EntryVersion',	uint8_t),		# 0x09
		('HeaderLength',	uint8_t),		# 0x0A
		('Reserved',		uint8_t),		# 0x0B
		('PartitionName',	char*4),		# 0x0C
		('Checksum',		uint32_t),		# 0x10 CRC-32 of Header + Entries with Checksum field = 0
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
		
class CPD_Entry(ctypes.LittleEndianStructure) : # (CPD_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("OffsetAttrib",	uint32_t),		# 0x0C 00:24 $CPD Offset, 25 Huffman Yes/No, 26:31 Reserved
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

class MFS_Page_Header(ctypes.LittleEndianStructure) : # MFS Page Header
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00
		('PageNumber',		uint32_t),		# 0x04
		('EraseCount',		uint32_t),		# 0x08
		('NextErasePage',	uint16_t),		# 0x0C
		('FirstChunkIndex',	uint16_t),		# 0x0E
		('CRC8',			uint8_t),		# 0x10
		('Reserved',		uint8_t),  		# 0x11
		# 0x12
	]
	
	def mfs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Page Header' + col_e
		pt.add_row(['Signature', '%0.8X' % self.Signature])
		pt.add_row(['Page Number', '%d' % self.PageNumber])
		pt.add_row(['Erase Count', '%d' % self.EraseCount])
		pt.add_row(['Next Erase Page Index', '%d' % self.NextErasePage])
		pt.add_row(['First Chunk Index', '%d' % self.FirstChunkIndex])
		pt.add_row(['CRC-8', '0x%0.2X' % self.CRC8])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
class MFS_Volume_Header(ctypes.LittleEndianStructure) : # MFS Volume Header
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00
		('FTBLDictionary',	uint8_t),		# 0x04 0A = CON, 0B = COR, 0C = SLM etc
		('FTBLPlatform',	uint8_t),		# 0x05 01 = ICP, 02 = CMP, 03 = LKF, 04 = TGP, 05 = CMP-V etc
		('FTBLReserved',	uint16_t),		# 0x06
		('VolumeSize',		uint32_t),		# 0x08 System + Data
		('FileRecordCount',	uint16_t),		# 0x0C Supported by FAT
		# 0x0E
	]
	
	def mfs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		is_ftbl = not (self.FTBLDictionary,self.FTBLPlatform,self.FTBLReserved) == (1,0,0)
		plat_name = ftbl_efst_plat[self.FTBLPlatform] if self.FTBLPlatform in ftbl_efst_plat else 'Unknown'
		
		pt.title = col_y + 'MFS Volume Header' + col_e
		pt.add_row(['Signature', '%0.8X' % self.Signature])
		if is_ftbl :
			pt.add_row(['FTBL Dictionary', '0x%0.2X' % self.FTBLDictionary])
			pt.add_row(['FTBL Platform', '0x%0.2X (%s)' % (self.FTBLPlatform, plat_name)])
			pt.add_row(['FTBL Reserved', '0x%X' % self.FTBLReserved])
		else :
			pt.add_row(['Revision', '%d' % self.FTBLDictionary])
		pt.add_row(['Volume Length', '0x%X' % self.VolumeSize])
		pt.add_row(['File Record Count', '%d' % self.FileRecordCount])
		
		return pt
		
class MFS_Config_Record_0x1C(ctypes.LittleEndianStructure) : # MFS Configuration Record 0x1C
	_pack_ = 1
	_fields_ = [
		('FileName',		char*12),		# 0x00
		('Reserved',		uint16_t),		# 0x0C
		('AccessMode',		uint16_t),		# 0x0E
		('DeployOptions',	uint16_t),		# 0x10
		('FileSize',		uint16_t),		# 0x12
		('OwnerUserID',		uint16_t),		# 0x14
		('OwnerGroupID',	uint16_t),		# 0x16
		('FileOffset',		uint32_t),		# 0x18
		# 0x1C
	]
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Configuration Record' + col_e
		pt.add_row(['Name', self.FileName.decode('utf-8')])
		pt.add_row(['Type', ['File','Folder'][f5]])
		pt.add_row(['Size', '0x%X' % self.FileSize])
		#pt.add_row(['Offset', '0x%X' % self.FileOffset])
		pt.add_row(['Access Rights', ''.join(map(str, self.get_rights(f1)))])
		pt.add_row(['Owner User ID', '%0.4X' % self.OwnerUserID])
		pt.add_row(['Owner Group ID', '%0.4X' % self.OwnerGroupID])
		pt.add_row(['OEM Configurable', fvalue[f7]])
		pt.add_row(['MCA Configurable', fvalue[f8]])
		pt.add_row(['Integrity Protection', fvalue[f2]])
		pt.add_row(['Encryption Protection', fvalue[f3]])
		pt.add_row(['Anti-Replay Protection', fvalue[f4]])
		pt.add_row(['Access Mode Unknown', '{0:03b}b'.format(f6)])
		pt.add_row(['Deploy Options Unknown', '{0:014b}b'.format(f9)])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
	@staticmethod
	def get_rights(f1) :
		bits = format(f1, '09b')
		for i in range(len(bits)) :
			yield 'rwxrwxrwx'[i] if bits[i] == '1' else '-'
	
	def get_flags(self) :
		a_flags = MFS_Config_Record_GetAccess()
		a_flags.asbytes = self.AccessMode
		o_flags = MFS_Config_Record_GetOptions()
		o_flags.asbytes = self.DeployOptions
		
		return a_flags.b.UnixRights, a_flags.b.Integrity, a_flags.b.Encryption, a_flags.b.AntiReplay, a_flags.b.RecordType,\
		       a_flags.b.Unknown, o_flags.b.OEMConfigurable, o_flags.b.MCAConfigurable, o_flags.b.Unknown
			   
class MFS_Config_Record_Access(ctypes.LittleEndianStructure):
	_fields_ = [
		('UnixRights', uint16_t, 9),
		('Integrity', uint16_t, 1), # HMAC
		('Encryption', uint16_t, 1),
		('AntiReplay', uint16_t, 1),
		('RecordType', uint16_t, 1), # 0 File, 1 Folder
		('Unknown', uint16_t, 3)
	]
	
class MFS_Config_Record_GetAccess(ctypes.Union):
	_fields_ = [
		('b', MFS_Config_Record_Access),
		('asbytes', uint16_t)
	]
	
class MFS_Config_Record_Options(ctypes.LittleEndianStructure):
	_fields_ = [
		('OEMConfigurable', uint16_t, 1), # OEM fitc.cfg setting can overwrite Intel intl.cfg equivalent setting via Flash Image Tool
		('MCAConfigurable', uint16_t, 1), # Manufacturing Configuration Architecture module can configure MFS CVARs in Manufacturing Mode
		('Unknown', uint16_t, 14)
	]
	
class MFS_Config_Record_GetOptions(ctypes.Union):
	_fields_ = [
		('b', MFS_Config_Record_Options),
		('asbytes', uint16_t)
	]
	
class MFS_Config_Record_0xC(ctypes.LittleEndianStructure) : # MFS Configuration Record 0xC
	_pack_ = 1
	_fields_ = [
		('FileID',			uint32_t),		# 0x00
		('FileOffset',		uint32_t),		# 0x04
		('FileSize',		uint16_t),		# 0x08
		('Flags',			uint16_t),		# 0x0A
		# 0x0C
	]
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Configuration Record' + col_e
		pt.add_row(['File ID', '0x%0.8X' % self.FileID])
		#pt.add_row(['Offset', '0x%X' % self.FileOffset])
		pt.add_row(['Size', '0x%X' % self.FileSize])
		pt.add_row(['OEM Configurable', fvalue[f1]])
		pt.add_row(['Reserved Flags', '{0:015b}b'.format(f2)])
		
		return pt
		
	def get_flags(self) :
		flags = MFS_Config_Record_0xC_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.OEMConfigurable, flags.b.Unknown
		
class MFS_Config_Record_0xC_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('OEMConfigurable', uint16_t, 1), # OEM fitc.cfg setting can overwrite Intel intl.cfg equivalent setting via Flash Image Tool
		('Unknown', uint16_t, 15)
	]
	
class MFS_Config_Record_0xC_GetFlags(ctypes.Union):
	_fields_ = [
		('b', MFS_Config_Record_0xC_Flags),
		('asbytes', uint16_t)
	]
	
class MFS_Home_Record_0x18(ctypes.LittleEndianStructure) : # MFS Home Directory Record 0x18
	_pack_ = 1
	_fields_ = [
		('FileInfo',		uint32_t),		# 0x00
		('AccessMode',		uint16_t),		# 0x04
		('OwnerUserID',		uint16_t),		# 0x06
		('OwnerGroupID',	uint16_t),		# 0x08
		('UnknownSalt',		uint16_t),		# 0x0A
		('FileName',		char*12),		# 0x0C
		# 0x18
	]
	
	# Remember to also adjust MFS_Home_Record_0x1C for common fields
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Home Record' + col_e
		pt.add_row(['Index', '%d' % f1])
		pt.add_row(['Name', self.FileName.decode('utf-8')])
		pt.add_row(['Type', ['File','Folder'][f10]])
		pt.add_row(['Keys', ['Intel','Other'][f9]])
		pt.add_row(['File System', mfs_type[f3]])
		pt.add_row(['Access Rights', ''.join(map(str, self.get_rights(f4)))])
		pt.add_row(['Owner User ID', '%0.4X' % self.OwnerUserID])
		pt.add_row(['Owner Group ID', '%0.4X' % self.OwnerGroupID])
		pt.add_row(['Integrity Protection', fvalue[f5]])
		pt.add_row(['Encryption Protection', fvalue[f6]])
		pt.add_row(['Anti-Replay Protection', fvalue[f7]])
		pt.add_row(['Access Mode Unknown 0', '{0:01b}b'.format(f8)])
		pt.add_row(['Access Mode Unknown 1', '{0:01b}b'.format(f11)])
		pt.add_row(['Integrity Salt', '0x%0.4X' % f2])
		pt.add_row(['Unknown Salt', '0x%X' % self.UnknownSalt])
		
		return pt
		
	@staticmethod
	def get_rights(f4) :
		bits = format(f4, '09b')
		for i in range(len(bits)) :
			yield 'rwxrwxrwx'[i] if bits[i] == '1' else '-'
	
	def get_flags(self) :
		f_flags = MFS_Home_Record_GetFileInfo()
		f_flags.asbytes = self.FileInfo
		a_flags = MFS_Home_Record_GetAccess()
		a_flags.asbytes = self.AccessMode
		
		return f_flags.b.FileIndex, f_flags.b.IntegritySalt, f_flags.b.FileSystemID, a_flags.b.UnixRights, a_flags.b.Integrity, \
		       a_flags.b.Encryption, a_flags.b.AntiReplay, a_flags.b.Unknown0, a_flags.b.KeyType, a_flags.b.RecordType, a_flags.b.Unknown1
			   
class MFS_Home_Record_0x1C(ctypes.LittleEndianStructure) : # MFS Home Directory Record 0x1C
	_pack_ = 1
	_fields_ = [
		('FileInfo',		uint32_t),		# 0x00
		('AccessMode',		uint16_t),		# 0x04
		('OwnerUserID',		uint16_t),		# 0x06
		('OwnerGroupID',	uint16_t),		# 0x08
		('UnknownSalt',		uint16_t*3),	# 0x0A
		('FileName',		char*12),		# 0x10
		# 0x1C
	]
	
	# Remember to also adjust MFS_Home_Record_0x18 for common fields
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11 = self.get_flags()
		
		UnknownSalt = '0x%0.*X' % (0x6 * 2, int.from_bytes(self.UnknownSalt, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Home Record' + col_e
		pt.add_row(['Index', '%d' % f1])
		pt.add_row(['Name', self.FileName.decode('utf-8')])
		pt.add_row(['Type', ['File','Folder'][f10]])
		pt.add_row(['Keys', ['Intel','Other'][f9]])
		pt.add_row(['File System', mfs_type[f3]])
		pt.add_row(['Access Rights', ''.join(map(str, self.get_rights(f4)))])
		pt.add_row(['Owner User ID', '%0.4X' % self.OwnerUserID])
		pt.add_row(['Owner Group ID', '%0.4X' % self.OwnerGroupID])
		pt.add_row(['Integrity Protection', fvalue[f5]])
		pt.add_row(['Encryption Protection', fvalue[f6]])
		pt.add_row(['Anti-Replay Protection', fvalue[f7]])
		pt.add_row(['Access Mode Unknown 0', '{0:01b}b'.format(f8)])
		pt.add_row(['Access Mode Unknown 1', '{0:01b}b'.format(f11)])
		pt.add_row(['Integrity Salt', '0x%0.4X' % f2])
		pt.add_row(['Unknown Salt', UnknownSalt])
		
		return pt
		
	@staticmethod
	def get_rights(f4) :
		bits = format(f4, '09b')
		for i in range(len(bits)) :
			yield 'rwxrwxrwx'[i] if bits[i] == '1' else '-'
	
	def get_flags(self) :
		f_flags = MFS_Home_Record_GetFileInfo()
		f_flags.asbytes = self.FileInfo
		a_flags = MFS_Home_Record_GetAccess()
		a_flags.asbytes = self.AccessMode
		
		return f_flags.b.FileIndex, f_flags.b.IntegritySalt, f_flags.b.FileSystemID, a_flags.b.UnixRights, a_flags.b.Integrity, \
		       a_flags.b.Encryption, a_flags.b.AntiReplay, a_flags.b.Unknown0, a_flags.b.KeyType, a_flags.b.RecordType, a_flags.b.Unknown1

class MFS_Home_Record_FileInfo(ctypes.LittleEndianStructure):
	_fields_ = [
		('FileIndex', uint32_t, 12), # MFS Low Level File Index
		('IntegritySalt', uint32_t, 16), # For MFS_Integrity_Table.HMAC
		('FileSystemID', uint32_t, 4) # 0 root, 1 home, 2 bin, 3 susram, 4 fpf, 5 dev, 6 umafs
	]
	
class MFS_Home_Record_GetFileInfo(ctypes.Union):
	_fields_ = [
		('b', MFS_Home_Record_FileInfo),
		('asbytes', uint32_t)
	]
	
class MFS_Home_Record_Access(ctypes.LittleEndianStructure):
	_fields_ = [
		('UnixRights', uint16_t, 9),
		('Integrity', uint16_t, 1), # HMAC
		('Encryption', uint16_t, 1),
		('AntiReplay', uint16_t, 1),
		('Unknown0', uint16_t, 1),
		('KeyType', uint16_t, 1), # 0 Intel, 1 Other
		('RecordType', uint16_t, 1), # 0 File, 1 Folder
		('Unknown1', uint16_t, 1)
	]
	
class MFS_Home_Record_GetAccess(ctypes.Union):
	_fields_ = [
		('b', MFS_Home_Record_Access),
		('asbytes', uint16_t)
	]

class MFS_Integrity_Table_0x34(ctypes.LittleEndianStructure) : # MFS Integrity Table 0x34
	_pack_ = 1
	_fields_ = [
		('HMACSHA256',		uint32_t*8),	# 0x00 HMAC SHA-256
		('Flags',			uint32_t),		# 0x20
		('ARValues_Nonce',	uint32_t*4),	# 0x2C Anti-Replay Random Value (32-bit) + Counter Value (32-bit) or AES-CTR Nonce (128-bit)
		# 0x34
	]
	
	# HMAC = File Contents + MFS_Integrity_Table with HMACSHA256 = 0, MFS_Home_Record.FileInfo.FileIndex + MFS_Home_Record.FileInfo.IntegritySalt (32-bit).
	# For MFS Low Level Files without MFS_Home_Record (2 Anti-Replay, 3 Anti-Replay, 8 Home): FileIndex = 0x10000000 + 2|3|8 and IntegritySalt = 0.
	# The MFS_Integrity_Table HMAC SHA-256 Integrity value cannot be verified by 3rd-party entities without Intel's Secret Key within the CSE.
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8 = self.get_flags()
		
		HMACSHA256 = '%0.*X' % (0x20 * 2, int.from_bytes(self.HMACSHA256, 'little'))
		ARValues_Nonce = '%0.*X' % (0x10 * 2, int.from_bytes(self.ARValues_Nonce, 'little'))
		ARRandom, ARCounter = struct.unpack_from('<II', self.ARValues_Nonce)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Integrity Table' + col_e
		pt.add_row(['HMAC SHA-256', HMACSHA256])
		pt.add_row(['Flags Unknown 0', '{0:01b}b'.format(f1)])
		pt.add_row(['Anti-Replay Protection', fvalue[f2]])
		pt.add_row(['Encryption Protection', fvalue[f3]])
		pt.add_row(['Flags Unknown 1', '{0:07b}b'.format(f4)])
		pt.add_row(['Anti-Replay Index', '%d' % f5])
		pt.add_row(['Flags Unknown 2', '{0:01b}b'.format(f6)])
		pt.add_row(['Security Version Number', '%d' % f7])
		pt.add_row(['Flags Unknown 3', '{0:03b}b'.format(f8)])
		pt.add_row(['Anti-Replay Random Value', '0x%0.8X' % ARRandom])
		pt.add_row(['Anti-Replay Counter Value', '0x%0.8X' % ARCounter])
		pt.add_row(['Encryption Nonce', ARValues_Nonce])
		
		return pt
	
	def get_flags(self) :
		i_flags = MFS_Integrity_Table_GetFlags_0x34()
		i_flags.asbytes = self.Flags
		
		return i_flags.b.Unknown0, i_flags.b.AntiReplay, i_flags.b.Encryption, i_flags.b.Unknown1, i_flags.b.ARIndex, \
			   i_flags.b.Unknown2, i_flags.b.SVN, i_flags.b.Unknown3

class MFS_Integrity_Table_Flags_0x34(ctypes.LittleEndianStructure):
	_fields_ = [
		('Unknown0', uint32_t, 1),
		('AntiReplay', uint32_t, 1),
		('Encryption', uint32_t, 1), # 0 Non-Encrypted, 1 Encrypted
		('Unknown1', uint32_t, 7),
		('ARIndex', uint32_t, 10), # Anti-Replay Index (0 < MFS Volume Records <= 1023, 1023 = 1111111111 or 10-bit length)
		('Unknown2', uint32_t, 1),
		('SVN', uint32_t, 8), # Security Version Number (0 < SVN <= 255, 255 = 11111111 or 8-bit length)
		('Unknown3', uint32_t, 3)
	]
	
class MFS_Integrity_Table_GetFlags_0x34(ctypes.Union):
	_fields_ = [
		('b', MFS_Integrity_Table_Flags_0x34),
		('asbytes', uint32_t)
	]
	
class MFS_Integrity_Table_0x28(ctypes.LittleEndianStructure) : # MFS Integrity Table 0x28
	_pack_ = 1
	_fields_ = [
		('HMACMD5',			uint32_t*4),	# 0x00 HMAC MD5
		('Flags',			uint32_t),		# 0x10
		('ARRandom',		uint32_t),		# 0x14 Anti-Replay Random Value
		('ARCounter',		uint32_t),		# 0x18 Anti-Replay Counter Value
		('AESGCMNonce',		uint32_t*3),	# 0x1C AES-GCM Nonce (96-bit)
		# 0x28
	]
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9 = self.get_flags()
		
		HMACMD5 = '%0.*X' % (0x10 * 2, int.from_bytes(self.HMACMD5, 'little'))
		AESGCMNonce = '%0.*X' % (0xC * 2, int.from_bytes(self.AESGCMNonce, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Integrity Table' + col_e
		pt.add_row(['HMAC MD5', HMACMD5])
		pt.add_row(['Flags Unknown 0', '{0:01b}b'.format(f1)])
		pt.add_row(['Anti-Replay Protection', fvalue[f2]])
		pt.add_row(['Flags Unknown 1', '{0:01b}b'.format(f3)])
		pt.add_row(['Encryption Protection', fvalue[f4]])
		pt.add_row(['Flags Unknown 2', '{0:07b}b'.format(f5)])
		pt.add_row(['Anti-Replay Index', '%d' % f6])
		pt.add_row(['Flags Unknown 3', '{0:01b}b'.format(f7)])
		pt.add_row(['Security Version Number', '%d' % f8])
		pt.add_row(['Flags Unknown 4', '{0:02b}b'.format(f9)])
		pt.add_row(['Anti-Replay Random Value', '0x%0.8X' % self.ARRandom])
		pt.add_row(['Anti-Replay Counter Value', '0x%0.8X' % self.ARCounter])
		pt.add_row(['AES-GCM Nonce', AESGCMNonce])
		
		return pt
		
	def get_flags(self) :
		i_flags = MFS_Integrity_Table_GetFlags_0x28()
		i_flags.asbytes = self.Flags
		
		return i_flags.b.Unknown0, i_flags.b.AntiReplay, i_flags.b.Unknown1, i_flags.b.Encryption, i_flags.b.Unknown2, \
			   i_flags.b.ARIndex, i_flags.b.Unknown3, i_flags.b.SVN, i_flags.b.Unknown4
			   
class MFS_Integrity_Table_Flags_0x28(ctypes.LittleEndianStructure):
	_fields_ = [
		('Unknown0', uint32_t, 1),
		('AntiReplay', uint32_t, 1),
		('Unknown1', uint32_t, 1),
		('Encryption', uint32_t, 1), # 0 Non-Encrypted or Encrypted w/o Size, 1 Encrypted
		('Unknown2', uint32_t, 7), # 0100111b for Encrypted, 0010111b for Non-Encrypted
		('ARIndex', uint32_t, 10), # Anti-Replay Index (0 < MFS Volume Records <= 1023, 1023 = 1111111111 or 10-bit length)
		('Unknown3', uint32_t, 1),
		('SVN', uint32_t, 8), # Security Version Number (0 < SVN <= 255, 255 = 11111111 or 8-bit length)
		('Unknown4', uint32_t, 2)
	]
	
class MFS_Integrity_Table_GetFlags_0x28(ctypes.Union):
	_fields_ = [
		('b', MFS_Integrity_Table_Flags_0x28),
		('asbytes', uint32_t)
	]
		
class MFS_Backup_Header_R0(ctypes.LittleEndianStructure) : # MFS Backup Header R0
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00 MFSB
		('CRC32',			uint32_t),		# 0x04
		('Reserved',		uint32_t*6),	# 0x08 FF * 24
		# 0x20
	]
	
	def mfs_print(self) :
		Reserved = '%0.*X' % (0x18 * 2, int.from_bytes(self.Reserved, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Backup Header' + col_e
		pt.add_row(['Signature', '0x%0.8X' % self.Signature])
		pt.add_row(['CRC32', '0x%0.8X' % self.CRC32])
		pt.add_row(['Reserved', '0x' + 'FF * 24' if Reserved == 'FF' * 24 else Reserved])
		
		return pt
		
class MFS_Backup_Header_R1(ctypes.LittleEndianStructure) : # MFS Backup Header R1
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00 MFSB
		('Revision',		uint32_t),		# 0x04 1
		('HeaderCRC32',		uint32_t),		# 0x08 CRC-32 of Header w/ HeaderCRC32 = 0
		('Entry6Offset',	uint32_t),		# 0x0C Intel Configuration (6)
		('Entry6Size',		uint32_t),		# 0x10
		('Entry9Offset',	uint32_t),		# 0x14 Manifest Backup (9)
		('Entry9Size',		uint32_t),		# 0x18
		('Entry7Offset',	uint32_t),		# 0x1C OEM Configuration (7)
		('Entry7Size',		uint32_t),		# 0x20
		# 0x24
	]
	
	def mfs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Backup Header' + col_e
		pt.add_row(['Signature', '0x%0.8X' % self.Signature])
		pt.add_row(['Revision', self.Revision])
		pt.add_row(['Header CRC-32', '0x%0.8X' % self.HeaderCRC32])
		pt.add_row(['Entry 6 Offset', '0x%X' % self.Entry6Offset])
		pt.add_row(['Entry 6 Size', '0x%X' % self.Entry6Size])
		pt.add_row(['Entry 9 Offset', '0x%X' % self.Entry9Offset])
		pt.add_row(['Entry 9 Size', '0x%X' % self.Entry9Size])
		pt.add_row(['Entry 7 Offset', '0x%X' % self.Entry7Offset])
		pt.add_row(['Entry 7 Size', '0x%X' % self.Entry7Size])
		
		return pt
		
class MFS_Backup_Entry(ctypes.LittleEndianStructure) : # MFS Backup Entry
	_pack_ = 1
	_fields_ = [
		('Revision',		uint32_t),		# 0x00 1
		('EntryCRC32',		uint32_t),		# 0x04 CRC-32 of MFSB Entry Header (EntryCRC32 = 0, w/o DataCRC32)
		('Size',			uint32_t),		# 0x08
		('DataCRC32',		uint32_t),		# 0x0C CRC-32 of MFSB Entry Data (Low Level File + DataCRC32 = 0)
		# 0x10
	]
	
	def mfs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Backup Entry' + col_e
		pt.add_row(['Entry Revision', self.Revision])
		pt.add_row(['Entry CRC-32', '0x%0.8X' % self.EntryCRC32])
		pt.add_row(['Data Size', '0x%X' % self.Size])
		pt.add_row(['Data CRC-32', '0x%0.8X' % self.DataCRC32])
		
		return pt
		
class FTBL_Header(ctypes.LittleEndianStructure) : # File Tables Header
	_pack_ = 1
	_fields_ = [
		('Signature',		char*4),		# 0x00
		('Unknown',			uint32_t),		# 0x04 Reserved ?
		('HeaderSize',		uint32_t),		# 0x08
		('TableCount',		uint32_t),		# 0x0C
		# 0x10
	]
	
	def ftbl_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'File Tables Header' + col_e
		pt.add_row(['Signature', self.Signature.decode('utf-8')])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		pt.add_row(['Header Size', '0x%X' % self.HeaderSize])
		pt.add_row(['Table Count', '%d' % self.TableCount])
		
		return pt
		
class FTBL_Table(ctypes.LittleEndianStructure) : # File Table Header
	_pack_ = 1
	_fields_ = [
		('Dictionary',		uint32_t),		# 0x00
		('Offset',			uint32_t),		# 0x04
		('EntryCount',		uint32_t),		# 0x08
		('Size',			uint32_t),		# 0x0C
		# 0x10
	]
	
	def ftbl_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'File Table Header' + col_e
		pt.add_row(['Dictionary', '0x%0.2X' % self.Dictionary])
		pt.add_row(['Offset', '0x%X' % self.Offset])
		pt.add_row(['Entry Count', '%d' % self.EntryCount])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
		
class FTBL_Entry(ctypes.LittleEndianStructure) : # File Table Entry
	_pack_ = 1
	_fields_ = [
		('Path',			char*48),		# 0x00
		('FileID',			uint32_t),		# 0x30
		('Access',			uint16_t),		# 0x34
		('GroudID',			uint16_t),		# 0x36
		('UserID',			uint16_t),		# 0x38
		('VFSID',			uint16_t),		# 0x3A
		('Unknown',			uint64_t),		# 0x3C
		# 0x44
	]
	
	# Remember to also adjust param.mfs_ftbl, mfs_home13_anl & efs_anl
	
	def ftbl_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'File Table Entry' + col_e
		pt.add_row(['Path', self.Path.decode('utf-8').strip()])
		pt.add_row(['File ID', '0x%X' % self.FileID])
		pt.add_row(['Integrity', fvalue[f1]])
		pt.add_row(['Encryption', fvalue[f2]])
		pt.add_row(['Anti-Replay', fvalue[f3]])
		pt.add_row(['Access Unknown', '{0:013b}b'.format(f4)])
		pt.add_row(['Group ID', '0x%0.4X' % self.GroudID])
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['VFS ID', '%0.4d' % self.VFSID])
		pt.add_row(['Unknown', '{0:064b}b'.format(f5)])
		
		return pt
	
	def get_flags(self) :
		a_flags = FTBL_Entry_GetAccess()
		a_flags.asbytes = self.Access
		o_flags = FTBL_Entry_GetUnknown()
		o_flags.asbytes = self.Unknown
		
		return a_flags.b.Integrity, a_flags.b.Encryption, a_flags.b.AntiReplay, a_flags.b.Unknown, o_flags.b.Unknown
		
class FTBL_Entry_Access(ctypes.LittleEndianStructure):
	_fields_ = [
		('Integrity', uint16_t, 1),
		('Encryption', uint16_t, 1),
		('AntiReplay', uint16_t, 1),
		('Unknown', uint16_t, 13)
	]
	
class FTBL_Entry_GetAccess(ctypes.Union):
	_fields_ = [
		('b', FTBL_Entry_Access),
		('asbytes', uint16_t)
	]
	
class FTBL_Entry_Unknown(ctypes.LittleEndianStructure):
	_fields_ = [
		('Unknown', uint32_t, 32)
	]
	
class FTBL_Entry_GetUnknown(ctypes.Union):
	_fields_ = [
		('b', FTBL_Entry_Unknown),
		('asbytes', uint32_t)
	]

class EFST_Header(ctypes.LittleEndianStructure) : # EFS Tables Header
	_pack_ = 1
	_fields_ = [
		('Signature',		char*4),		# 0x00
		('Unknown',			uint32_t),		# 0x04 Reserved ?
		('HeaderSize',		uint32_t),		# 0x08
		('TableCount',		uint32_t),		# 0x0C
		# 0x10
	]
	
	def efst_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'EFS Tables Header' + col_e
		pt.add_row(['Signature', self.Signature.decode('utf-8')])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		pt.add_row(['Header Size', '0x%X' % self.HeaderSize])
		pt.add_row(['Table Count', '%d' % self.TableCount])
		
		return pt
		
class EFST_Table(ctypes.LittleEndianStructure) : # EFS Table Header
	_pack_ = 1
	_fields_ = [
		('Dictionary',		uint32_t),		# 0x00
		('Offset',			uint32_t),		# 0x04
		('EntryCount',		uint32_t),		# 0x08 EFST Entries/Files Count
		('Size',			uint32_t),		# 0x0C
		('Unknown0',		uint32_t),		# 0x10 00000002
		('DataPagesCom',	uint32_t),		# 0x14 Committed Data Pages Count
		('DataPagesRes',	uint32_t),		# 0x18 Reserved Data Pages Count
		('MaxEntries',		uint32_t),		# 0x1C Maximum Supported Files
		('Unknown1',		uint32_t),		# 0x20 Maximum Supported Pages (?)
		('Revision',		uint32_t),		# 0x24 EFST Revision
		# 0x28
	]
	
	def efst_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'EFS Table Header' + col_e
		pt.add_row(['Dictionary', '0x%0.2X' % self.Dictionary])
		pt.add_row(['Offset', '0x%X' % self.Offset])
		pt.add_row(['Entry Count', '%d' % self.EntryCount])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Data Pages Committed', self.DataPagesCom])
		pt.add_row(['Data Pages Reserved', self.DataPagesRes])
		pt.add_row(['Maximum Entries', self.MaxEntries])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Revision', self.Revision])
		
		return pt
		
class EFST_Entry(ctypes.LittleEndianStructure) : # EFS Table Entry
	_pack_ = 1
	_fields_ = [
		('FileID',			uint16_t),		# 0x00
		('FileName',		char*48),		# 0x02
		('FilePage',		uint16_t),		# 0x32
		('FileOffset',		uint16_t),		# 0x34
		('FileSize',		uint16_t),		# 0x36
		('Reserved',		uint32_t),		# 0x38 0
		# 0x3C
	]
	
	def efst_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'EFS Table Entry' + col_e
		pt.add_row(['File ID', self.FileID])
		pt.add_row(['File Name', self.FileName.decode('utf-8').strip()])
		pt.add_row(['File Page', self.FilePage])
		pt.add_row(['File Offset', '0x%X' % self.FileOffset])
		pt.add_row(['File Size', '0x%X' % self.FileSize])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
class EFS_Page_Header(ctypes.LittleEndianStructure) : # EFS Page Header
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint16_t),		# 0x00 ?
		('Dictionary',		uint16_t),		# 0x02 EFS Table
		('Revision',		uint32_t),		# 0x04 EFS Revision (?)
		('Unknown1',		uint8_t),		# 0x08 02
		('DataPagesCom',	uint8_t),		# 0x09 Committed Data Pages Count
		('DataPagesRes',	uint8_t),		# 0x0A Reserved Data Pages Count
		('DictRevision',	uint8_t),		# 0x0B Dictionary/EFST Revision
		('CRC32',			uint32_t),		# 0x0C CRC-32 (Unknown0 - DictRevision, IV 0)
		# 0x10
	]
	
	def efs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'EFS Page Header' + col_e
		pt.add_row(['Unknown 0', '%0.4X' % self.Unknown0])
		pt.add_row(['Dictionary', '%0.2X' % self.Dictionary])
		pt.add_row(['Revision', self.Revision])
		pt.add_row(['Unknown 1', '0x%0.2X' % self.Unknown1])
		pt.add_row(['Data Pages Committed', self.DataPagesCom])
		pt.add_row(['Data Pages Reserved', self.DataPagesRes])
		pt.add_row(['Dictionary Revision', self.DictRevision])
		pt.add_row(['Header CRC-32', '0x%0.8X' % self.CRC32])
		
		return pt
		
class EFS_Page_Footer(ctypes.LittleEndianStructure) : # EFS Page Footer
	_pack_ = 1
	_fields_ = [
		('Unknown',			uint32_t),		# 0x00 FFFFFFFF
		('CRC32',			uint32_t),		# 0x04 CRC-32 (Header end - CRC32 start, IV 0)
		# 0x08
	]
	
	def efs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'EFS Page Footer' + col_e
		pt.add_row(['Unknown', '0x%0.8X' % self.Unknown])
		pt.add_row(['Page CRC-32', '0x%0.8X' % self.CRC32])
		
		return pt
		
class EFS_File_Metadata(ctypes.LittleEndianStructure) : # EFS File Metadata
	_pack_ = 1
	_fields_ = [
		('Size',			uint16_t),		# 0x00
		('Unknown',			uint16_t),		# 0x02
		# 0x04
	]
	
	def efs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'EFS Metadata' + col_e
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Unknown', '0x%0.4X' % self.Unknown])
		
		return pt

class UTFL_Header(ctypes.LittleEndianStructure) : # Unlock Token Flags (DebugTokenSubPartition)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('DelayedAuthMode',	uint8_t),		# 0x04
		('Reserved',		uint8_t*27),	# 0x05
		# 0x20 (End of 8KB UTOK/STKN)
	]
	
	def hdr_print(self) :
		Reserved = '%0.*X' % (0x1B * 2, int.from_bytes(self.Reserved, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Unlock Token Flags' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Delayed Authentication Mode', ['No','Yes'][self.DelayedAuthMode]])
		pt.add_row(['Reserved', '0x' + '00/FF * 27' if Reserved in ('00' * 27,'FF' * 27) else Reserved])
		
		return pt
		
class FITC_Header(ctypes.LittleEndianStructure) : # OEM Configuration Partition
	_pack_ = 1
	_fields_ = [
		('HeaderRevision',	uint32_t),		# 0x00 1
		('HeaderChecksum',	uint32_t),		# 0x04 CRC-32 of Header w/o DataChecksum, HeaderChecksum = 0
		('DataLength',		uint32_t),		# 0x08
		('DataChecksum',	uint32_t),		# 0x0C CRC-32 from Header end + DataLength
		# 0x10
	]
	
	def hdr_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'FITC Header' + col_e
		pt.add_row(['Header Revision', self.HeaderRevision])
		pt.add_row(['Header Checksum', '0x%0.8X' % self.HeaderChecksum])
		pt.add_row(['Data Length', '0x%X' % self.DataLength])
		pt.add_row(['Data Checksum', '0x%0.8X' % self.DataChecksum])
		
		return pt
	
class CSE_Ext_00(ctypes.LittleEndianStructure) : # R1 - System Information (SYSTEM_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("MinUMASize",		uint32_t),		# 0x08
		("ChipsetVersion",	uint32_t),		# 0x0C
		("IMGDefaultHash",	uint32_t*8),	# 0x10 SHA-256, CSME/SPS MFS > Low Level File 6 or CSTXE FTPR > intl.cfg
		("PageableUMASize",	uint32_t),		# 0x30
		("Reserved0",		uint64_t),		# 0x34
		("Reserved1",		uint32_t),		# 0x3C
		# 0x40
	]
	
	# The MFS Intel Configuration (Low Level File 6) Hash is only checked at first boot, before the MFS is Initialized.
	# After the MFS Home Directory (Low Level Files 8+) is generated, MFS Intel Configuration is no longer used or checked.
	# The initial MFS Intel Configuration remains the same even after FWUpdate is executed so the FTPR Manifest Hash is wrong.
	# Thus, the MFS Intel Configuration Hash must only be checked at non-Initialized MFS before any possible FWUpdate operations.
	
	def ext_print(self) :
		IMGDefaultHash = '%0.*X' % (0x20 * 2, int.from_bytes(self.IMGDefaultHash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, System Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minimum UMA Size', '0x%X' % self.MinUMASize])
		pt.add_row(['Chipset Version', '0x%X' % self.ChipsetVersion])
		pt.add_row(['Intel Config Hash', IMGDefaultHash])
		pt.add_row(['Pageable UMA Size', '0x%X' % self.PageableUMASize])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		return pt
		
class CSE_Ext_00_R2(ctypes.LittleEndianStructure) : # R2 - System Information (SYSTEM_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("MinUMASize",		uint32_t),		# 0x08
		("ChipsetVersion",	uint32_t),		# 0x0C
		("IMGDefaultHash",	uint32_t*12),	# 0x10 SHA-384, CSME/SPS MFS > Low Level File 6 or CSTXE FTPR > intl.cfg
		("PageableUMASize",	uint32_t),		# 0x40
		("Reserved0",		uint64_t),		# 0x44
		("Reserved1",		uint32_t),		# 0x4C
		# 0x50
	]
	
	# The MFS Intel Configuration (Low Level File 6) Hash is only checked at first boot, before the MFS is Initialized.
	# After the MFS Home Directory (Low Level Files 8+) is generated, MFS Intel Configuration is no longer used or checked.
	# The initial MFS Intel Configuration remains the same even after FWUpdate is executed so the FTPR Manifest Hash is wrong.
	# Thus, the MFS Intel Configuration Hash must only be checked at non-Initialized MFS before any possible FWUpdate operations.
	
	def ext_print(self) :
		IMGDefaultHash = '%0.*X' % (0x30 * 2, int.from_bytes(self.IMGDefaultHash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, System Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minimum UMA Size', '0x%X' % self.MinUMASize])
		pt.add_row(['Chipset Version', '0x%X' % self.ChipsetVersion])
		pt.add_row(['Intel Config Hash', IMGDefaultHash])
		pt.add_row(['Pageable UMA Size', '0x%X' % self.PageableUMASize])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		return pt

class CSE_Ext_00_Mod(ctypes.LittleEndianStructure) : # R1 - (INDEPENDENT_PARTITION_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*4),		# 0x00
		("Version",			uint32_t),		# 0x04
		("UserID",			uint16_t),		# 0x08
		("GroupID",			uint16_t),		# 0x0A (Guess, not in XML)
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, Independent Partition' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Version', '0x%X' % self.Version])
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Group ID', '0x%0.4X' % self.GroupID])
		
		return pt
		
class CSE_Ext_00_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (INDEPENDENT_PARTITION_ENTRY)
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

class CSE_Ext_01(ctypes.LittleEndianStructure) : # R1 - Initialization Script (InitScript)
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

class CSE_Ext_01_Mod(ctypes.LittleEndianStructure) : # R1 - (InitScriptEntry)
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

class CSE_Ext_01_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (InitScriptEntry)
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
		pt.add_row(['Init Flow Reserved', '{0:025b}b'.format(f8)])
		pt.add_row(['Normal', fvalue[f9]])
		pt.add_row(['HAP', fvalue[f10]])
		pt.add_row(['HMRFPO', fvalue[f11]])
		pt.add_row(['Temp Disable', fvalue[f12]])
		pt.add_row(['Recovery', fvalue[f13]])
		pt.add_row(['Safe Mode', fvalue[f14]])
		pt.add_row(['FWUpdate', fvalue[f15]])
		pt.add_row(['Boot Type Reserved', '{0:025b}b'.format(f16)])
		pt.add_row(['Unknown Flags', '{0:032b}b'.format(self.UnknownFlags)])
		
		return pt
	
	def get_flags(self) :
		i_flags = CSE_Ext_01_GetInitFlowFlags()
		b_flags = CSE_Ext_01_GetBootTypeFlags()
		i_flags.asbytes = self.InitFlowFlags
		b_flags.asbytes = self.BootTypeFlags
		
		return i_flags.b.IBL, i_flags.b.Removable, i_flags.b.InitImmediately, i_flags.b.RestartPolicy, i_flags.b.CM0_UMA,\
		       i_flags.b.CM0_NO_UMA, i_flags.b.CM3, i_flags.b.Reserved, b_flags.b.Normal, b_flags.b.HAP, b_flags.b.HMRFPO,\
			   b_flags.b.TempDisable, b_flags.b.Recovery, b_flags.b.SafeMode, b_flags.b.FWUpdate, b_flags.b.Reserved
			   
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

class CSE_Ext_02(ctypes.LittleEndianStructure) : # R1 - Feature Permissions (FEATURE_PERMISSIONS_EXTENSION)
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

class CSE_Ext_02_Mod(ctypes.LittleEndianStructure) : # R1 - (FEATURE_PERMISION_ENTRY)
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

class CSE_Ext_03(ctypes.LittleEndianStructure) : # R1 - Partition Information (MANIFEST_PARTITION_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('Hash',			uint32_t*8),	# 0x10 SHA-256, Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('VCN',				uint32_t),		# 0x30 Version Control Number
		('PartitionVerMin',	uint16_t),  	# 0x34
		('PartitionVerMaj',	uint16_t),  	# 0x36
		('DataFormatMinor',	uint16_t),		# 0x38
		('DataFormatMajor',	uint16_t),		# 0x3A
		('InstanceID', 		uint32_t),  	# 0x3C
		('Flags', 			uint32_t),  	# 0x40 Used at CSE_Ext_16 as well, remember to change both!
		('Reserved', 		uint32_t*4),  	# 0x44
		('Unknown', 		uint32_t),  	# 0x54 Unknown (>= 11.6.0.1109, 1 CSSPS, 3 CSME)
		# 0x58
	]
	
	# Used at $FPT size calculation as well, remember to change in case of new Extension Revision!
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10 = self.get_flags()
		
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'little'))
		Reserved = '%0.*X' % (0x10 * 2, int.from_bytes(self.Reserved, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 3, Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Partition Hash', Hash])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		pt.add_row(['Partition Version', '%X.%X' % (self.PartitionVerMaj, self.PartitionVerMin)])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Support Multiple Instances', fvalue[f1]])
		pt.add_row(['Support API Version Based Update', fvalue[f2]])
		pt.add_row(['Action On Update', '0x%X' % f3])
		pt.add_row(['Obey Full Update Rules', fvalue[f4]])
		pt.add_row(['IFR Enable Only', fvalue[f5]])
		pt.add_row(['Allow Cross Point Update', fvalue[f6]])
		pt.add_row(['Allow Cross Hotfix Update', fvalue[f7]])
		pt.add_row(['Partial Update Only', fvalue[f8]])
		pt.add_row(['Not Measured', fvalue[f9]])
		pt.add_row(['Flags Reserved', '0x%X' % f10])
		pt.add_row(['Reserved', '0x' + 'FF * 16' if Reserved == 'FF' * 16 else Reserved])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Ext_03_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SupportMultipleInstances, flags.b.SupportApiVersionBasedUpdate, flags.b.ActionOnUpdate, \
			   flags.b.ObeyFullUpdateRules, flags.b.IfrEnableOnly, flags.b.AllowCrossPointUpdate, flags.b.AllowCrossHotfixUpdate, \
			   flags.b.PartialUpdateOnly, flags.b.NotMeasured, flags.b.Reserved
			   
class CSE_Ext_03_R2(ctypes.LittleEndianStructure) : # R2 - Partition Information (MANIFEST_PARTITION_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('Hash',			uint32_t*12),	# 0x10 SHA-384, Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('VCN',				uint32_t),		# 0x40 Version Control Number
		('PartitionVerMin',	uint16_t),  	# 0x44
		('PartitionVerMaj',	uint16_t),  	# 0x46
		('DataFormatMinor',	uint16_t),		# 0x48
		('DataFormatMajor',	uint16_t),		# 0x4A
		('InstanceID', 		uint32_t),  	# 0x4C
		('Flags', 			uint32_t),  	# 0x50 Used at CSE_Ext_16 as well, remember to change both!
		('Reserved', 		uint32_t*4),  	# 0x54
		('Unknown', 		uint32_t),  	# 0x64 Unknown (>= 11.6.0.1109, 1 CSSPS, 3 CSME)
		# 0x68
	]
	
	# Used at $FPT size calculation as well, remember to change in case of new Extension Revision!
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10 = self.get_flags()
		
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'little'))
		Reserved = '%0.*X' % (0x10 * 2, int.from_bytes(self.Reserved, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 3, Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Partition Hash', Hash])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		pt.add_row(['Partition Version', '%X.%X' % (self.PartitionVerMaj, self.PartitionVerMin)])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Support Multiple Instances', fvalue[f1]])
		pt.add_row(['Support API Version Based Update', fvalue[f2]])
		pt.add_row(['Action On Update', '0x%X' % f3])
		pt.add_row(['Obey Full Update Rules', fvalue[f4]])
		pt.add_row(['IFR Enable Only', fvalue[f5]])
		pt.add_row(['Allow Cross Point Update', fvalue[f6]])
		pt.add_row(['Allow Cross Hotfix Update', fvalue[f7]])
		pt.add_row(['Partial Update Only', fvalue[f8]])
		pt.add_row(['Not Measured', fvalue[f9]])
		pt.add_row(['Flags Reserved', '0x%X' % f10])
		pt.add_row(['Reserved', '0x' + 'FF * 16' if Reserved == 'FF' * 16 else Reserved])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Ext_03_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SupportMultipleInstances, flags.b.SupportApiVersionBasedUpdate, flags.b.ActionOnUpdate, \
			   flags.b.ObeyFullUpdateRules, flags.b.IfrEnableOnly, flags.b.AllowCrossPointUpdate, flags.b.AllowCrossHotfixUpdate, \
			   flags.b.PartialUpdateOnly, flags.b.NotMeasured, flags.b.Reserved
	
class CSE_Ext_03_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('SupportMultipleInstances', uint32_t, 1), # For independently updated WCOD/LOCL partitions with multiple instances
		('SupportApiVersionBasedUpdate', uint32_t, 1),
		('ActionOnUpdate', uint32_t, 2),
		('ObeyFullUpdateRules', uint32_t, 1),
		('IfrEnableOnly', uint32_t, 1),
		('AllowCrossPointUpdate', uint32_t, 1),
		('AllowCrossHotfixUpdate', uint32_t, 1),
		('PartialUpdateOnly', uint32_t, 1),
		('NotMeasured', uint32_t, 1),
		('Reserved', uint32_t, 22)
	]

class CSE_Ext_03_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_03_Flags),
		('asbytes', uint32_t)
	]

class CSE_Ext_03_Mod(ctypes.LittleEndianStructure) : # R1 - Module Information (MANIFEST_MODULE_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("Type",			uint8_t),		# 0x0C 0 Process, 1 Shared Library, 2 Data, 3 Independent (MODULE_TYPES)
		("Compression",		uint8_t),		# 0x0D 0 None, 1 Huffman, 2 LZMA
		("Reserved",		uint16_t),		# 0x0E FFFF
		("MetadataSize",	uint32_t),		# 0x10
		("MetadataHash",	uint32_t*8),	# 0x14
		# 0x34
	]
	
	def ext_print(self) :
		Type = cse_mod_type[self.Type] if self.Type in cse_mod_type else 'Unknown (%d)' % self.Type
		MetadataHash = '%0.*X' % (0x20 * 2, int.from_bytes(self.MetadataHash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 3, Module Information' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', Type])
		pt.add_row(['Compression', ['None','Huffman','LZMA'][self.Compression]])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt

class CSE_Ext_04(ctypes.LittleEndianStructure) : # R1 - Shared Library Attributes (SHARED_LIB_EXTENSION)
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
		
		pt.title = col_y + 'Extension 4, Shared Library Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Context Size', '0x%X' % self.ContextSize])
		pt.add_row(['Total Allocated Virtual Space', '0x%X' % self.TotAlocVirtSpc])
		pt.add_row(['Code Base Address', '0x%X' % self.CodeBaseAddress])
		pt.add_row(['TLS Size', '0x%X' % self.TLSSize])
		pt.add_row(['Reserved', '0x0' if self.Reserved == 0 else '0x%X' % self.Reserved])
		
		return pt

class CSE_Ext_05(ctypes.LittleEndianStructure) : # R1 - Process Attributes (MAN_PROCESS_EXTENSION)
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
		# 0x44
	]
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1value = ['Reset System','Terminate Process']
		f1,f2,f3,f4,f5,f6,f7,f8 = self.get_flags()
		
		AllowedSysCalls = '%0.*X' % (0xC * 2, int.from_bytes(self.AllowedSysCalls, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 5, Process Attributes' + col_e
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
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Ext_05_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.FaultTolerant, flags.b.PermanentProcess, flags.b.SingleInstance, flags.b.TrustedSendReceiveSender,\
		       flags.b.TrustedNotifySender, flags.b.PublicSendReceiveReceiver, flags.b.PublicNotifyReceiver, flags.b.Reserved

class CSE_Ext_05_Mod(ctypes.LittleEndianStructure) : # R1 - Group ID (PROCESS_GROUP_ID)
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

class CSE_Ext_06(ctypes.LittleEndianStructure) : # R1 - Thread Attributes (Threads)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 6, Thread Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_06_Mod(ctypes.LittleEndianStructure) : # R1 - (Thread)
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

class CSE_Ext_07(ctypes.LittleEndianStructure) : # R1 - Device Types (DeviceIds)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 7, Devices' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_07_Mod(ctypes.LittleEndianStructure) : # R1 - (Device)
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
		
class CSE_Ext_07_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (Device)
	_pack_ = 1
	_fields_ = [
		("DeviceID",		uint32_t),		# 0x00
		# 0x04
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 7, Device' + col_e
		pt.add_row(['Device ID', '0x%0.8X' % self.DeviceID])
		
		return pt

class CSE_Ext_08(ctypes.LittleEndianStructure) : # R1 - MMIO Ranges (MmioRanges)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 8, MMIO Ranges' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_08_Mod(ctypes.LittleEndianStructure) : # R1 - (MmioRange)
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

class CSE_Ext_09(ctypes.LittleEndianStructure) : # R1 - Special File Producer (SPECIAL_FILE_PRODUCER_EXTENSION)
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

class CSE_Ext_09_Mod(ctypes.LittleEndianStructure) : # R1 - (SPECIAL_FILE_DEF)
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

class CSE_Ext_0A(ctypes.LittleEndianStructure) : # R1 - Module Attributes (MOD_ATTR_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Compression",		uint8_t),		# 0x08 0 None, 1 Huffman, 2 LZMA
		("Encryption",		uint8_t),		# 0x09 0 None, 1 AES-CBC (?)
		("Reserved0",		uint8_t),		# 0x0A
		("Reserved1",		uint8_t),		# 0x0B
		("SizeUncomp",		uint32_t),		# 0x0C
		("SizeComp",		uint32_t),		# 0x10 LZMA & Huffman w/o EOM alignment
		("DEV_ID",			uint16_t),		# 0x14
		("VEN_ID",			uint16_t),		# 0x16 0x8086
		("Hash",			uint32_t*8),	# 0x18 SHA-256 (Compressed for LZMA, Uncompressed for Huffman)
		# 0x38
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 10, Module Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Compression', ['None','Huffman','LZMA'][self.Compression]])
		pt.add_row(['Encryption', ['None','AES-CBC'][self.Encryption]])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['Device ID', '0x%0.4X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%0.4X' % self.VEN_ID])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class CSE_Ext_0A_R2(ctypes.LittleEndianStructure) : # R2 - Module Attributes (MOD_ATTR_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Compression',		uint8_t),		# 0x08 0 None, 1 Huffman, 2 LZMA
		('Encryption',		uint8_t),		# 0x09 0 None, 1 AES-ECB (?), 2 AES-CTR (?)
		('Reserved0',		uint8_t),		# 0x0A
		('Reserved1',		uint8_t),		# 0x0B
		('SizeUncomp',		uint32_t),		# 0x0C
		('SizeComp',		uint32_t),		# 0x10 LZMA & Huffman w/o EOM alignment
		('DEV_ID',			uint16_t),		# 0x14
		('VEN_ID',			uint16_t),		# 0x16 0x8086
		('Hash',			uint32_t*12),	# 0x18 SHA-384 (Compressed for LZMA, Uncompressed for Huffman)
		# 0x48
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 10, Module Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Compression', ['None','Huffman','LZMA'][self.Compression]])
		pt.add_row(['Encryption', ['None','AES-ECB','AES-CTR'][self.Encryption]])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['Device ID', '0x%0.4X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%0.4X' % self.VEN_ID])
		pt.add_row(['Hash', Hash])
		
		return pt

class CSE_Ext_0B(ctypes.LittleEndianStructure) : # R1 - Locked Ranges (LockedRanges)
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

class CSE_Ext_0B_Mod(ctypes.LittleEndianStructure) : # R1 - (LockedRange)
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

class CSE_Ext_0C(ctypes.LittleEndianStructure) : # R1 - Client System Information (CLIENT_SYSTEM_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("FWSKUCaps",		uint32_t),		# 0x08 (ConfigRuleSettings)
		("FWSKUCapsRes",	uint32_t*7),	# 0x0C
		("FWSKUAttrib",		uint64_t),		# 0x28
		# 0x30
	]
	
	def __init__(self, variant, major, minor, hotfix, build, year, month, variant_p, *args, **kwargs) :
		super().__init__(*args, **kwargs)
		self.variant = variant
		self.major = major
		self.minor = minor
		self.hotfix = hotfix
		self.build = build
		self.year = year
		self.month = month
		self.variant_p = variant_p
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8 = self.get_flags()
		sku_capabilities = self.get_skuc()
		sku_capabilities_pt = self.skuc_pt(sku_capabilities)
		
		FWSKUCapsRes = '%0.*X' % (0x1C * 2, int.from_bytes(self.FWSKUCapsRes, 'little'))
		
		if (self.variant,self.major) == ('CSME',11) and (self.minor > 0 or self.hotfix > 0 or (self.hotfix == 0 and self.build >= 1205 and self.build != 7101)) \
		or (self.variant,self.major,self.minor,self.hotfix) == ('CSME',12,0,0) and self.build >= 7000 and self.year < 0x2018 and self.month < 0x8 :
			sku_value = ['H','LP','Reserved','Reserved'][f6]
			sku_field = 'SKU Platform'
		else :
			sku_value = '0x%X' % f6
			sku_field = 'Reserved'
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 12, Client System Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['SKU Capabilities', sku_capabilities_pt])
		pt.add_row(['SKU Capabilities Reserved', 'FF * 28' if FWSKUCapsRes == 'FF' * 28 else FWSKUCapsRes])
		pt.add_row(['CSE Size', '0x%X' % f1])
		pt.add_row(['SKU Type', ext12_fw_sku[f2][0] if f2 in ext12_fw_sku else 'Unknown (%d)' % f2])
		pt.add_row(['Workstation', fvalue[f3]])
		pt.add_row(['M3', fvalue[f4]])
		pt.add_row(['M0', fvalue[f5]])
		pt.add_row([sku_field, sku_value])
		pt.add_row(['Si Class', '%d' % f7])
		pt.add_row(['Reserved', '0x0' if f8 == 0 else '0x%X' % f8])
		
		return pt
	
	def get_skuc(self) :
		sku_capabilities = []
		
		skuc_bits = list(format(self.FWSKUCaps, '032b'))
		skuc_bits.reverse()
		
		for sku_bit in range(len(skuc_bits)) :
			if skuc_bits[sku_bit] == '1' :
				sku_capabilities.append(skuc_dict[sku_bit] if sku_bit in skuc_dict else 'Unknown (%d)' % sku_bit)
		
		return sku_capabilities
		
	@staticmethod
	def skuc_pt(sku_capabilities) :
		skuc_print = ''
		
		for cap_idx in range(len(sku_capabilities)) :
			skuc_print += ('%s, \n' if cap_idx > 0 and cap_idx % 10 == 0 else '%s, ') % sku_capabilities[cap_idx]
		
		return skuc_print.strip(', ').strip(', \n') # Strip last comma
	
	def get_flags(self) :
		flags = CSE_Ext_0C_GetFWSKUAttrib()
		flags.asbytes = self.FWSKUAttrib
		
		return flags.b.CSESize, flags.b.SKUType, flags.b.Workstation, flags.b.M3, flags.b.M0,\
		       flags.b.SKUPlatform, flags.b.SiClass, flags.b.Reserved
	
class CSE_Ext_0C_FWSKUAttrib(ctypes.LittleEndianStructure):
	_fields_ = [
		('CSESize', uint64_t, 4), # CSESize * 0.5MB, always 0
		('SKUType', uint64_t, 3), # 0 COR, 1 CON, 2 SLM, 3 SVR
		('Workstation', uint64_t, 1), # 0 11.0-12, 1 11.20-22
		('M3', uint64_t, 1), # 0 CON & SLM, 1 COR
		('M0', uint64_t, 1), # 1 CON & SLM & COR
		('SKUPlatform', uint64_t, 2), # 0 H/LP <= 11.0.0.1202, 0 H & 1 LP >= 11.0.0.1205 (CSME 11 only)
		('SiClass', uint64_t, 4), # 2 CON & SLM, 4 COR (all, H, M, L)
		('Reserved', uint64_t, 50) # 0
	]

class CSE_Ext_0C_GetFWSKUAttrib(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_0C_FWSKUAttrib),
		('asbytes', uint64_t)
	]

class CSE_Ext_0D(ctypes.LittleEndianStructure) : # R1 - User Information (USER_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 13, User Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_0D_Mod(ctypes.LittleEndianStructure) : # R1 - (USER_INFO_ENTRY)
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

class CSE_Ext_0D_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (not in XML, Reverse Engineered)
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

class CSE_Ext_0E(ctypes.LittleEndianStructure) : # R1 - Key Manifest (KEY_MANIFEST_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("KeyType",			uint32_t),		# 0x08 1 RoT, 2 OEM (KeyManifestTypeValues)
		("KeySVN",			uint32_t),		# 0x0C
		("OEMID",			uint16_t),		# 0x10
		("KeyID",			uint8_t),		# 0x12 Matched against Field Programmable Fuses (FPF)
		("Reserved0",		uint8_t),		# 0x13
		("Reserved1",		uint32_t*4),	# 0x14
		# 0x24
	]
	
	def ext_print(self) :		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 14, Key Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Key Type', ['Reserved','RoT','OEM'][self.KeyType]])
		pt.add_row(['Key SVN', '%d' % self.KeySVN])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Key ID', '0x%0.2X' % self.KeyID])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % int.from_bytes(self.Reserved1, 'little')])
		
		return pt

class CSE_Ext_0E_Mod(ctypes.LittleEndianStructure) : # R1 - (KEY_MANIFEST_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		("UsageBitmap",		uint8_t*16),	# 0x00 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		("Reserved0",		uint32_t*4),	# 0x10
		("Flags",			uint8_t),		# 0x20
		("HashAlgorithm",	uint8_t),		# 0x21
		("HashSize",		uint16_t),		# 0x22
		("Hash",			uint32_t*8),	# 0x24 SHA-256 (Big Endian, PKEY + EXP)
		# 0x44
	]
	
	def ext_print(self) :
		f1,f2 = self.get_flags()
		hash_usages = get_key_usages(self.UsageBitmap)
		
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'big'))
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 14, Entry' + col_e
		pt.add_row(['Hash Usages', ', '.join(map(str, hash_usages))])
		pt.add_row(['Reserved 0', '0x%X' % int.from_bytes(self.Reserved0, 'little')])
		pt.add_row(['IPI Policy', ['OEM or Intel','Intel Only'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Modulus & Exponent Hash', Hash])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_0E_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.IPIPolicy, flags.b.Reserved
		
class CSE_Ext_0E_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (KEY_MANIFEST_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		("UsageBitmap",		uint8_t*16),	# 0x00 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		("Reserved0",		uint32_t*4),	# 0x10
		("Flags",			uint8_t),		# 0x20
		("HashAlgorithm",	uint8_t),		# 0x21
		("HashSize",		uint16_t),		# 0x22
		("Hash",			uint32_t*12),	# 0x24 SHA-384 (Big Endian, PKEY + EXP)
		# 0x54
	]
	
	def ext_print(self) :
		f1,f2 = self.get_flags()
		hash_usages = get_key_usages(self.UsageBitmap)
		
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'big'))
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 14, Entry' + col_e
		pt.add_row(['Hash Usages', ', '.join(map(str, hash_usages))])
		pt.add_row(['Reserved 0', '0x%X' % int.from_bytes(self.Reserved0, 'little')])
		pt.add_row(['IPI Policy', ['OEM or Intel','Intel Only'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Modulus & Exponent Hash', Hash])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_0E_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.IPIPolicy, flags.b.Reserved
	
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

class CSE_Ext_0F(ctypes.LittleEndianStructure) : # R1 - Signed Package Information (SIGNED_PACKAGE_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("PartitionName",	char*4),		# 0x08
		("VCN",				uint32_t),		# 0x0C Version Control Number
		("UsageBitmap",		uint8_t*16),	# 0x10 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		("ARBSVN",			uint32_t),		# 0x20 FPF Anti-Rollback (ARB) Security Version Number
		("Reserved",		uint32_t*4),  	# 0x24
		# 0x34
	]
	
	def ext_print(self) :
		hash_usages = get_key_usages(self.UsageBitmap)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Signed Package Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		pt.add_row(['Hash Usages', ', '.join(map(str, hash_usages))])
		pt.add_row(['ARB Security Version Number', '%d' % self.ARBSVN])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt
		
class CSE_Ext_0F_R2(ctypes.LittleEndianStructure) : # R2 - Signed Package Information (SIGNED_PACKAGE_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('VCN',				uint32_t),		# 0x0C Version Control Number
		('UsageBitmap',		uint8_t*16),	# 0x10 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		('ARBSVN',			uint32_t),		# 0x20 FPF Anti-Rollback (ARB) Security Version Number
		('FWType',			uint8_t),  		# 0x24 Bits 0-2 FW Type, 3-7 Reserved (FwTypeValues)
		('FWSKU',			uint8_t),  		# 0x25 Bits 0-2 FW SKU, 3-7 Reserved (FwSkuIdValues)
		('NVMCompatibility',uint32_t),  	# 0x26 Bits 0-1 NVM (00 Undefined, 01 UFS, 10 SPI, 11 Reserved), 2-31 Reserved
		('Reserved',		uint8_t*10),  	# 0x2A
		# 0x34
	]
	
	# FWType & FWSKU are also used by CSE_Ext_23 & GSC_Info_FWI, remember to change them as well!
	
	def ext_print(self) :
		f1,f2,f3,f4,f5,f6 = self.get_flags()
		hash_usages = get_key_usages(self.UsageBitmap)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Signed Package Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		pt.add_row(['Hash Usages', ', '.join(map(str, hash_usages))])
		pt.add_row(['ARB Security Version Number', '%d' % self.ARBSVN])
		pt.add_row(['Firmware Type', ext15_fw_type[f1] if f1 in ext15_fw_type else 'Unknown (%d)' % f1])
		pt.add_row(['Firmware Type Reserved', '0x%X' % f2])
		pt.add_row(['Firmware SKU', ext15_fw_sku[f3][0] if f3 in ext15_fw_sku else 'Unknown (%d)' % f3])
		pt.add_row(['Firmware SKU Reserved', '0x%X' % f4])
		pt.add_row(['NVM Compatibility', ext15_nvm_type[f5] if f5 in ext15_nvm_type else 'Unknown (%d)' % f5])
		pt.add_row(['NVM Compatibility Reserved', '0x%X' % f6])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt
	
	def get_flags(self) :
		fw_type = CSE_Ext_0F_R2_GetFWType()
		fw_type.asbytes = self.FWType
		fw_sub_type = CSE_Ext_0F_R2_GetFWSKU()
		fw_sub_type.asbytes = self.FWSKU
		nvm_compatibility = CSE_Ext_0F_R2_GetNVMCompatibility()
		nvm_compatibility.asbytes = self.NVMCompatibility
		
		return fw_type.b.FWType, fw_type.b.Reserved, fw_sub_type.b.FWSKU, fw_sub_type.b.Reserved, \
			   nvm_compatibility.b.NVMCompatibility, nvm_compatibility.b.Reserved

class CSE_Ext_0F_R2_FWType(ctypes.LittleEndianStructure):
	_fields_ = [
		('FWType', uint8_t, 3),
		('Reserved', uint8_t, 5)
	]

class CSE_Ext_0F_R2_GetFWType(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_0F_R2_FWType),
		('asbytes', uint8_t)
	]
	
class CSE_Ext_0F_R2_FWSKU(ctypes.LittleEndianStructure):
	_fields_ = [
		('FWSKU', uint8_t, 3),
		('Reserved', uint8_t, 5)
	]

class CSE_Ext_0F_R2_GetFWSKU(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_0F_R2_FWSKU),
		('asbytes', uint8_t)
	]
	
class CSE_Ext_0F_R2_NVMCompatibility(ctypes.LittleEndianStructure):
	_fields_ = [
		('NVMCompatibility', uint32_t, 2),
		('Reserved', uint32_t, 30)
	]

class CSE_Ext_0F_R2_GetNVMCompatibility(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_0F_R2_NVMCompatibility),
		('asbytes', uint32_t)
	]

class CSE_Ext_0F_Mod(ctypes.LittleEndianStructure) : # R1 - (SIGNED_PACKAGE_INFO_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("Type",			uint8_t),		# 0x0C 0 Process, 1 Shared Library, 2 Data, 3 Independent (MODULE_TYPES)
		("HashAlgorithm",	uint8_t),		# 0x0D 0 None, 1 SHA-1, 2 SHA-256
		("HashSize",		uint16_t),		# 0x0E
		("MetadataSize",	uint32_t),		# 0x10
		("MetadataHash",	uint32_t*8),	# 0x14 SHA-256
		# 0x34
	]
	
	def ext_print(self) :
		Type = cse_mod_type[self.Type] if self.Type in cse_mod_type else 'Unknown (%d)' % self.Type
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		MetadataHash = '%0.*X' % (0x20 * 2, int.from_bytes(self.MetadataHash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', Type])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt
		
class CSE_Ext_0F_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (SIGNED_PACKAGE_INFO_EXT_ENTRY, STRONG_SIGNED_PACKAGE_INFO_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		('Name',			char*12),		# 0x00
		('Type',			uint8_t),		# 0x0C 0 Process, 1 Shared Library, 2 Data, 3 Independent (MODULE_TYPES)
		('HashAlgorithm',	uint8_t),		# 0x0D 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint16_t),		# 0x0E
		('MetadataSize',	uint32_t),		# 0x10
		('MetadataHash',	uint32_t*12),	# 0x14 SHA-384
		# 0x44
	]
	
	def ext_print(self) :
		Type = cse_mod_type[self.Type] if self.Type in cse_mod_type else 'Unknown (%d)' % self.Type
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		MetadataHash = '%0.*X' % (0x30 * 2, int.from_bytes(self.MetadataHash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', Type])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt
		
class CSE_Ext_0F_Mod_R3(ctypes.LittleEndianStructure) : # R3 - (SIGNED_PACKAGE_INFO_EXT_ENTRY, STRONG_SIGNED_PACKAGE_INFO_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		('Name',			char*12),		# 0x00
		('Type',			uint8_t),		# 0x0C 0 Process, 1 Shared Library, 2 Data, 3 Independent (MODULE_TYPES)
		('ModuleSVN',		uint8_t),		# 0x0D
		('HashSize',		uint16_t),		# 0x0E
		('MetadataSize',	uint32_t),		# 0x10
		('MetadataHash',	uint32_t*12),	# 0x14 SHA-384
		# 0x44
	]
	
	def ext_print(self) :
		Type = cse_mod_type[self.Type] if self.Type in cse_mod_type else 'Unknown (%d)' % self.Type
		MetadataHash = '%0.*X' % (0x30 * 2, int.from_bytes(self.MetadataHash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', Type])
		pt.add_row(['Module SVN', self.ModuleSVN])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt

class CSE_Ext_10(ctypes.LittleEndianStructure) : # R1 - Anti-Cloning SKU ID (iUnit/IUNP/IUNM, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Type',			uint32_t),		# 0x08 1 = BootLoader (IUNP), 2 = Firmware (IUNM)
		('Reserved',		uint32_t*4),	# 0x0C
		# 0x1C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		types = {1:'BootLoader', 2:'Firmware'}
		
		pt.title = col_y + 'Extension 16, Anti-Cloning SKU ID' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Type', types[self.Type] if self.Type in types else 'Unknown'])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt
		
class CSE_Ext_10_Mod(ctypes.LittleEndianStructure) : # R1 - Anti-Cloning SKU ID Chunk (iUnit/IUNP/IUNM, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Chunk',			uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Day',				uint8_t),		# 0x08
		('Month',			uint8_t),		# 0x09
		('Year',			uint16_t),		# 0x0A
		('Hash',			uint32_t*8),	# 0x0C SHA-256 Big Endian
		('Unknown0',		uint32_t),		# 0x2C
		('Unknown1',		uint32_t),		# 0x30 Base Address ? (start of Chunk)
		('Reserved',		uint32_t*4),	# 0x34
		# 0x44
	]
	
	def ext_print(self) :
		Date = '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'big'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 16, Anti-Cloning SKU ID Chunk' + col_e
		pt.add_row(['Number', '%d' % self.Chunk])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Date', Date])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt
		
class CSE_Ext_10_Mod_R2(ctypes.LittleEndianStructure) : # R2 - Anti-Cloning SKU ID Chunk (iUnit/IUNP, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Chunk',			uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Day',				uint8_t),		# 0x08
		('Month',			uint8_t),		# 0x09
		('Year',			uint16_t),		# 0x0A
		('Hash',			uint32_t*12),	# 0x0C SHA-384 Big Endian
		('Unknown0',		uint32_t),		# 0x3C
		('Unknown1',		uint32_t),		# 0x40 Base Address ? (start of Chunk)
		('Reserved',		uint32_t*4),	# 0x44
		# 0x54
	]
	
	def ext_print(self) :
		Date = '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'big'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 16, Anti-Cloning SKU ID Chunk' + col_e
		pt.add_row(['Number', '%d' % self.Chunk])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Date', Date])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt

class CSE_Ext_11(ctypes.LittleEndianStructure) : # R1 - cAVS (ADSP, sof_ri_info.py)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('IMRType',			uint32_t),		# 0x08
		('Reserved',		uint32_t*6),	# 0x0C
		('Version',			uint32_t),		# 0x24
		('Hash',			uint32_t*8),	# 0x28 SHA-256 Big Endian
		('OffsetBase',		uint32_t),		# 0x48
		('OffsetLimit',		uint32_t),		# 0x4C OffsetLimit - OffsetBase = Actual ($CPD) Size
		('Attributes',		uint32_t*4),	# 0x50
		# 0x60
	]
	
	# https://thesofproject.github.io/latest/developer_guides/debugability/ri-info/index.html
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'big'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 17, Clear Audio Voice Speech (aDSP)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['IMR Type', '0x%X' % self.IMRType])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		pt.add_row(['Version', '0x%X' % self.Version])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Offset Base', '0x%X' % self.OffsetBase])
		pt.add_row(['Offset Limit', '0x%X' % self.OffsetLimit])
		pt.add_row(['Attributes', '0x%X' % int.from_bytes(self.Attributes, 'little')])
		
		return pt
		
class CSE_Ext_11_R2(ctypes.LittleEndianStructure) : # R2 - cAVS (ADSP, sof_ri_info.py)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('IMRType',			uint32_t),		# 0x08
		('Reserved',		uint32_t*6),	# 0x0C
		('Version',			uint32_t),		# 0x24
		('Hash',			uint32_t*12),	# 0x28 SHA-384 Big Endian
		('OffsetBase',		uint32_t),		# 0x58
		('OffsetLimit',		uint32_t),		# 0x5C OffsetLimit - OffsetBase = Actual ($CPD) Size
		('Attributes',		uint32_t*4),	# 0x60
		# 0x70
	]
	
	# https://thesofproject.github.io/latest/developer_guides/debugability/ri-info/index.html
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'big'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 17, Clear Audio Voice Speech (aDSP)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['IMR Type', '0x%X' % self.IMRType])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		pt.add_row(['Version', '0x%X' % self.Version])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Offset Base', '0x%X' % self.OffsetBase])
		pt.add_row(['Offset Limit', '0x%X' % self.OffsetLimit])
		pt.add_row(['Attributes', '0x%X' % int.from_bytes(self.Attributes, 'little')])
		
		return pt
		
class CSE_Ext_12(ctypes.LittleEndianStructure) : # R1 - Isolated Memory Ranges (FTPR, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("ModuleCount",		uint32_t),		# 0x08 Range Count
		("Reserved",		uint32_t*4),	# 0x0C
		# 0x1C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 18, Isolated Memory Ranges' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Module Count', '%d' % self.ModuleCount])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt

class CSE_Ext_12_Mod(ctypes.LittleEndianStructure) : # R1 - (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint32_t),		# 0x00
		('Unknown1',		uint32_t),		# 0x04
		('Unknown2',		uint32_t),		# 0x08
		('Unknown3',		uint32_t),		# 0x0C
		('Unknown4',		uint64_t),		# 0x10
		('Unknown5',		uint32_t),		# 0x18
		('Unknown6',		uint32_t),		# 0x1C
		('Unknown7',		uint64_t),		# 0x20
		('Unknown8',		uint32_t),		# 0x28
		('Unknown9',		uint32_t),		# 0x2C
		('Unknown10',		uint64_t),		# 0x30
		# 0x38
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 18, Isolated Memory Range' + col_e
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Unknown 2', '0x%X' % self.Unknown2])
		pt.add_row(['Unknown 3', '0x%X' % self.Unknown3])
		pt.add_row(['Unknown 4', '0x%X' % self.Unknown4])
		pt.add_row(['Unknown 5', '0x%X' % self.Unknown5])
		pt.add_row(['Unknown 6', '0x%X' % self.Unknown6])
		pt.add_row(['Unknown 7', '0x%X' % self.Unknown7])
		pt.add_row(['Unknown 8', '0x%X' % self.Unknown8])
		pt.add_row(['Unknown 9', '0x%X' % self.Unknown9])
		pt.add_row(['Unknown 10', '0x%X' % self.Unknown10])
		
		return pt

class CSE_Ext_13(ctypes.LittleEndianStructure) : # R1 - Boot Policy (BOOT_POLICY_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("IBBNEMSize",		uint32_t),		# 0x08 in 4K pages (NEM: No Evict Mode or CAR: Cache as RAM)
		("IBBLHashAlg",		uint32_t),		# 0x0C 0 None, 1 SHA-1, 2 SHA-256
		("IBBLHashSize",	uint32_t),		# 0x10
		("IBBLHash",		uint32_t*8),	# 0x14 Big Endian
		("IBBHashAlg",		uint32_t),		# 0x34 0 None, 1 SHA-1, 2 SHA-256
		("IBBHashSize",		uint32_t),		# 0x38
		("IBBHash",			uint32_t*8),	# 0x3C Big Endian
		("OBBHashAlg",		uint32_t),		# 0x5C 0 None, 1 SHA-1, 2 SHA-256
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
		IBBLHash = '%0.*X' % (0x20 * 2, int.from_bytes(self.IBBLHash, 'big'))
		IBBHash = '%0.*X' % (0x20 * 2, int.from_bytes(self.IBBHash, 'big'))
		OBBHash = '%0.*X' % (0x20 * 2, int.from_bytes(self.OBBHash, 'big'))
		IBBLHashAlg = cse_hash_alg[self.IBBLHashAlg] if self.IBBLHashAlg in cse_hash_alg else 'Unknown (%d)' % self.IBBLHashAlg
		IBBHashAlg = cse_hash_alg[self.IBBHashAlg] if self.IBBHashAlg in cse_hash_alg else 'Unknown (%d)' % self.IBBHashAlg
		OBBHashAlg = cse_hash_alg[self.OBBHashAlg] if self.OBBHashAlg in cse_hash_alg else 'Unknown (%d)' % self.OBBHashAlg
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 19, Boot Policy' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['No Evict Mode Size', '0x%X' % (self.IBBNEMSize * 4096)])
		pt.add_row(['IBBL Hash Algorithm', IBBLHashAlg])
		pt.add_row(['IBBL Hash Size', '0x%X' % self.IBBLHashSize])
		pt.add_row(['IBBL Hash', IBBLHash])
		pt.add_row(['IBB Hash Algorithm', IBBHashAlg])
		pt.add_row(['IBB Hash Size', '0x%X' % self.IBBHashSize])
		pt.add_row(['IBB Hash', IBBHash])
		pt.add_row(['OBB Hash Algorithm', OBBHashAlg])
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
		
class CSE_Ext_13_R2(ctypes.LittleEndianStructure) : # R2 - Boot Policy (BOOT_POLICY_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("IBBNEMSize",		uint32_t),		# 0x08 in 4K pages (NEM: No Evict Mode or CAR: Cache as RAM)
		("IBBLHashAlg",		uint32_t),		# 0x0C 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		("IBBLHashSize",	uint32_t),		# 0x10
		("IBBLHash",		uint32_t*12),	# 0x14 Big Endian
		("IBBHashAlg",		uint32_t),		# 0x44 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		("IBBHashSize",		uint32_t),		# 0x48
		("IBBHash",			uint32_t*12),	# 0x4C Big Endian
		("OBBHashAlg",		uint32_t),		# 0x7C 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		("OBBHashSize",		uint32_t),		# 0x80
		("OBBHash",			uint32_t*12),	# 0x84 Big Endian
		("IBBFlags",		uint32_t),		# 0xB4 Unknown/Unused
		("IBBMCHBar",		uint64_t),		# 0xB8
		("IBBVTDBar",		uint64_t),		# 0xC0
		("PMRLBase",		uint32_t),		# 0xC8
		("PMRLLimit",		uint32_t),		# 0xCC
		("PMRHBase",		uint32_t),		# 0xD0
		("PMRHLimit",		uint32_t),		# 0xD4
		("IBBEntryPoint",	uint32_t),		# 0xD8
		("IBBSegmentCount",	uint32_t),		# 0xDC
		("VendorAttrSize",	uint32_t),		# 0xE0
		# 0xE4
	]
	
	def ext_print(self) :
		IBBLHash = '%0.*X' % (0x30 * 2, int.from_bytes(self.IBBLHash, 'big'))
		IBBHash = '%0.*X' % (0x30 * 2, int.from_bytes(self.IBBHash, 'big'))
		OBBHash = '%0.*X' % (0x30 * 2, int.from_bytes(self.OBBHash, 'big'))
		IBBLHashAlg = cse_hash_alg[self.IBBLHashAlg] if self.IBBLHashAlg in cse_hash_alg else 'Unknown (%d)' % self.IBBLHashAlg
		IBBHashAlg = cse_hash_alg[self.IBBHashAlg] if self.IBBHashAlg in cse_hash_alg else 'Unknown (%d)' % self.IBBHashAlg
		OBBHashAlg = cse_hash_alg[self.OBBHashAlg] if self.OBBHashAlg in cse_hash_alg else 'Unknown (%d)' % self.OBBHashAlg
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 19, Boot Policy' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['No Evict Mode Size', '0x%X' % (self.IBBNEMSize * 4096)])
		pt.add_row(['IBBL Hash Algorithm', IBBLHashAlg])
		pt.add_row(['IBBL Hash Size', '0x%X' % self.IBBLHashSize])
		pt.add_row(['IBBL Hash', IBBLHash])
		pt.add_row(['IBB Hash Algorithm', IBBHashAlg])
		pt.add_row(['IBB Hash Size', '0x%X' % self.IBBHashSize])
		pt.add_row(['IBB Hash', IBBHash])
		pt.add_row(['OBB Hash Algorithm', OBBHashAlg])
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

class CSE_Ext_14(ctypes.LittleEndianStructure) : # R1 - DnX Manifest (DnxManifestExtension)
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
		PublicKey = '%0.*X' % (0x100 * 2, int.from_bytes(self.PublicKey, 'little'))
		
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
		pt.add_row(['Machine ID', '0x%X' % int.from_bytes(self.MachineID, 'little')])
		pt.add_row(['Salt ID', '0x%0.8X' % self.SaltID])
		pt.add_row(['Public Key', '%s [...]' % PublicKey[:8]])
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

class CSE_Ext_14_R2(ctypes.LittleEndianStructure) : # R2 - DnX Manifest (DnxManifestExtension_ver2)
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
		PublicKey = '%0.*X' % (0x100 * 2, int.from_bytes(self.PublicKey, 'little'))
		HashArrHashAlg = cse_hash_alg[self.HashArrHashAlg] if self.HashArrHashAlg in cse_hash_alg else 'Unknown (%d)' % self.HashArrHashAlg
		ChunkHashAlg = cse_hash_alg[self.ChunkHashAlg] if self.ChunkHashAlg in cse_hash_alg else 'Unknown (%d)' % self.ChunkHashAlg
		
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
		pt.add_row(['Machine ID', '0x%X' % int.from_bytes(self.MachineID, 'little')])
		pt.add_row(['Salt ID', '0x%0.8X' % self.SaltID])
		pt.add_row(['Public Key', '%s [...]' % PublicKey[:8]])
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
		pt.add_row(['Hashes Array Hash Algorithm', HashArrHashAlg])
		pt.add_row(['Hashes Array Hash Size', '0x%X' % self.HashArrHashSize])
		pt.add_row(['IFWI Chunk Hash Algorithm', ChunkHashAlg])
		pt.add_row(['Reserved 7', '0x%X' % self.Reserved7])
		pt.add_row(['Reserved 8', '0x%X' % self.Reserved8])
		pt.add_row(['Reserved 9', '0x%X' % self.Reserved9])
		pt.add_row(['IFWI Chunk Hash Size', '0x%X' % self.ChunkHashSize])
		pt.add_row(['Reserved 10', '0x%X' % self.Reserved10])
		pt.add_row(['Reserved 11', '0x%X' % self.Reserved11])
		pt.add_row(['IFWI Chunk Data Size', '0x%X' % self.ChunkSize])
		
		return pt
		
class CSE_Ext_14_R3(ctypes.LittleEndianStructure) : # R3 - DnX Manifest (DnxManifestExtension_ver2)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Minor',			uint8_t),		# 0x08
		('Major',			uint8_t),		# 0x09
		('Reserved0',		uint8_t),		# 0x0A
		('Reserved1',		uint8_t),		# 0x0B
		('OEMID',			uint16_t),		# 0x0C
		('PlatformID',		uint16_t),		# 0x0E
		('MachineID',		uint32_t*4),	# 0x10
		('SaltID',			uint32_t),		# 0x20
		('PublicKey',		uint32_t*96),	# 0x24
		('PublicExponent',	uint32_t),		# 0x1A4
		('IFWIRegionCount',	uint32_t),		# 0x1A8 Number of eMMC/UFS components (LBPs)
		('Flags',			uint32_t),		# 0x1AC Unknown/Unused
		('Reserved2',		uint8_t),		# 0x1AD
		('Reserved3',		uint8_t),		# 0x1AE
		('Reserved4',		uint8_t),		# 0x1AF
		('Reserved5',		uint8_t),		# 0x1B0
		('HashArrHdrMajor',	uint8_t),		# 0x1B1
		('HashArrHdrMinor',	uint8_t),		# 0x1B2
		('HashArrHdrCount',	uint16_t),		# 0x1B3
		('Reserved6',		uint8_t),		# 0x1B5
		('HashArrHashAlg',	uint8_t),		# 0x1B6 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashArrHashSize',	uint16_t),		# 0x1B7
		('ChunkHashAlg',	uint8_t),		# 0x1B9 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('Reserved7',		uint8_t),		# 0x1BA
		('Reserved8',		uint8_t),		# 0x1BB
		('Reserved9',		uint8_t),		# 0x1BC
		('ChunkHashSize',	uint16_t),		# 0x1BD
		('Reserved10',		uint8_t),		# 0x1BF
		('Reserved11',		uint8_t),		# 0x1C0
		('ChunkSize',		uint32_t),		# 0x1C4 0x10000 (64KB)
		# 0x1C8
	]
	
	def ext_print(self) :
		PublicKey = '%0.*X' % (0x180 * 2, int.from_bytes(self.PublicKey, 'little'))
		HashArrHashAlg = cse_hash_alg[self.HashArrHashAlg] if self.HashArrHashAlg in cse_hash_alg else 'Unknown (%d)' % self.HashArrHashAlg
		ChunkHashAlg = cse_hash_alg[self.ChunkHashAlg] if self.ChunkHashAlg in cse_hash_alg else 'Unknown (%d)' % self.ChunkHashAlg
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 20 R3, DnX Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minor', '%d' % self.Minor])
		pt.add_row(['Major', '%d' % self.Major])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Platform ID', '0x%0.4X' % self.PlatformID])
		pt.add_row(['Machine ID', '0x%X' % int.from_bytes(self.MachineID, 'little')])
		pt.add_row(['Salt ID', '0x%0.8X' % self.SaltID])
		pt.add_row(['Public Key', '%s [...]' % PublicKey[:8]])
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
		pt.add_row(['Hashes Array Hash Algorithm', HashArrHashAlg])
		pt.add_row(['Hashes Array Hash Size', '0x%X' % self.HashArrHashSize])
		pt.add_row(['IFWI Chunk Hash Algorithm', ChunkHashAlg])
		pt.add_row(['Reserved 7', '0x%X' % self.Reserved7])
		pt.add_row(['Reserved 8', '0x%X' % self.Reserved8])
		pt.add_row(['Reserved 9', '0x%X' % self.Reserved9])
		pt.add_row(['IFWI Chunk Hash Size', '0x%X' % self.ChunkHashSize])
		pt.add_row(['Reserved 10', '0x%X' % self.Reserved10])
		pt.add_row(['Reserved 11', '0x%X' % self.Reserved11])
		pt.add_row(['IFWI Chunk Data Size', '0x%X' % self.ChunkSize])
		
		return pt

class CSE_Ext_14_HashArray(ctypes.LittleEndianStructure) : # R1 - DnX R2 Hashes Array (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("HashArrSize",		uint32_t),		# 0x0 dwords
		("HashArrHash",		uint32_t*8),	# 0x4 SHA-256
		# 0x24
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		HashArrHash = '%0.*X' % (0x20 * 2, int.from_bytes(self.HashArrHash, 'little'))
		
		pt.title = col_y + 'Extension 20 R2, Hashes Array' + col_e
		pt.add_row(['Hashes Array Size', '0x%X' % (self.HashArrSize * 4)])
		pt.add_row(['Hashes Array Hash', HashArrHash])
		
		return pt
		
class CSE_Ext_14_HashArray_R2(ctypes.LittleEndianStructure) : # R2 - DnX R2 Hashes Array (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("HashArrSize",		uint32_t),		# 0x0 dwords
		("HashArrHash",		uint32_t*12),	# 0x4 SHA-384
		# 0x34
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		HashArrHash = '%0.*X' % (0x30 * 2, int.from_bytes(self.HashArrHash, 'little'))
		
		pt.title = col_y + 'Extension 20 R2, Hashes Array' + col_e
		pt.add_row(['Hashes Array Size', '0x%X' % (self.HashArrSize * 4)])
		pt.add_row(['Hashes Array Hash', HashArrHash])
		
		return pt
		
class CSE_Ext_14_RegionMap(ctypes.LittleEndianStructure) : # R1 - DnX R1/R2 Region Map (not in XML, Reverse Engineered)
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

class CSE_Ext_15(ctypes.LittleEndianStructure) : # R1 - Unlock/Secure Token UTOK/STKN (SECURE_TOKEN_EXT)
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
					2: 'IDLM Unlock', # Intel Debug Launch Module
					3: 'OEM Unlock',
					4: 'PAVP Unlock',
					5: 'Visa Override',
					8: 'Change Device Lifecycle'
					}
		f1,f2,f3,f4,f5,f6,f7 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Unlock/Secure Token' + col_e
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
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
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

class CSE_Ext_15_PartID(ctypes.LittleEndianStructure) : # After CSE_Ext_15 (SECURE_TOKEN_PARTID)
	_pack_ = 1
	_fields_ = [
		("PartID",			uint32_t*3),	# 0x00
		("Nonce",			uint32_t),		# 0x0C
		("TimeBase",		uint32_t),		# 0x10
		# 0x14
	]
	
	def ext_print(self) :		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Part ID' + col_e
		pt.add_row(['Part ID', '0x%X' % int.from_bytes(self.PartID, 'little')])
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
		("ID",			uint32_t),			# 0x00 (KnobIdValues)
		("Data",		uint32_t),			# 0x04
		# 0x08
	]
	
	def __init__(self, variant, major, minor, hotfix, build, year, month, variant_p, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.variant = variant
		self.major = major
		self.minor = minor
		self.hotfix = hotfix
		self.build = build
		self.year = year
		self.month = month
		self.variant_p = variant_p
	
	def ext_print(self) :
		knob_ids = {
			0x80860001 : ['Intel Unlock', ['None', 'Intel/RED', 'DAM']],
			0x80860002 : ['OEM Unlock', ['None', 'OEM/ORANGE', 'DAM']],
			0x80860003 : ['PAVP Unlock', ['Disabled', 'Enabled']],
			0x80860010 : ['Allow Visa Override', ['Disabled', 'Enabled']],
			0x80860011 : ['Enable DCI', ['No', 'Yes']],
			0x80860020 : ['ISH GDB Support', ['Disabled', 'Enabled']],
			0x80860030 : ['Boot Guard & CPU Run Control', ['Nothing', 'Disabled', 'No Enforcement', 'No Timeouts', 'No Enforcement & Timeouts']] \
			if self.variant == 'CSME' and self.major >= 12 else ['BIOS Secure Boot', ['Enforced', 'Allow RnD Keys & Policies', 'Disabled']],
			0x80860031 : ['Audio FW Authentication', ['Enforced', 'Allow RnD Keys', 'Disabled']],
			0x80860032 : ['ISH FW Authentication', ['Enforced', 'Allow RnD Keys', 'Disabled']],
			0x80860033 : ['IUNIT FW Authentication', ['Enforced', 'Allow RnD Keys', 'Disabled']],
			0x80860040 : ['Anti-Rollback', ['Enabled', 'Disabled']], # (BtGuardArbOemKeyManifest)
			0x80860050 : ['PSF and System Agent Debug', ['PSF & System Agent Disabled', 'System Agent Enabled', 'PSF Enabled', 'PSF & System Agent Enabled']], # (KnobIdValues)
			0x80860051 : ['OEM BIOS Payload', ['Disabled', 'Enabled']], # (KnobIdValues, lkf_knobs_values)
			0x80860052 : ['Intel BIOS Payload', ['Disabled', 'Enabled']], # (lkf_knobs_values)
			0x80860060 : ['Debug/CDF Unlock', ['Disabled', 'Enabled']], # (bxt_knobs_values)
			0x80860070 : ['Cancel OEM Signing', {0: 'Do Nothing', 0xFFFFFFFF: 'Cancel'}],
			0x80860075 : ['CSE Tracing', {1: 'Enabled', 4: 'Disabled'}], # (lkf_knobs_values)
			0x80860080 : ['Debug Interface (USB2.DBC)', ['Disabled', 'Enabled']], # (bxt_knobs_values)
			0x80860090 : ['Authorized Debug (JTAG)', {1: 'Temporary re-enable TAP network', 16: 'Temporary re-enable BSCAN',
													  17: 'Temporary re-enable TAP network and BSCAN', 256: 'Permanently re-enable TAP network and BSCAN'}], # (bxt_knobs_values)
			0x80860101 : ['DnX Capabilities', ['Get NVM Properties', 'NVM Configuration', 'Clear Platform Configuration', 'Write NVM Content', 'Read NVM Content']] \
			if (self.variant == 'CSME' and self.major >= 15 or self.variant == 'CSTXE' and self.major >= 5 or self.variant == 'CSSPS' and self.major >= 6) else \
			['Change Device Lifecycle', ['No', 'Customer Care', 'RnD', 'Refurbish']],
			0x80860201 : ['Co-Signing', ['Enabled', 'Disabled']]
			}
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Payload Knob' + col_e
		pt.add_row(['ID', knob_ids[self.ID][0] if self.ID in knob_ids else 'Unknown: 0x%X' % self.ID])
		pt.add_row(['Data', knob_ids[self.ID][1][self.Data] if self.ID in knob_ids else 'Unknown: 0x%X' % self.Data])
		
		return pt

class CSE_Ext_16(ctypes.LittleEndianStructure) : # R1 - IFWI Partition Information (IFWI_PARTITION_MANIFEST_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('PartitionVerMin',	uint16_t),		# 0x10
		('PartitionVerMaj',	uint16_t),		# 0x12
		('DataFormatMinor',	uint16_t),		# 0x14
		('DataFormatMajor',	uint16_t),		# 0x16
		('InstanceID',		uint32_t),		# 0x18
		('Flags',			uint32_t),		# 0x1C Used at CSE_Ext_03 as well, remember to change both!
		('HashAlgorithm',	uint8_t),		# 0x20 0 None, 1 SHA-1, 2 SHA-256
		('HashSize',		uint8_t*3),		# 0x21
		('Hash',			uint32_t*8),	# 0x24 Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('FlagsPrivate',	uint32_t),		# 0x44
		('Reserved',		uint32_t*4),	# 0x48
		# 0x58
	]
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12 = self.get_flags()
		
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'little'))
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 22, IFWI Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Partition Version', '%X.%X' % (self.PartitionVerMaj, self.PartitionVerMin)])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Support Multiple Instances', fvalue[f1]])
		pt.add_row(['Support API Version Based Update', fvalue[f2]])
		pt.add_row(['Action On Update', '0x%X' % f3])
		pt.add_row(['Obey Full Update Rules', fvalue[f4]])
		pt.add_row(['IFR Enable Only', fvalue[f5]])
		pt.add_row(['Allow Cross Point Update', fvalue[f6]])
		pt.add_row(['Allow Cross Hotfix Update', fvalue[f7]])
		pt.add_row(['Partial Update Only', fvalue[f8]])
		pt.add_row(['Not Measured', fvalue[f9]])
		pt.add_row(['Flags Reserved', '0x%X' % f10])
		pt.add_row(['Hash Type', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % int.from_bytes(self.HashSize, 'little')])
		pt.add_row(['Partition Hash', Hash])
		pt.add_row(['Ignore FWU Disable Policy', fvalue[f11]])
		pt.add_row(['Flags Private Reserved', '0x%X' % f12])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_16_GetFlags()
		flags_p = CSE_Ext_16_GetFlagsPrivate()
		flags.asbytes = self.Flags
		flags_p.asbytes = self.FlagsPrivate
		
		return flags.b.SupportMultipleInstances, flags.b.SupportApiVersionBasedUpdate, flags.b.ActionOnUpdate, \
			   flags.b.ObeyFullUpdateRules, flags.b.IfrEnableOnly, flags.b.AllowCrossPointUpdate, flags.b.AllowCrossHotfixUpdate, \
			   flags.b.PartialUpdateOnly, flags.b.NotMeasured, flags.b.Reserved, flags_p.b.IgnoreFwuDisablePolicy, flags_p.b.Reserved

class CSE_Ext_16_R2(ctypes.LittleEndianStructure) : # R2 - IFWI Partition Information (IFWI_PARTITION_MANIFEST_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('PartitionVerMin',	uint16_t),		# 0x10
		('PartitionVerMaj',	uint16_t),		# 0x12
		('DataFormatMinor',	uint16_t),		# 0x14
		('DataFormatMajor',	uint16_t),		# 0x16
		('InstanceID',		uint32_t),		# 0x18
		('Flags',			uint32_t),		# 0x1C
		('HashAlgorithm',	uint8_t),		# 0x20 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint8_t*3),		# 0x21
		('Hash',			uint32_t*12),	# 0x24 Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('FlagsPrivate',	uint32_t),		# 0x54
		('Reserved',		uint32_t*4),	# 0x58
		# 0x68
	]
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12 = self.get_flags()
		
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'little'))
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 22, IFWI Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Partition Version', '%X.%X' % (self.PartitionVerMaj, self.PartitionVerMin)])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Support Multiple Instances', fvalue[f1]])
		pt.add_row(['Support API Version Based Update', fvalue[f2]])
		pt.add_row(['Action On Update', '0x%X' % f3])
		pt.add_row(['Obey Full Update Rules', fvalue[f4]])
		pt.add_row(['IFR Enable Only', fvalue[f5]])
		pt.add_row(['Allow Cross Point Update', fvalue[f6]])
		pt.add_row(['Allow Cross Hotfix Update', fvalue[f7]])
		pt.add_row(['Partial Update Only', fvalue[f8]])
		pt.add_row(['Not Measured', fvalue[f9]])
		pt.add_row(['Flags Reserved', '0x%X' % f10])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % int.from_bytes(self.HashSize, 'little')])
		pt.add_row(['Partition Hash', Hash])
		pt.add_row(['Ignore FWU Disable Policy', fvalue[f11]])
		pt.add_row(['Flags Private Reserved', '0x%X' % f12])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Ext_16_GetFlags()
		flags_p = CSE_Ext_16_GetFlagsPrivate()
		flags.asbytes = self.Flags
		flags_p.asbytes = self.FlagsPrivate
		
		return flags.b.SupportMultipleInstances, flags.b.SupportApiVersionBasedUpdate, flags.b.ActionOnUpdate, \
			   flags.b.ObeyFullUpdateRules, flags.b.IfrEnableOnly, flags.b.AllowCrossPointUpdate, flags.b.AllowCrossHotfixUpdate, \
			   flags.b.PartialUpdateOnly, flags.b.NotMeasured, flags.b.Reserved, flags_p.b.IgnoreFwuDisablePolicy, flags_p.b.Reserved
	
class CSE_Ext_16_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('SupportMultipleInstances', uint32_t, 1), # For independently updated WCOD/LOCL partitions with multiple instances
		('SupportApiVersionBasedUpdate', uint32_t, 1),
		('ActionOnUpdate', uint32_t, 2),
		('ObeyFullUpdateRules', uint32_t, 1),
		('IfrEnableOnly', uint32_t, 1),
		('AllowCrossPointUpdate', uint32_t, 1),
		('AllowCrossHotfixUpdate', uint32_t, 1),
		('PartialUpdateOnly', uint32_t, 1),
		('NotMeasured', uint32_t, 1),
		('Reserved', uint32_t, 22)
	]

class CSE_Ext_16_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_16_Flags),
		('asbytes', uint32_t)
	]
	
class CSE_Ext_16_FlagsPrivate(ctypes.LittleEndianStructure):
	_fields_ = [
		('IgnoreFwuDisablePolicy', uint32_t, 1),
		('Reserved', uint32_t, 31)
	]

class CSE_Ext_16_GetFlagsPrivate(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_16_FlagsPrivate),
		('asbytes', uint32_t)
	]

class CSE_Ext_17(ctypes.LittleEndianStructure) : # R1 - Flash Descriptor Hash (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Range1Start',		uint16_t),		# 0x08 Exclusion Range 1 (Intel, Manifest)
		('Range1End',		uint16_t),		# 0x0A
		('Range2Start',		uint16_t),		# 0x0C Exclusion Range 2 (OEM, Master Access)
		('Range2End',		uint16_t),		# 0x0E
		('Range3Start',		uint16_t),		# 0x10 Exclusion Range 3 (OEM, Custom)
		('Range3End',		uint16_t),		# 0x12
		('Range4Start',		uint16_t),		# 0x14 Exclusion Range 4 (OEM, Custom)
		('Range4End',		uint16_t),		# 0x16
		('Range5Start',		uint16_t),		# 0x18 Exclusion Range 5 (OEM, Custom)
		('Range5End',		uint16_t),		# 0x1A
		('Range6Start',		uint16_t),		# 0x1C Exclusion Range 6 (OEM, Custom)
		('Range6End',		uint16_t),		# 0x1E
		('Range7Start',		uint16_t),		# 0x20 Exclusion Range 7 (OEM, Custom)
		('Range7End',		uint16_t),		# 0x22
		('Range8Start',		uint16_t),		# 0x24 Exclusion Range 8 (OEM, Custom)
		('Range8End',		uint16_t),		# 0x26
		('Hash',			uint32_t*8),	# 0x28 SHA-256 LE
		# 0x48
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'little'))
		
		pt.title = col_y + 'Extension 23, Flash Descriptor Hash' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Range 1', '0x%X - 0x%X' % (self.Range1Start, self.Range1End)])
		pt.add_row(['Range 2', '0x%X - 0x%X' % (self.Range2Start, self.Range2End)])
		pt.add_row(['Range 3', '0x%X - 0x%X' % (self.Range3Start, self.Range3End)])
		pt.add_row(['Range 4', '0x%X - 0x%X' % (self.Range4Start, self.Range4End)])
		pt.add_row(['Range 5', '0x%X - 0x%X' % (self.Range5Start, self.Range5End)])
		pt.add_row(['Range 6', '0x%X - 0x%X' % (self.Range6Start, self.Range6End)])
		pt.add_row(['Range 7', '0x%X - 0x%X' % (self.Range7Start, self.Range7End)])
		pt.add_row(['Range 8', '0x%X - 0x%X' % (self.Range8Start, self.Range8End)])
		pt.add_row(['Hash', Hash])
		
		return pt
	
class CSE_Ext_17_R2(ctypes.LittleEndianStructure) : # R2 - Flash Descriptor Hash (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Range1Start',		uint16_t),		# 0x08 Exclusion Range 1 (Intel, Manifest)
		('Range1End',		uint16_t),		# 0x0A
		('Range2Start',		uint16_t),		# 0x0C Exclusion Range 2 (OEM, Master Access)
		('Range2End',		uint16_t),		# 0x0E
		('Range3Start',		uint16_t),		# 0x10 Exclusion Range 3 (OEM, Custom)
		('Range3End',		uint16_t),		# 0x12
		('Range4Start',		uint16_t),		# 0x14 Exclusion Range 4 (OEM, Custom)
		('Range4End',		uint16_t),		# 0x16
		('Range5Start',		uint16_t),		# 0x18 Exclusion Range 5 (OEM, Custom)
		('Range5End',		uint16_t),		# 0x1A
		('Range6Start',		uint16_t),		# 0x1C Exclusion Range 6 (OEM, Custom)
		('Range6End',		uint16_t),		# 0x1E
		('Range7Start',		uint16_t),		# 0x20 Exclusion Range 7 (OEM, Custom)
		('Range7End',		uint16_t),		# 0x22
		('Range8Start',		uint16_t),		# 0x24 Exclusion Range 8 (OEM, Custom)
		('Range8End',		uint16_t),		# 0x26
		('Hash',			uint32_t*12),	# 0x28 SHA-384 LE
		# 0x58
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'little'))
		
		pt.title = col_y + 'Extension 23, Flash Descriptor Hash' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Range 1', '0x%X - 0x%X' % (self.Range1Start, self.Range1End)])
		pt.add_row(['Range 2', '0x%X - 0x%X' % (self.Range2Start, self.Range2End)])
		pt.add_row(['Range 3', '0x%X - 0x%X' % (self.Range3Start, self.Range3End)])
		pt.add_row(['Range 4', '0x%X - 0x%X' % (self.Range4Start, self.Range4End)])
		pt.add_row(['Range 5', '0x%X - 0x%X' % (self.Range5Start, self.Range5End)])
		pt.add_row(['Range 6', '0x%X - 0x%X' % (self.Range6Start, self.Range6End)])
		pt.add_row(['Range 7', '0x%X - 0x%X' % (self.Range7Start, self.Range7End)])
		pt.add_row(['Range 8', '0x%X - 0x%X' % (self.Range8Start, self.Range8End)])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class CSE_Ext_18(ctypes.LittleEndianStructure) : # R1 - USB Type C IO Manageability (TCSS_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Reserved',		uint32_t),		# 0x08
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 24, USB Type C IO Manageability' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
class CSE_Ext_18_R2(ctypes.LittleEndianStructure) : # R2 - GSC IUP Manifests (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 24, GSC IUP Manifests' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
		
class CSE_Ext_18_Mod(ctypes.LittleEndianStructure) : # R1 - USB Type C IO Manageability Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 SHA-1, 1 SHA-256, 2 MD5
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*8),	# 0x0C SHA-256 Big Endian
		# 0x2C
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'big'))
		HashAlgorithm = tcs_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in tcs_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 24, USB Type C IO Manageability Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class CSE_Ext_18_Mod_R2(ctypes.LittleEndianStructure) : # R2 - USB Type C IO Manageability Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*12),	# 0x0C SHA-384 Big Endian
		# 0x3C
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'big'))
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 24, USB Type C IO Manageability Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class CSE_Ext_18_Mod_R3(ctypes.LittleEndianStructure) : # R3 - GSC IUP Manifest Hash (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Name',			char*4),		# 0x00
		('Hash',			uint32_t*12),	# 0x0C SHA-384 BE (Manifest w/o RSA)
		# 0x34
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'big'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 24, GSC IUP Manifest Hash' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Hash', Hash])
		
		return pt

class CSE_Ext_19(ctypes.LittleEndianStructure) : # R1 - USB Type C MG (TCSS_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Reserved',		uint32_t),		# 0x08
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 25, USB Type C MG' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
class CSE_Ext_19_R2(ctypes.LittleEndianStructure) : # R2 - GSC Project Info (gsc_fwu_external_version)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Project',			char*4),		# 0x08
		('Hotfix',			uint16_t),		# 0x0C Hotfix at DG1, SKU at DG2+
		('Build',			uint16_t),		# 0x0E Year & Week at DG1, Stepping/Build at DG2+
		# 0x10
	]
	
	# The version of the overall IFWI image, i.e. the combination of IPs (igsc_system.h)
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 25, GSC Project Info' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Project', self.Project.decode('utf-8')])
		pt.add_row(['Hotfix', self.Hotfix])
		pt.add_row(['Build', self.Build])
		
		return pt
		
class CSE_Ext_19_Mod(ctypes.LittleEndianStructure) : # R1 - USB Type C MG Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 SHA-1, 1 SHA-256, 2 MD5
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*8),	# 0x0C SHA-256 Big Endian
		# 0x2C
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'big'))
		HashAlgorithm = tcs_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in tcs_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 25, USB Type C MG Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class CSE_Ext_19_Mod_R2(ctypes.LittleEndianStructure) : # R2 - USB Type C MG Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*12),	# 0x0C SHA-384 Big Endian
		# 0x3C
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'big'))
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 25, USB Type C MG Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class CSE_Ext_1A(ctypes.LittleEndianStructure) : # R1 - USB Type C Thunderbolt (TCSS_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Reserved',		uint32_t),		# 0x08
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 26, USB Type C Thunderbolt' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
class CSE_Ext_1A_R2(ctypes.LittleEndianStructure) : # R2 - GSC FWI Manifests (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 26, GSC FWI Manifests' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
		
class CSE_Ext_1A_Mod(ctypes.LittleEndianStructure) : # R1 - USB Type C Thunderbolt Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 SHA-1, 1 SHA-256, 2 MD5
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*8),	# 0x0C SHA-256 Big Endian
		# 0x2C
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'big'))
		HashAlgorithm = tcs_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in tcs_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 26, USB Type C Thunderbolt Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class CSE_Ext_1A_Mod_R2(ctypes.LittleEndianStructure) : # R2 - USB Type C Thunderbolt Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*12),	# 0x0C SHA-384 Big Endian
		# 0x3C
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'big'))
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 26, USB Type C Thunderbolt Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class CSE_Ext_1A_Mod_R3(ctypes.LittleEndianStructure) : # R3 - GSC FWI Manifest Hash (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Name',			char*4),		# 0x00
		('Hash',			uint32_t*12),	# 0x0C SHA-384 BE (Manifest w/o RSA)
		# 0x34
	]
	
	def ext_print(self) :
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'big'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 26, GSC FWI Manifest Hash' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class CSE_Ext_1B(ctypes.LittleEndianStructure) : # R1 - GSC Alpha PCOD Initial Vector (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Nonce',			uint32_t*4),	# 0x08 AES-CTR 128-bit Nonce
		# 0x18
	]
	
	def ext_print(self) :
		Nonce = '%0.*X' % (0x10 * 2, int.from_bytes(self.Nonce, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 27, GSC Alpha PCOD Initial Vector' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Nonce', Nonce])
		
		return pt

class CSE_Ext_1B_R2(ctypes.LittleEndianStructure) : # R2 - OEM Key Revocation Manifest (REVOCATION_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		# 0x08
	]
	
	# TODO: Should be followed by a MN2_Manifest_R2, sample required
	
	def ext_print(self) :		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 27, OEM Key Revocation Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
		
class CSE_Ext_1E(ctypes.LittleEndianStructure) : # R1 - Golden Measurements File Certificate (CERTIFICATE_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('CertificateSize',	uint32_t),		# 0x08
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 30, Golden Measurements File Certificate' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Certificate Size', '0x%X' % self.CertificateSize])
		
		return pt
		
class CSE_Ext_1F(ctypes.LittleEndianStructure) : # R1 - Golden Measurements File Body (GMF_BODY_HEADER_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 31, Golden Measurements File Body' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Body Size (MEA)', '0x%X' % (self.Size - ctypes.sizeof(CSE_Ext_1F))]) # Calculated by MEA
		
		return pt

class CSE_Ext_22(ctypes.LittleEndianStructure) : # R1 - Key Manifest v2 (KEY_MANIFEST_EXT, KeyManifestV2)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('KeyType',			uint32_t),		# 0x08 1 RoT, 2 OEM (KeyManifestTypeValues)
		('OEMID',			uint16_t),		# 0x0C
		('KeyID',			uint8_t),		# 0x0E Matched against Field Programmable Fuses (FPF)
		('Reserved',		uint8_t*12),	# 0x0F
		('ModuleCount',		uint8_t),		# 0x1B Keys Number
		# 0x1C
	]
	
	def ext_print(self) :		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 34, Key Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Key Type', ['Reserved','RoT','OEM'][self.KeyType]])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Key ID', '0x%0.2X' % self.KeyID])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		pt.add_row(['Key Count', self.ModuleCount])
		
		return pt

class CSE_Ext_22_Mod(ctypes.LittleEndianStructure) : # R1 - (KEY_MANIFEST_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		('Usage',			uint16_t),		# 0x00 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		('Flags',			uint8_t),		# 0x02
		('HashAlgorithm',	uint8_t),		# 0x03
		('MinimalSVN',		uint8_t),		# 0x04
		('Reserved',		uint8_t*3),		# 0x05
		# 0x08
	]
	
	def ext_print(self) :
		f1,f2 = self.get_flags()
		
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 34, Entry' + col_e
		pt.add_row(['Hash Usage', key_dict[self.Usage] if self.Usage in key_dict else 'Unknown (%d)' % self.Usage])
		pt.add_row(['IPI Policy', ['OEM or Intel','Intel Only'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Minimal SVN', self.MinimalSVN])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_0E_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.IPIPolicy, flags.b.Reserved

class CSE_Ext_23(ctypes.LittleEndianStructure) : # R1 - Signed Package Information v2 (SIGNED_PACKAGE_INFO_EXT, SignedPackageInfoV2)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('VCN',				uint32_t),		# 0x0C Version Control Number
		('ARBSVN',			uint32_t),		# 0x10 FPF Anti-Rollback (ARB) Security Version Number
		('Usage',			uint16_t),		# 0x14 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		('FWType',			uint8_t),  		# 0x16 Bits 0-2 FW Type, 3-7 Reserved (FwTypeValues)
		('FWSKU',			uint8_t),  		# 0x17 Bits 0-2 FW SKU, 3-7 Reserved (FwSkuIdValues)
		('ModuleCount',		uint8_t),  		# 0x18
		('Reserved',		uint8_t*15),  	# 0x19
		# 0x28
	]
	
	# FWType & FWSKU are also used by CSE_Ext_0F_R2 & GSC_Info_FWI, remember to change them as well!
	
	def ext_print(self) :
		f1,f2,f3,f4 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 35, Signed Package Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Version Control Number', self.VCN])
		pt.add_row(['ARB Security Version Number', self.ARBSVN])
		pt.add_row(['Hash Usage', key_dict[self.Usage] if self.Usage in key_dict else 'Unknown (%d)' % self.Usage])
		pt.add_row(['Firmware Type', ext15_fw_type[f1] if f1 in ext15_fw_type else 'Unknown (%d)' % f1])
		pt.add_row(['Firmware Type Reserved', '0x%X' % f2])
		pt.add_row(['Firmware SKU', ext15_fw_sku[f3][0] if f3 in ext15_fw_sku else 'Unknown (%d)' % f3])
		pt.add_row(['Firmware SKU Reserved', '0x%X' % f4])
		pt.add_row(['Module Count', self.ModuleCount])
		pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
		
		return pt
	
	def get_flags(self) :
		fw_type = CSE_Ext_0F_R2_GetFWType()
		fw_type.asbytes = self.FWType
		fw_sub_type = CSE_Ext_0F_R2_GetFWSKU()
		fw_sub_type.asbytes = self.FWSKU
		
		return fw_type.b.FWType, fw_type.b.Reserved, fw_sub_type.b.FWSKU, fw_sub_type.b.Reserved

class CSE_Ext_23_Mod(ctypes.LittleEndianStructure) : # R1 - (SIGNED_PACKAGE_INFO_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		('Name',			char*12),		# 0x00
		('Type',			uint8_t),		# 0x0C 0 Process, 1 Shared Library, 2 Data, 3 Independent (MODULE_TYPES)
		('HashAlgorithm',	uint8_t),		# 0x0D 0 None, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint16_t),		# 0x0E
		('MetadataSize',	uint32_t),		# 0x10
		('MetadataHash',	uint32_t*12),	# 0x14 SHA-384
		# 0x44
	]
	
	def ext_print(self) :
		Type = cse_mod_type[self.Type] if self.Type in cse_mod_type else 'Unknown (%d)' % self.Type
		HashAlgorithm = cse_hash_alg[self.HashAlgorithm] if self.HashAlgorithm in cse_hash_alg else 'Unknown (%d)' % self.HashAlgorithm
		MetadataHash = '%0.*X' % (0x30 * 2, int.from_bytes(self.MetadataHash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 35, Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', Type])
		pt.add_row(['Hash Algorithm', HashAlgorithm])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt
		
class CSE_Ext_32(ctypes.LittleEndianStructure) : # R1 - SPS Platform ID (MFT_EXT_MANIFEST_PLATFORM_ID)
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
		
		pt.title = col_y + 'Extension 50, CSSPS Platform ID' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Type', 'Unknown' if type_str not in cssps_type_fw else cssps_type_fw[type_str]])
		pt.add_row(['Platform', 'Unknown (%s)' % platform_str if platform_str not in cssps_platform else cssps_platform[platform_str]])
		pt.add_row(['Reserved', '0x0' if self.Reserved == 0 else '0x%X' % self.Reserved])
		
		return pt

class CSE_Ext_544F4F46(ctypes.LittleEndianStructure) : # R1 - CPU Co-Signing 3K (Not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*8),		# 0x00 FOOT (544F4F46)
		('TotalSize',		uint32_t),		# 0x08
		('HeaderSize',		uint32_t),		# 0x0C dwords (w/o Tag)
		('ModulusSize',		uint32_t),		# 0x10 dwords
		('ExponentSize',	uint32_t),		# 0x14 dwords
		('RSAModulus',		uint32_t*96),	# 0x18 3072-bits
		('RSAExponent',		uint32_t),		# 0x198
		('RSASignature',	uint32_t*96),	# 0x19C 3072-bits
		# 0x31C
	]
	
	def ext_print(self) :		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		ModulusSize = self.ModulusSize * 4
		RSAModulus = '%0.*X' % (ModulusSize * 2, int.from_bytes(self.RSAModulus, 'little'))
		RSASignature = '%0.*X' % (ModulusSize * 2, int.from_bytes(self.RSASignature, 'little'))
		
		pt.title = col_y + 'Extension FOOT, CPU Co-Signing' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Total Size', '0x%X' % self.TotalSize])
		pt.add_row(['Header Size', '0x%X' % (self.HeaderSize * 4)])
		pt.add_row(['Modulus Size', '0x%X' % ModulusSize])
		pt.add_row(['Exponent Size', '0x%X' % (self.ExponentSize * 4)])
		pt.add_row(['RSA Modulus', '%s [...]' % RSAModulus[:8]])
		pt.add_row(['RSA Exponent', '0x%X' % self.RSAExponent])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		return pt

class RBE_PM_Metadata(ctypes.LittleEndianStructure) : # R1 - RBEP > rbe or FTPR > pm Module "Metadata"
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint32_t),		# 0x00
		('DEV_ID',			uint16_t),		# 0x04
		('VEN_ID',			uint16_t),		# 0x06 8086
		('SizeUncomp',		uint32_t),		# 0x08
		('SizeComp',		uint32_t),		# 0x0C
		('BSSSize',			uint32_t),		# 0x10
		('CodeSizeUncomp',	uint32_t),		# 0x14
		('CodeBaseAddress',	uint32_t),		# 0x18
		('MainThreadEntry',	uint32_t),		# 0x1C
		('Unknown1',		uint32_t),		# 0x20
		('Unknown2',		uint32_t),		# 0x24
		('Hash',			uint32_t*8),	# 0x28 SHA-256 LE
		# 0x48
	]
	
	def mod_print(self) :
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'RBE/PM Module "Metadata"' + col_e
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Device ID', '0x%X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['BSS Size', '0x%X' % self.BSSSize])
		pt.add_row(['Code Size Uncompressed', '0x%X' % self.CodeSizeUncomp])
		pt.add_row(['Code Base Address', '0x%X' % self.CodeBaseAddress])
		pt.add_row(['Main Thread Entry', '0x%X' % self.MainThreadEntry])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Unknown 2', '0x%X' % self.Unknown2])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class RBE_PM_Metadata_R2(ctypes.LittleEndianStructure) : # R2 - RBEP > rbe or FTPR > pm Module "Metadata"
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint32_t),		# 0x00
		('DEV_ID',			uint16_t),		# 0x04
		('VEN_ID',			uint16_t),		# 0x06 8086
		('SizeUncomp',		uint32_t),		# 0x08
		('SizeComp',		uint32_t),		# 0x0C
		('Hash',			uint32_t*8),	# 0x10 SHA-256 LE
		# 0x30
	]
	
	def mod_print(self) :
		Hash = '%0.*X' % (0x20 * 2, int.from_bytes(self.Hash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'RBE/PM Module "Metadata"' + col_e
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Device ID', '0x%X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['Hash', Hash])
		
		return pt
		
class RBE_PM_Metadata_R3(ctypes.LittleEndianStructure) : # R3 - RBEP > rbe or FTPR > pm Module "Metadata"
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint32_t),		# 0x00
		('DEV_ID',			uint16_t),		# 0x04
		('VEN_ID',			uint16_t),		# 0x06 8086
		('SizeUncomp',		uint32_t),		# 0x08
		('SizeComp',		uint32_t),		# 0x0C
		('BSSSize',			uint32_t),		# 0x10
		('CodeSizeUncomp',	uint32_t),		# 0x14
		('CodeBaseAddress',	uint32_t),		# 0x18
		('MainThreadEntry',	uint32_t),		# 0x1C
		('Unknown1',		uint32_t),		# 0x20
		('Unknown2',		uint32_t),		# 0x24
		('Hash',			uint32_t*12),	# 0x28 SHA-384 LE
		# 0x58
	]
	
	def mod_print(self) :
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'RBE/PM Module "Metadata"' + col_e
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Device ID', '0x%X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['BSS Size', '0x%X' % self.BSSSize])
		pt.add_row(['Code Size Uncompressed', '0x%X' % self.CodeSizeUncomp])
		pt.add_row(['Code Base Address', '0x%X' % self.CodeBaseAddress])
		pt.add_row(['Main Thread Entry', '0x%X' % self.MainThreadEntry])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Unknown 2', '0x%X' % self.Unknown2])
		pt.add_row(['Hash', Hash])
		
		return pt

class RBE_PM_Metadata_R4(ctypes.LittleEndianStructure) : # R4 - RBEP > rbe or FTPR > pm Module "Metadata"
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint32_t),		# 0x00
		('DEV_ID',			uint16_t),		# 0x04
		('VEN_ID',			uint16_t),		# 0x06 8086
		('SizeUncomp',		uint32_t),		# 0x08
		('SizeComp',		uint32_t),		# 0x0C
		('Hash',			uint32_t*12),	# 0x10 SHA-384 LE
		# 0x40
	]
	
	def mod_print(self) :
		Hash = '%0.*X' % (0x30 * 2, int.from_bytes(self.Hash, 'little'))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'RBE/PM Module "Metadata"' + col_e
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Device ID', '0x%X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['Hash', Hash])
		
		return pt
	
# Unpack Engine/Graphics/Independent CSE firmware
# noinspection PyUnusedLocal
def cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start, fpt_chk_fail, cse_lt_chk_fail, cse_red_info, fdv_status, reading_msg, orom_hdr_all) :
	rbe_pm_data_d = b''
	vol_ftbl_id = -0x1
	vol_ftbl_pl = -0x1
	mfs_parsed_idx = None
	fpt_hdr_0_print = None
	intel_cfg_hash_mfs = None
	pch_init_final = []
	rbe_man_hashes = []
	rbe_pm_met_valid = []
	rbe_pm_met_hashes = []
	len_fpt_part_all = len(fpt_part_all)
	len_bpdt_part_all = len(bpdt_part_all)
	len_orom_hdr_all = len(orom_hdr_all)
	config_rec_size = get_cfg_rec_size(variant,major,minor,hotfix)
	huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, minor, 'error') # Load Huffman Dictionaries for rbe/pm Decompression
	
	# Create main Firmware Extraction Directory
	fw_name = 'Unpacked_' + os.path.basename(file_in)
	if os.path.isdir(os.path.join(mea_dir, fw_name, '')) : shutil.rmtree(os.path.join(mea_dir, fw_name, ''))
	os.mkdir(os.path.join(mea_dir, fw_name, ''))
	
	# Print Input File Name
	file_pt = ext_table([], False, 1)
	file_pt.add_row([col_c + os.path.basename(file_in) + col_e])
	print('\n%s\n' % file_pt)
	
	if reading_msg : print('%s\n' % reading_msg)
	
	# CSSPS 4.2 & 4.4 (WTL) is simply too terrible of a firmware to waste time and effort in order to add "proper" MEA parsing & unpacking
	if (variant,major) == ('CSSPS',4) and minor in [4,2] :
		input_col(col_m + 'Warning: CSE SPS 4.%d (Whitley) is partially supported only, errors are expected!\n' % minor + col_e)
	
	# Show & Validate Flash Descriptor RSA Signature & Hash
	if fdv_status[0] :
		fdv_rsa_valid = fdv_status[1] # RSA Signature validity
		fdv_rsa_crash = fdv_status[2] # RSA Signature crashed
		fdv_hash_valid = fdv_status[3] # Hash validity
		fdv_print = fdv_status[4] # FDV Manifest/Extension Info
		fdv_path = os.path.join(mea_dir, fw_name, 'CSE Flash Descriptor') # FDV Info File
		
		# Print Flash Descriptor Manifest/Extension Info
		for index in range(0, len(fdv_print), 2) : # Only Name (index), skip Info (index + 1)
			if str(fdv_print[index]).startswith('FDV') :
				for ext in fdv_print[index + 1] :
					ext_str = ansi_escape.sub('', str(ext))
					
					with open(fdv_path + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
					
					if param.write_html :
						with open(fdv_path + '.html', 'a', encoding = 'utf-8') as text_file : text_file.write('\n<br/>\n%s' % pt_html(ext))
					if param.write_json :
						with open(fdv_path + '.json', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % pt_json(ext))
					
					print(ext) # Print Flash Descriptor Manifest/Extension Info
					
					if 'Manifest' in ext.title :
						if fdv_rsa_valid :
							print(col_g + '\nFlash Descriptor RSA Signature is VALID\n' + col_e)
						elif fdv_rsa_crash :
							if param.cse_pause :
								input_col(col_m + '\nFlash Descriptor RSA Signature is UNKNOWN!\n' + col_e) # Debug
							else :
								print(col_m + '\nFlash Descriptor RSA Signature is UNKNOWN!\n' + col_e)
						else :
							if param.cse_pause :
								input_col(col_r + '\nFlash Descriptor RSA Signature is INVALID!\n' + col_e) # Debug
							else :
								print(col_r + '\nFlash Descriptor RSA Signature is INVALID!\n' + col_e)
					
					elif 'Hash' in ext.title :
						if fdv_hash_valid :
							print(col_g + '\nFlash Descriptor Hash is VALID\n' + col_e)
						else :
							if param.cse_pause :
								input_col(col_r + '\nFlash Descriptor Hash is INVALID!\n' + col_e) # Debug
							else :
								print(col_r + '\nFlash Descriptor Hash is INVALID!\n' + col_e)
				
				break
	
	# Show & Store CSE Layout Table info
	if cse_lt_struct :
		cse_lt_info = cse_lt_struct.hdr_print()
		cse_lt_fname = os.path.join(mea_dir, fw_name, 'CSE LT [0x%0.6X]' % cse_lt_off)
		
		print('%s' % cse_lt_info)
		
		if not cse_lt_chk_fail :
			print(col_g + '\nCSE Layout Table CRC is VALID\n' + col_e)
		else :
			if param.cse_pause :
				input_col(col_r + '\nCSE Layout Table CRC is INVALID!\n' + col_e) # Debug
			else :
				print(col_r + '\nCSE Layout Table CRC is INVALID!\n' + col_e)
		
		if cse_red_info[0] and cse_red_info[1] :
			print(col_g + 'CSE Boot Partition Redundancy is VALID\n' + col_e)
		elif cse_red_info[0] and not cse_red_info[1] :
			if param.cse_pause :
				input_col(col_r + 'CSE Boot Partition Redundancy is INVALID!\n' + col_e) # Debug
			else :
				print(col_r + 'CSE Boot Partition Redundancy is INVALID!\n' + col_e)
		
		with open(cse_lt_fname + '.bin', 'w+b') as cse_lt_file : cse_lt_file.write(reading[cse_lt_off:cse_lt_off + cse_lt_size])
		with open(cse_lt_fname + '.txt', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write(ansi_escape.sub('', '\n%s' % cse_lt_info))
		if param.write_html :
			with open(cse_lt_fname + '.html', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n<br/>\n%s' % pt_html(cse_lt_info))
		if param.write_json :
			with open(cse_lt_fname + '.json', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n%s' % pt_json(cse_lt_info))
		
		pt_dcselt.title = col_y + 'Detected %d Partition(s) at CSE LT [0x%0.6X]' % (len(cse_lt_part_all), cse_lt_off) + col_e
		print('%s\n' % pt_dcselt) # Local copy with different title for cse_unpack function
		
		cse_lt_hdr = ansi_escape.sub('', str(pt_dcselt))
		with open(cse_lt_fname + '.txt', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n%s' % cse_lt_hdr)
		if param.write_html :
			with open(cse_lt_fname + '.html', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n<br/>\n%s' % pt_html(pt_dcselt))
		if param.write_json :
			with open(cse_lt_fname + '.json', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n%s' % pt_json(pt_dcselt))
		
		print(col_y + '--> Stored CSE Layout Table [0x%0.6X - 0x%0.6X]\n' % (cse_lt_off, cse_lt_off + cse_lt_size) + col_e)
		
		for part in cse_lt_part_all :
			part_name = part[0]
			part_start = part[1]
			part_end = part[3]
			part_empty = part[4]
			
			if not part_empty : # Skip Empty Partitions
				file_name = os.path.join(fw_name, 'CSE LT ' + part_name + ' [0x%0.6X].bin' % part_start) # Start offset covers any cases with duplicate name entries (CSE_Layout_Table_17)
				mod_fname = os.path.join(mea_dir, file_name)
				
				with open(mod_fname, 'w+b') as part_file : part_file.write(reading[part_start:part_end])
			
				print(col_y + '--> Stored CSE LT Partition "%s" [0x%0.6X - 0x%0.6X]\n' % (part_name, part_start, part_end) + col_e)
	
	# Parse all Flash Partition Table ($FPT) entries
	if len_fpt_part_all :
		if reading[fpt_start:fpt_start + 0x4] == b'$FPT' :
			fpt_romb_exist = False
			fpt_hdr_1 = get_struct(reading, fpt_start, get_fpt(reading, fpt_start)[0])
		else :
			fpt_romb_exist = True
			fpt_hdr_1 = get_struct(reading, fpt_start + 0x10, get_fpt(reading, fpt_start + 0x10)[0])
		
		if fpt_romb_exist :
			fpt_hdr_0 = get_struct(reading, fpt_start, FPT_Pre_Header)
			fpt_hdr_0_print = fpt_hdr_0.hdr_print_cse()
			print('%s\n' % fpt_hdr_0_print)
		
		fpt_hdr_1_print = fpt_hdr_1.hdr_print_cse()
		print('%s' % fpt_hdr_1_print)
		
		if not fpt_chk_fail :
			print(col_g + '\nFlash Partition Table Checksum is VALID\n' + col_e)
		else :
			if param.cse_pause :
				input_col(col_r + '\nFlash Partition Table Checksum is INVALID!\n' + col_e) # Debug
			else :
				print(col_r + '\nFlash Partition Table Checksum is INVALID!\n' + col_e)
				
		if cse_red_info[0] and cse_red_info[2] :
			print(col_g + 'CSE Data Partition Redundancy is VALID\n' + col_e)
		elif cse_red_info[0] and not cse_red_info[2] :
			if param.cse_pause :
				input_col(col_r + 'CSE Data Partition Redundancy is INVALID!\n' + col_e) # Debug
			else :
				print(col_r + 'CSE Data Partition Redundancy is INVALID!\n' + col_e)
		
		pt = ext_table([col_y + 'Name' + col_e, col_y + 'Start' + col_e, col_y + 'End' + col_e, col_y + 'ID' + col_e, col_y + 'Type' + col_e,
		                col_y + 'Valid' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt.title = col_y + 'Detected %d Partition(s) at $FPT [0x%0.6X]' % (len_fpt_part_all, fpt_start) + col_e
		
		for part in fpt_part_all :
			pt.add_row([part[0], '0x%0.6X' % part[1], '0x%0.6X' % part[2], '%0.4X' % part[3], part[4], part[5], part[6]]) # Store Partition details
		
		print(pt) # Show Partition details
		
		if cse_lt_struct : fpt_fname = os.path.join(mea_dir, fw_name, 'CSE LT Data [0x%0.6X]' % fpt_start)
		else : fpt_fname = os.path.join(mea_dir, fw_name, 'FPT [0x%0.6X]' % fpt_start)
		
		# Store Flash Partition Table ($FPT) Data
		if not cse_lt_struct : # Stored at CSE LT section too
			with open(fpt_fname + '.bin', 'w+b') as fpt_file : fpt_file.write(reading[fpt_start:fpt_start + 0x1000]) # $FPT size is 4K
			
			print(col_y + '\n--> Stored Flash Partition Table [0x%0.6X - 0x%0.6X]' % (fpt_start, fpt_start + 0x1000) + col_e)
		
		# Store Flash Partition Table ($FPT) Info
		# Ignore Colorama ANSI Escape Character Sequences
		if fpt_romb_exist :
			fpt_hdr_romb = ansi_escape.sub('', str(fpt_hdr_0_print))
			with open(fpt_fname + '.txt', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s' % fpt_hdr_romb)
			if param.write_html :
				with open(fpt_fname + '.html', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n<br/>\n%s' % pt_html(fpt_hdr_0_print))
			if param.write_json :
				with open(fpt_fname + '.json', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s' % pt_json(fpt_hdr_0_print))
		
		fpt_hdr_main = ansi_escape.sub('', str(fpt_hdr_1_print))
		fpt_hdr_part = ansi_escape.sub('', str(pt))
		with open(fpt_fname + '.txt', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s\n%s' % (fpt_hdr_main, fpt_hdr_part))
		if param.write_html :
			with open(fpt_fname + '.html', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n<br/>\n%s\n<br/>\n%s' % (pt_html(fpt_hdr_1_print), pt_html(pt)))
		if param.write_json :
			with open(fpt_fname + '.json', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s\n%s' % (pt_json(fpt_hdr_1_print), pt_json(pt)))
		
		# Place MFS first to validate FTPR > FTPR.man > 0x00 > Intel Configuration Hash
		# and get MFS FTBL ID & Record Size for FTPR/FITC Partition intl.cfg/fitc.cfg
		for i in range(len(fpt_part_all)) :
			if fpt_part_all[i][0] in ['MFS','AFSP'] :
				fpt_part_all.insert(0, fpt_part_all.pop(i))
				break
		
		# Charted Partitions include fpt_start, Uncharted do not (RGN only, non-SPI)
		for part in fpt_part_all :
			part_name = part[0]
			part_start = part[1]
			part_end = part[2]
			part_inid = part[3]
			part_type = part[4]
			part_empty = part[6]
			
			if not part_empty : # Skip Empty Partitions
				part_name_p = '%s %0.4X' % (part_name, part_inid) # Partition Name with Instance ID
				
				mod_f_path = os.path.join(mea_dir, fw_name, part_name_p + ' [0x%0.6X].bin' % part_start) # Start offset covers any cases with duplicate name entries (Joule_C0-X64-Release)
				
				with open(mod_f_path, 'w+b') as part_file : part_file.write(reading[part_start:part_end])
			
				print(col_y + '\n--> Stored $FPT %s Partition "%s" [0x%0.6X - 0x%0.6X]' % (part_type, part_name_p, part_start, part_end) + col_e)
				
				if part_name in ['UTOK','STKN'] :
					ext_print,mn2_signs,_ = ext_anl(reading[part_start:part_end], '$MN2', 0x1B, file_end, [variant,major,minor,hotfix,build,year,month,variant_p],
														  part_name, [[],''], [[],-1,-1,-1]) # Retrieve & Store UTOK/STKN Extension Info
					
					# Print Manifest Info, when applicable (UTOK w/ UTFL or UTOK w/o UTFL)
					if man_pat.search(reading[part_start:part_end][:0x20]) :
						if param.cse_pause :
							print('\n    MN2: %s' % mn2_signs[1]) # Debug
							print('    MEA: %s' % mn2_signs[2]) # Debug
						
						if mn2_signs[3] :
							if param.cse_pause :
								input_col(col_m + '\n    RSA Signature of partition %s is UNKNOWN!' % part_name + col_e) # Debug
							else :
								print(col_m + '\n    RSA Signature of partition %s is UNKNOWN!' % part_name + col_e)
						elif mn2_signs[0] :
							print(col_g + '\n    RSA Signature of partition %s is VALID' % part_name + col_e)
						else :
							if param.cse_pause and [mn2_signs[1],mn2_signs[2]] not in cse_known_bad_hashes :
								input_col(col_r + '\n    RSA Signature of partition %s is INVALID!' % part_name + col_e) # Debug
							elif [mn2_signs[1],mn2_signs[2]] in cse_known_bad_hashes :
								print(col_r + '\n    RSA Signature of partition %s is INVALID (Known CSE Bad RSA Signature)!' % part_name + col_e)
							else :
								print(col_r + '\n    RSA Signature of partition %s is INVALID!' % part_name + col_e)
					
						if not param.cse_verbose : print('\n%s' % ext_print[1][0]) # Print Manifest Info (already included in -ver86)
					
					# Print Manifest/Metadata/Key Extension Info (UTOK w/ UTFL or UTOK w/o UTFL or UTFL w/o UTOK)
					for index in range(0, len(ext_print), 2) : # Only Name (index), skip Info (index + 1)
						if str(ext_print[index]).startswith(part_name) :
							if param.cse_verbose : print() # Print Manifest/Metadata/Key Extension Info
							for ext in ext_print[index + 1] :
								ext_str = ansi_escape.sub('', str(ext))
								with open(mod_f_path[:-4] + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
								if param.write_html :
									with open(mod_f_path[:-4] + '.html', 'a', encoding = 'utf-8') as text_file : text_file.write('\n<br/>\n%s' % pt_html(ext))
								if param.write_json :
									with open(mod_f_path[:-4] + '.json', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % pt_json(ext))
								if param.cse_verbose : print(ext) # Print Manifest/Metadata/Key Extension Info
							break
							
				if part_name in ['MFS','AFSP','MFSB'] :
					mfs_is_afs = part_name == 'AFSP' # Check if File System is MFS or AFS
					mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final,vol_ftbl_id,config_rec_size,vol_ftbl_pl \
					= mfs_anl(os.path.join(mod_f_path[:-4], ''),part_start,part_end,variant,vol_ftbl_id,vol_ftbl_pl,mfs_is_afs) # Parse MFS
					for pt in mfs_info : mfs_txt(pt, os.path.join(mod_f_path[:-4], ''), mod_f_path[:-4], 'a', False) # Print MFS Structure Info
				
				# TODO: ADD CDMD Partition analysis
				
				if part_name == 'FITC' : fitc_anl(mod_f_path, part_start, part_end, config_rec_size, vol_ftbl_id, vol_ftbl_pl)
				
				if part_name == 'EFS' : _ = efs_anl(mod_f_path, part_start, part_end, vol_ftbl_id, vol_ftbl_pl)
				
				if part_name == 'INFO' : info_anl(mod_f_path, part_start, part_end)
				
				# Store RBEP > rbe and FTPR > pm "Metadata" within Module for Module w/o Metadata Hash validation
				if part_name in ['FTPR','RBEP'] :
					_,rbe_pm_mod_attr,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,fwi_iup_hashes,_ = ext_anl(reading, '$CPD', part_start, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], None,
																												[mfs_parsed_idx,intel_cfg_hash_mfs], [pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl])
					
					for mod in rbe_pm_mod_attr :
						if mod[0] in ['rbe','pm'] :
							rbe_pm_data = reading[mod[3]:mod[3] + mod[4]] # Store RBEP > rbe or FTPR > pm Module Compressed Huffman data
							try : rbe_pm_data_d, _ = cse_huffman_decompress(rbe_pm_data, mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none') # Huffman Decompress
							except : rbe_pm_data_d = rbe_pm_data
					
					rbe_pm_met_hashes = get_rbe_pm_met(rbe_pm_data_d, rbe_pm_met_hashes)
					
					if fwi_iup_hashes : rbe_man_hashes = fwi_iup_hashes
	
	# Parse all Boot Partition Description Table (BPDT/IFWI) entries
	if len_bpdt_part_all :
		if len_fpt_part_all : print()
		for hdr in bpdt_hdr_all : print('%s\n' % hdr)
		
		pt = ext_table([col_y + 'Name' + col_e, col_y + 'Type' + col_e, col_y + 'Partition' + col_e, col_y + 'ID' + col_e, col_y + 'Start' + col_e, col_y + 'End' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt.title = col_y + 'Detected %d Partition(s) at %d BPDT(s)' % (len_bpdt_part_all, len(bpdt_hdr_all)) + col_e
		
		for part in bpdt_part_all :
			pt.add_row([part[0], '%0.2d' % part[3], part[5], '%0.4X' % part[6], '0x%0.6X' % part[1], '0x%0.6X' % part[2], part[4]]) # Store Entry details
		
		print('%s' % pt) # Show Entry details
		
		if cse_lt_struct : bpdt_fname = os.path.join(mea_dir, fw_name, 'CSE LT Boot x [%d]' % len(bpdt_hdr_all))
		else : bpdt_fname = os.path.join(mea_dir, fw_name, 'BPDT [%d]' % len(bpdt_hdr_all))
		
		# Store Boot Partition Description Table (BPDT/IFWI) Info in TXT
		with open(bpdt_fname + '.txt', 'a', encoding = 'utf-8') as bpdt_file :
			for hdr in bpdt_hdr_all : bpdt_file.write('\n%s' % ansi_escape.sub('', str(hdr)))
			bpdt_file.write('\n%s' % ansi_escape.sub('', str(pt)))
			
		# Store Boot Partition Description Table (BPDT/IFWI) Info in HTML
		if param.write_html :
			with open(bpdt_fname + '.html', 'a', encoding = 'utf-8') as bpdt_file :
				for hdr in bpdt_hdr_all : bpdt_file.write('\n<br/>\n%s' % pt_html(hdr))
				bpdt_file.write('\n<br/>\n%s' % pt_html(pt))
				
		# Store Boot Partition Description Table (BPDT/IFWI) Info in JSON
		if param.write_json :
			with open(bpdt_fname + '.json', 'a', encoding = 'utf-8') as bpdt_file :
				for hdr in bpdt_hdr_all : bpdt_file.write('\n%s' % pt_json(hdr))
				bpdt_file.write('\n%s' % pt_json(pt))
		
		# Store Boot Partition Descriptor Table (BPDT/IFWI) Data
		if not cse_lt_struct : # Stored at CSE LT section too
			with open(bpdt_fname + '.bin', 'w+b') as bpdt_file :
				for bpdt in bpdt_data_all : bpdt_file.write(bpdt)
				
			print(col_y + '\n--> Stored Boot Partition Descriptor Table(s) [%d]' % len(bpdt_hdr_all) + col_e)
		
		# Place MFS first to validate FTPR > FTPR.man > 0x00 > Intel Configuration Hash
		# and get MFS FTBL ID & Record Size for FTPR/FITC Partition intl.cfg/fitc.cfg
		for i in range(len(bpdt_part_all)) :
			if bpdt_part_all[i][0] in ['MFS','AFSP'] :
				bpdt_part_all.insert(0, bpdt_part_all.pop(i))
				break
		
		for part in bpdt_part_all :
			part_name = part[0]
			part_start = part[1]
			part_end = part[2]
			part_empty = part[4]
			part_order = part[5]
			part_inid = part[6]
			
			if not part_empty : # Skip Empty Partitions
				part_name_p = '%s %0.4X' % (part_name, part_inid) # Partition Name with Instance ID
				
				mod_f_path = os.path.join(mea_dir, fw_name, part_name_p + ' [0x%0.6X].bin' % part_start) # Start offset covers any cases with duplicate name entries ("Unknown" etc)
				
				with open(mod_f_path, 'w+b') as part_file : part_file.write(reading[part_start:part_end])
				
				print(col_y + '\n--> Stored BPDT %s Partition "%s" [0x%0.6X - 0x%0.6X]' % (part_order, part_name_p, part_start, part_end) + col_e)
				
				if part_name in ['UTOK'] :
					ext_print,mn2_signs,_ = ext_anl(reading[part_start:part_end], '$MN2', 0x1B, file_end, [variant,major,minor,hotfix,build,year,month,variant_p],
												  part_name, [[],''], [[],-1,-1,-1]) # Retrieve & Store UTOK/STKN Extension Info
					
					# Print Manifest Info, when applicable (UTOK w/ UTFL or UTOK w/o UTFL)
					if man_pat.search(reading[part_start:part_end][:0x20]) :
						if param.cse_pause :
							print('\n    MN2: %s' % mn2_signs[1]) # Debug
							print('    MEA: %s' % mn2_signs[2]) # Debug
						
						if mn2_signs[3] :
							if param.cse_pause :
								input_col(col_m + '\n    RSA Signature of partition %s is UNKNOWN!' % part_name + col_e) # Debug
							else :
								print(col_m + '\n    RSA Signature of partition %s is UNKNOWN!' % part_name + col_e)
						elif mn2_signs[0] :
							print(col_g + '\n    RSA Signature of partition %s is VALID' % part_name + col_e)
						else :
							if param.cse_pause and [mn2_signs[1],mn2_signs[2]] not in cse_known_bad_hashes :
								input_col(col_r + '\n    RSA Signature of partition %s is INVALID!' % part_name + col_e) # Debug
							elif [mn2_signs[1],mn2_signs[2]] in cse_known_bad_hashes :
								print(col_r + '\n    RSA Signature of partition %s is INVALID (Known CSE Bad RSA Signature)!' % part_name + col_e)
							else :
								print(col_r + '\n    RSA Signature of partition %s is INVALID!' % part_name + col_e)
						
						if not param.cse_verbose : print('\n%s' % ext_print[1][0]) # Print Manifest Info (already included in -ver86)
					
					# Print Manifest/Metadata/Key Extension Info (UTOK w/ UTFL or UTOK w/o UTFL or UTFL w/o UTOK)
					for index in range(0, len(ext_print), 2) : # Only Name (index), skip Info (index + 1)
						if str(ext_print[index]).startswith(part_name) :
							if param.cse_verbose : print() # Print Manifest/Metadata/Key Extension Info
							for ext in ext_print[index + 1] :
								ext_str = ansi_escape.sub('', str(ext))
								with open(mod_f_path[:-4] + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
								if param.write_html :
									with open(mod_f_path[:-4] + '.html', 'a', encoding = 'utf-8') as text_file : text_file.write('\n<br/>\n%s' % pt_html(ext))
								if param.write_json :
									with open(mod_f_path[:-4] + '.json', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % pt_json(ext))
								if param.cse_verbose : print(ext) # Print Manifest/Metadata/Key Extension Info
							break
							
				if part_name in ['MFS','AFSP','MFSB'] :
					mfs_is_afs = part_name == 'AFSP' # Check if File System is MFS or AFS
					mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final,vol_ftbl_id,config_rec_size,vol_ftbl_pl \
					= mfs_anl(os.path.join(mod_f_path[:-4], ''),part_start,part_end,variant,vol_ftbl_id,vol_ftbl_pl,mfs_is_afs) # Parse MFS
					for pt in mfs_info : mfs_txt(pt, os.path.join(mod_f_path[:-4], ''), mod_f_path[:-4], 'a', False) # Print MFS Structure Info				
				
				# TODO: ADD CDMD Partition analysis
				
				if part_name == 'FITC' : fitc_anl(mod_f_path, part_start, part_end, config_rec_size, vol_ftbl_id, vol_ftbl_pl)
				
				if part_name == 'EFS' : _ = efs_anl(mod_f_path, part_start, part_end, vol_ftbl_id, vol_ftbl_pl)
				
				if part_name == 'INFO' : info_anl(mod_f_path, part_start, part_end)
				
				# Store RBEP > rbe and FTPR > pm "Metadata" within Module for Module w/o Metadata Hash validation
				if part_name in ['FTPR','RBEP'] :
					_,rbe_pm_mod_attr,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,fwi_iup_hashes,_ = ext_anl(reading, '$CPD', part_start, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], None,
																												[mfs_parsed_idx,intel_cfg_hash_mfs], [pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl])
					
					for mod in rbe_pm_mod_attr :
						if mod[0] in ['rbe','pm'] :
							rbe_pm_data = reading[mod[3]:mod[3] + mod[4]] # Store RBEP > rbe or FTPR > pm Module Compressed Huffman data
							try : rbe_pm_data_d, _ = cse_huffman_decompress(rbe_pm_data, mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none') # Huffman Decompress
							except : rbe_pm_data_d = rbe_pm_data
					
					rbe_pm_met_hashes = get_rbe_pm_met(rbe_pm_data_d, rbe_pm_met_hashes)
					
					if fwi_iup_hashes : rbe_man_hashes = fwi_iup_hashes
	
	# Print all Graphics System Controller Option ROM (OROM) entries
	if len_orom_hdr_all :
		if len_fpt_part_all or len_bpdt_part_all : print()
		orom_fname = os.path.join(mea_dir, fw_name, 'OROM-PCIR Images [%d].txt' % (len_orom_hdr_all // 2))
		for hdr in orom_hdr_all :
			print('%s\n' % hdr)
			with open(orom_fname, 'a', encoding = 'utf-8') as orom_file : orom_file.write('%s\n' % ansi_escape.sub('', str(hdr)))
	
	# Parse all Code Partition Directory ($CPD) ranges/entries. Separate $CPD from $FPT/BPDT to avoid duplicate FTUP/NFTP ($FPT) issue.
	for cpdrange in list(cpd_pat.finditer(reading)) :
		# Store any Platform Data (PDR) Flash Descriptor Regions with Code Partition Directory ($CPD) structure (not in $FPT or BPDT)
		if fd_pdr_rgn_exist and reading[cpdrange.start() + 0xC:cpdrange.start() + 0x10] == b'PDRP' :
			mod_f_path = os.path.join(mea_dir, fw_name, 'PDRP 0000 [0x%0.6X].bin' % cpdrange.start()) # Start offset covers any cases with multiple PDR (not POR, just in case)
			with open(mod_f_path, 'w+b') as part_file : part_file.write(reading[cpdrange.start():cpdrange.start() + pdr_fd_size])
			
			print(col_y + '\n--> Stored Flash Descriptor Region "PDRP 0000" [0x%0.6X - 0x%0.6X]' % (cpdrange.start(), cpdrange.start() + pdr_fd_size) + col_e)
		
		cpd_offset_e,cpd_mod_attr_e,cpd_ext_attr_e,_,ext12_info,ext_print,_,_,ext_phval,ext_dnx_val,_,_,cpd_mn2_info,ext_iunit_val,_,_,gmf_blob_info,_,_ \
		= ext_anl(reading, '$CPD', cpdrange.start(), file_end, [variant,major,minor,hotfix,build,year,month,variant_p], None, [mfs_parsed_idx,intel_cfg_hash_mfs],
		[pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl])
		
		if cse_lt_struct or len_fpt_part_all or len_bpdt_part_all or len_orom_hdr_all : print() # For visual purposes before $CPD info is shown
		
		rbe_pm_met_valid = mod_anl(cpd_offset_e, cpd_mod_attr_e, cpd_ext_attr_e, fw_name, ext_print, ext_phval, ext_dnx_val, ext_iunit_val,
						   rbe_pm_met_hashes, rbe_pm_met_valid, ext12_info, vol_ftbl_id, config_rec_size, gmf_blob_info, vol_ftbl_pl, cpd_mn2_info, rbe_man_hashes)
		
	# Store all RBEP > rbe and FTPR > pm "Metadata" leftover Hashes for Huffman symbol reversing
	# The leftover Hashes for Huffman symbol reversing should be n+* if NFTP > pavp and/or PCOD > PCOD are encrypted
	if param.bypass :
		for l_hash in [l_hash for l_hash in rbe_pm_met_hashes if l_hash not in rbe_pm_met_valid] : print(l_hash) # Debug/Research
	
# Analyze CSE Extensions
# noinspection PyUnusedLocal
def ext_anl(buffer, input_type, input_offset, file_end, ftpr_var_ver, single_man_name, mfs_idx_cfg, pch_init_input) :
	vcn = -1
	in_id = 0
	cpd_num = 0
	mn2_size = -1
	ext_psize = -1
	mea_phash = -1
	cpd_offset = -1
	mn2_offset = -1
	dnx_version = -1
	dnx_rcip_off = -1
	dnx_rcip_len = -1
	cpd_hdr_size = -1
	end_man_match = -1
	start_man_match = -1
	mn2_rsa_key_len = -1
	dnx_hash_arr_off = -1
	iunit_chunk_start = -1
	hash_arr_valid_count = 0
	chunk_hash_valid_count = 0
	cpd_hdr = None
	mn2_hdr = None
	utfl_hdr = None
	msg_shown = False
	cpd_chk_ok = False
	oem_config = False
	oem_signed = False
	intel_cfg_ftpr = False
	cpd_name = ''
	ext_pname = ''
	fd_info = []
	gsc_info = []
	ibbp_all = []
	ibbp_del = []
	ext_print = []
	cpd_ext_hash = []
	cpd_mod_attr = []
	cpd_ext_attr = []
	cpd_mn2_info = []
	cpd_mod_names = []
	cpd_ext_names = []
	mn2_hdr_print = []
	gmf_blob_info = []
	fwi_iup_hashes = []
	cpd_wo_met_info = []
	cpd_wo_met_back = []
	iunit_chunk_valid = []
	intel_cfg_hash_ftpr = []
	ext50_info = ['UNK', 'XX']
	ext15_info = [0, '', ('',''), '']
	fptemp_info = [False, -1, -1]
	cpd_chk_info = [True,['','']]
	ibbp_bpm = ['IBBL', 'IBB', 'OBB']
	ext12_info = [[], ('',''), 0, 0] # SKU Capabilities, SKU Type, LBG Support, SKU Platform
	ext_dnx_val = [-1, False, False] # [DnXVer, AllHashArrValid, AllChunkValid]
	ext_iunit_val = [False] # [AllChunkValid]
	ext_phval = [False, False, 0, 0]
	mn2_sigs = [False, -1, -1, True, -1, None]
	variant,major,minor,hotfix,build,year,month,variant_p = ftpr_var_ver # Remember to also adjust any ftpr_var_ver Classes/Constructors
	anl_major,anl_minor,anl_hotfix,anl_build = ftpr_var_ver[1:5] # pylint: disable=W0612
	anl_meu_major,anl_meu_minor,anl_meu_hotfix,anl_meu_build = ftpr_var_ver[1:5] # pylint: disable=W0612
	mfs_parsed_idx,intel_cfg_hash_mfs = mfs_idx_cfg
	pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl = pch_init_input
	buffer_len = len(buffer)
	
	if input_type.startswith('$MN2') :
		start_man_match = input_offset
		end_man_match = start_man_match + 0x5 # .$MN2
		
		# Scan backwards for $CPD (max $CPD size = 0x2000, .$MN2 Tag starts at 0x1B, works with both RGN --> $FPT & UPD --> 0x0)
		for offset in range(start_man_match + 2, start_man_match + 2 - 0x201D, -4) : # Search from MN2 (no .$) to find CPD (no $) at 1, before loop break at 0
			if b'$CPD' in buffer[offset - 1:offset - 1 + 4] :
				cpd_offset = offset - 1 # Adjust $CPD to 0 (offset - 1 = 1 - 1 = 0)
				break # Stop at first detected $CPD
	
	elif input_type.startswith('$CPD') :
		cpd_offset = input_offset
		
		# Scan forward for .$MN2 (max $CPD size = 0x2000, .$MN2 Tag ends at 0x20, works with both RGN --> $FPT & UPD --> 0x0)
		mn2_pat = re.compile(br'\x00\$MN2').search(buffer[cpd_offset:cpd_offset + 0x2020]) # .$MN2 detection, 0x00 for extra sanity check
		if mn2_pat is not None :
			(start_man_match, end_man_match) = mn2_pat.span()
			start_man_match += cpd_offset
			end_man_match += cpd_offset
	
	# $MN2 existence not mandatory
	if start_man_match != -1 :
		mn2_hdr = get_struct(buffer, start_man_match - 0x1B, get_manifest(buffer, start_man_match - 0x1B))
		
		if mn2_hdr.Tag == b'$MN2' : # Sanity Check (also UTOK w/o Manifest)
			mn2_offset = start_man_match - 0x1B # $MN2 Manifest Offset
			mn2_size = mn2_hdr.Size * 4 # $MN2 Manifest Size
			mn2_date = '%0.4X-%0.2X-%0.2X' % (mn2_hdr.Year,mn2_hdr.Month,mn2_hdr.Day)
			mn2_hdr_print = mn2_hdr.hdr_print_cse()
			
			mn2_rsa_key_len = mn2_hdr.PublicKeySize * 4 # RSA Key/Signature Length
			mn2_rsa_exp_len = mn2_hdr.ExponentSize * 4 # RSA Exponent Length
			mn2_rsa_key_start = mn2_offset + 0x80 # RSA Public Key Start
			mn2_rsa_key_end = mn2_rsa_key_start + mn2_rsa_key_len # RSA Public Key End
			mn2_rsa_key_data = buffer[mn2_rsa_key_start:mn2_rsa_key_end] # RSA Public Key Data
			mn2_rsa_key_hash = get_hash(mn2_rsa_key_data, 0x20) # SHA-256 of RSA Public Key Data
			mn2_rsa_sig_start = mn2_rsa_key_end + mn2_rsa_exp_len # RSA Signature Start
			mn2_rsa_sig_end = mn2_rsa_sig_start + mn2_rsa_key_len # RSA Signature End
			mn2_rsa_sig_data = buffer[mn2_rsa_sig_start:mn2_rsa_sig_end] # RSA Signature Data
			mn2_rsa_sig_hash = get_hash(mn2_rsa_sig_data, 0x20) # SHA-256 of RSA Signature Data
			mn2_wo_rsa_data = buffer[mn2_offset:mn2_rsa_key_start] + buffer[mn2_rsa_sig_end:mn2_offset + mn2_size] # $MN2 Manifest w/o RSA Block
			mn2_wo_rsa_hashes = [get_hash(mn2_wo_rsa_data, 0x30), get_hash(mn2_wo_rsa_data, 0x20)] # Hashes of $MN2 Manifest w/o RSA Block (RBEP)
			
			mn2_flags_pvbit,_,_,_,mn2_flags_debug = mn2_hdr.get_flags()
			
			if hasattr(mn2_hdr, 'MEU_Major') and mn2_hdr.MEU_Major not in (0,0xFFFF) :
				cpd_mn2_info = [mn2_hdr.Major, mn2_hdr.Minor, mn2_hdr.Hotfix, mn2_hdr.Build, ['Production','Debug'][mn2_flags_debug],
								mn2_rsa_key_hash, mn2_rsa_sig_hash, mn2_date, mn2_hdr.SVN, mn2_flags_pvbit, mn2_hdr.MEU_Major, mn2_hdr.MEU_Minor,
								mn2_hdr.MEU_Hotfix, mn2_hdr.MEU_Build, mn2_wo_rsa_hashes, mn2_hdr, start_man_match, end_man_match]
			else :
				cpd_mn2_info = [mn2_hdr.Major, mn2_hdr.Minor, mn2_hdr.Hotfix, mn2_hdr.Build, ['Production','Debug'][mn2_flags_debug],
								mn2_rsa_key_hash, mn2_rsa_sig_hash, mn2_date, mn2_hdr.SVN, mn2_flags_pvbit, 0, 0, 0, 0, mn2_wo_rsa_hashes,
								mn2_hdr, start_man_match, end_man_match]
			
			# It is sometimes necessary to use the analyzed $MN2 info instead of the external ftpr_var_ver parameter
			anl_major,anl_minor,anl_hotfix,anl_build = cpd_mn2_info[0],cpd_mn2_info[1],cpd_mn2_info[2],cpd_mn2_info[3]
			anl_meu_major,anl_meu_minor,anl_meu_hotfix,anl_meu_build = cpd_mn2_info[10],cpd_mn2_info[11],cpd_mn2_info[12],cpd_mn2_info[13]
			
			mn2_sigs = rsa_sig_val(mn2_hdr, buffer, mn2_offset) # For each Partition
		else :
			mn2_hdr = None
			start_man_match = -1
	
	# $CPD detected
	if cpd_offset > -1 :
		cpd_hdr_struct, cpd_hdr_size = get_cpd(buffer, cpd_offset)
		cpd_hdr = get_struct(buffer, cpd_offset, cpd_hdr_struct)
		cpd_num = cpd_entry_num_fix(buffer, cpd_offset, cpd_hdr.NumModules, cpd_hdr_size)
		cpd_name = cpd_hdr.PartitionName.strip(b'\x00').decode('utf-8')
		
		# Validate $CPD Checksum, skip at special _Stage1 mode (Variant/fptemp) to not see duplicate messages
		if not input_type.endswith('_Stage1') :
			cpd_chk_ok,cpd_chk_fw,cpd_chk_exp,cpd_chk_rslt = cpd_chk(buffer[cpd_offset:cpd_offset + cpd_hdr_size + cpd_num * 0x18], variant, major)
			cpd_chk_info = [cpd_chk_ok, cpd_chk_rslt] # Store $CPD Checksum Validity & Values
			
			if not cpd_chk_ok :
				cse_anl_err(col_r + 'Error: Wrong $CPD "%s" Checksum 0x%0.2X, expected 0x%0.2X' % (cpd_name, cpd_chk_fw, cpd_chk_exp) + col_e, cpd_chk_rslt)
		
		# Stage 1: Store $CPD Entry names to detect Partition attributes for MEA
		for entry in range(0, cpd_num) :
			cpd_entry_hdr = get_struct(buffer, cpd_offset + cpd_hdr_size + entry * 0x18, CPD_Entry)
			cpd_entry_name = cpd_entry_hdr.Name.decode('utf-8')
			cpd_mod_names.append(cpd_entry_name) # Store each $CPD Module name
			cpd_entry_size = cpd_entry_hdr.Size # Uncompressed only
			cpd_entry_res0 = cpd_entry_hdr.Reserved
			cpd_entry_offset,cpd_entry_huff,cpd_entry_res1 = cpd_entry_hdr.get_flags()
			cpd_entry_offset += cpd_offset # Adjust $CPD Entry Offset based on $CPD start
			
			# Determine if Entry is Empty/Missing
			entry_data = buffer[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
			entry_empty = 1 if entry_data in (b'', b'\xFF' * cpd_entry_size) or cpd_entry_offset >= file_end else 0
			
			# Detect if FTPR Partition is FWUpdate-customized to skip potential $FPT false positive at fptemp module
			if cpd_entry_name == 'fptemp' and entry_empty == 0 : # FWUpdate -save (fptemp not empty)
				fptemp_info = [True, cpd_entry_offset, cpd_entry_offset + cpd_entry_size]
			
			# Gathered any info for special _Stage1 mode (cpd_mod_names, fptemp_info)
			if input_type.endswith('_Stage1') : continue
			
			# Check if $CPD Entry Reserved field is zero, skip at special _Stage1 mode
			if (cpd_entry_res0,cpd_entry_res1) != (0,0) and not input_type.endswith('_Stage1') :
				cse_anl_err(col_m + 'Warning: Detected $CPD Entry with non-zero Reserved field at %s > %s' % (cpd_name, cpd_entry_name) + col_e, None)
			
			cpd_wo_met_info.append([cpd_entry_name,cpd_entry_offset,cpd_entry_size,cpd_entry_huff,cpd_entry_res0,cpd_entry_res1,entry_empty])
		
			# Detect if FTPR Partition includes MFS Intel Configuration (intl.cfg) to validate FTPR Extension 0x00 Hash at Stage 2
			# The FTPR intl.cfg Hash is stored separately from $FPT MFS Low Level File 6 Hash to validate both at Stage 2 (CSTXE, CSME 12 Alpha)
			if cpd_entry_name == 'intl.cfg' and entry_empty == 0 :
				intel_cfg_ftpr = True # Detected FTPR > intl.cfg module
				intel_cfg_data = buffer[cpd_entry_offset:cpd_entry_offset + cpd_entry_size] # FTPR > intl.cfg Contents
				intel_cfg_hash_ftpr = [get_hash(intel_cfg_data, 0x20), get_hash(intel_cfg_data, 0x30)] # Store FTPR MFS Intel Configuration Hashes
				
				# For Platform/Stepping analysis via the Chipset Initialization Table, prefer the FTPR Low Level File 6 (intl.cfg)
				# instead of the one from MFS, when possible (i.e. MFS & FTPR) or necessary (i.e. FTPR only, MFS empty).
				if not param.cse_unpack :
					try :
						intel_cfg_folder = os.path.join(mea_dir, 'intl.cfg_placeholder', '') # Not used here, placeholder value for mfs_cfg_anl to work
						pch_init_info = mfs_cfg_anl(6, intel_cfg_data, intel_cfg_folder, intel_cfg_folder, config_rec_size, [], vol_ftbl_id, vol_ftbl_pl) # Parse MFS Configuration Records
						pch_init_final = pch_init_anl(pch_init_info) # Parse MFS Initialization Tables and store their Platforms/Steppings
					except :
						cse_anl_err(col_r + 'Error: Failed to analyze MFS Low Level File 6 (Intel Configuration) at %s > %s' % (cpd_name, cpd_entry_name) + col_e, None)
		
			# Detect if FTPR Partition is FIT/OEM-customized to skip Hash check at Stages 2 & 4
			if cpd_entry_name == 'fitc.cfg' and entry_empty == 0 : oem_config = True # FIT OEM Configuration
			if cpd_entry_name == 'oem.key' and entry_empty == 0 and not bccb_pat.search(entry_data[:0x50]) :
				oem_signed = True # OEM RSA Signature, skip Intel "OEM" Placeholder Keys with VEN_ID 0xBCCB
			
			# Detect Recovery Image Partition (RCIP)
			if cpd_name == 'RCIP' :
				# Get DNX version 1 (R1 SHA-256) or 2 (R2 SHA-256, R3 SHA-384)
				if cpd_entry_name == 'version' : dnx_version = int.from_bytes(buffer[cpd_entry_offset:cpd_entry_offset + 0x4], 'little')
				
				# Get DNX R2 Hash Array offset
				elif cpd_entry_name == 'hash.array' : dnx_hash_arr_off = cpd_entry_offset
				
				# Get DNX R1/R2 RCIP IFWI offset
				elif cpd_entry_name == 'rcipifwi' :
					dnx_rcip_off = cpd_entry_offset
					dnx_rcip_len = cpd_entry_size # RCIP IFWI is uncompressed
		
		# Return only $CPD Module Names & fptemp info for special _Stage1 mode
		if input_type.endswith('_Stage1') : return cpd_mod_names, fptemp_info
	
		# Sort $CPD Entry Info based on Offset in ascending order
		cpd_wo_met_info = sorted(cpd_wo_met_info, key=lambda entry: entry[1])
		cpd_wo_met_back = cpd_wo_met_info # Backup for adjustments validation
	
	# $CPD not found but special _Stage1 mode requires it, return null info
	elif input_type.endswith('_Stage1') : return cpd_mod_names, fptemp_info
	
	# Stage 2: Analyze Manifest & Metadata (must be before Module analysis)
	# Set cpd_num = 1 to analyze single $MN2 w/o $CPD (CSSPS MFS Low Level File 9)
	for entry in range(0, 1 if single_man_name else cpd_num) :
		# Variable Initialization based on Single Manifest existence
		if not single_man_name :
			cpd_entry_hdr = get_struct(buffer, cpd_offset + cpd_hdr_size + entry * 0x18, CPD_Entry)
			cpd_mod_off,_,_ = cpd_entry_hdr.get_flags()
			
			cpd_entry_offset = cpd_offset + cpd_mod_off
			cpd_entry_size = cpd_entry_hdr.Size # Uncompressed only
			cpd_entry_name = cpd_entry_hdr.Name
		else :
			cpd_offset = 0
			cpd_name = single_man_name
			cpd_entry_offset = 0
			cpd_entry_size = mn2_size
			cpd_entry_name = bytes(single_man_name, 'utf-8')
			dnx_rcip_off = 0
			dnx_rcip_len = 0
			cpd_chk_info = [True,['','']]
			
		ext_print_temp = []
		cpd_ext_offset = 0
		loop_break = 0
		entry_empty = 0
		
		if b'.man' in cpd_entry_name or b'.met' in cpd_entry_name or (single_man_name and start_man_match != -1) :
			# Set initial CSE Extension Offset
			if (b'.man' in cpd_entry_name or single_man_name) and start_man_match != -1 :
				cpd_ext_offset = cpd_entry_offset + mn2_hdr.HeaderLength * 4 # Skip $MN2 at .man
			elif b'.met' in cpd_entry_name :
				cpd_ext_offset = cpd_entry_offset # Metadata is always Uncompressed
			
			# Analyze all Manifest & Metadata Extensions
			ext_tag = int.from_bytes(buffer[cpd_ext_offset:cpd_ext_offset + 0x4], 'little') # Initial Extension Tag
			
			ext_print.append(cpd_entry_name.decode('utf-8')) # Store Manifest/Metadata name
			
			while True : # Parse all CSE Extensions and break at Manifest/Metadata end
				
				# Break loop just in case it becomes infinite
				loop_break += 1
				if loop_break > 100 :
					cse_anl_err(col_r + 'Error: Forced CSE Extension Analysis break after 100 loops at %s > %s!' % (cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					break
				
				# Determine if Entry is Empty/Missing
				entry_data = buffer[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
				if entry_data in (b'', b'\xFF' * cpd_entry_size) or cpd_entry_offset >= file_end : entry_empty = 1
				
				# Detect unknown CSE Extension & notify user
				if ext_tag not in ext_tag_all :
					cse_anl_err(col_r + 'Error: Detected unknown CSE Extension 0x%0.2X at %s > %s!\n       Some modules may not be detected without adding 0x%0.2X support!'
					% (ext_tag, cpd_name, cpd_entry_name.decode('utf-8'), ext_tag) + col_e, None)
				
				# Determine Extension Size & End Offset
				if ext_tag == 0x544F4F46 : cpd_ext_size = int.from_bytes(buffer[cpd_ext_offset + 0x8:cpd_ext_offset + 0xC], 'little')
				else : cpd_ext_size = int.from_bytes(buffer[cpd_ext_offset + 0x4:cpd_ext_offset + 0x8], 'little')
				cpd_ext_end = cpd_ext_offset + cpd_ext_size
				
				# Detect CSE Extension with null size & break loop
				if cpd_ext_size == 0 :
					cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with null size at %s > %s!\n       Possible false positive, skipping rest of Manifest/Metadata!'
					% (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					break # Break loop because it will become infinite with null size
				
				# Detect CSE Extension data overflow & notify user
				if entry_empty == 0 and (cpd_ext_end > cpd_entry_offset + cpd_entry_size) : # Manifest/Metadata Entry overflow
					cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X data overflow at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				hdr_rev_tag = '' # CSE Extension Header Revision Tag
				mod_rev_tag = '' # CSE Extension Module Revision Tag
				
				if (variant,major) in [('GSC',100),('GSC',101)] or (variant_p,anl_meu_major) in [('PMC',100),('OROM',100),('PMC',101),('OROM',101)] :
					if ext_tag in ext_tag_rev_hdr_gsc100 : hdr_rev_tag = ext_tag_rev_hdr_gsc100[ext_tag]
					if ext_tag in ext_tag_rev_mod_gsc100 : mod_rev_tag = ext_tag_rev_mod_gsc100[ext_tag]
				elif (variant,major) in [('CSME',15),('CSME',16),('CSSPS',6)] or (variant_p,anl_major) in [('PMC',150),('PMC',160),('PCHC',15),('PCHC',16)] or mn2_rsa_key_len == 0x180 :
					if ext_tag in ext_tag_rev_hdr_csme15 : hdr_rev_tag = ext_tag_rev_hdr_csme15[ext_tag]
					if ext_tag in ext_tag_rev_mod_csme15 : mod_rev_tag = ext_tag_rev_mod_csme15[ext_tag]
				elif (variant,major) == ('CSME',12) and not ((minor,hotfix) == (0,0) and build >= 7000 and year < 0x2018 and month < 0x8) or (variant,major) in [('CSME',13),('CSME',14)] :
					if ext_tag in ext_tag_rev_hdr_csme12 : hdr_rev_tag = ext_tag_rev_hdr_csme12[ext_tag]
					if ext_tag in ext_tag_rev_mod_csme12 : mod_rev_tag = ext_tag_rev_mod_csme12[ext_tag]
				elif (variant,major,minor,hotfix) == ('CSSPS',5,0,3) :
					if ext_tag in ext_tag_rev_hdr_cssps503 : hdr_rev_tag = ext_tag_rev_hdr_cssps503[ext_tag]
					if ext_tag in ext_tag_rev_mod_cssps503 : mod_rev_tag = ext_tag_rev_mod_cssps503[ext_tag]
				elif (variant,major) == ('CSSPS',5) or (variant,major,minor) == ('CSSPS',4,4) :
					if ext_tag in ext_tag_rev_hdr_cssps5 : hdr_rev_tag = ext_tag_rev_hdr_cssps5[ext_tag]
					if ext_tag in ext_tag_rev_mod_cssps5 : mod_rev_tag = ext_tag_rev_mod_cssps5[ext_tag]
				else :
					pass # These CSE use the original Header/Module Structures
				
				ext_dict_name = 'CSE_Ext_%0.2X%s' % (ext_tag, hdr_rev_tag)
				ext_struct_name = ext_dict[ext_dict_name] if ext_dict_name in ext_dict else None
				ext_dict_mod = 'CSE_Ext_%0.2X_Mod%s' % (ext_tag, mod_rev_tag)
				ext_struct_mod = ext_dict[ext_dict_mod] if ext_dict_mod in ext_dict else None
				
				ext_length = ctypes.sizeof(ext_struct_name) if ext_struct_name else 0
				mod_length = ctypes.sizeof(ext_struct_mod) if ext_struct_mod else 0
				cpd_mod_offset = cpd_ext_offset + ext_length
				cpd_mod_area = cpd_ext_end - cpd_mod_offset
				
				ext_hdr_extra = ['CSE_Ext_0C'] # Extensions which require extra get_struct parameters
				
				# Detect CSE Extension without Modules different size & notify user
				if (ext_tag,hdr_rev_tag) in ext_tag_mod_none and cpd_ext_size != ext_length :
					cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				# Check if Module data is divisible by Module size
				if mod_length and cpd_mod_area % mod_length != 0 :
					cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				# Get Extension Structure when no extra get_struct parameters are required. The Extension Info storing for
				# Extensions which require extra get_struct parameters must occur after their own Structure initialization.
				if ext_struct_name and ext_dict_name not in ext_hdr_extra :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name) # Get Extension Structure for non ext_hdr_extra Extensions
					ext_print_temp.append(ext_hdr.ext_print()) # Store Extension Info for non ext_hdr_extra Extensions
				else :
					ext_hdr = None # Get Extension Structure for ext_hdr_extra Extensions later
				
				special_mod_anl = False # Mark all Extension Modules which require special/unique processing
				
				if ext_tag == 0x0 :
					intel_cfg_hash_len = len(ext_hdr.IMGDefaultHash) * 4
					intel_cfg_hash_ext = '%0.*X' % (intel_cfg_hash_len * 2, int.from_bytes(ext_hdr.IMGDefaultHash, 'little'))
					
					# Validate CSME/CSSPS MFS Intel Configuration (Low Level File 6) Hash at Non-Initialized/Non-FWUpdated MFS. Ignore at (CS)SPS with different FTPR & OPR Versions.
					if intel_cfg_hash_mfs and mfs_found and mfs_parsed_idx and not any(idx in mfs_parsed_idx for idx in [0,1,2,3,4,5,8]) and not sps_extr_ignore and intel_cfg_hash_ext not in intel_cfg_hash_mfs :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong $FPT MFS Intel Configuration Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e,
						[intel_cfg_hash_ext,intel_cfg_hash_mfs])
					
					# Validate CSTXE or CSME 12 Alpha MFS/AFS Intel Configuration (FTPR > intl.cfg) Hash
					if intel_cfg_hash_ftpr and intel_cfg_ftpr and intel_cfg_hash_ext not in intel_cfg_hash_ftpr :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong FTPR MFS Intel Configuration Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e,
						[intel_cfg_hash_ext,intel_cfg_hash_ftpr])
					
					# Detect unexpected inability to validate Non-Initialized/Non-FWUpdated $FPT (Low Level File 6) or FTPR (intl.cfg) MFS/AFS Intel Configuration Hash
					if ((mfs_found and 6 in mfs_parsed_idx and not any(idx in mfs_parsed_idx for idx in [0,1,2,3,4,5,8]) and not intel_cfg_hash_mfs) or (intel_cfg_ftpr and not intel_cfg_hash_ftpr)) and not param.cse_unpack :
						cse_anl_err(col_m + 'Warning: Could not validate CSE Extension 0x%0.2X MFS Intel Configuration Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				elif ext_tag == 0x3 :
					ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name
					ext_psize = ext_hdr.PartitionSize # Partition Size
					ext_phash_len = len(ext_hdr.Hash) * 4 # Partition Hash Length
					ext_phash = '%0.*X' % (ext_phash_len * 2, int.from_bytes(ext_hdr.Hash, 'little')) # Partition Hash
					vcn = ext_hdr.VCN # Version Control Number
					in_id = ext_hdr.InstanceID # LOCL/WCOD identifier
					if gmf_blob_info : gmf_blob_info[1] = in_id # Fill GMF Blobs Partition Instance ID (Not POR, just in case)
					special_mod_anl = True # CSE_Ext_03 requires special/unique Module processing
					
					# Verify Partition Hash ($CPD - $MN2 + Data)
					if start_man_match != -1 and not single_man_name and not oem_config and not oem_signed and not fptemp_info[0] :
						mea_pdata = buffer[cpd_offset:mn2_offset] + buffer[mn2_offset + mn2_size:cpd_offset + ext_psize] # $CPD + Data (no $MN2)
						mea_phash = get_hash(mea_pdata, len(ext_phash) // 2) # Hash for CSE_Ext_03
						
						ext_phval = [True, ext_phash == mea_phash, ext_phash, mea_phash]
						if not ext_phval[1] and int(ext_phval[2], 16) != 0 :
							if (variant,major,minor,ext_psize) == ('CSME',11,8,0x88000) : (ext_phash, mea_phash) = ('IGNORE', 'IGNORE') # CSME 11.8 Slim Partition Hash is always wrong, ignore
							elif (variant,major) == ('CSSPS',1) : (ext_phash, mea_phash) = ('IGNORE', 'IGNORE') # CSSPS 1/IGN Partition Hash is always wrong, ignore
							elif (variant,major,minor) == ('CSSPS',4,2) : (ext_phash, mea_phash) = ('IGNORE', 'IGNORE') # CSSPS 4.2/IGN Partition Hash is always wrong, ignore
							cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong Partition Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, [ext_phash,mea_phash])
						
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr = get_struct(buffer, cpd_mod_offset, ext_struct_mod)
						met_name = mod_hdr.Name.decode('utf-8') + '.met'
						# Some Modules may have multiple 03/0F/16/23 and/or MetadataHash mismatch and/or double .met extension (GREAT WORK INTEL/OEMs...)
						if met_name.endswith('.met.met') : met_name = met_name[:-4]
						met_hash_len = len(mod_hdr.MetadataHash) * 4 # Metadata Hash Length
						met_hash = '%0.*X' % (met_hash_len * 2, int.from_bytes(mod_hdr.MetadataHash, 'little')) # Metadata Hash
						
						cpd_ext_hash.append([cpd_name, met_name, met_hash])
						
						ext_print_temp.append(mod_hdr.ext_print())
						
						cpd_mod_offset += mod_length
					
				elif ext_tag == 0xA :
					mod_comp_type = ext_hdr.Compression # Metadata's Module Compression Type (0-2)
					mod_encr_type = ext_hdr.Encryption # Metadata's Module Encryption Type (0-1)
					mod_comp_size = ext_hdr.SizeComp # Metadata's Module Compressed Size ($CPD Entry's Module Size is always Uncompressed)
					mod_uncomp_size = ext_hdr.SizeUncomp # Metadata's Module Uncompressed Size (equal to $CPD Entry's Module Size)
					mod_hash_len = len(ext_hdr.Hash) * 4 # Metadata's Module Hash Length
					mod_hash = '%0.*X' % (mod_hash_len * 2, int.from_bytes(ext_hdr.Hash, 'little')) # Metadata's Module Hash
					
					cpd_mod_attr.append([cpd_entry_name.decode('utf-8')[:-4], mod_comp_type, mod_encr_type, 0, mod_comp_size, mod_uncomp_size, 0, mod_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_chk_info])
				
				elif ext_tag == 0xC :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, ftpr_var_ver)
					ext_print_temp.append(ext_hdr.ext_print()) # Store Extension 0C Info, requires extra get_struct parameters
					
					_,fw_0C_sku1,fw_0C_lbg,_,_,fw_0C_sku2,_,_ = ext_hdr.get_flags()
					fw_0C_sku0 = ext_hdr.get_skuc() # SKU Capabilities
					
					# Check if SKU Capabilities Reserved are actually reserved
					skuc_res_len = len(ext_hdr.FWSKUCapsRes) * 4
					skuc_res = '%0.*X' % (skuc_res_len * 2, int.from_bytes(ext_hdr.FWSKUCapsRes, 'little'))
					if skuc_res != 'FF' * 28 :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with new SKU Capabilities at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					ext12_sku1 = ext12_fw_sku[fw_0C_sku1] if fw_0C_sku1 in ext12_fw_sku else ('Unknown','UNK') # Firmware SKU (COR, CON, SLM, SVR)
					
					ext12_info = [fw_0C_sku0, ext12_sku1, fw_0C_lbg, fw_0C_sku2]
				
				elif ext_tag == 0xF :
					if ext_pname == '' : ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name (prefer CSE_Ext_03)
					if vcn == -1 : vcn = ext_hdr.VCN # Version Control Number (prefer CSE_Ext_03)
					arb_svn = ext_hdr.ARBSVN # FPF Anti-Rollback (ARB) Security Version Number
					ext15_info[0] = arb_svn # Adjust CSE Extension 15 Info with ARB SVN
					special_mod_anl = True # CSE_Ext_0F requires special/unique Module processing
					
					if hasattr(ext_hdr, 'NVMCompatibility') : # Parse CSE_Ext_0F_R2 fields
						ext15_type = ext15_fw_type[ext_hdr.FWType] if ext_hdr.FWType in ext15_fw_type else 'Unknown' # Firmware Type (Client, SPS etc)
						ext15_sku = ext15_fw_sku[ext_hdr.FWSKU] if ext_hdr.FWSKU in ext15_fw_sku else ('Unknown','UNK') # Firmware SKU (CON, COR, SLM, LIT, SVR etc)
						ext15_nvm = ext15_nvm_type[ext_hdr.NVMCompatibility] if ext_hdr.NVMCompatibility in ext15_nvm_type else 'Unknown' # NVM Compatibility (SPI, UFS etc)
						
						ext15_info[1:4] = ext15_type, ext15_sku, ext15_nvm # Adjust CSE Extension 15 Info with FW Type, FW SKU, NVM Type
					
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr = get_struct(buffer, cpd_mod_offset, ext_struct_mod)
						met_name = mod_hdr.Name.decode('utf-8') + '.met'
						# Some Modules may have multiple 03/0F/16/23 and/or MetadataHash mismatch and/or double .met extension (GREAT WORK INTEL/OEMs...)
						if met_name.endswith('.met.met') : met_name = met_name[:-4]
						met_hash_len = len(mod_hdr.MetadataHash) * 4 # Metadata Hash Length
						met_hash = '%0.*X' % (met_hash_len * 2, int.from_bytes(mod_hdr.MetadataHash, 'little')) # Metadata Hash
						
						cpd_ext_hash.append([cpd_name, met_name, met_hash])
						
						ext_print_temp.append(mod_hdr.ext_print())
						
						cpd_mod_offset += mod_length
				
				elif ext_tag == 0x10 :
					CSE_Ext_10_Chunk_count = divmod(cpd_mod_area, mod_length) # Number of iUnit Entries/Chunks
					CSE_Ext_10_iUnit_offset = cpd_ext_end # iUnit Module data begin after iUnit Metadata
					while buffer[CSE_Ext_10_iUnit_offset] == 0xFF : CSE_Ext_10_iUnit_offset += 1 # Skip padding before iUnit Module data
					
					# Check if iUnit Entries/Chunks Area is divisible by Entry/Chunk Size size
					if CSE_Ext_10_Chunk_count[1] != 0 :
						cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					# Parse all iUnit Module Chunks via their Extension Metadata
					for chunk in range(CSE_Ext_10_Chunk_count[0]) :
						chunk_hdr = get_struct(buffer, cpd_mod_offset + chunk * mod_length, ext_struct_mod) # iUnit Chunk Metadata
						iunit_chunk_size = chunk_hdr.Size # iUnit Module Chunk Size
						if chunk == 0 : iunit_chunk_start = CSE_Ext_10_iUnit_offset + chunk_hdr.Unknown1 # First Chunk starts from a Base Address ?
						iunit_chunk_hash_ext_len = len(chunk_hdr.Hash) * 4 # iUnit Module Chunk Intel Hash (BE) Length
						iunit_chunk_hash_ext = '%0.*X' % (iunit_chunk_hash_ext_len * 2, int.from_bytes(chunk_hdr.Hash, 'big')) # iUnit Module Chunk Intel Hash (BE)
						iunit_chunk_hash_mea = get_hash(buffer[iunit_chunk_start:iunit_chunk_start + iunit_chunk_size], len(iunit_chunk_hash_ext) // 2) # iUnit Module Chunk MEA Hash
						iunit_chunk_valid.append(iunit_chunk_hash_mea == iunit_chunk_hash_ext) # Store iUnit Module Chunk(s) Hash validation results
						iunit_chunk_start += iunit_chunk_size # Next iUnit Module Chunk starts at the previous plus its size
					
					# Verify that all iUnit Module data Chunks are valid
					if iunit_chunk_valid == [True] * len(iunit_chunk_valid) : ext_iunit_val[0] = True
					
					CSE_Ext_10_iUnit_size = iunit_chunk_start - CSE_Ext_10_iUnit_offset # iUnit Module full Size for CSE Unpacking
					cpd_mod_attr.append([cpd_entry_name.decode('utf-8')[:-4], 0, 0, 0, CSE_Ext_10_iUnit_size, CSE_Ext_10_iUnit_size, 0, 0, cpd_name, 0, mn2_sigs, cpd_offset, cpd_chk_info])
					
				elif ext_tag == 0x11 :
					mod_size = ext_hdr.OffsetLimit - ext_hdr.OffsetBase # cAVS Module Size = OffsetLimit - OffsetBase (should match $CPD Entry)
					mod_hash_len = len(ext_hdr.Hash) * 4 # Metadata's Module Hash (BE) Length
					mod_hash = '%0.*X' % (mod_hash_len * 2, int.from_bytes(ext_hdr.Hash, 'big')) # Metadata's Module Hash (BE)
					
					cpd_mod_attr.append([cpd_entry_name.decode('utf-8')[:-4], 0, 0, 0, mod_size, mod_size, 0, mod_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_chk_info])
				
				elif ext_tag == 0x13 :
					hash_len = len(ext_hdr.IBBLHash) * 4 # IBBL/IBB/OBB Hash Length
					ibbl_hash = '%0.*X' % (hash_len * 2, int.from_bytes(ext_hdr.IBBLHash, 'big')) # IBBL Hash (BE)
					ibb_hash = '%0.*X' % (hash_len * 2, int.from_bytes(ext_hdr.IBBHash, 'big')) # IBB Hash (BE)
					obb_hash = '%0.*X' % (hash_len * 2, int.from_bytes(ext_hdr.OBBHash, 'big')) # OBB Hash (BE)
					if ibbl_hash not in ['00' * ext_hdr.IBBLHashSize, 'FF' * ext_hdr.IBBLHashSize] : cpd_mod_attr.append(['IBBL', 0, 0, 0, 0, 0, 0, ibbl_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_chk_info])
					if ibb_hash not in ['00' * ext_hdr.IBBHashSize, 'FF' * ext_hdr.IBBHashSize] : cpd_mod_attr.append(['IBB', 0, 0, 0, 0, 0, 0, ibb_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_chk_info])
					if obb_hash not in ['00' * ext_hdr.OBBHashSize, 'FF' * ext_hdr.OBBHashSize] : cpd_mod_attr.append(['OBB', 0, 0, 0, 0, 0, 0, obb_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_chk_info])
					
				elif ext_tag == 0x14 and dnx_version == 1 : # CSE_Ext_14 Revision 1 (R1) has a unique structure
					# For CSE_Ext_14_R1, all the processing is done at the Manifest Analysis level. All validation results
					# are transferred to mod_anl via ext_dnx_val list so that they can be displayed in logical -unp86 order.
					
					ext_dnx_val[0] = dnx_version # DnX Version 1 (R1 SHA-256)
					ifwi_rgn_hdr_step = 0 # Step to loop through IFWI Region Maps
					rcip_chunk_size = ext_hdr.ChunkSize # RCIP IFWI Chunk Size
					rcip_chunk_count_ext = ext_hdr.ChunkCount # RCIP IFWI Chunk Count from Extension
					rcip_chunk_count_mea = int(dnx_rcip_len / rcip_chunk_size) # RCIP IFWI Chunk Count from MEA
					ifwi_rgn_count = ext_hdr.IFWIRegionCount # IFWI Region Count (eMMC/UFS)
					special_mod_anl = True # CSE_Ext_14_R1 requires special/unique Module processing
					
					# Check if RCIP length is divisible by RCIP Chunk length and if RCIP Chunk count from EXT is the same as MEA's
					if (dnx_rcip_len % rcip_chunk_size != 0) or (rcip_chunk_count_ext != rcip_chunk_count_mea) :
						cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					# Parse each IFWI Region Map
					for _ in range(ifwi_rgn_count) :
						ifwi_rgn_map = get_struct(buffer, cpd_mod_offset + ifwi_rgn_hdr_step, CSE_Ext_14_RegionMap)
						ext_print_temp.append(ifwi_rgn_map.ext_print())
						
						ifwi_rgn_hdr_step += ctypes.sizeof(CSE_Ext_14_RegionMap)
					
					# Parse each RCIP IFWI Chunk
					for chunk in range(rcip_chunk_count_ext) :
						rcip_chunk_off = dnx_rcip_off + chunk * rcip_chunk_size
						chunk_hash_off = cpd_mod_offset + ifwi_rgn_hdr_step + chunk * 0x20
						
						rcip_chunk_hash = get_hash(buffer[rcip_chunk_off:rcip_chunk_off + rcip_chunk_size], 0x20) # SHA-256
						ext_chunk_hash = format(int.from_bytes(buffer[chunk_hash_off:chunk_hash_off + 0x20], 'little'), '064X')
						
						# Check if Extension Chunk Hash is equal to RCIP IFWI Chunk Hash
						if ext_chunk_hash == rcip_chunk_hash : chunk_hash_valid_count += 1
						
						pt_14_R2 = ext_table(['Field', 'Value'], False, 1)
						pt_14_R2.title = col_y + 'Extension 20 R1 Chunk %d/%d' % (chunk + 1, rcip_chunk_count_ext) + col_e
						pt_14_R2.add_row(['Chunk EXT Hash', ext_chunk_hash])
						pt_14_R2.add_row(['Chunk MEA Hash', rcip_chunk_hash])
						
						ext_print_temp.append(pt_14_R2)
						
					# Check if all Extension Chunk Hashes and RCIP IFWI Chunk Hashes are Valid
					if chunk_hash_valid_count == rcip_chunk_count_ext : ext_dnx_val[2] = True
					
				elif ext_tag == 0x14 and dnx_version == 2 : # CSE_Ext_14 Revision 2 (R2-R3) has a unique structure
					# For CSE_Ext_14_R2, all the processing is done at the Manifest Analysis level. All validation results
					# are transferred to mod_anl via ext_dnx_val list so that they can be displayed in logical -unp86 order.
					
					ext_dnx_val[0] = dnx_version # DnX Version 2 (R2 SHA-256, R3 SHA-384)
					ifwi_rgn_hdr_step = 0 # Step to loop through IFWI Region Maps
					hash_arr_hdr_step = 0 # Step to loop through Hashes Array Headers
					hash_arr_prev_part_size = 0 # Step to loop through Hashes Array file sections
					hash_arr_hdr_count = ext_hdr.HashArrHdrCount # Hashes Array Header Count
					chunk_hash_size = ext_hdr.ChunkHashSize # Hashes Array Chunk Hash Size
					rcip_chunk_size = ext_hdr.ChunkSize # RCIP IFWI Chunk Size
					rcip_chunk_count = int(dnx_rcip_len / rcip_chunk_size) # RCIP IFWI Chunk Count
					ifwi_rgn_count = ext_hdr.IFWIRegionCount # IFWI Region Count (eMMC/UFS)
					special_mod_anl = True # CSE_Ext_14_R2/R3 requires special/unique Module processing
					
					# Parse each Hashes Array Header
					for header in range(hash_arr_hdr_count) :
						hash_arr_part_struct = CSE_Ext_14_HashArray if mn2_rsa_key_len == 0x100 else CSE_Ext_14_HashArray_R2
						hash_arr_part_hdr = get_struct(buffer, cpd_mod_offset + hash_arr_hdr_step, hash_arr_part_struct)
						hash_arr_part_size = hash_arr_part_hdr.HashArrSize * 4 # Hashes Array file section size
						hash_arr_part_hash_len = len(hash_arr_part_hdr.HashArrHash) * 4 # Hashes Array file section Hash Length
						hash_arr_part_hash = '%0.*X' % (hash_arr_part_hash_len * 2, int.from_bytes(hash_arr_part_hdr.HashArrHash, 'little')) # Hashes Array file section Hash
						
						hash_arr_part_data_off = dnx_hash_arr_off + hash_arr_prev_part_size # Hashes Array file section data offset
						hash_arr_part_data = buffer[hash_arr_part_data_off:hash_arr_part_data_off + hash_arr_part_size] # Hashes Array file section data
						hash_arr_part_data_hash = get_hash(hash_arr_part_data, chunk_hash_size) # Hashes Array file section data hash
						
						# Check if RCIP length is divisible by RCIP Chunk length and if Hashes Array file section length is divisible by its Size
						if (dnx_rcip_len % rcip_chunk_size != 0) or (len(hash_arr_part_data) % hash_arr_part_size != 0) :
							cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
						
						# Check if Hashes Array file section Hash is valid to Hashes Array file section Header
						if hash_arr_part_hash == hash_arr_part_data_hash : hash_arr_valid_count += 1
						
						pt_14_R2 = ext_table(['Field', 'Value'], False, 1)
						pt_14_R2.title = col_y + 'Extension 20 R2/R3 Hashes Array %d/%d' % (header + 1, hash_arr_hdr_count) + col_e
						pt_14_R2.add_row(['Hashes Array EXT Hash', hash_arr_part_hash])
						pt_14_R2.add_row(['Hashes Array MEA Hash', hash_arr_part_data_hash])
						
						ext_print_temp.append(pt_14_R2)
						
						# Parse each RCIP IFWI Chunk
						for chunk in range(rcip_chunk_count) :
							rcip_chunk_off = dnx_rcip_off + chunk * rcip_chunk_size
							hash_arr_chunk_off = dnx_hash_arr_off + chunk * chunk_hash_size
							
							rcip_chunk_hash = get_hash(buffer[rcip_chunk_off:rcip_chunk_off + rcip_chunk_size], chunk_hash_size) # SHA-256 or SHA-384
							hash_arr_chunk_hash = format(int.from_bytes(buffer[hash_arr_chunk_off:hash_arr_chunk_off + chunk_hash_size], 'little'), '0%dX' % (chunk_hash_size * 2))
							
							# Check if Hashes Array Chunk Hash is equal to RCIP IFWI Chunk Hash
							if hash_arr_chunk_hash == rcip_chunk_hash : chunk_hash_valid_count += 1
							
							pt_14_R2 = ext_table(['Field', 'Value'], False, 1)
							pt_14_R2.title = col_y + 'Extension 20 R2/R3 Chunk %d/%d' % (chunk + 1, rcip_chunk_count) + col_e
							pt_14_R2.add_row(['Chunk EXT Hash', hash_arr_chunk_hash])
							pt_14_R2.add_row(['Chunk MEA Hash', rcip_chunk_hash])
							
							ext_print_temp.append(pt_14_R2)
						
						hash_arr_prev_part_size += hash_arr_part_size
						hash_arr_hdr_step += ctypes.sizeof(hash_arr_part_struct)

					# Parse each IFWI Region Map
					for _ in range(ifwi_rgn_count) :
						ifwi_rgn_map = get_struct(buffer, cpd_mod_offset + hash_arr_hdr_step + ifwi_rgn_hdr_step, CSE_Ext_14_RegionMap)
						ext_print_temp.append(ifwi_rgn_map.ext_print())
						
						ifwi_rgn_hdr_step += ctypes.sizeof(CSE_Ext_14_RegionMap)
						
					# Check if all Hashes Array Header Hashes and RCIP IFWI Chunk Hashes are Valid
					if hash_arr_valid_count == hash_arr_hdr_count : ext_dnx_val[1] = True
					if chunk_hash_valid_count == rcip_chunk_count * hash_arr_hdr_count : ext_dnx_val[2] = True
				
				elif ext_tag == 0x15 : # CSE_Ext_15 has a unique structure
					CSE_Ext_15_PartID_length = ctypes.sizeof(CSE_Ext_15_PartID)
					CSE_Ext_15_Payload_length = ctypes.sizeof(CSE_Ext_15_Payload)
					CSE_Ext_15_Payload_Knob_length = ctypes.sizeof(CSE_Ext_15_Payload_Knob)
					special_mod_anl = True # CSE_Ext_15 requires special/unique Module processing
					
					part_id_count = ext_hdr.PartIDCount
					cpd_part_id_offset = cpd_mod_offset # CSE_Ext_15 structure size (not entire Extension 15)
					cpd_payload_offset = cpd_part_id_offset + part_id_count * 0x14
					cpd_payload_knob_offset = cpd_payload_offset + 0x4
					
					for _ in range(part_id_count) :
						part_id_struct = get_struct(buffer, cpd_part_id_offset, CSE_Ext_15_PartID)
						ext_print_temp.append(part_id_struct.ext_print())
						cpd_part_id_offset += 0x14
					
					payload_struct = get_struct(buffer, cpd_payload_offset, CSE_Ext_15_Payload)
					ext_print_temp.append(payload_struct.ext_print())
					payload_knob_count = payload_struct.KnobCount
					payload_knob_area = cpd_ext_end - cpd_payload_knob_offset
					
					# Check Extension full size when Module Counter exists
					if (ext_tag,hdr_rev_tag) in ext_tag_mod_count and (cpd_ext_size != ext_length + part_id_count * CSE_Ext_15_PartID_length + CSE_Ext_15_Payload_length +
					payload_knob_count * CSE_Ext_15_Payload_Knob_length) :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					# Check if Knob data is divisible by Knob size
					if payload_knob_area % CSE_Ext_15_Payload_Knob_length != 0 :
						cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					for _ in range(payload_knob_count) :
						payload_knob_struct = get_struct(buffer, cpd_payload_knob_offset, CSE_Ext_15_Payload_Knob, ftpr_var_ver)
						ext_print_temp.append(payload_knob_struct.ext_print())
						cpd_payload_knob_offset += 0x08
					
				elif ext_tag == 0x16 :
					ext_psize = ext_hdr.PartitionSize # Partition Size
					if ext_pname == '' : ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name (prefer CSE_Ext_03)
					if in_id == 0 : in_id = ext_hdr.InstanceID # LOCL/WCOD identifier (prefer CSE_Ext_03)
					if gmf_blob_info : gmf_blob_info[1] = in_id # Fill GMF Blobs Partition Instance ID
					ext_phlen = int.from_bytes(ext_hdr.HashSize, 'little') # Partition Hash Length
					ext_phash = '%0.*X' % (ext_phlen * 2, int.from_bytes(ext_hdr.Hash, 'little')) # Partition Hash
					
					# Verify Partition Hash ($CPD - $MN2 + Data)
					if start_man_match != -1 and not single_man_name and not oem_config and not oem_signed and not fptemp_info[0] :
						mea_pdata = buffer[cpd_offset:mn2_offset] + buffer[mn2_offset + mn2_size:cpd_offset + ext_psize] # $CPD + Data (no $MN2)
						
						mea_phash = get_hash(mea_pdata, ext_phlen)
						ext_phval = [True, ext_phash == mea_phash, ext_phash, mea_phash]
						if not ext_phval[1] and int(ext_phval[2], 16) != 0 :
							if (variant,major) in [('CSSPS',5),('CSSPS',6)] : (ext_phash, mea_phash) = ('IGNORE', 'IGNORE') # CSSPS 5-6 Partition Hash is always wrong, ignore
							elif (variant,major,minor) == ('CSSPS',4,4) : (ext_phash, mea_phash) = ('IGNORE', 'IGNORE') # CSSPS 4.4 Partition Hash is always wrong, ignore
							elif (variant,anl_major,anl_meu_major) == ('PHY',12,0) : (ext_phash, mea_phash) = ('IGNORE', 'IGNORE') # PHYP EBG Partition Hash is always wrong, ignore
							cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong Partition Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, [ext_phash,mea_phash])
							
				elif ext_tag == 0x17 :
					fd_ranges = [(ext_hdr.Range1Start,ext_hdr.Range1End),(ext_hdr.Range2Start,ext_hdr.Range2End),(ext_hdr.Range3Start,ext_hdr.Range3End),(ext_hdr.Range4Start,ext_hdr.Range4End),
								 (ext_hdr.Range5Start,ext_hdr.Range5End),(ext_hdr.Range6Start,ext_hdr.Range6End),(ext_hdr.Range7Start,ext_hdr.Range7End),(ext_hdr.Range8Start,ext_hdr.Range8End)]
					fd_hash_len = len(ext_hdr.Hash) * 4
					fd_hash = '%0.*X' % (fd_hash_len * 2, int.from_bytes(ext_hdr.Hash, 'little'))
					
					fd_info = [fd_hash,fd_ranges] # Store Flash Descriptor Verification Hash and Exclusion Ranges

				elif ext_tag in (0x18,0x19,0x1A) and hasattr(ext_hdr, 'Reserved') :
					iom_names = {'SAMF':'samf', 'IOMP':'iom'}
					tbt_names = {'TBTP':'tbt'}
					mg_names = {'PPHY':'pphy', 'NPHY':'nphy', 'SPHY':'sphy', 'DPHY':'dphy', 'MGPP':'mg'}
					tcss_types = {
								1:iom_names[cpd_name] if cpd_name in iom_names else 'iom',
								2:mg_names[cpd_name] if cpd_name in mg_names else 'mg',
								3:tbt_names[cpd_name] if cpd_name in tbt_names else 'tbt',
								4:(iom_names[cpd_name] if cpd_name in iom_names else 'iom') + '.cd',
								5:(tbt_names[cpd_name] if cpd_name in tbt_names else 'tbt') + '.cd',
								11:(iom_names[cpd_name] if cpd_name in iom_names else 'iom') + '.hwcd'
								}
					special_mod_anl = True # CSE_Ext_18/19/1A require special/unique Module processing
					
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr = get_struct(buffer, cpd_mod_offset, ext_struct_mod)
						
						tcss_type = mod_hdr.HashType # Numeric value which corresponds to specific TCSS module filename
						tcss_hash_len = len(mod_hdr.Hash) * 4 # Hash (BE) Length
						tcss_hash = '%0.*X' % (tcss_hash_len * 2, int.from_bytes(mod_hdr.Hash, 'big')) # Hash (BE)
						
						if tcss_type in tcss_types :
							tcss_name = tcss_types[tcss_type] # Get TCSS Module Name based on its Type and $CPD Name
							
							# Check if the generated TCSS Module Name is actually one of the $CPD Partition Modules Names
							if tcss_name not in cpd_mod_names : cse_anl_err(col_r + 'Error: Detected unknown CSE TCSS Name at %s > %s!' % (cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
							
							cpd_mod_attr.append([tcss_name, 0, 0, 0, 0, 0, 0, tcss_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_chk_info])
						else :
							cse_anl_err(col_r + 'Error: Detected unknown CSE TCSS Type %d at %s > %s!' % (tcss_type, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
						
						ext_print_temp.append(mod_hdr.ext_print())
						
						cpd_mod_offset += mod_length

				elif ext_tag == 0x19 :
					gsc_project = ext_hdr.Project.decode('utf-8') # DG01, DG02 etc
					gsc_hotfix = ext_hdr.Hotfix # Hotfix for DG1 (e.g. 0), SKU at DG2+ (e.g. 1 = SOC1, 2 = SOC2)
					gsc_build = ext_hdr.Build # Year/Week at DG1 (2035 = 2020 W35), Stepping/Build at DG2 (e.g. 2054 = B)
					
					gsc_info = [gsc_project, gsc_hotfix, gsc_build]
				
				elif ext_tag in (0x18,0x1A) :
					special_mod_anl = True # CSE_Ext_18/1A require special/unique Module processing
					
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr = get_struct(buffer, cpd_mod_offset, ext_struct_mod)
						
						fwi_iup_name = mod_hdr.Name.decode('utf-8')
						fwi_iup_hash_len = len(mod_hdr.Hash) * 4
						fwi_iup_hash = '%0.*X' % (fwi_iup_hash_len * 2, int.from_bytes(mod_hdr.Hash, 'big'))
						
						fwi_iup_hashes.append([fwi_iup_name,fwi_iup_hash])
						
						ext_print_temp.append(mod_hdr.ext_print())
						
						cpd_mod_offset += mod_length
				
				elif ext_tag == 0x1E : # CSE_Ext_1E has a unique structure
					# At CSE_Ext_1E, the GMF Certificate file/blob is within the Extension so its data must be
					# transferred to mod_anl via gmf_blob_info so that it can be extracted during unpacking.
					
					gmf_cert_size = ext_hdr.CertificateSize
					gmf_cert_start = cpd_mod_offset
					gmf_cert_end = gmf_cert_start + gmf_cert_size
					gmf_cert_data = buffer[gmf_cert_start:gmf_cert_end]
					gmf_cert_padd = buffer[gmf_cert_end:cpd_ext_end]
					
					# Gather GMF Certificate Data for current Partition Name, Instance ID & Offset
					if gmf_blob_info : gmf_blob_info[3][0] = gmf_cert_data
					else : gmf_blob_info = [cpd_name, in_id, cpd_offset, [gmf_cert_data, b'']]
					
					# Check Extension padding after GMF Certificate
					if gmf_cert_padd != b'\xFF' * (cpd_ext_end - gmf_cert_end) :
						cse_anl_err(col_r + 'Error: Detected invalid CSE Extension 0x%0.2X padding at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
						
				elif ext_tag == 0x1F : # CSE_Ext_1F has a unique structure
					# At CSE_Ext_1F, the GMF Body file/blob is within the Extension so its data must be
					# transferred to mod_anl via gmf_blob_info so that it can be extracted during unpacking.
					
					gmf_body_data = buffer[cpd_mod_offset:cpd_ext_end]
					
					# Gather GMF Body Data for current Partition Name, Instance ID & Offset
					if gmf_blob_info : gmf_blob_info[3][1] = gmf_body_data
					else : gmf_blob_info = [cpd_name, in_id, cpd_offset, [b'', gmf_body_data]]
				
				elif ext_tag == 0x23 :
					ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name
					vcn = ext_hdr.VCN # Version Control Number
					arb_svn = ext_hdr.ARBSVN # FPF Anti-Rollback (ARB) Security Version Number
					ext15_info[0] = arb_svn # Adjust CSE Extension 15/35 Info with ARB SVN
					special_mod_anl = True # CSE_Ext_23 requires special/unique Module processing
					
					'''
					# Extension 35 FWType & FWSKU processing, waiting for first sample before implementation
					ext15_type = ext15_fw_type[ext_hdr.FWType] if ext_hdr.FWType in ext15_fw_type else 'Unknown' # Firmware Type (Client, SPS etc)
					ext15_sku = ext15_fw_sku[ext_hdr.FWSKU] if ext_hdr.FWSKU in ext15_fw_sku else ('Unknown','UNK') # Firmware SKU (CON, COR, SLM, LIT, SVR etc)
					
					ext15_info[1:3] = ext15_type, ext15_sku # Adjust CSE Extension 15 Info with FW Type, FW SKU
					'''
					
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr = get_struct(buffer, cpd_mod_offset, ext_struct_mod)
						met_name = mod_hdr.Name.decode('utf-8') + '.met'
						# Some Modules may have multiple 03/0F/16/23 and/or MetadataHash mismatch and/or double .met extension (GREAT WORK INTEL/OEMs...)
						if met_name.endswith('.met.met') : met_name = met_name[:-4]
						met_hash_len = len(mod_hdr.MetadataHash) * 4 # Metadata Hash Length
						met_hash = '%0.*X' % (met_hash_len * 2, int.from_bytes(mod_hdr.MetadataHash, 'little')) # Metadata Hash
						
						cpd_ext_hash.append([cpd_name, met_name, met_hash])
						
						ext_print_temp.append(mod_hdr.ext_print())
						
						cpd_mod_offset += mod_length
				
				elif ext_tag == 0x32 :
					ext50_type = ext_hdr.Type.decode('utf-8') # SPS Type (OP, RC)
					ext50_plat = ext_hdr.Platform.decode('utf-8') # SPS Platform (GE, HA, PU, PE etc)
					
					ext50_info = [ext50_type, ext50_plat]
				
				# Check Extension full size when Module Counter exists
				if (ext_tag,hdr_rev_tag) in ext_tag_mod_count and (cpd_ext_size != ext_length + ext_hdr.ModuleCount * mod_length) :
					cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				# Parse generic Extension Modules w/o special processing
				if ext_dict_mod in ext_dict and not special_mod_anl :
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr = get_struct(buffer, cpd_mod_offset, ext_struct_mod)
						ext_print_temp.append(mod_hdr.ext_print())
				
						cpd_mod_offset += mod_length
				
				cpd_ext_offset += cpd_ext_size # Next Extension Offset
				
				if cpd_ext_offset + 0x4 > cpd_entry_offset + cpd_entry_size : # End of Manifest/Metadata Entry reached (at least 0x4 needed for next ext_tag)
					cpd_ext_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, entry_empty, 0, cpd_name, in_id, mn2_sigs, cpd_offset, cpd_chk_info])
					cpd_ext_names.append(cpd_entry_name.decode('utf-8')[:-4]) # Store Module names which have Manifest/Metadata
					
					break # Stop Extension scanning at the end of Manifest/Metadata Entry
				
				ext_tag = int.from_bytes(buffer[cpd_ext_offset:cpd_ext_offset + 0x4], 'little') # Next Extension Tag
			
			# Detect last 0x20 of UTOK/STKN for Unlock Token Flags Structure (Optional)
			if buffer[buffer_len - 0x20:buffer_len - 0x1C] == b'UTFL' :
				utfl_hdr = get_struct(buffer, buffer_len - 0x20, UTFL_Header)
				ext_print_temp.append(utfl_hdr.hdr_print())
			
			# Add $MN2 Info followed by Manifest/Metadata/UTFL Info
			if single_man_name and mn2_hdr_print : ext_print_temp = [mn2_hdr_print] + ext_print_temp
			
			ext_print.append(ext_print_temp) # Store Manifest/Metadata/UTFL Info
			
		# Actions when parsing UTOK/STKN without Manifest (a.k.a. UTFL only)
		if single_man_name and start_man_match == -1 :
			ext_print.append(cpd_entry_name.decode('utf-8')) # Store UTOK w/o $MN2 Partition Name
			# Detect last 0x20 of UTOK/STKN for Unlock Token Flags Structure
			if buffer[buffer_len - 0x20:buffer_len - 0x1C] == b'UTFL' :
				utfl_hdr = get_struct(buffer, buffer_len - 0x20, UTFL_Header)
				ext_print_temp.append(utfl_hdr.hdr_print())
			ext_print.append(ext_print_temp) # Store UTFL Info

	if single_man_name : return ext_print, mn2_sigs, fd_info # Stop Manifest/Metadata/UTFL analysis early when the input is a single Manifest
	
	# Stage 3: Calculate Module Compressed Size when no Metadata exists, thus treated as "Data" instead of "Module with Metadata" below
	# When the firmware lacks Module Metadata, the Compression Type, Encryption Yes/No, Compressed Size & Uncompressed Size are unknown
	# $CPD contains Huffman Yes/No and Uncompressed Size but Compressed Size is needed for Header parsing during Huffman decompression
	# RBEP > rbe and FTPR > pm Modules contain the Compressed Size, Uncompressed Size & Hash but without Names, only hardcoded DEV_IDs
	# With only Huffman Yes/No bit at $CPD, we can no longer discern between Uncompressed, LZMA Compressed and Encrypted Modules
	# This adjustment should only be required for Huffman Modules without Metadata but MEA calculates everything just in case
	for i in range(len(cpd_wo_met_info)) : # All $CPD entries should be ordered by Offset in ascending order for the calculation
		if cpd_wo_met_info[i][6] == 1 : # Check if entry has valid Starting Offset & Size (not empty)
			continue # Do not adjust empty entries to skip them during unpacking (i.e. fitc.cfg or oem.key w/o Data)
		if oem_config or oem_signed : # Check if entry is FIT/OEM customized and thus outside Stock/RGN Partition
			continue # Do not adjust FIT/OEM-customized Partition entries (fitc.cfg, oem.key) since $CPD info is accurate
		
		if i < len(cpd_wo_met_info) - 1 : # For all entries, use the next module offset to find its size, if possible
			cpd_wo_met_info[i][2] = cpd_wo_met_info[i + 1][1] - cpd_wo_met_info[i][1] # Size is Next Start - Current Start
		elif ext_psize != -1 : # For the last entry, use CSE Extension 0x3/0x16 to find its size via the total Partition size
			cpd_wo_met_info[i][2] = cpd_offset + ext_psize - cpd_wo_met_info[i][1] # Size is Partition End - Current Start
		else : # For the last entry, if CSE Extension 0x3/0x16 is missing, find its size manually via EOF 0xFF padding
			entry_size = buffer[cpd_wo_met_info[i][1]:].find(b'\xFF\xFF') # There is no Huffman codeword 0xFFFF
			if entry_size != -1 : cpd_wo_met_info[i][2] = entry_size # Size ends where the padding starts
			else : cse_anl_err(col_r + 'Error: Could not determine the size of Module %s > %s!' % (cpd_name,cpd_wo_met_info[i][0]) + col_e, None)
			
		if cpd_wo_met_info[i][2] > cpd_wo_met_back[i][2] or cpd_wo_met_info[i][2] < 0 : # Report obvious wrong Module Size adjustments
			cpd_wo_met_info[i][2] = cpd_wo_met_back[i][2] # Restore default Module Size from backup in case of wrong adjustment
			cse_anl_err(col_r + 'Error: Could not verify the size of Module %s > %s!' % (cpd_name,cpd_wo_met_info[i][0]) + col_e, None)
	
	# Stage 4: Fill Metadata Hash from Manifest
	for attr in cpd_ext_attr :
		for met_hash in cpd_ext_hash :
			if attr[8] == met_hash[0] and attr[0] == met_hash[1] : # Verify $CPD and Metadata name match
				attr[7] = met_hash[2] # Fill Metadata's Hash Attribute from Manifest Extension 0x3, 0xF, 0x16 or 0x23
				break # To hopefully avoid some 03/0F/16/23 MetadataHash mismatch, assuming 1st has correct MetadataHash
	
	# Stage 5: Analyze Modules, Keys, Microcodes & Data (must be after all Manifest & Metadata Extension analysis)
	for entry in range(0, cpd_num) :
		cpd_entry_hdr = get_struct(buffer, cpd_offset + cpd_hdr_size + entry * 0x18, CPD_Entry)
		cpd_mod_off,_,_ = cpd_entry_hdr.get_flags()
		
		cpd_entry_name = cpd_entry_hdr.Name
		cpd_entry_size = cpd_entry_hdr.Size # Uncompressed only
		cpd_entry_offset = cpd_offset + cpd_mod_off
		mod_size = cpd_entry_size # Uncompressed initially, to replace with Compressed for Modules
		mod_empty = 0 # Assume that Module is not empty initially
		
		# Manifest & Metadata Skip
		if b'.man' in cpd_entry_name or b'.met' in cpd_entry_name : continue
		
		# Fill Module Attributes by single unified Metadata (BPM.met > [IBBL, IBB, OBB] or iom.met > [iom, iom.cd, iom.hwcd] etc...)
		if cpd_name in ('IBBP','IOMP','MGPP','NPHY','TBTP') : # MGPP = NPHY
			for mod in range(len(cpd_mod_attr)) :
				if cpd_mod_attr[mod][0] == cpd_entry_name.decode('utf-8') :
					cpd_mod_attr[mod][4] = cpd_entry_size # Fill Module Uncompressed Size from $CPD Entry
					cpd_mod_attr[mod][5] = cpd_entry_size # Fill Module Uncompressed Size from $CPD Entry
					cpd_ext_names.append(cpd_entry_name.decode('utf-8')) # To enter "Module with Metadata" section below
					
					break
					
			# Store all IBBP Module names to exclude those missing but with Hash at .met (GREAT WORK INTEL/OEMs...)
			if cpd_name == 'IBBP' : ibbp_all.append(cpd_entry_name.decode('utf-8'))
		
		# Module with Metadata
		if cpd_entry_name.decode('utf-8') in cpd_ext_names :
			for mod in range(len(cpd_mod_attr)) :
				if cpd_mod_attr[mod][0] == cpd_entry_name.decode('utf-8') :
					
					cpd_mod_attr[mod][3] = cpd_entry_offset # Fill Module Starting Offset from $CPD Entry
					if cpd_mod_attr[mod][4] == 0 : cpd_mod_attr[mod][4] = cpd_entry_size # Prefer Metadata info, if available (!= 0)
					if cpd_mod_attr[mod][5] == 0 : cpd_mod_attr[mod][5] = cpd_entry_size # Prefer Metadata info, if available (!= 0)
					cpd_mod_attr[mod][9] = in_id # Fill Module Instance ID from CSE_Ext_03
					
					mod_comp_size = cpd_mod_attr[mod][4] # Store Module Compressed Size for Empty check
					mod_size = mod_comp_size # Store Module Compressed Size for Out of Partition Bounds check
					mod_data = buffer[cpd_entry_offset:cpd_entry_offset + mod_comp_size] # Store Module data for Empty check
					if mod_data in (b'', b'\xFF' * mod_comp_size) or cpd_entry_offset >= file_end : cpd_mod_attr[mod][6] = 1 # Determine if Module is Empty/Missing
					
					break
				
			# Detect $FPT Partition Size mismatch vs CSE_Ext_03/16
			for part in fpt_part_all :
				# Verify that CSE_Ext_03/16.PartitionSize exists and that the same $CPD Partition was found at fpt_part_all
				# by its unique Name, Offset & Instance ID. If $FPT Entry size is smaller than Extension size, error is shown.
				# The check is skipped when Extension size is not found so no problem with OEM/FIT firmware configuration.
				# The check is skipped when IDLM partition (DLMP) is parsed because its $FPT size is wrong by Intel design.
				if not msg_shown and ext_psize != -1 and part[0] == cpd_name and part[0] != 'DLMP' \
				and part[1] == cpd_offset and part[3] == in_id and part[2] < (cpd_offset + ext_psize) :
					cse_anl_err(col_r + 'Error: Size of %s Partition at $FPT is smaller than CSE Extension 0x3/0x16!' % cpd_name + col_e, None)
					msg_shown = True # Partition related error, show only once
			
			# Detect BPDT Partition Size mismatch vs CSE_Ext_03/16
			for part in bpdt_part_all :
				# Verify that CSE_Ext_03/16.PartitionSize exists and that the same $CPD Partition was found at bpdt_part_all
				# by its unique Name, Offset & Instance ID. If BPDT Entry size is smaller than Extension size, error is shown.
				# The check is skipped when Extension size is not found so no problem with OEM/FIT firmware configuration.
				# The check is skipped when IDLM partition (DLMP) is parsed because its BPDT size is wrong by Intel design.
				if not msg_shown and ext_psize != -1 and part[0] == cpd_name and part[0] != 'DLMP' \
				and part[1] == cpd_offset and part[6] == in_id and part[2] < (cpd_offset + ext_psize) :
					cse_anl_err(col_r + 'Error: Size of %s Partition at BPDT is smaller than CSE Extension 0x3/0x16!' % cpd_name + col_e, None)
					msg_shown = True # Partition related error, show only once
					
		# Key
		elif '.key' in cpd_entry_name.decode('utf-8') :
			mod_data = buffer[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
			if mod_data in (b'', b'\xFF' * cpd_entry_size) or cpd_entry_offset >= file_end : mod_empty = 1 # Determine if Key is Empty/Missing
			
			key_man_pat = man_pat.search(mod_data[:0x50]) or bccb_pat.search(mod_data[:0x50]) # Search for 0x8086 or 0xBCCB Key Manifest Pattern
			
			if not mod_empty and key_man_pat :
				key_man_off = key_man_pat.start() - 0x10 # Key Manifest Start Offset
				key_man_len = int.from_bytes(mod_data[key_man_pat.end() - 0x8:key_man_pat.end() - 0x4], 'little') * 4 # Key Manifest Size
				mod_data = mod_data[key_man_off:key_man_off + key_man_len] # Adjust Key Data to Manifest contents only (i.e. ignore $CPD)
				
				# Get Key Manifest/Extension Info when applicable (print at mod_anl only)
				key_print,mn2_signs,fd_info = ext_anl(mod_data, '$MN2', 0x1B, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], cpd_entry_name.decode('utf-8'),
												  [[],''], [[],-1,-1,-1]) # Retrieve & Store Key Manifest/Extension Info
				
				ext_print += key_print # Append Key Manifest/Extension Info (key_print is the ext_print of .key file, same structure)
			
			# noinspection PyUnboundLocalVariable
			cpd_mod_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, mod_empty, 0, cpd_name, 0, mn2_signs, cpd_offset, cpd_chk_info])
		
		# Microcode
		elif 'upatch' in cpd_entry_name.decode('utf-8') :
			mod_data = buffer[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
			if mod_data in (b'', b'\xFF' * cpd_entry_size) or cpd_entry_offset >= file_end : mod_empty = 1 # Determine if Microcode is Empty/Missing
			
			# Detect actual Microcode length
			mc_len = int.from_bytes(mod_data[0x20:0x24], 'little')
			mc_data = buffer[cpd_entry_offset:cpd_entry_offset + mc_len]
			
			cpd_mod_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, mod_empty, mc_chk32(mc_data), cpd_name, 0, mn2_sigs, cpd_offset, cpd_chk_info])
		
		# Data
		else :
			mod_comp_type = 0 # The Type is Uncompressed by default since "Data" shouldn't have Metadata
			mod_comp_size = cpd_entry_size # Compressed = Uncompressed (via $CPD) size by default since "Data" shouldn't have Metadata
			mod_uncomp_size = cpd_entry_size # The Uncompressed Size can be taken directly from $CPD
			
			# When the firmware lacks Huffman Module Metadata, we must manually fill the Compression Type via $CPD and calculated Compressed Size
			for i in range(len(cpd_wo_met_info)) :
				if (cpd_wo_met_info[i][0], cpd_wo_met_info[i][3]) == (cpd_entry_name.decode('utf-8'), 1) :
					mod_comp_type = cpd_wo_met_info[i][3] # As taken from $CPD Huffman Yes/No bit
					mod_comp_size = cpd_wo_met_info[i][2] # As calculated at Stage 3 of the analysis
					mod_size = mod_comp_size # Store calculated Compressed Size for Out of Partition Bounds check
					break
			
			mod_data = buffer[cpd_entry_offset:cpd_entry_offset + mod_size]
			
			# When the firmware lacks LZMA Module Metadata, we must manually fill the Compression Type and calculated Uncompressed Size
			if mod_data.startswith(b'\x36\x00\x40\x00\x00') and mod_data[0xE:0x11] == b'\x00\x00\x00' :
				mod_comp_type = 2 # Compression Type 2 is LZMA
				mod_uncomp_size = int.from_bytes(mod_data[0x5:0xD], 'little') # LZMA Header 0x5-0xD (uint64) is the Uncompressed Size in LE
			
			if mod_data in (b'', b'\xFF' * mod_size) or cpd_entry_offset >= file_end : mod_empty = 1 # Determine if Module is Empty/Missing
			
			cpd_mod_attr.append([cpd_entry_name.decode('utf-8'), mod_comp_type, 0, cpd_entry_offset, mod_comp_size, mod_uncomp_size, mod_empty, 0, cpd_name, 0, mn2_sigs, cpd_offset, cpd_chk_info])
		
		# Detect Modules which exceed or are located at/after the end of RGN Partition size (CSE_Ext_03/16.PartitionSize)
		if not oem_config and not oem_signed and ext_psize != -1 and ((cpd_entry_offset >= cpd_offset + ext_psize) or (cpd_entry_offset + mod_size > cpd_offset + ext_psize)) :
			cse_anl_err(col_r + 'Error: Detected out of Partition bounds Module at %s > %s!' % (cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
		
	# Stage 6: Remove missing APL IBBP Module Attributes
	if len(ibbp_all) :
		for ibbp in ibbp_bpm :
			if ibbp not in ibbp_all : # Module has hash at unified Metadata but is actually missing
				for mod_index in range(len(cpd_mod_attr)) :
					if cpd_mod_attr[mod_index][0] == ibbp : ibbp_del.append(mod_index) # Store missing Module's Attributes
					
		for mod_index in ibbp_del : del cpd_mod_attr[mod_index] # Delete missing Module's Attributes
	
	return cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext50_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info,ext_iunit_val,ext15_info,pch_init_final,gmf_blob_info,fwi_iup_hashes,gsc_info

# Analyze & Store CSE Modules
def mod_anl(cpd_offset, cpd_mod_attr, cpd_ext_attr, fw_name, ext_print, ext_phval, ext_dnx_val, ext_iunit_val, rbe_pm_met_hashes, rbe_pm_met_valid, ext12_info, vol_ftbl_id, config_rec_size, gmf_blob_info, vol_ftbl_pl, cpd_mn2_info, rbe_man_hashes) :
	# noinspection PyUnusedLocal
	mea_hash_c = 0
	mea_hash_u = 0
	mod_hash_u_ok = False
	comp = ['Uncompressed','Huffman','LZMA']
	encr_type = ['None','AES-ECB','AES-CTR']
	is_empty = ['No','Yes']
	
	pt = ext_table([col_y + 'Name' + col_e, col_y + 'Compression' + col_e, col_y + 'Encryption' + col_e, col_y + 'Offset' + col_e, col_y + 'Compressed' + col_e, col_y + 'Uncompressed' + col_e,
					col_y + 'Empty' + col_e], True, 1)
	
	cpd_all_attr = cpd_ext_attr + cpd_mod_attr
	
	# $CPD validity verified
	if cpd_offset > -1 and cpd_all_attr :
		
		# Store Module details
		for mod in cpd_all_attr :
			comp_print = 'None' if mod[1] == 0 else comp[mod[1]] # Print Compression "None" instead of "Uncompressed" at Module details
			pt.add_row([mod[0],comp_print,encr_type[mod[2]],'0x%0.6X' % mod[3],'0x%0.6X' % mod[4],'0x%0.6X' % mod[5],is_empty[mod[6]]])
		
		# Parent Partition Attributes (same for all cpd_all_attr list instance entries)
		cpd_pname = cpd_all_attr[0][8] # $CPD Name
		cpd_poffset = cpd_all_attr[0][11] # $CPD Offset, covers any cases with duplicate name entries (Joule_C0-X64-Release)
		cpd_chk_ok,cpd_chk_rslt = cpd_all_attr[0][12] # CPD Checksum Validity & Values
		ext_inid = cpd_all_attr[0][9] # Partition Instance ID
		
		pt.title = col_y + 'Detected %s Module(s) at %s %0.4X [0x%0.6X]' % (len(cpd_all_attr), cpd_pname, ext_inid, cpd_poffset) + col_e
		folder_name = os.path.join(mea_dir, fw_name, '%s %0.4X [0x%0.6X]' % (cpd_pname, ext_inid, cpd_poffset), '')
		info_fname = os.path.join(mea_dir, fw_name, '%s %0.4X [0x%0.6X].txt' % (cpd_pname, ext_inid, cpd_poffset))
		
		cpd_hdr_struct, _ = get_cpd(reading, cpd_poffset)
		cpd_phdr = get_struct(reading, cpd_poffset, cpd_hdr_struct)
		if param.cse_unpack : print('%s' % cpd_phdr.hdr_print())
		
		if cpd_chk_ok :
			print(col_g + '\n$CPD Checksum of partition "%s" is VALID\n' % cpd_pname + col_e)
		else :
			if param.cse_pause and cpd_chk_rslt not in cse_known_bad_hashes :
				input_col(col_r + '\n$CPD Checksum of partition "%s" is INVALID\n' % cpd_pname + col_e) # Debug
			elif param.cse_pause and cpd_chk_rslt in cse_known_bad_hashes :
				print(col_r + '\n$CPD Checksum of partition "%s" is INVALID (Known CSE Bad Checksum)\n' % cpd_pname + col_e)
			else :
				print(col_r + '\n$CPD Checksum of partition "%s" is INVALID\n' % cpd_pname + col_e)
			
		print(pt) # Show Module details
		
		os.mkdir(folder_name)
		
		# Store Partition $CPD Header & Entry details in TXT
		with open(info_fname, 'a', encoding = 'utf-8') as info_file :
			info_file.write('\n%s\n%s' % (ansi_escape.sub('', str(cpd_phdr.hdr_print())), ansi_escape.sub('', str(pt))))
		
		# Store Partition $CPD Header & Entry details in HTML
		if param.write_html :
			with open(info_fname[:-4] + '.html', 'a', encoding = 'utf-8') as info_file :
				info_file.write('\n<br/>\n%s\n<br/>\n%s' % (pt_html(cpd_phdr.hdr_print()), pt_html(pt)))
		
		# Store Partition $CPD Header & Entry details in JSON
		if param.write_json :
			with open(info_fname[:-4] + '.json', 'a', encoding = 'utf-8') as info_file :
				info_file.write('\n%s\n%s' % (pt_json(cpd_phdr.hdr_print()), pt_json(pt)))
		
		# Load Huffman Dictionaries for Decompression
		huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, minor, 'error')
		
		# Parse all Modules based on their Metadata
		for mod in cpd_all_attr :
			mod_name = mod[0] # Name
			mod_comp = mod[1] # Compression
			mod_encr = mod[2] # Encryption
			mod_start = mod[3] # Starting Offset
			mod_size_comp = mod[4] # Compressed Size
			mod_size_uncomp = mod[5] # Uncompressed Size
			mod_empty = mod[6] # Empty/Missing
			mod_hash = mod[7] # Hash (LZMA --> Compressed + zeros, Huffman --> Uncompressed)
			mod_end = mod_start + mod_size_comp # Ending Offset
			mn2_valid = mod[10][0] # Check if RSA Signature is valid (rsa_hash == dec_hash)
			mn2_sig_dec = mod[10][1] # RSA Signature Decrypted Hash
			mn2_sig_sha = mod[10][2] # RSA Signature Data Hash
			mn2_error = mod[10][3] # Check if RSA validation crashed (try-except)
			mn2_struct = mod[10][5] # Manifest Structure Object
			
			if mod_empty == 1 : continue # Skip Empty/Missing Modules
			
			if '.man' in mod_name or '.met' in mod_name :
				mod_fname = folder_name + mod_name
				mod_type = 'metadata'
			else :
				mod_fname = folder_name + mod_name
				mod_type = 'module'
				
			mod_data = reading[mod_start:mod_end]
			
			if not mod_encr : print(col_y + '\n--> Stored %s %s "%s" [0x%0.6X - 0x%0.6X]' % (comp[mod_comp], mod_type, mod_name, mod_start, mod_end - 0x1) + col_e)
			else : print(col_m + '\n--> Stored Encrypted %s %s "%s" [0x%0.6X - 0x%0.6X]' % (comp[mod_comp], mod_type, mod_name, mod_start, mod_end - 0x1) + col_e)
			
			# Store & Ignore Encrypted Data
			if mod_encr >= 1 :
				
				if param.cse_pause : # Debug
					print('\n    MOD: %s' % mod_hash)
					print(col_m + '\n    Hash of Encrypted %s "%s" cannot be verified' % (mod_type, mod_name) + col_e)
					
				with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data) # Store Encrypted Data, cannot validate
			
			# Store Uncompressed Data
			elif mod_comp == 0 :
				
				# Manifest
				if '.man' in mod_name :
					for rbep_man in rbe_man_hashes :
						rbe_man_name = rbep_man[0]
						
						if rbe_man_name == cpd_pname :
							rbe_man_hash = rbep_man[1]
							cpd_man_hash = cpd_mn2_info[14][{0x30: 0, 0x20: 1}[len(rbe_man_hash) // 2]]
							
							if param.cse_pause :
								print('\n    %s: %s' % (cpd_pname, cpd_man_hash)) # Debug
								print('    RBEP: %s' % rbe_man_hash) # Debug
								
							if cpd_man_hash == rbe_man_hash :
								print(col_g + '\n    Manifest of partition "%s" is VALID' % cpd_pname + col_e)
							else :
								if param.cse_pause :
									input_col(col_r + '\n    Manifest of partition "%s" is INVALID' % cpd_pname + col_e) # Debug
								else :
									print(col_r + '\n    Manifest of partition "%s" is INVALID' % cpd_pname + col_e)
									
							break
					
					if param.cse_pause :
						print('\n    MN2: %s' % mn2_sig_dec) # Debug
						print('    MEA: %s' % mn2_sig_sha) # Debug
					
					if mn2_error :
						if param.cse_pause :
							input_col(col_m + '\n    RSA Signature of partition "%s" is UNKNOWN' % cpd_pname + col_e) # Debug
						else :
							print(col_m + '\n    RSA Signature of partition "%s" is UNKNOWN' % cpd_pname + col_e)
					elif mn2_valid :
						print(col_g + '\n    RSA Signature of partition "%s" is VALID' % cpd_pname + col_e)
					else :
						if param.cse_pause and [mn2_sig_dec,mn2_sig_sha] not in cse_known_bad_hashes :
							input_col(col_r + '\n    RSA Signature of partition "%s" is INVALID' % cpd_pname + col_e) # Debug
						elif [mn2_sig_dec,mn2_sig_sha] in cse_known_bad_hashes :
							print(col_r + '\n    RSA Signature of partition "%s" is INVALID (Known CSE Bad RSA Signature)' % cpd_pname + col_e)
						else :
							print(col_r + '\n    RSA Signature of partition "%s" is INVALID' % cpd_pname + col_e)
							
					mn2_hdr_print = mn2_struct.hdr_print_cse()
					if not param.cse_verbose : print('\n%s' % mn2_hdr_print) # Show $MN2 details (already included in -ver86)
					
					# Insert $MN2 Manifest details at Extension Info list (ext_print)
					ext_print_cur_len = len(ext_print) # Current length of Extension Info list
					for index in range(0, ext_print_cur_len, 2) : # Only Name (index), skip Info (index + 1)
						if str(ext_print[index]).startswith(mod_name) :
							ext_print[index + 1] = [mn2_hdr_print] + (ext_print[index + 1])
							break
					
					if param.cse_pause and ext_phval[0] :
						print('\n    EXT: %s' % ext_phval[2]) # Debug
						print('    MEA: %s' % ext_phval[3]) # Debug
					
					if ext_phval[0] and int(ext_phval[2], 16) == 0 : # Hash exists but is not used (0)
						print(col_m + '\n    Hash of partition "%s" is UNKNOWN' % cpd_pname + col_e)
					elif ext_phval[0] and ext_phval[1] : # Hash exists and is Valid
						print(col_g + '\n    Hash of partition "%s" is VALID' % cpd_pname + col_e)
					elif ext_phval[0] : # Hash exists but is Invalid (CSME 11.8 SLM, CSSPS 5-6 & PHYP EBG Hashes are always wrong)
						if (variant,major,minor,ext12_info[1][1]) == ('CSME',11,8,'SLM') :
							print(col_r + '\n    Hash of partition "%s" is INVALID (CSME 11.8 Slim Ignore)' % cpd_pname + col_e)
						elif (variant,major) in [('CSSPS',1),('CSSPS',5),('CSSPS',6)] or (variant,major,minor) in [('CSSPS',4,4),('CSSPS',4,2)] :
							print(col_r + '\n    Hash of partition "%s" is INVALID (%s %d.%d Ignore)' % (cpd_pname,variant,major,minor) + col_e)
						elif (variant,cpd_mn2_info[0],cpd_mn2_info[10]) == ('PHYPEBG',12,0) :
							print(col_r + '\n    Hash of partition "%s" is INVALID (%s %d Ignore)' % (cpd_pname,variant,cpd_mn2_info[0]) + col_e)
						elif param.cse_pause and [ext_phval[2],ext_phval[3]] not in cse_known_bad_hashes :
							input_col(col_r + '\n    Hash of partition "%s" is INVALID' % cpd_pname + col_e) # Debug
						elif param.cse_pause and [ext_phval[2],ext_phval[3]] in cse_known_bad_hashes :
							print(col_r + '\n    Hash of partition "%s" is INVALID (Known CSE Bad Hash)' % cpd_pname + col_e)
						else :
							print(col_r + '\n    Hash of partition "%s" is INVALID' % cpd_pname + col_e)
						
					# Store Golden Measurements File (GMF) Blobs from RBEP.man > CSE_Ext_1E & CSE_Ext_1F
					if gmf_blob_info and (gmf_blob_info[0],gmf_blob_info[1],gmf_blob_info[2]) == (cpd_pname,ext_inid,cpd_poffset) :
						if gmf_blob_info[3][0] :
							gmf_cert_path = os.path.join(mea_dir, folder_name, 'GMF_Certificate.crt')
							with open(gmf_cert_path, 'wb') as gmf_cert : gmf_cert.write(gmf_blob_info[3][0])
						if gmf_blob_info[3][1] :
							gmf_body_path = os.path.join(mea_dir, folder_name, 'GMF_Body.bin')
							with open(gmf_body_path, 'wb') as gmf_body : gmf_body.write(gmf_blob_info[3][1])
				
				# Metadata
				elif '.met' in mod_name :
					mea_hash = get_hash(mod_data, len(mod_hash) // 2)
					
					if param.cse_pause :
						print('\n    MOD: %s' % mod_hash) # Debug
						print('    MEA: %s' % mea_hash) # Debug
				
					if mod_hash == mea_hash :
						print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.cse_pause and [mod_hash,mea_hash] not in cse_known_bad_hashes :
							input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						elif param.cse_pause and [mod_hash,mea_hash] in cse_known_bad_hashes :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID (Known CSE Bad Hash)' % (comp[mod_comp], mod_type, mod_name) + col_e)
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
				# Key
				elif '.key' in mod_name :
					if param.cse_pause :
						print('\n    MN2: %s' % mn2_sig_dec) # Debug
						print('    MEA: %s' % mn2_sig_sha) # Debug
					
					if mn2_error :
						if param.cse_pause :
							input_col(col_m + '\n    RSA Signature of %s %s "%s" is UNKNOWN!' % (comp[mod_comp], mod_type, mod_name)) # Debug
						else :
							print(col_m + '\n    RSA Signature of %s %s "%s" is UNKNOWN!' % (comp[mod_comp], mod_type, mod_name))
					elif mn2_valid :
						print(col_g + '\n    RSA Signature of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.cse_pause :
							input_col(col_r + '\n    RSA Signature of %s %s "%s" is INVALID!' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						else :
							print(col_r + '\n    RSA Signature of %s %s "%s" is INVALID!' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
					mn2_hdr_print = mn2_struct.hdr_print_cse()
					if not param.cse_verbose : print('\n%s' % mn2_hdr_print) # Show $MN2 details (already included in -ver86)
				
				# MFS Configuration
				elif mod_name in ('intl.cfg','fitc.cfg') :
					mfs_file_no = 6 if mod_name == 'intl.cfg' else 7
					if param.cse_unpack : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (mfs_file_no, mfs_dict[mfs_file_no]) + col_e)
					rec_folder = os.path.join(mea_dir, folder_name, mfs_dict[mfs_file_no], '')
					try :
						pch_init_info = mfs_cfg_anl(mfs_file_no, mod_data, rec_folder, rec_folder, config_rec_size, [], vol_ftbl_id, vol_ftbl_pl) # Parse MFS Configuration Records
						# noinspection PyUnusedLocal
						_ = pch_init_anl(pch_init_info) # Parse MFS Initialization Tables and store their Platforms/Steppings
					except :
						if param.cse_pause :
							input_col(col_r + '\n    Failed to analyze MFS Low Level File %d (%s)' % (mfs_file_no, mfs_dict[mfs_file_no]) + col_e) # Debug
						else :
							print(col_r + '\n    Failed to analyze MFS Low Level File %d (%s)' % (mfs_file_no, mfs_dict[mfs_file_no]) + col_e)
					
					# Only Intel MFS Configuration protected by Hash
					if mod_name == 'intl.cfg' :
						mea_hash = get_hash(mod_data, len(mod_hash) // 2)
						
						if param.cse_pause :
							print('\n    MOD: %s' % mod_hash) # Debug
							print('    MEA: %s' % mea_hash) # Debug
				
						if mod_hash == mea_hash :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						else :
							if param.cse_pause and [mod_hash,mea_hash] not in cse_known_bad_hashes :
								input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							elif param.cse_pause and [mod_hash,mea_hash] in cse_known_bad_hashes :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID (Known CSE Bad Hash)' % (comp[mod_comp], mod_type, mod_name) + col_e)
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
				# Microcode
				elif 'upatch' in mod_name :
					if mod_hash == 0 :
						print(col_g + '\n    Checksum of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.cse_pause :
							input_col(col_r + '\n    Checksum of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						else :
							print(col_r + '\n    Checksum of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
				# Data
				elif mod_hash == 0 :
					
					# CSE_Ext_14 R1/R2 has a unique structure
					if cpd_pname == 'RCIP' :
						if (mod_name,ext_dnx_val[1]) == ('hash.array',True) or (mod_name,ext_dnx_val[2]) == ('rcipifwi',True) :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						elif mod_name == 'version' :
							print(col_m + '\n    Hash of %s %s "%s" is UNKNOWN' % (comp[mod_comp], mod_type, mod_name) + col_e)
						elif param.cse_pause :
							input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					elif cpd_pname in ('IUNP','IUNM') :
						if (mod_name,ext_iunit_val[0]) == ('iunit',True) :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						elif param.cse_pause :
							input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					elif mod_name != 'pavp' and rbe_pm_met_hashes :
						# Ignore PAVP w/o Metadata Hash check at rbe/pm as it's LZMA compressed and then AES encrypted
						mea_hash = get_hash(mod_data, len(rbe_pm_met_hashes[0]) // 2)
						
						if param.cse_pause :
							print('\n    MOD: No Metadata, validation via RBEP > rbe and FTPR > pm Modules') # Debug
							print('    MEA: %s' % mea_hash) # Debug
							
						if mea_hash in rbe_pm_met_hashes :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							rbe_pm_met_valid.append(mea_hash) # Store valid RBEP > rbe or FTPR > pm Hash to single out leftovers
						else :
							if param.cse_pause and [mod_hash,mea_hash] not in cse_known_bad_hashes :
								input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							elif param.cse_pause and [mod_hash,mea_hash] in cse_known_bad_hashes :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID (Known CSE Bad Hash)' % (comp[mod_comp], mod_type, mod_name) + col_e)
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						print(col_m + '\n    Hash of %s %s "%s" is UNKNOWN' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
				# Module
				else :
					mea_hash = get_hash(mod_data, len(mod_hash) // 2)
					
					if param.cse_pause :
						print('\n    MOD: %s' % mod_hash) # Debug
						print('    MEA: %s' % mea_hash) # Debug
					
					# Detect & Cut Module OROM Headers
					if orom_pat.search(mod_data[:0x28]) :
						orom_hdr = get_struct(mod_data, 0, GSC_OROM_Header) # OROM Header Structure
						pcir_hdr = get_struct(mod_data, orom_hdr.PCIDataHdrOff, GSC_OROM_PCI_Data) # OROM PCIR Structure
						modp_off = max(orom_hdr.PCIDataHdrOff + pcir_hdr.PCIDataHdrLen, orom_hdr.EFIImageOffset, orom_hdr.OROMPayloadOff) # Payload Offset
						
						with open(mod_fname + '.bin', 'wb') as raw_file : raw_file.write(mod_data[modp_off:]) # Store Module Payload w/o OROM Headers
					
					if mod_hash == mea_hash :
						print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.cse_pause and [mod_hash,mea_hash] not in cse_known_bad_hashes :
							input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						elif param.cse_pause and [mod_hash,mea_hash] in cse_known_bad_hashes :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID (Known CSE Bad Hash)' % (comp[mod_comp], mod_type, mod_name) + col_e)
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
				with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data) # Store Metadata or Module

			# Store & Decompress Huffman Data
			elif mod_comp == 1 :
				
				try :
					if param.cse_pause :
						mod_data_d, huff_error = cse_huffman_decompress(mod_data, mod_size_comp, mod_size_uncomp, huff_shape, huff_sym, huff_unk, 'error') # Debug
						if (huff_error,mod_hash) == (True,0) : input() # Decompression incomplete, pause when no Module Metadata exist
					else :
						mod_data_d, huff_error = cse_huffman_decompress(mod_data, mod_size_comp, mod_size_uncomp, huff_shape, huff_sym, huff_unk, 'none')
						
					print(col_c + '\n    Decompressed %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
					
					# Open decompressed Huffman module for Hash validation, when Metadata info is available
					if mod_hash != 0 :
						mea_hash = get_hash(mod_data_d, len(mod_hash) // 2)
						
						if param.cse_pause :
							print('\n    MOD: %s' % mod_hash) # Debug
							print('    MEA: %s' % mea_hash) # Debug
							
						if mod_hash == mea_hash :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, valid data
						else :
							if param.cse_pause and [mod_hash,mea_hash] not in cse_known_bad_hashes :
								input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							elif param.cse_pause and [mod_hash,mea_hash] in cse_known_bad_hashes :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID (Known CSE Bad Hash)' % (comp[mod_comp], mod_type, mod_name) + col_e)
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, invalid data
					
					# Open decompressed Huffman module for Hash validation, when Metadata info is not available
					# When the firmware lacks Module Metadata, check RBEP > rbe and FTPR > pm Modules instead
					elif rbe_pm_met_hashes :
						mea_hash = get_hash(mod_data_d, len(rbe_pm_met_hashes[0]) // 2)
						
						if param.cse_pause :
							print('\n    MOD: No Metadata, validation via RBEP > rbe and FTPR > pm Modules') # Debug
							print('    MEA: %s' % mea_hash) # Debug
							
						if mea_hash in rbe_pm_met_hashes :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							rbe_pm_met_valid.append(mea_hash) # Store valid RBEP > rbe or FTPR > pm Hash to single out leftovers
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, valid data
						else :
							if param.cse_pause and [mod_hash,mea_hash] not in cse_known_bad_hashes :
								input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							elif param.cse_pause and [mod_hash,mea_hash] in cse_known_bad_hashes :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID (Known CSE Bad Hash)' % (comp[mod_comp], mod_type, mod_name) + col_e)
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, invalid data
						
					else :
						with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, cannot validate
				
				except :
					if param.cse_pause :
						input_col(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
					else :
						print(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
						
					with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data) # Decompression failed
			
			# Store & Decompress LZMA Data
			elif mod_comp == 2 :
				
				mod_data_r = mod_data # Store raw LZMA Module contents before zeros removal, for hashing
				
				# Remove three extra zeros from LZMA Module header for proper decompression
				# https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
				if mod_data.startswith(b'\x36\x00\x40\x00\x00') and mod_data[0xE:0x11] == b'\x00\x00\x00' :
					mod_data = mod_data[:0xE] + mod_data[0x11:] # Visually, mod_size_comp += -3 for compressed module
				
				try :
					# noinspection PyArgumentList
					mod_data_d = lzma.LZMADecompressor().decompress(mod_data)
					
					# Add missing EOF Padding when needed (usually at NFTP.ptt Module)
					data_size_uncomp = len(mod_data_d)
					if data_size_uncomp != mod_size_uncomp :
						mod_last_byte = struct.pack('B', mod_data_d[data_size_uncomp - 1]) # Determine padding type (0xFF or 0x00)
						mod_miss_padd = mod_size_uncomp - data_size_uncomp # Determine missing padding size
						mod_data_d += mod_last_byte * mod_miss_padd # Fill module with missing padding
					
					print(col_c + '\n    Decompressed %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
					
					# Open decompressed LZMA module for Hash validation, when Metadata info is available
					if mod_hash != 0 :
						# Calculate LZMA Module Hash
						mea_hash_c = get_hash(mod_data_r, len(mod_hash) // 2) # Compressed, Header zeros included (most LZMA Modules)
						
						mod_hash_c_ok = mod_hash == mea_hash_c # Check Compressed LZMA validity
						if not mod_hash_c_ok : # Skip Uncompressed LZMA hash if not needed
							mea_hash_u = get_hash(mod_data_d, len(mod_hash) // 2) # Uncompressed (few LZMA Modules)
							mod_hash_u_ok = mod_hash == mea_hash_u # Check Uncompressed LZMA validity
						
						if param.cse_pause : # Debug
							if mod_hash_c_ok :
								print('\n    MOD: %s' % mod_hash)
								print('    MEA: %s' % mea_hash_c)
							elif mod_hash_u_ok :
								print('\n    MOD: %s' % mod_hash)
								print('    MEA: %s' % mea_hash_u)
							else :
								print('\n    MOD  : %s' % mod_hash)
								print('    MEA C: %s' % mea_hash_c)
								print('    MEA U: %s' % mea_hash_u)
						
						if mod_hash_c_ok or mod_hash_u_ok :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data_d) # Decompression complete, valid data
						else :
							if param.cse_pause and [mod_hash,mea_hash_c] not in cse_known_bad_hashes :
								input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							elif param.cse_pause and [mod_hash,mea_hash_c] in cse_known_bad_hashes :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID (Known CSE Bad Hash)' % (comp[mod_comp], mod_type, mod_name) + col_e)
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
								
							with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data_d) # Decompression complete, invalid data
							
					# Open decompressed LZMA module for Hash validation, when Metadata info is not available
					# When the firmware lacks Module Metadata, check RBEP > rbe and FTPR > pm Modules instead
					elif rbe_pm_met_hashes :
						mea_hash_c = get_hash(mod_data_r, len(rbe_pm_met_hashes[0]) // 2) # Compressed, Header zeros included (most LZMA Modules)
						
						mod_hash_c_ok = mea_hash_c in rbe_pm_met_hashes # Check Compressed LZMA validity
						if not mod_hash_c_ok : # Skip Uncompressed LZMA hash if not needed
							mea_hash_u = get_hash(mod_data_d, len(rbe_pm_met_hashes[0]) // 2) # Uncompressed (few LZMA Modules)
							mod_hash_u_ok = mea_hash_u in rbe_pm_met_hashes # Check Uncompressed LZMA validity
						
						if param.cse_pause : # Debug
							print('\n    MOD: No Metadata, validation via RBEP > rbe and FTPR > pm Modules') # Debug
							if mod_hash_c_ok :
								print('    MEA: %s' % mea_hash_c)
							elif mod_hash_u_ok :
								print('    MEA: %s' % mea_hash_u)
							else :
								print('    MEA C: %s' % mea_hash_c)
								print('    MEA U: %s' % mea_hash_u)
						
						if mod_hash_c_ok :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							rbe_pm_met_valid.append(mea_hash_c) # Store valid RBEP > rbe or FTPR > pm Hash to single out leftovers
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, valid data
						elif mod_hash_u_ok :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							rbe_pm_met_valid.append(mea_hash_u) # Store valid RBEP > rbe or FTPR > pm Hash to single out leftovers
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, valid data
						else :
							if param.cse_pause and [mod_hash,mea_hash_c] not in cse_known_bad_hashes :
								input_col(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							elif param.cse_pause and [mod_hash,mea_hash_c] in cse_known_bad_hashes :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID (Known CSE Bad Hash)' % (comp[mod_comp], mod_type, mod_name) + col_e)
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, invalid data
				
				except :
					if param.cse_pause :
						input_col(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
					else :
						print(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
						
					with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data) # Decompression failed
				
			# Print Manifest/Metadata/Key Extension Info
			ext_print_len = len(ext_print) # Final length of Extension Info list (must be after Manifest & Key extraction)
			if mod_type == 'metadata' or '.key' in mod_name :
				for index in range(0, ext_print_len, 2) : # Only Name (index), skip Info (index + 1)
					if str(ext_print[index]).startswith(mod_name) :
						if param.cse_verbose : print() # Print Manifest/Metadata/Key Extension Info
						for ext in ext_print[index + 1] :
							ext_str = ansi_escape.sub('', str(ext)) # Ignore Colorama ANSI Escape Character Sequences
							with open(mod_fname + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
							if param.write_html :
								with open(mod_fname + '.html', 'a', encoding = 'utf-8') as text_file : text_file.write('\n<br/>\n%s' % pt_html(ext))
							if param.write_json :
								with open(mod_fname + '.json', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % pt_json(ext))
							if param.cse_verbose : print(ext) # Print Manifest/Metadata/Key Extension Info
						break
						
	return rbe_pm_met_valid

# Get CSE Key Hash Usages
def get_key_usages(key_bitmap) :
	hash_usages = []
	
	usage_bits = list(format(int.from_bytes(key_bitmap, 'little'), '0128b'))
	usage_bits.reverse()
	
	for usage_bit in range(len(usage_bits)) :
		if usage_bits[usage_bit] == '1' :
			hash_usages.append(key_dict[usage_bit] if usage_bit in key_dict else 'Unknown (%d)' % usage_bit)
			
	return hash_usages
	
# Store and show CSE Analysis Errors
def cse_anl_err(ext_err_msg, checked_hashes) :
	if checked_hashes is None : checked_hashes = ['','']
	
	copy_file = not checked_hashes in cse_known_bad_hashes
	err_stor.append([ext_err_msg, copy_file])
	
	if param.cse_unpack :
		if copy_file and param.cse_pause : input_col('\n%s' % ext_err_msg)
		else : print('\n%s' % ext_err_msg)
		
# Check if CSE File System FTBL/EFST Dictionary exists
def check_ftbl_id(vol_ftbl_id, ftbl_dict, vol_ftbl_pl) :
	plat_name = ftbl_efst_plat[vol_ftbl_pl] if vol_ftbl_pl in ftbl_efst_plat else 'Unknown'
	
	if vol_ftbl_id == -1 :
		msg_pad = '    ' if param.cse_unpack else '' # Message "Tab" spacing during unpacking
		ftbl_id_msg = col_m + '%sWarning: Could not find any File System Dictionary, assuming 0x0A!' % msg_pad + col_e
		if param.cse_unpack : print('\n%s' % ftbl_id_msg)
		else : warn_stor.append([ftbl_id_msg, False])
		
		vol_ftbl_id = 0xA # When MFS/AFS > Volume Header > vol_ftbl_id is missing, assume FTBL/EFST Dictionary of 0xA (CON)
	elif '%0.2X' % vol_ftbl_id not in ftbl_dict['%0.2X' % vol_ftbl_pl] :
		msg_pad = '    ' if param.cse_unpack else '' # Message "Tab" spacing during unpacking
		ftbl_id_msg = col_m + '%sWarning: Could not find File System Dictionary 0x%0.2X (%s) > 0x%0.2X, assuming 0x0A!' % (
					  msg_pad, vol_ftbl_pl, plat_name, vol_ftbl_id) + col_e
		if param.cse_unpack : print('\n%s' % ftbl_id_msg)
		else : warn_stor.append([ftbl_id_msg, False])
		
		vol_ftbl_id = 0xA # When FTBL/EFST > Platform > Dictionary is missing, assume FTBL/EFST Dictionary of 0xA (CON)
		
	return vol_ftbl_id
	
# Check if CSE File System FTBL/EFST Platform exists
def check_ftbl_pl(vol_ftbl_pl, ftbl_dict) :
	plat_name = ftbl_efst_plat[vol_ftbl_pl] if vol_ftbl_pl in ftbl_efst_plat else 'Unknown'
	
	if vol_ftbl_pl == -1 :
		msg_pad = '    ' if param.cse_unpack else '' # Message "Tab" spacing during unpacking
		ftbl_pl_msg = col_m + '%sWarning: Could not find any File System Platform, assuming 0x01 (ICP)!' % msg_pad + col_e
		if param.cse_unpack : print('\n%s' % ftbl_pl_msg)
		else : warn_stor.append([ftbl_pl_msg, False])
		
		vol_ftbl_pl = 0x1 # When MFS/AFS > Volume Header > vol_ftbl_pl is missing, assume FTBL/EFST Platform of 0x1 (ICP)
	elif '%0.2X' % vol_ftbl_pl not in ftbl_dict :
		msg_pad = '    ' if param.cse_unpack else '' # Message "Tab" spacing during unpacking
		ftbl_pl_msg = col_m + '%sWarning: Could not find File System Platform 0x%0.2X (%s), assuming 0x01 (ICP)!' % (
					  msg_pad, vol_ftbl_pl, plat_name) + col_e
		if param.cse_unpack : print('\n%s' % ftbl_pl_msg)
		else : warn_stor.append([ftbl_pl_msg, False])
		
		vol_ftbl_pl = 0x1 # When FTBL/EFST > Platform is missing, assume FTBL/EFST Platform of 0x1 (ICP)
		
	return vol_ftbl_pl

# Get CSE File System Integrity Table Structure Size
def get_sec_hdr_size(variant,major,minor,hotfix) :
	if (variant,major,minor) == ('CSME',14,5) : return 0x34
	if (variant,major,minor) == ('CSSPS',4,4) or (variant,major,minor,hotfix) == ('CSSPS',5,0,0) : return 0x28
	if (variant,major) in [('CSME',11),('CSTXE',3),('CSTXE',4),('CSSPS',4),('CSSPS',5)] : return 0x34
	if (variant,major) in [('CSME',12),('CSME',13),('CSME',14),('CSME',15)] : return 0x28
	
	return 0x28

# Get CSE File System Configuration Record Structure Size
def get_cfg_rec_size(variant,major,minor,hotfix) :
	if (variant,major,minor) == ('CSSPS',4,4) or (variant,major,minor,hotfix) == ('CSSPS',5,0,0) : return 0xC
	if (variant,major) in [('CSME',11),('CSME',12),('CSTXE',3),('CSTXE',4),('CSSPS',4),('CSSPS',5)] : return 0x1C
	if (variant,major) in [('CSME',13),('CSME',14),('CSME',15),('CSME',16),('CSSPS',6)] : return 0xC
	
	return 0xC

# Get CSE File System Files start at 0 or not
# noinspection PyUnusedLocal
def get_vfs_start_0(variant,major,minor,hotfix) : # pylint: disable=W0613
	if (variant,major,minor) in [('CSME',13,30)] : return True
	if (variant,major) in [('CSME',15),('CSME',16)] : return True
	if (variant,major) in [('CSME',11),('CSME',12),('CSME',13),('CSME',14),('CSTXE',3),('CSTXE',4),('CSSPS',4),('CSSPS',5),('CSSPS',6)] : return False
	
	return True

# Get CSE File System Attributes & Configuration State
def get_mfs_anl(mfs_state, mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final) :
	vol_ftbl_id = -0x1
	vol_ftbl_pl = -0x1
	config_rec_size = get_cfg_rec_size(variant,major,minor,hotfix) # Get CSE File System Configuration Record Structure Size
	
	if mfs_found and not param.cse_unpack :
		try :
			# Get CSE File System Attributes
			mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final,vol_ftbl_id,config_rec_size,vol_ftbl_pl = mfs_anl('NA',mfs_start,mfs_start + mfs_size,variant,vol_ftbl_id,vol_ftbl_pl,mfs_is_afs)
			
			# Get CSE File System Backup Attributes when Main lacks Intel Configuration
			if mfsb_found and 6 not in mfs_parsed_idx : mfs_parsed_idx,intel_cfg_hash_mfs,_,pch_init_final,_,_,_ = mfs_anl('NA',mfsb_start,mfsb_start + mfsb_size,variant,vol_ftbl_id,vol_ftbl_pl,mfs_is_afs)
			
			# CSE File System exists, determine its Configuration State
			if any(idx in mfs_parsed_idx for idx in [0,1,2,3,4,5,8]) : mfs_state = 'Initialized'
			elif any(idx in mfs_parsed_idx for idx in [7,9]) : mfs_state = 'Configured'
		except :
			# CSE File System analysis failed, maybe corrupted
			mfs_state = col_r + 'Error' + col_e
		
	return mfs_state, mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, vol_ftbl_id, config_rec_size, vol_ftbl_pl

# Analyze & Extract CSE File Systems
# noinspection PyUnusedLocal
def mfs_anl(mfs_folder, mfs_start, mfs_end, variant, vol_ftbl_id, vol_ftbl_pl, mfs_is_afs) :
	mfs_buffer_init = reading[mfs_start:mfs_end] # MFS Initial Buffer
	sec_hdr_size = get_sec_hdr_size(variant,major,minor,hotfix) # Get CSE File System Integrity Table Structure Size
	config_rec_size = get_cfg_rec_size(variant,major,minor,hotfix) # Get CSE File System Configuration Record Structure Size
	vfs_starts_at_0 = get_vfs_start_0(variant,major,minor,hotfix) # Get CSE File System Files start at 0 or not
	page_size = 0x2000 # MFS Page Length
	chunk_all_size = 0x42 # MFS Chunk Payload + CRC Length
	chunk_raw_size = chunk_all_size - 2 # MFS Chunk Payload
	index_size_sys = 0x2 # MFS System Page Index Entry Length
	index_size_dat = 0x1 # MFS Data Page Index Entry Length
	page_hdr_size = 0x12 # MFS Page Header Structure Size
	vol_hdr_size = 0xE # MFS Volume Header Structure Size
	chunks_count_sys = 0xFFFF # MFS Actual System Chunks Count
	mfs_info = [] # MFS Initial Info Printing
	mfs_files = [] # MFS Low Level Files Numbers & Contents
	mfs_tmp_page = [] # MFS Temporary Pages Message Storage
	mfs_page_init = [] # MFS Total Unsorted Pages Contents
	pch_init_info = [] # Store PCH Initialization Table Info
	pch_init_final = [] # Store PCH Initialization Table Final Info
	mfs_parsed_idx = [] # Store all parsed MFS Low Level Files
	sys_page_sorted = [] # MFS Total Sorted System Pages Contents
	dat_page_sorted = [] # MFS Total Sorted Data Pages Contents
	all_chunks_dict = {} # MFS Total Chunk Index & Data Dictionary
	intel_cfg_hash_mfs = None # Store MFS Low Level File 6 Hash
	mfs_signature1 = mfs_buffer_init[:0x4] # Store 1st MFS Signature Tag (MFS 0x877855AA or MFSB 0x4D465342 or Scratch)
	mfs_signature2 = mfs_buffer_init[page_size:page_size + 0x4] # Store 2nd MFS Signature Tag (MFS 0x877855AA or Scratch)
	mfsb_reserved = mfs_buffer_init[0x8:0x20] == b'\xFF' * 0x18 # Check MFSB Reserved area
	
	# Check if MFS is in MFS Backup R0 state
	if mfs_signature1 == b'\x4D\x46\x53\x42' and mfsb_reserved : # MFSB Tag & MFSB R0 Reserved = 0xFF * 24
		mfsb_hdr = get_struct(mfs_buffer_init, 0, MFS_Backup_Header_R0) # MFSB Header R0 Structure
		if param.cse_unpack :
			print('\n%s' % mfsb_hdr.mfs_print()) # Print Structure Info during CSE Unpacking
			mfs_info.append(mfsb_hdr.mfs_print()) # Store Structure Info during CSE Unpacking
		
		mfsb_buffer = mfs_buffer_init[ctypes.sizeof(mfsb_hdr):] # MFS Backup Buffer without Header
		mfsb_crc32 = mfsb_hdr.CRC32 # Intel CRC-32 of MFS Backup Buffer
		mea_crc32 = ~crccheck.crc.Crc32.calc(mfsb_buffer, initvalue=0) & 0xFFFFFFFF # MEA CRC-32 of MFS Backup Buffer
		mfsb_patterns = re.compile(br'\x01\x03\x02\x04').finditer(mfsb_buffer) # Each MFS Backup Chunk ends with 0x01030204
		mfsb_end = re.compile(br'\xFF{32}').search(mfsb_buffer).start() # MFS Backup Buffer ends where enough Padding (0xFF) is found
		
		if mfsb_crc32 != mea_crc32 : _ = mfs_anl_msg(col_r + 'Error: MFS Backup Header CRC-32 0x%0.8X is INVALID, expected 0x%0.8X!'
									 % (mfsb_crc32, mea_crc32) + col_e, 'error', True, False, False, [])
		else : _ = mfs_anl_msg(col_g + 'MFS Backup Header CRC-32 is VALID' + col_e, '', True, False, False, [])
		
		data_start = 0 # Starting Offset of each MFS Backup Chunk
		mfs_buffer_init = b'' # Actual MFS Buffer from converted MFS Backup state
		for pattern in mfsb_patterns : # Iterate over all 0x01030204 chunk endings
			padding = int.from_bytes(mfsb_buffer[pattern.end():pattern.end() + 0x4], 'big') # The 4 bytes after 0x01030204 are Padding (0xFF) Size in BE
			mfs_buffer_init += (mfsb_buffer[data_start:pattern.start()] + b'\xFF' * padding) # Append Chunk Data to Actual MFS Buffer
			data_start = pattern.end() + 0x4 # Adjust Starting Offset to 0x01030204 + Padding Size
		mfs_buffer_init += mfsb_buffer[data_start:mfsb_end] # Append Last MFS Backup Chunk Contents as has no 0x01030204 ending
		mfs_buffer_init += b'\xFF' * (- len(mfs_buffer_init) % 0x2000) # Append EOF Alignment Padding based on MFS Page Size of 0x2000
	
	# Check if MFS is in MFS Backup R1 state
	elif mfs_signature1 == b'\x4D\x46\x53\x42' : # MFSB Tag & MFSB R0 Reserved != 0xFF * 24
		mfsb_hdr = get_struct(mfs_buffer_init, 0, MFS_Backup_Header_R1) # MFSB Header R1 Structure
		if param.cse_unpack :
			print('\n%s' % mfsb_hdr.mfs_print()) # Print Structure Info during CSE Unpacking
			mfs_info.append(mfsb_hdr.mfs_print()) # Store Structure Info during CSE Unpacking
		
		mfsb_rev = mfsb_hdr.Revision # MFSB Header R1 Revision Tag
		if mfsb_rev != 1 : # Validate MFSB Header Revision, should be 1
			_ = mfs_anl_msg(col_r + 'Error: Unknown MFS Backup Header Revision %d at 0x%X!' % (mfsb_rev,mfs_start) + col_e, 'error', True, False, False, [])
		
		mfsb_len = mfsb_hdr.Entry6Offset # MFSB Header R1 Size based on 1st Entry Offset
		mfsb_hdr_data = mfs_buffer_init[:0x8] + b'\x00' * 4 + mfs_buffer_init[0xC:mfsb_len] # MFS Backup Header Data
		mfsb_crc32 = mfsb_hdr.HeaderCRC32 # Intel CRC-32 of MFS Backup Header Data with HeaderCRC32 = 0
		mea_crc32 = crccheck.crc.Crc32.calc(mfsb_hdr_data) # MEA CRC-32 of MFS Backup Header Data with HeaderCRC32 = 0
		
		if mfsb_crc32 != mea_crc32 :
			_ = mfs_anl_msg(col_r + 'Error: MFS Backup Header CRC-32 0x%0.8X is INVALID, expected 0x%0.8X!' % (mfsb_crc32,mea_crc32) + col_e, 'error', True, False, False, [])
		else :
			_ = mfs_anl_msg(col_g + 'MFS Backup Header CRC-32 is VALID' + col_e, '', True, False, False, [])
		
		mfsb_entry_6 = [6, mfsb_hdr.Entry6Offset, mfsb_hdr.Entry6Size] # MFSB Entry 6 (Intel Configuration) Info
		mfsb_entry_7 = [7, mfsb_hdr.Entry7Offset, mfsb_hdr.Entry7Size] # MFSB Entry 7 (OEM Configuration) Info
		mfsb_entry_9 = [9, mfsb_hdr.Entry9Offset, mfsb_hdr.Entry9Size] # MFSB Entry 9 (Manifest Backup) Info
		mfsb_entries = [mfsb_entry_6, mfsb_entry_7, mfsb_entry_9] # MFSB Entries 6,7,9 Info Storage
		
		for entry in mfsb_entries :
			entry_file = entry[0] # MFSB R1 Entry Low Level File Index
			entry_data = mfs_buffer_init[entry[1]:entry[1] + entry[2]] # MFSB R1 Entry Data
			
			entry_hdr = get_struct(entry_data, 0, MFS_Backup_Entry) # MFSB R1 Entry Structure
			if param.cse_unpack :
				print('\n%s' % entry_hdr.mfs_print()) # Print Structure Info during CSE Unpacking
				mfs_info.append(entry_hdr.mfs_print()) # Store Structure Info during CSE Unpacking
			
			entry_rev = entry_hdr.Revision # MFSB R1 Entry Revision Tag
			if entry_rev != 1 : # Validate MFSB Entry Revision, should be 1
				_ = mfs_anl_msg(col_r + 'Error: Unknown MFS Backup Entry %d Revision %d at 0x%X!' % (entry_file,entry_rev,mfs_start) + col_e, 'error', True, False, False, [])
			
			hdr_len = ctypes.sizeof(MFS_Backup_Entry) # MFSB R1 Entry Size based on Structure
			
			hdr_data_crc = entry_data[:0x4] + b'\x00' * 0x4 + entry_data[0x8:0xC]
			
			hdr_crc32_int = entry_hdr.EntryCRC32 # Intel CRC-32 of MFSB R1 Entry Header with EntryCRC32 = 0 w/o DataCRC32
			hdr_crc32_mea = crccheck.crc.Crc32.calc(hdr_data_crc) # MEA CRC-32 of MFSB R1 Entry Header with EntryCRC32 = 0 w/o DataCRC32
			
			if hdr_crc32_int != hdr_crc32_mea :
				_ = mfs_anl_msg(col_r + 'Error: MFS Backup Entry %d Header CRC-32 0x%0.8X is INVALID, expected 0x%0.8X!' % (
										   entry_file,hdr_crc32_int,hdr_crc32_mea) + col_e, 'error', True, False, False, [])
			else :
				_ = mfs_anl_msg(col_g + 'MFS Backup Entry %d Header CRC-32 is VALID' % entry_file + col_e, '', True, False, False, [])
			
			file_data = entry_data[hdr_len:hdr_len + entry_hdr.Size]
			
			file_crc32_int = entry_hdr.DataCRC32 # Intel CRC-32 of MFSB R1 Entry Data (Low Level File + DataCRC32 = 0)
			file_crc32_mea = crccheck.crc.Crc32.calc(file_data) # MEA CRC-32 of MFSB R1 Entry Data (Low Level File + DataCRC32 = 0)
			
			if file_crc32_int != file_crc32_mea :
				_ = mfs_anl_msg(col_r + 'Error: MFS Backup Entry %d Data CRC-32 0x%0.8X is INVALID, expected 0x%0.8X!' % (
										   entry_file,file_crc32_int,file_crc32_mea) + col_e, 'error', True, False, False, [])
			else :
				_ = mfs_anl_msg(col_g + 'MFS Backup Entry %d Data CRC-32 is VALID' % entry_file + col_e, '', True, False, False, [])
			
			if param.cse_unpack : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (entry_file, mfs_dict[entry_file]) + col_e)
			
			if entry_file in (6,7) :
				rec_folder = os.path.join(mea_dir, mfs_folder, '%0.3d %s' % (entry_file, mfs_dict[entry_file]), '')
				root_folder = rec_folder # Store File Root Folder for Local Path printing
				mfs_parsed_idx.append(entry_file) # Set MFS Backup Low Level File as Parsed
				
				pch_init_info = mfs_cfg_anl(entry_file, file_data, rec_folder, root_folder, config_rec_size, pch_init_info, vol_ftbl_id, vol_ftbl_pl) # Parse MFSB Config Records
				pch_init_final = pch_init_anl(pch_init_info) # Parse MFSB Initialization Tables and store their Platforms/Steppings
				
				if entry_file == 6 : intel_cfg_hash_mfs = [get_hash(file_data, 0x20), get_hash(file_data, 0x30)] # Store MFSB Intel Configuration Hashes
				
			elif entry_file == 9 and man_pat.search(file_data[:0x20]) :
				file_9_folder = os.path.join(mea_dir, mfs_folder, '%0.3d %s' % (entry_file, mfs_dict[entry_file]), '')
				file_9_data_path = os.path.join(file_9_folder, 'FTPR.man') # MFS Manifest Backup Contents Path
				mfs_write(file_9_folder, file_9_data_path, file_data) # Store MFS Manifest Backup Contents
				mfs_parsed_idx.append(entry_file) # Set MFS Backup Low Level File as Parsed
				
				ext_print,mn2_signs,_ = ext_anl(file_data, '$MN2', 0x1B, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], 'FTPR.man', [mfs_parsed_idx,intel_cfg_hash_mfs],
													  [pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl]) # Get Manifest Backup Extension Info
				
				if param.cse_unpack :
					if param.cse_pause :
						print('\n    MN2: %s' % mn2_signs[1]) # Debug
						print('    MEA: %s' % mn2_signs[2]) # Debug
					
					if mn2_signs[3] :
						if param.cse_pause :
							input_col(col_m + '\n    RSA Signature of %s is UNKNOWN!' % mfs_dict[entry_file] + col_e) # Debug
						else :
							print(col_m + '\n    RSA Signature of %s is UNKNOWN!' % mfs_dict[entry_file] + col_e)
					elif mn2_signs[0] :
						print(col_g + '\n    RSA Signature of %s is VALID' % mfs_dict[entry_file] + col_e)
					else :
						if param.cse_pause :
							input_col(col_r + '\n    RSA Signature of %s is INVALID!' % mfs_dict[entry_file] + col_e) # Debug
						else :
							print(col_r + '\n    RSA Signature of %s is INVALID!' % mfs_dict[entry_file] + col_e)
					
					if not param.cse_verbose : print('\n%s' % ext_print[1][0]) # Print Manifest Backup Manifest Info
					else : print()
					
					for man_pt in ext_print[1] :
						if param.cse_verbose : print(man_pt)
						mfs_txt(man_pt, file_9_folder, os.path.join(file_9_folder + 'FTPR.man'), 'a', False) # Store MFS Manifest Backup Extension Info
				
		return mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, vol_ftbl_id, config_rec_size, vol_ftbl_pl
	
	# Verify that MFS Partition can be parsed by mfs_anl
	elif b'\x87\x78\x55\xAA' not in (mfs_signature1, mfs_signature2) : # Check 1st & 2nd System Page MFS Signature Tag
		_ = mfs_anl_msg(col_r + 'Error: Skipped MFS partition at 0x%X, unrecognizable format!' % mfs_start + col_e, 'error', True, False, False, [])
		
		if not param.cse_unpack : raise Exception('BAD_MFS_FORMAT') # Try-Except used outside of unp86, trigger exception to show Error at MFS state
		
		return mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, vol_ftbl_id, config_rec_size, vol_ftbl_pl
	
	# MFS Size related Variable Initialization (must be after MFSB R0)
	mfs_size = len(mfs_buffer_init) # MFS Total Length
	page_count = mfs_size // page_size # MFS Total Pages Count
	sys_count = page_count // 12 # MFS System Pages Count
	dat_count = page_count - sys_count - 1 # MFS Data Pages Count
	#chunks_max_sys = sys_count * ((page_size - page_hdr_size - index_size_sys) // (index_size_sys + chunk_all_size)) # MFS Maximum System Chunks Count
	chunks_max_dat = dat_count * ((page_size - page_hdr_size) // (index_size_dat + chunk_all_size)) # MFS Maximum Data Chunks Count (= Actual)
	
	# Sort MFS System & Data Pages
	for page_index in range(page_count) :
		page_start = page_index * page_size # Page Offset
		page_hdr = get_struct(mfs_buffer_init, page_start, MFS_Page_Header) # Page Header Structure
		if page_hdr.FirstChunkIndex != 0 : chunks_count_sys = min(chunks_count_sys, page_hdr.FirstChunkIndex) # Store MFS Actual System Chunks Count
		# Page Number for System Page Sorting, Page First Chunk Index for Data Page Sorting, Page Contents
		mfs_page_init.append([page_hdr.PageNumber, page_hdr.FirstChunkIndex, mfs_buffer_init[page_start:page_start + page_size]])
	
	for i in range(len(mfs_page_init)) : # Parse all MFS unsorted System & Data Pages
		if mfs_page_init[i][1] == 0 : sys_page_sorted.append([mfs_page_init[i][0], mfs_page_init[i][2]]) # System Pages are sorted via Page Number
		else : dat_page_sorted.append([mfs_page_init[i][1], mfs_page_init[i][2]]) # Data Pages are sorted via Page First Chunk Index
	sys_page_sorted = [i[1] for i in sorted(sys_page_sorted, key=lambda sys: sys[0])] # Store System Pages after Page Number sorting
	dat_page_sorted = [i[1] for i in sorted(dat_page_sorted, key=lambda dat: dat[0])] # Store Data Pages after Page First Chunk Index sorting
	mfs_sorted = sys_page_sorted + dat_page_sorted # Store total MFS sorted System & Data Pages
	
	mfs_pages_pt = ext_table([col_y + 'Type' + col_e, col_y + 'Signature' + col_e, col_y + 'Number' + col_e, col_y + 'Erase Count' + col_e,
				   col_y + 'Next Erase' + col_e, col_y + 'First Chunk' + col_e, col_y + 'CRC-8' + col_e, col_y + 'Reserved' + col_e], True, 1)
	mfs_pages_pt.title = col_y + 'MFS Page Records' + col_e
	
	# Parse each MFS Page sequentially
	for mfs_page in mfs_sorted :
		page_hdr = get_struct(mfs_page, 0, MFS_Page_Header) # Page Header Structure
		page_hdr_data = mfs_page[:page_hdr_size] # Page Header Data
		page_tag = page_hdr.Signature # Page Signature Tag
		page_number = page_hdr.PageNumber # Page Number starting from 1
		page_erase_count = page_hdr.EraseCount # Counter of Page Erases
		page_erase_next = page_hdr.NextErasePage # Page Number to be Erased Next
		page_chunk_first = page_hdr.FirstChunkIndex # Index number of Data Pages' 1st Chunk from total MFS Chunks (MFS start)
		page_hdr_crc8_int = page_hdr.CRC8 # Intel CRC-8 of Page Header (0x12) with initial value of 1
		page_reserved = page_hdr.Reserved # Page Reserved Data
		page_type = 'System' if page_chunk_first == 0 else 'Data' # Page System or Data Type
		
		# MEA CRC-8 of System/Data/Scratch Page Header (0x12) with initial value of 1
		if page_tag == 0xAA557887 :
			page_hdr_crc8_mea = crccheck.crc.Crc8.calc(page_hdr_data[:-2] + bytes(page_hdr_data[-1]), initvalue = 1)
		else :
			page_type = 'Scratch' # Only one Scratch Page initially exists at the MFS
			if not page_number : page_hdr_crc8_mea = 0 # Workaround only for Alpha CSME 11.0.0.1100 firmware (completely empty MFS Page Header)
			else : page_hdr_crc8_mea = crccheck.crc.Crc8.calc(b'\x87\x78\x55\xAA' + page_hdr_data[4:-2] + bytes(page_hdr_data[-1]), initvalue = 1) # Add MFS Signature
		
		mfs_pages_pt.add_row([page_type, '%0.8X' % page_tag, page_number, page_erase_count, page_erase_next, page_chunk_first, '0x%0.2X' % page_hdr_crc8_int, '0x%X' % page_reserved])
		
		# Verify System/Data/Scratch Page CRC-8
		if page_hdr_crc8_mea != page_hdr_crc8_int :
			mfs_tmp_page = mfs_anl_msg(col_r + 'Error: MFS %s Page %d Header CRC-8 0x%0.2X is INVALID, expected 0x%0.2X!'
						   % (page_type, page_number, page_hdr_crc8_int, page_hdr_crc8_mea) + col_e, 'error', True, True, False, mfs_tmp_page)
		else :
			mfs_tmp_page = mfs_anl_msg(col_g + 'MFS %s Page %d Header CRC-8 is VALID' % (page_type, page_number) + col_e, '', True, True, False, mfs_tmp_page)
		
		if page_tag != 0xAA557887 : continue # Skip Scratch Page after CRC-8 check
		
		# MFS System Page
		if page_type == 'System' :
			chunk_count = (page_size - page_hdr_size - index_size_sys) // (index_size_sys + chunk_all_size) # System Page Chunks have a 2-byte Index after Page Header
			index_size = chunk_count * index_size_sys + index_size_sys # System Page Total Chunk Indexes size is Chunk Count * Index Byte Length + Index Byte Length
			index_data_obf = mfs_page[page_hdr_size:page_hdr_size + index_size] # System Page Total Obfuscated Chunk Indexes Buffer
			index_values_obf = struct.unpack('%dH' % (chunk_count + 1), index_data_obf) # System Page Total Obfuscated Chunk Indexes List, each Index is 2 bytes
			chunk_start = page_hdr_size + index_size # System Page First Chunk Offset
			
			# Calculate actual System Page Chunk Indexes
			chunk_index = 0 # Unobfuscated System Page Chunk Index
			chunk_indexes = [] # Unobfuscated System Page Chunk Indexes
			for i in range(len(index_values_obf)) :
				# Obfuscated Index Bit 0 = 0 (0x8000) for Next Usable Entry, Obfuscated Index Bit 1 = 0 (0x4000) for Used Entry
				if index_values_obf[i] & 0xC000 : break # Skip all the Unused System Page Chunks when Bits 0-1 = 1 (0xC000) = Unused Entry
				chunk_index = Crc16_14(chunk_index) ^ index_values_obf[i] # Unobfuscated System Page Chunk Index via reverse CRC-16 14-bit (no 0 and 1)
				chunk_indexes.append(chunk_index) # Store all Unobfuscated System Page Chunk Indexes (subset of index_values_obf when Unused Entries exist)
			
			# Parse all Used System Page Chunks
			chunk_healthy = 0 # System Page Healthy Chunks Count
			chunk_used_count = len(chunk_indexes) # System Page Total Used Chunks Count
			for i in range(chunk_used_count) :
				chunk_index = chunk_indexes[i] # Index of used System Page Chunk from total MFS Chunks (MFS start)
				chunk_all = mfs_page[chunk_start + chunk_all_size * i:chunk_start + chunk_all_size * i + chunk_all_size] # System Page Chunk with CRC-16 (0x42)
				chunk_raw = chunk_all[:-2] # System Page Chunk without CRC-16 (0x40)
				all_chunks_dict[chunk_index] = chunk_raw # Store System Page Chunk Index & Contents
				
				chunk_crc16_int = int.from_bytes(chunk_all[0x40:0x42], 'little') # Intel CRC-16 of Chunk (0x40) with initial value of 0xFFFF
				chunk_crc16_mea = crccheck.crc.Crc16.calc(chunk_raw + struct.pack('<H', chunk_index), initvalue = 0xFFFF) # MEA CRC-16 of Chunk (0x40) with initial value of 0xFFFF
				
				# Validate Chunk CRC-16. Ignore 0x0000 as it possibly (?) indicates a "hot" VFS dump.
				if chunk_crc16_int not in (chunk_crc16_mea, 0x0000) :
					mfs_tmp_page = mfs_anl_msg(col_r + 'Error: MFS %s Page %d > Chunk %d CRC-16 0x%0.4X is INVALID, expected 0x%0.4X!'
								   % (page_type, page_number, chunk_index, chunk_crc16_int, chunk_crc16_mea) + col_e, 'error', True, True, True, mfs_tmp_page)
				else :
					#mfs_tmp_page = mfs_anl_msg(col_g + 'MFS %s Page %d > Chunk %d CRC-16 is VALID' % (page_type, page_number, chunk_index) + col_e, '', True, True, True, mfs_tmp_page)
					chunk_healthy += 1
			
			if chunk_used_count and chunk_used_count == chunk_healthy :
				mfs_tmp_page = mfs_anl_msg(col_g + 'All MFS %s Page %d Chunks (%d) CRC-16 are VALID' % (page_type, page_number, chunk_used_count) + col_e, '', True, True, True, mfs_tmp_page)
		
		# MFS Data Page
		elif page_type == 'Data' :
			chunk_count = (page_size - page_hdr_size) // (index_size_dat + chunk_all_size) # Data Page Chunks have a 1-byte Index after Page Header
			index_size = chunk_count * index_size_dat # Data Page Total Chunk Indexes size is Chunk Count * Index Byte Length
			index_data = mfs_page[page_hdr_size:page_hdr_size + index_size] # Data Page Total Chunk Indexes Buffer
			index_values = struct.unpack('%dB' % chunk_count, index_data) # Data Page Total Chunk Indexes List, each index is 1 byte
			chunk_start = page_hdr_size + index_size # Data Page First Chunk Offset
			
			# Parse all Used Data Page Chunks
			chunk_healthy = 0 # Data Page Healthy Chunks Count
			chunk_used_count = 0 # Data Page Total Used Chunks Count
			for i in range(len(index_values)) :
				if index_values[i] == 0 : # Used Data Page Chunk Index = 0x00, Unused = 0xFF
					chunk_used_count += 1 # Add Used Data Page Chunk to Total Used Count
					chunk_index = page_chunk_first + i # Index of used Data Page Chunk from total MFS Chunks (MFS start)
					chunk_all = mfs_page[chunk_start + chunk_all_size * i:chunk_start + chunk_all_size * i + chunk_all_size] # Data Page Chunk with CRC-16 (0x42)
					chunk_raw = chunk_all[:-2] # Data Page Chunk without CRC-16 (0x40)
					all_chunks_dict[chunk_index] = chunk_raw # Store Data Page Chunk Index & Contents
					chunk_crc16_int = int.from_bytes(chunk_all[0x40:0x42], 'little') # Intel CRC-16 of Chunk (0x40) with initial value of 0xFFFF
					chunk_crc16_mea = crccheck.crc.Crc16.calc(chunk_raw + struct.pack('<H', chunk_index), initvalue = 0xFFFF) # MEA CRC-16 of Chunk (0x40) with initial value of 0xFFFF
					
					# Validate Chunk CRC-16. Ignore 0x0000 as it possibly (?) indicates a "hot" VFS dump.
					if chunk_crc16_int not in (chunk_crc16_mea, 0x0000) :
						mfs_tmp_page = mfs_anl_msg(col_r + 'Error: MFS %s Page %d > Chunk %d CRC-16 0x%0.4X is INVALID, expected 0x%0.4X!'
									   % (page_type, page_number, chunk_index, chunk_crc16_int, chunk_crc16_mea) + col_e, 'error', True, True, True, mfs_tmp_page)
					else :
						#mfs_tmp_page = mfs_anl_msg(col_g + 'MFS %s Page %d > Chunk %d CRC-16 is VALID' % (page_type, page_number, chunk_index) + col_e, '', True, True, True, mfs_tmp_page)
						chunk_healthy += 1 
			
			if chunk_used_count and chunk_used_count == chunk_healthy :
				mfs_tmp_page = mfs_anl_msg(col_g + 'All MFS %s Page %d Chunks (%d) CRC-16 are VALID' % (page_type, page_number, chunk_used_count) + col_e, '', True, True, True, mfs_tmp_page)
	
	# Print/Store MFS Page Records during CSE Unpacking
	if param.cse_unpack :
		print('\n%s' % mfs_pages_pt) # Show MFS Page Records Log before messages
		for page_msg in mfs_tmp_page : # Print MFS Page Records Messages after Log
			if page_msg[1] == 'error' and param.cse_pause : input_col('\n%s' % page_msg[0])
			else : print('\n%s' % page_msg[0])
		mfs_info.append(mfs_pages_pt) # Store MFS Page Records Log during CSE Unpacking
	
	# Build MFS Total System Chunks Buffer
	all_mfs_sys = bytearray(chunks_count_sys * chunk_raw_size) # Empty System Area Buffer
	for i in range(chunks_count_sys) :
		# The final System Area Buffer must include all empty chunks for proper File Allocation Table parsing
		if i in all_chunks_dict : all_mfs_sys[i * chunk_raw_size:(i + 1) * chunk_raw_size] = bytearray(all_chunks_dict[i])
	
	# Parse MFS System Volume Structure
	if not all_chunks_dict :
		_ = mfs_anl_msg(col_r + 'Error: MFS final System Area Buffer is empty!' + col_e, 'error', True, False, False, [])
		return mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, vol_ftbl_id, config_rec_size, vol_ftbl_pl # The final System Area Buffer must not be empty
	vol_hdr = get_struct(all_chunks_dict[0], 0, MFS_Volume_Header) # System Volume is at the LAST Index 0 Chunk (the dictionary does that automatically)
	vol_sig = vol_hdr.Signature # Volume Signature (0x724F6201)
	if vol_sig != 0x724F6201 :
		_ = mfs_anl_msg(col_r + 'Error: MFS Volume Signature 0x%0.8X is invalid!' % vol_sig + col_e, 'error', True, False, False, [])
		return mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, vol_ftbl_id, config_rec_size, vol_ftbl_pl # The MFS Volume Signature must be valid
	if param.cse_unpack :
		print('\n%s' % vol_hdr.mfs_print()) # Print System Volume Structure Info during CSE Unpacking
		mfs_info.append(vol_hdr.mfs_print()) # Store System Volume Structure Info during CSE Unpacking
	vol_ftbl_id = vol_hdr.FTBLDictionary # FTBL/EFST Dictionary
	vol_ftbl_pl = vol_hdr.FTBLPlatform # FTBL/EFST Platform
	vol_ftbl_rs = vol_hdr.FTBLReserved # FTBL/EFST Reserved
	vol_has_ftbl = not (vol_ftbl_id,vol_ftbl_pl,vol_ftbl_rs) == (1,0,0) # Detect if MFS uses FTBL/EFST
	vol_file_rec = vol_hdr.FileRecordCount # Number of File Records in Volume
	vol_total_size = vol_hdr.VolumeSize # Size of MFS System & Data Volume via Volume
	mea_total_size = chunks_count_sys * chunk_raw_size + chunks_max_dat * chunk_raw_size # Size of MFS System & Data Volume via MEA
	if vol_total_size != mea_total_size : _ = mfs_anl_msg(col_r + 'Error: Detected MFS System Volume Size mismatch!' + col_e, 'error', True, False, False, [])
	else : _ = mfs_anl_msg(col_g + 'MFS System Volume Size is VALID' + col_e, '', True, False, False, [])
	
	# Parse MFS File Allocation Table
	fat_count = vol_file_rec + chunks_max_dat # MFS FAT Value Count (Low Level Files + their Data Chunks)
	fat_trail = len(all_mfs_sys) - fat_count * 2 - vol_hdr_size # MFS FAT Value End Trail Count
	fat_values = struct.unpack_from('<%dH' % fat_count, all_mfs_sys, vol_hdr_size) # MFS FAT Values are 2 bytes each
	for index in range(vol_file_rec) : # Parse all MFS Volume (Low Level File) FAT Values
		if fat_values[index] in (0x0000,0xFFFE,0xFFFF) : # 0x0000 = Unused, 0xFFFE = Erased, 0xFFFF = Used but Empty
			mfs_files.append([index, None]) # Store MFS Low Level File Index & Contents
		else :
			file_chunks = b'' # Initial MFS Low Level File Contents Buffer
			fat_value = fat_values[index] # Initial Used File FAT Value
			
			# Parse Data/Chunk FAT Values for each Used Low Level File
			while True :
				# Data FAT Values (Low Level File Chunks) start after Volume FAT Values (Low Level File Numbers/1st Chunk)
				if fat_value < vol_file_rec :
					_ = mfs_anl_msg(col_r + 'Error: Detected MFS File %d > FAT Value %d less than Volume Files Count %d!' % (index,fat_value,vol_file_rec) + col_e, 'error', True, False, False, [])
					break # Critical error while parsing Used File FAT Value
				
				# Data Page Chunks start after System Page Chunks and their Volume FAT Values
				file_chunk_index = chunks_count_sys + fat_value - vol_file_rec # Determine File Chunk Index for MFS Chunk Index & Data Dictionary use
				if file_chunk_index not in all_chunks_dict : # The File Chunk index/key must exist at the MFS Chunk Index & Data Dictionary
					_ = mfs_anl_msg(col_r + 'Error: Detected MFS File %d > Chunk %d not in Total Chunk Index/Data Area!' % (index,file_chunk_index) + col_e, 'error', True, False, False, [])
					break # Critical error while parsing Used File FAT Value
				
				file_chunk = all_chunks_dict[file_chunk_index] # Get File Chunk contents from the MFS Chunk Index & Data Dictionary
				fat_value = fat_values[fat_value] # Get Next Chunk FAT Value by using the current value as List index (starts from 0)
				
				# Small FAT Values (1 - 64) are markers for both EOF and Size of last Chunk
				if 1 <= fat_value <= chunk_raw_size :
					file_chunks += file_chunk[:fat_value] # Append the last File Chunk with its size adjusted based on the EOF FAT Value marker
					break # File ends when the Next FAT Value is between 1 and 64 (EOF marker)
				
				file_chunks += file_chunk # Append File Chunk Contents to the MFS Low Level File Contents Buffer
			
			mfs_files.append([index, file_chunks]) # Store MFS Low Level File Index & Contents
	
	# Check that the MFS FAT Trail Contents are empty/zeroes
	if all_mfs_sys[vol_hdr_size + fat_count * 2:] != b'\x00' * fat_trail :
		_ = mfs_anl_msg(col_r + 'Error: Detected additional MFS System Buffer contents after FAT ending!' + col_e, 'error', True, False, False, [])
	
	# Determine if the MFS has any Low Level Files based on their Contents
	mfs_has_files = [mfs_file[1] for mfs_file in mfs_files] != [None] * len(mfs_files)
	
	# Parse Reserved MFS Low Level Files
	for mfs_file in mfs_files :
		if vfs_starts_at_0 or not mfs_has_files : break # Skip at MFS which are empty or w/o Reserved Low Level Files
		
		# Parse MFS Low Level File 0 (Unknown)
		if mfs_file[1] and mfs_file[0] == 0 :
			if param.cse_unpack : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (mfs_file[0], mfs_dict[mfs_file[0]]) + col_e)
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level File as Parsed
			file_folder = os.path.join(mea_dir, mfs_folder, '%0.3d %s' % (mfs_file[0], mfs_dict[mfs_file[0]]), '')
			file_path = os.path.join(file_folder, 'Contents.bin') # MFS Low Level File Path
			mfs_write(file_folder, file_path, mfs_file[1]) # Store MFS Low Level File
		
		# Parse MFS Low Level Files 1 (Unknown), 2-3 (Anti-Replay) and 4 (SVN Migration)
		# At AFSP, MFS Low Level Files 6 & 7 are not Intel & OEM Configurations (Unknown)
		elif mfs_file[1] and ((mfs_file[0] in (1,2,3,4)) or (mfs_is_afs and mfs_file[0] in (6,7))) :
			mfs_file_name = 'Unknown' if mfs_is_afs and mfs_file[0] in (6,7) else mfs_dict[mfs_file[0]]
			if param.cse_unpack : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (mfs_file[0], mfs_file_name) + col_e)
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level File as Parsed
			file_folder = os.path.join(mea_dir, mfs_folder, '%0.3d %s' % (mfs_file[0], mfs_file_name), '')
			file_data = mfs_file[1][:-sec_hdr_size] # MFS Low Level File Contents without Integrity
			file_sec = mfs_file[1][-sec_hdr_size:] # MFS Low Level File Integrity without Contents
			file_sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size]) # MFS Low Level File Integrity Structure
			if param.cse_verbose :
				file_sec_ptv = file_sec_hdr.mfs_print() # MFS Low Level File Integrity Structure Info
				file_sec_ptv.title = 'MFS %0.3d %s Integrity' % (mfs_file[0], mfs_file_name) # Adjust Integrity Structure Verbose Info Title
				print('\n%s' % file_sec_ptv) # Print Integrity Structure Info during Verbose CSE Unpacking
			file_data_path = os.path.join(file_folder, 'Contents.bin') # MFS Low Level File Contents Path
			file_sec_path = os.path.join(file_folder, 'Integrity.bin') # MFS Low Level File Integrity Path
			mfs_write(file_folder, file_data_path, file_data) # Store MFS Low Level File Contents
			mfs_write(file_folder, file_sec_path, file_sec) # Store MFS Low Level File Integrity
			mfs_txt(file_sec_hdr.mfs_print(), file_folder, file_sec_path, 'w', False) # Store/Print MFS Low Level File Integrity Info
		
		# Parse MFS Low Level File 5 (Quota Storage)
		elif mfs_file[1] and mfs_file[0] == 5 :
			if param.cse_unpack : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (mfs_file[0], mfs_dict[mfs_file[0]]) + col_e)
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level File 5 as Parsed
			file_folder = os.path.join(mea_dir, mfs_folder, '%0.3d %s' % (mfs_file[0], mfs_dict[mfs_file[0]]), '')
			file_data_path = os.path.join(file_folder, 'Contents.bin') # MFS Low Level File 5 Contents Path
			file_sec_path = os.path.join(file_folder, 'Integrity.bin') # MFS Low Level File 5 Integrity Path
			
			# Detect MFS Low Level File 5 (Quota Storage) Integrity
			if variant == 'CSME' and major >= 12 :
				file_data = mfs_file[1][:-sec_hdr_size] # MFS Low Level File 5 Contents without Integrity
				file_sec = mfs_file[1][-sec_hdr_size:] # MFS Low Level File 5 Integrity without Contents
				mfs_write(file_folder, file_sec_path, file_sec) # Store MFS Low Level File 5 Integrity
				file_sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size]) # MFS Low Level File 5 Integrity Structure
				mfs_txt(file_sec_hdr.mfs_print(), file_folder, file_sec_path, 'w', False) # Store/Print MFS Low Level File 5 Integrity Info
				if param.cse_verbose :
					file_sec_ptv = file_sec_hdr.mfs_print() # MFS Low Level File 5 Integrity Structure Info
					file_sec_ptv.title = 'MFS %0.3d %s Integrity' % (mfs_file[0], mfs_dict[mfs_file[0]]) # Adjust Integrity Structure Verbose Info Title
					print('\n%s' % file_sec_ptv) # Print Integrity Structure Info during Verbose CSE Unpacking
			else :
				file_data = mfs_file[1][:] # MFS Low Level File 5 Contents
			
			mfs_write(file_folder, file_data_path, file_data) # Store MFS Low Level File 5 Contents
		
		# Parse MFS Low Level File 6 (Intel Configuration) and 7 (OEM Configuration)
		elif mfs_file[1] and mfs_file[0] in (6,7) :
			# Create copy of input firmware with clean/unconfigured MFS
			# MFSTool by Peter Bosch (https://github.com/peterbjornx/meimagetool)
			# MFS Templates AFS_region_256K|400K|1272K.bin by Flash Image Tool v11
			if param.mfs_rcfg and mfs_file[0] == 6 :
				mfstool_path = os.path.join(mea_dir, 'mfstool', '')
				mfs_tmpl_name = 'AFS_region_%sK.bin' % (mfs_size // 1024)
				mfs_tmpl_path = os.path.join(mfstool_path, mfs_tmpl_name)
				
				# MFS Templates depend on their Size (256K,400K,1272K), Volume File Record Count (256,512,1024,2048 etc) and
				# Total Volume Size (0x39240,0x58B80,0x58F80,0x11D900,0x11E100 etc). When the Volume File Record Count and/or
				# the Total Volume Size increase, a new template must be created with adjusted Volume Header Info but also
				# with adjusted Page First Chunk & CRC-8 at each Data Page. To determine the Data Page First Chunk increase
				# for each page, calculate Total Volume Size Difference / Raw Chunk Size. For example, to create template
				# 1272K_2048_0x11E100 from 1272K_1024_0x11D900, add (0x11E100 - 0x11D900) / 0x40 = 0x20 to each Data Page
				# First Chunk. After adjusting all Data Page First Chunk & CRC-8, the Volume Header Info must be updated
				# as well by copying only the MFS Volume FTBL fields from old to new MFS and then recalculating CRC-16.
				# Note that, at CSTXE, the Initialized AFS Size is variable as it expands during CSE operation at DevExp
				# SPI Region based on operational needs. That is OK because CSTXE does not need AFS cleaning either way
				# due to its use of FTPR > intl.cfg and fitc.cfg files as base even if its RGN includes the 256K MFS.
				
				if os.path.isfile(mfs_tmpl_path) :
					temp_dir = os.path.join(mfstool_path, 'temp', '')
					if os.path.isdir(temp_dir) : shutil.rmtree(temp_dir)
					os.mkdir(temp_dir)
					
					with open(os.path.join(temp_dir, 'intel.cfg'), 'wb') as o :
						# noinspection PyTypeChecker
						o.write(mfs_file[1])
					
					temp_mfs_path = os.path.join(mfstool_path, 'MFS_TEMP.bin')
					if os.path.isfile(temp_mfs_path) : os.remove(temp_mfs_path)
					clean_mfs_path = os.path.join(mfstool_path, 'MFS_CLEAN.bin')
					if os.path.isfile(clean_mfs_path) : os.remove(clean_mfs_path)
					
					with open(mfs_tmpl_path, 'rb') as mfs_tmpl : mfs_tmpl_new = bytearray(mfs_tmpl.read())
					
					tmpl_vol_size = int.from_bytes(mfs_tmpl_new[0x10C:0x110], 'little') # Get template MFS Volume Size
					
					start_diff = (vol_total_size - tmpl_vol_size) // chunk_raw_size # Calculate Data Page First Chunk difference
					
					# Parse template MFS and adjust all Data Pages First Chunk
					page_offset = 0 # First Page Offset (System)
					for i in range(page_count) :
						chunk_start = int.from_bytes(mfs_tmpl_new[page_offset + 0xE:page_offset + 0x10], 'little') # Get Page First Chunk value
						if chunk_start != 0 : # Adjust Data Pages only (First Chunk != 0), not System Pages
							mfs_tmpl_new[page_offset + 0xE:page_offset + 0x10] = struct.pack('<H', chunk_start + start_diff) # Adjust Data Page First Chunk
							crc8 = crccheck.crc.Crc8.calc(mfs_tmpl_new[page_offset:page_offset + 0x10], initvalue = 1) # Re-calculate Data Page CRC-8
							mfs_tmpl_new[page_offset + 0x10] = crc8 # Adjust Data Page CRC-8
		
						page_offset += page_size # Adjust Page Offset to the next one
					
					mfs_tmpl_new[0x104:0x112] = struct.pack('<IBBHIH', vol_sig, vol_ftbl_id, vol_ftbl_pl, vol_ftbl_rs, vol_total_size, vol_file_rec) # Copy Volume Header Info from dirty MFS to template
					first_crc16 = crccheck.crc.Crc16.calc(mfs_tmpl_new[0x104:0x144] + b'\x00\x00', initvalue = 0xFFFF) # CRC-16 of 1st Chunk with Index 0
					mfs_tmpl_new[0x144:0x146] = struct.pack('<H', first_crc16) # Recalculate template's 1st Chunk CRC-16
					with open(temp_mfs_path, 'wb') as o : o.write(mfs_tmpl_new)
					
					print(col_y + '\nCleaning %s\n' % os.path.basename(file_in) + col_e)
					
					# The temp_dir for MFSTool must NOT include files other than intel.cfg and fitc.cfg
					_ = subprocess.run([os.path.join(mfstool_path, 'mfstool'), 'c', clean_mfs_path, temp_mfs_path, temp_dir], check=True)
					
					if os.path.isfile(clean_mfs_path) :
						with open(clean_mfs_path, 'rb') as mfs_new : clean_mfs = mfs_new.read()
						if len(clean_mfs) != mfs_size : input_col(col_r + '\nError: MFS size mismatch!' + col_e)
						output_data = reading[:mfs_start] + clean_mfs + reading[mfs_end:]
						output_path = os.path.join(mea_dir, '__RCFG__%s' % os.path.basename(file_in))
						with open(output_path, 'wb') as o : o.write(output_data)
					
					shutil.rmtree(temp_dir)
					os.remove(temp_mfs_path)
					os.remove(clean_mfs_path)
				
				else :
					input_col(col_r + '\nError: MFS template %s could not be found!' % mfs_tmpl_name + col_e)
			
			if param.cse_unpack : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (mfs_file[0], mfs_dict[mfs_file[0]]) + col_e)
			if mfs_file[0] == 6 : intel_cfg_hash_mfs = [get_hash(mfs_file[1], 0x20), get_hash(mfs_file[1], 0x30)] # Store MFS Intel Configuration Hashes
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level Files 6,7 as Parsed
			rec_folder = os.path.join(mea_dir, mfs_folder, '%0.3d %s' % (mfs_file[0], mfs_dict[mfs_file[0]]), '')
			root_folder = rec_folder # Store File Root Folder for Local Path printing
			
			pch_init_info = mfs_cfg_anl(mfs_file[0], mfs_file[1], rec_folder, root_folder, config_rec_size, pch_init_info, vol_ftbl_id, vol_ftbl_pl) # Parse MFS Config Records
			pch_init_final = pch_init_anl(pch_init_info) # Parse MFS Initialization Tables and store their Platforms/Steppings
		
		# Parse MFS Low Level File 8 (Home Directory)
		elif mfs_file[1] and mfs_file[0] == 8 :
			if param.cse_unpack : print(col_g + '\n    Analyzing MFS Low Level File 8 (Home Directory) ...' + col_e)
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level File 8 as Parsed
			root_folder = os.path.join(mea_dir, mfs_folder, '008 Home Directory', 'home', '') # MFS Home Directory Root/Start folder is called "home"
			init_folder = os.path.join(mea_dir, mfs_folder, '008 Home Directory', '') # MFS Home Directory Parent folder for printing
			
			# Detect MFS Home Directory Record Size
			home_rec_patt = list(re.compile(br'\x2E[\x00\xAA]{10}').finditer(mfs_file[1][:])) # Find the first Current (.) & Parent (..) directory markers
			if len(home_rec_patt) < 2 : _ = mfs_anl_msg(col_r + 'Error: Detected unknown Home Directory Record Structure!' + col_e, 'error', True, False, False, [])
			home_rec_size = home_rec_patt[1].start() - home_rec_patt[0].start() - 1 # Determine MFS Home Directory Record Size via pattern offset difference
			file_8_data = mfs_file[1][:-sec_hdr_size] # MFS Home Directory Root/Start (Low Level File 8) Contents
			if divmod(len(file_8_data), home_rec_size)[1] != 0 :
				_ = mfs_anl_msg(col_r + 'Error: Detected unknown Home Directory Record or Integrity Size!' + col_e, 'error', True, False, False, [])
				home_rec_size = 0x0 # Crash at next step due to division by 0
			
			file_8_records = divmod(len(file_8_data), home_rec_size)[0] # MFS Home Directory Root/Start (Low Level File 8) Records Count
			
			# Generate MFS Home Directory Records Log
			if sec_hdr_size == 0x34 :
				mfs_pt = ext_table([col_y + 'Index' + col_e, col_y + 'Path' + col_e, col_y + 'Type' + col_e, col_y + 'Size' + col_e, col_y + 'Integrity' + col_e, col_y + 'IR Salt' + col_e,
				col_y + 'Encryption' + col_e, col_y + 'SVN' + col_e, col_y + 'Nonce' + col_e, col_y + 'AntiReplay' + col_e, col_y + 'AR Index' + col_e, col_y + 'AR Random' + col_e,
				col_y + 'AR Counter' + col_e, col_y + 'Keys' + col_e, col_y + 'Rights' + col_e, col_y + 'User ID' + col_e, col_y + 'Group ID' + col_e, col_y + 'Unknown Access' + col_e,
				col_y + 'Unknown Integrity 1' + col_e, col_y + 'HMAC SHA-256' + col_e, col_y + 'Unknown Integrity 2' + col_e], True, 1)
				mfs_pt.title = col_y + 'MFS 008 Home Directory Records' + col_e
			elif sec_hdr_size == 0x28 :
				mfs_pt = ext_table([col_y + 'Index' + col_e, col_y + 'Path' + col_e, col_y + 'Type' + col_e, col_y + 'Size' + col_e, col_y + 'Integrity' + col_e, col_y + 'IR Salt' + col_e,
				col_y + 'Encryption' + col_e, col_y + 'SVN' + col_e, col_y + 'AntiReplay' + col_e, col_y + 'AR Index' + col_e, col_y + 'AR Random' + col_e, col_y + 'AR Counter' + col_e,
				col_y + 'Keys' + col_e, col_y + 'Rights' + col_e, col_y + 'User ID' + col_e, col_y + 'Group ID' + col_e, col_y + 'Unknown Access' + col_e, col_y + 'Unknown Integrity 1' + col_e,
				col_y + 'HMAC MD5' + col_e, col_y + 'AES-GCM Nonce' + col_e, col_y + 'Unknown Integrity 2' + col_e], True, 1)
				mfs_pt.title = col_y + 'MFS 008 Home Directory Records' + col_e
			else :
				mfs_pt = None
			
			mfs_home_anl(mfs_files, file_8_data, file_8_records, root_folder, home_rec_size, sec_hdr_size, mfs_parsed_idx, init_folder, mfs_pt) # Parse MFS Home Directory Root/Start Records
			
			mfs_txt(mfs_pt, init_folder, os.path.join(init_folder + 'home_records'), 'w', True) # Store/Print MFS Home Directory Records Log
		
		# Parse MFS Low Level File 9 (Manifest Backup), if applicable
		elif mfs_file[1] and mfs_file[0] == 9 and man_pat.search(mfs_file[1][:0x20]) :
			if param.cse_unpack : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (mfs_file[0], mfs_dict[mfs_file[0]]) + col_e)
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level File 9 as Parsed
			file_9_folder = os.path.join(mea_dir, mfs_folder, '%0.3d %s' % (mfs_file[0], mfs_dict[mfs_file[0]]), '') # MFS Manifest Backup root folder
			file_9_data_path = os.path.join(file_9_folder, 'FTPR.man') # MFS Manifest Backup Contents Path
			mfs_write(file_9_folder, file_9_data_path, mfs_file[1]) # Store MFS Manifest Backup Contents
			# noinspection PyTypeChecker
			ext_print,mn2_signs,_ = ext_anl(mfs_file[1], '$MN2', 0x1B, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], 'FTPR.man', [mfs_parsed_idx,intel_cfg_hash_mfs],
												  [pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl]) # Get Manifest Backup Extension Info
			
			if param.cse_unpack :
				if param.cse_pause :
					print('\n    MN2: %s' % mn2_signs[1]) # Debug
					print('    MEA: %s' % mn2_signs[2]) # Debug
				
				if mn2_signs[3] :
					if param.cse_pause :
						input_col(col_m + '\n    RSA Signature of %s is UNKNOWN!' % mfs_dict[mfs_file[0]] + col_e) # Debug
					else :
						print(col_m + '\n    RSA Signature of %s is UNKNOWN!' % mfs_dict[mfs_file[0]] + col_e)
				elif mn2_signs[0] :
					print(col_g + '\n    RSA Signature of %s is VALID' % mfs_dict[mfs_file[0]] + col_e)
				else :
					if param.cse_pause :
						input_col(col_r + '\n    RSA Signature of %s is INVALID!' % mfs_dict[mfs_file[0]] + col_e) # Debug
					else :
						print(col_r + '\n    RSA Signature of %s is INVALID!' % mfs_dict[mfs_file[0]] + col_e)
				
				if not param.cse_verbose : print('\n%s' % ext_print[1][0]) # Print Manifest Backup Manifest Info
				else : print()
			
				for man_pt in ext_print[1] :
					if param.cse_verbose : print(man_pt)
					mfs_txt(man_pt, file_9_folder, os.path.join(file_9_folder + 'FTPR.man'), 'a', False) # Store MFS Manifest Backup Extension Info
	
	# Parse FTBL/EFST-based Initialized MFS Low Level Files (VFS Home Directory)
	
	if vol_has_ftbl and mfs_has_files and (vfs_starts_at_0 or any(idx in mfs_parsed_idx for idx in [0,1,2,3,4,5])) :
		if param.cse_unpack : print(col_g + '\n    Analyzing MFS Low Level Files (Home Directory) ...' + col_e)
		
		ftbl_json = os.path.join(mea_dir, 'FileTable.dat')
		
		# Check if MFS File Table Dictionary file exists
		if os.path.isfile(ftbl_json) :
			with open(ftbl_json, 'r', encoding='utf-8') as json_file : ftbl_dict = json.load(json_file)
		else :
			ftbl_dict = {}
			_ = mfs_anl_msg(col_r + 'Error: MFS File Table Dictionary file is missing!' + col_e, 'error', True, False, False, [])
		
		# Generate MFS Home Directory Records Log
		if sec_hdr_size == 0x28 :
			mfs_pt = ext_table([col_y + 'VFS ID' + col_e, col_y + 'Path' + col_e, col_y + 'File ID' + col_e, col_y + 'Size' + col_e, col_y + 'Integrity' + col_e, col_y + 'Encryption' + col_e,
			col_y + 'SVN' + col_e, col_y + 'Anti-Replay' + col_e, col_y + 'AR Index' + col_e, col_y + 'AR Random' + col_e, col_y + 'AR Counter' + col_e, col_y + 'User ID' + col_e,
			col_y + 'Group ID' + col_e, col_y + 'Unknown Access' + col_e, col_y + 'Unknown Options' + col_e, col_y + 'HMAC MD5' + col_e, col_y + 'AES-GCM Nonce' + col_e,
			col_y + 'Unknown Integrity 1' + col_e, col_y + 'Unknown Integrity 2' + col_e], True, 1)
			mfs_pt.title = col_y + 'VFS Home Directory Records' + col_e
		
		elif sec_hdr_size == 0x34 :
			mfs_pt = ext_table([col_y + 'VFS ID' + col_e, col_y + 'Path' + col_e, col_y + 'File ID' + col_e, col_y + 'Size' + col_e, col_y + 'Integrity' + col_e, col_y + 'Encryption' + col_e,
			col_y + 'SVN' + col_e, col_y + 'Anti-Replay' + col_e, col_y + 'AR Index' + col_e, col_y + 'AR Random' + col_e, col_y + 'AR Counter' + col_e, col_y + 'User ID' + col_e,
			col_y + 'Group ID' + col_e, col_y + 'Unknown Access' + col_e, col_y + 'Unknown Options' + col_e, col_y + 'HMAC SHA-256' + col_e, col_y + 'Nonce' + col_e,
			col_y + 'Unknown Integrity 1' + col_e, col_y + 'Unknown Integrity 2' + col_e], True, 1)
			mfs_pt.title = col_y + 'VFS Home Directory Records' + col_e
		
		else :
			mfs_pt = None
		
		if vfs_starts_at_0 : mfs_home13_dir = os.path.join(mea_dir, mfs_folder, '')
		else : mfs_home13_dir = os.path.join(mea_dir, mfs_folder, 'VFS Home Directory', '')
		
		for mfs_file in mfs_files :
			if mfs_file[1] and mfs_file[0] not in mfs_parsed_idx : # Check if MFS Low Level File has Contents but it has not been Parsed
				mfs_parsed_idx = mfs_home13_anl(mfs_file[0], mfs_file[1], vol_ftbl_id, sec_hdr_size, mfs_home13_dir, mfs_parsed_idx, mfs_pt, ftbl_dict, vol_ftbl_pl)
		
		mfs_txt(mfs_pt, mfs_home13_dir, os.path.join(mfs_home13_dir + 'home_records'), 'w', True) # Store/Print MFS Home Directory Records Log
		
	# Store all Non-Parsed MFS Low Level Files
	for mfs_file in mfs_files :
		if not mfs_has_files : break # Skip at empty MFS
		
		if mfs_file[1] and mfs_file[0] not in mfs_parsed_idx : # Check if MFS Low Level File has Contents but it has not been Parsed
			_ = mfs_anl_msg(col_r + 'Error: Detected MFS Low Level File %d which has not been parsed!' % (mfs_file[0]) + col_e, 'error', True, False, False, [])
			mfs_file_path = os.path.join(mfs_folder, '%0.3d.bin' % mfs_file[0])
			if not vol_has_ftbl : mfs_write(mfs_folder, mfs_file_path, mfs_file[1]) # Store MFS Low Level File, for FTBL/EFST-based MFS it is handled by mfs_home13_anl
		
	# Remember to also update any prior function return statements
	return mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, vol_ftbl_id, config_rec_size, vol_ftbl_pl

# Parse all MFS Home Directory Records Recursively
def mfs_home_anl(mfs_files, file_buffer, file_records, root_folder, home_rec_size, sec_hdr_size, mfs_parsed_idx, init_folder, mfs_pt) :
	for record in range(file_records) : # Process MFS Home Directory Record
		file_rec = get_struct(file_buffer, record * home_rec_size, home_rec_struct[home_rec_size]) # MFS Home Directory Record Structure
		file_name = file_rec.FileName.decode('utf-8') # MFS Home Directory Record Name
		user_id = '0x%0.4X' % file_rec.OwnerUserID # MFS Home Directory Record Owner User ID
		group_id = '0x%0.4X' % file_rec.OwnerGroupID # MFS Home Directory Record Owner Group ID
		unk_salt = file_rec.UnknownSalt # MFS Home Directory Record Unknown Integrity Salt
		file_index,integrity_salt,fs_id,unix_rights,integrity,encryption,anti_replay,acc_unk0,key_type,rec_type,acc_unk1 = file_rec.get_flags() # Get MFS Home Directory Record Flags
		
		file_data = mfs_files[file_index][1] if mfs_files[file_index][1] else b'' # MFS Home Directory Record Contents
		
		acc_unk_flags = '{0:01b}b'.format(acc_unk0) + ' {0:01b}b'.format(acc_unk1) # Store Unknown Record Access Flags
		
		unix_rights = ''.join(map(str, file_rec.get_rights(unix_rights))) # Store Record Access Unix Rights
		
		integrity_salt = '' if not integrity and not integrity_salt else '0x%0.4X' % integrity_salt # Initialize Integrity Salt
		
		# Initialize Unknown Integrity Salt
		if not integrity and not unk_salt : unk_salt = ''
		elif home_rec_size == 0x18 : unk_salt = '0x%0.4X' % file_rec.UnknownSalt
		elif home_rec_size == 0x1C : unk_salt = '0x%0.*X' % (0x6 * 2, int.from_bytes(file_rec.UnknownSalt, 'little'))
		else : unk_salt = '0x%X' % unk_salt
		
		# Initialize Integrity related variables
		sec_hmac, sec_encr_nonce, sec_ar_random, sec_ar_counter, sec_svn, sec_ar_idx, sec_aes_nonce, sec_unk_flags = [''] * 8
		sec_hdr = None
		file_sec = b''
		
		# Perform Integrity related actions
		if integrity :
			# Split MFS Home Directory Record Contents & Integrity, if Integrity Protection is present
			file_data = mfs_files[file_index][1][:-sec_hdr_size] if mfs_files[file_index][1] else b'' # MFS Home Directory Record Contents without Integrity
			file_sec = mfs_files[file_index][1][-sec_hdr_size:] if mfs_files[file_index][1] else b'' # MFS Home Directory Record Integrity without Contents
			
			# Parse MFS Home Directory Record Integrity Info
			if file_sec :
				sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size]) # MFS Home Directory Record/File or Record/Folder Integrity Structure
				
				if sec_hdr_size == 0x34 :
					sec_unk0, sec_ar, sec_encr, sec_unk1, sec_ar_idx, sec_unk2, sec_svn, sec_unk3 = sec_hdr.get_flags()
					
					sec_unk_flags = '{0:01b}b'.format(sec_unk0) + ' {0:07b}b'.format(sec_unk1) + ' {0:03b}b'.format(sec_unk2) + ' {0:01b}b'.format(sec_unk3)
					sec_hmac = '%0.*X' % (0x20 * 2, int.from_bytes(sec_hdr.HMACSHA256, 'little'))
					sec_encr_nonce = '%0.*X' % (0x10 * 2, int.from_bytes(sec_hdr.ARValues_Nonce, 'little')) if sec_encr else ''
					sec_ar_random = '0x%0.8X' % struct.unpack_from('<I', sec_hdr.ARValues_Nonce)[0] if sec_ar else ''
					sec_ar_counter = '0x%0.8X' % struct.unpack_from('<I', sec_hdr.ARValues_Nonce, 4)[0] if sec_ar else ''
					if not sec_encr : sec_svn = ''
					if not sec_ar : sec_ar_idx = ''
				
				elif sec_hdr_size == 0x28 :
					sec_unk0, sec_ar, sec_unk1, sec_encr, sec_unk2, sec_ar_idx, sec_unk3, sec_svn, sec_unk4 = sec_hdr.get_flags()
					
					sec_unk_flags = '{0:01b}b'.format(sec_unk0) + ' {0:01b}b'.format(sec_unk1) + ' {0:07b}b'.format(sec_unk2) + ' {0:01b}b'.format(sec_unk3) + ' {0:02b}b'.format(sec_unk4)
					sec_hmac = '%0.*X' % (0x10 * 2, int.from_bytes(sec_hdr.HMACMD5, 'little'))
					sec_aes_nonce = '%0.*X' % (0xC * 2, int.from_bytes(sec_hdr.AESGCMNonce, 'little'))
					sec_ar_random = '0x%0.8X' % sec_hdr.ARRandom if sec_ar else ''
					sec_ar_counter = '0x%0.8X' % sec_hdr.ARCounter if sec_ar else ''
					if not sec_encr : sec_svn = ''
					if not sec_ar : sec_ar_idx = ''
		
		# Store & Print MFS Home Directory Root/Start (8) Record Contents & Integrity Info
		if file_index == 8 and file_name == '.' : # MFS Low Level File 8 at Current (.) directory
			home_path = os.path.normpath(os.path.join(root_folder, '..', 'home')) # Set MFS Home Directory Root/Start Record Path
			file_rec_8 = file_rec # Duplicate MFS Home Directory Root/Start Record for adjustments
			file_rec_8.FileName = b'home' # Adjust MFS Home Directory Root/Start Record File Name from "." to "home" for printing
			file_rec_p = file_rec_8.mfs_print() # Get MFS Home Directory Root/Start Record PLTable Object after adjustment
			file_rec_p.add_row(['Path', 'home']) # Add MFS Home Directory Root/Start Record Local Path "home" for printing
			mfs_txt(file_rec_p, home_path, home_path, 'w', False) # Store/Print MFS Home Directory Root/Start Record Info
			sec_path = os.path.normpath(os.path.join(init_folder, 'home_integrity')) # Set MFS Home Directory Root/Start Record Integrity Path
			mfs_write(os.path.normpath(os.path.join(init_folder)), sec_path, file_sec) # Store MFS Home Directory Root/Start Record Integrity Contents
			mfs_txt(sec_hdr.mfs_print(), home_path, home_path + '_integrity', 'w', False) # Store/Print MFS Home Directory Root/Start Record Integrity Info
			
		# Set current Low Level File as Parsed, skip Folder Marker Records
		if file_name not in ('.','..') : mfs_parsed_idx.append(file_index)
		
		# Detect File System ID mismatch within MFS Home Directory
		if file_index >= 8 and fs_id != 1 : # File System ID for MFS Home Directory (Low Level File >= 8) is 1 (home)
			_ = mfs_anl_msg(col_r + 'Error: Detected bad File System ID %d at MFS Home Directory > %0.3d %s' % (fs_id, file_index, file_name) + col_e, 'error', True, False, False, [])
		
		# MFS Home Directory Record Nested Records Count
		file_records = divmod(len(file_data), home_rec_size)[0]
		
		# MFS Home Directory Record is a Folder Marker
		if file_name in ('.','..') :
			folder_path = os.path.normpath(os.path.join(root_folder, file_name, '')) # Set currently working MFS Home Directory Record/Folder Path
			rec_path = os.path.relpath(folder_path, start=init_folder) if file_index >= 8 else mfs_type[fs_id] # Set actual Record Path for printing
			
			if mfs_parsed_idx[-1] != 8 : continue # Skip logging & further parsing for Current (.) & Parent (..) directories of Low Level Files after 8 (home)
			
			# Append MFS Home Directory Record/Folder Info to Log
			if sec_hdr_size == 0x34 :
				# noinspection PyUnboundLocalVariable
				mfs_pt.add_row([file_index, rec_path, 'Folder', '', ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, sec_encr_nonce, ['No','Yes'][anti_replay],
				sec_ar_idx, sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_unk_flags])
			
			elif sec_hdr_size == 0x28 :
				# noinspection PyUnboundLocalVariable
				mfs_pt.add_row([file_index, rec_path, 'Folder', '', ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, ['No','Yes'][anti_replay], sec_ar_idx,
				sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_aes_nonce, sec_unk_flags])
			
			continue # Log but skip further parsing of Current (.) & Parent (..) Low Level File 8 (home) directories
		
		# MFS Home Directory Record is a File (Type 0)
		if rec_type == 0 :
			file_path = os.path.normpath(os.path.join(root_folder, file_name)) # Set MFS Home Directory Record/File Path
			rec_path = os.path.relpath(file_path, start=init_folder) if file_index >= 8 else mfs_type[fs_id] # Set actual Record Path for printing
			mfs_write(os.path.normpath(os.path.join(root_folder)), file_path, file_data) # Store MFS Home Directory Record/File Contents
			file_rec_p = file_rec.mfs_print() # Get MFS Home Directory Record/File PLTable Object for printing adjustments
			file_rec_p.add_row(['Path', rec_path]) # Add MFS Home Directory Record/File Local Path for printing
			mfs_txt(file_rec_p, os.path.normpath(os.path.join(root_folder)), file_path, 'w', False) # Store/Print MFS Home Directory Record/File Info
			
			if integrity : # Store & Print MFS Home Directory Record/File Integrity
				sec_path = os.path.normpath(os.path.join(root_folder, file_name + '_integrity')) # Set MFS Home Directory Record/File Integrity Path
				mfs_write(os.path.normpath(os.path.join(root_folder)), sec_path, file_sec) # Store MFS Home Directory Record/File Integrity Contents
				mfs_txt(sec_hdr.mfs_print(), os.path.normpath(os.path.join(root_folder)), sec_path, 'w', False) # Store/Print MFS Home Directory Record/File Integrity Info
			
			# Append MFS Home Directory Record/File Info to Log
			if sec_hdr_size == 0x34 :
				mfs_pt.add_row([file_index, rec_path, 'File', '0x%X' % len(file_data), ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, sec_encr_nonce,
				['No','Yes'][anti_replay], sec_ar_idx, sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_unk_flags])
			
			elif sec_hdr_size == 0x28 :
				mfs_pt.add_row([file_index, rec_path, 'File', '0x%X' % len(file_data), ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, ['No','Yes'][anti_replay],
				sec_ar_idx, sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_aes_nonce, sec_unk_flags])
		
		# MFS Home Directory Record is a Folder (Type 1)
		else :
			folder_path = os.path.normpath(os.path.join(root_folder, file_name, '')) # Set currently working MFS Home Directory Record/Folder Path
			rec_path = os.path.relpath(folder_path, start=init_folder) if file_index >= 8 else mfs_type[fs_id] # Set actual Record Path for printing
			file_rec_p = file_rec.mfs_print() # Get MFS Home Directory Record/Folder PLTable Object for printing adjustments
			file_rec_p.add_row(['Path', rec_path]) # Add MFS Home Directory Record/File Local Path for printing
			mfs_txt(file_rec_p, folder_path, folder_path, 'w', False) # Store/Print MFS Home Directory Record/Folder Info
			
			if integrity : # Store & Print MFS Home Directory Record/Folder Integrity
				sec_path = os.path.normpath(os.path.join(root_folder, file_name + '_integrity')) # Set MFS Home Directory Record/Folder Integrity Path
				mfs_write(os.path.normpath(os.path.join(root_folder)), sec_path, file_sec) # Store MFS Home Directory Record/Folder Integrity Contents
				mfs_txt(sec_hdr.mfs_print(), folder_path, folder_path + '_integrity', 'w', False) # Store/Print MFS Home Directory Record/Folder Integrity Info
			
			# Append MFS Home Directory Record/Folder Info to Log
			if sec_hdr_size == 0x34 :
				mfs_pt.add_row([file_index, rec_path, 'Folder', '', ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, sec_encr_nonce, ['No','Yes'][anti_replay],
				sec_ar_idx, sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_unk_flags])
			
			elif sec_hdr_size == 0x28 :
				mfs_pt.add_row([file_index, rec_path, 'Folder', '', ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, ['No','Yes'][anti_replay], sec_ar_idx,
				sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_aes_nonce, sec_unk_flags])
			
			mfs_home_anl(mfs_files, file_data, file_records, folder_path, home_rec_size, sec_hdr_size, mfs_parsed_idx, init_folder, mfs_pt) # Recursively parse all Folder Records
	
# Parse all FTBL-based MFS Home Directory Low Level Files
# noinspection PyUnusedLocal
def mfs_home13_anl(mfs_file_idx, mfs_file_data, vol_ftbl_id, sec_hdr_size, mfs_home13_dir, mfs_parsed_idx, mfs_pt, ftbl_dict, vol_ftbl_pl) :
	fvalue = ['No','Yes']
	
	file_data = mfs_file_data if mfs_file_data else b'' # MFS Home Directory File Contents
	vol_ftbl_pl = check_ftbl_pl(vol_ftbl_pl, ftbl_dict) # Check if MFS Volume FTBL Platform exists
	vol_ftbl_id = check_ftbl_id(vol_ftbl_id, ftbl_dict, vol_ftbl_pl) # Check if MFS Volume FTBL Dictionary exists
	ftbl_dict_id = '%0.2X' % vol_ftbl_id # FTBL Dictionary ID Tag
	ftbl_plat_id = '%0.2X' % vol_ftbl_pl # FTBL Platform ID Tag
	
	if ftbl_plat_id not in ftbl_dict or ftbl_dict_id not in ftbl_dict[ftbl_plat_id] or 'FTBL' not in ftbl_dict[ftbl_plat_id][ftbl_dict_id] :
		if ftbl_dict : _ = mfs_anl_msg(col_m + 'Warning: File Table %s > %s does not exist!' % (ftbl_plat_id,ftbl_dict_id) + col_e, '', True, False, False, [])
		rec_path = os.path.normpath(os.path.join('/Unknown', '%d.bin' % mfs_file_idx)) # Set generic/unknown File local path when warnings occur
		rec_file = os.path.normpath(mfs_home13_dir + rec_path) # Set generic/unknown File actual path when warnings occur
		rec_parent = os.path.normpath(os.path.join(mfs_home13_dir, 'Unknown')) # Set generic/unknown parent Folder actual path when warnings occur
		
		mfs_write(rec_parent, rec_file, file_data) # Store File to currently working Folder
		
		# Append MFS Home Directory File Info to Log
		if sec_hdr_size == 0x28 :
			mfs_pt.add_row(['%0.4d' % mfs_file_idx, rec_path, 'Unknown', '0x%X' % len(file_data), 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown',
			'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown'])
		
		elif sec_hdr_size == 0x34 :
			mfs_pt.add_row(['%0.4d' % mfs_file_idx, rec_path, 'Unknown', '0x%X' % len(file_data), 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown',
			'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown'])
	else :
		for ftbl_file_id in ftbl_dict[ftbl_plat_id][ftbl_dict_id]['FTBL'] :
			ftbl_entry = ftbl_dict[ftbl_plat_id][ftbl_dict_id]['FTBL'][ftbl_file_id].split(',') # Split FTBL Entry string data
			ftbl_entry = [ftbl_entry[0]] + [int(s) for s in ftbl_entry[1:]] # Convert FTBL Entry non-path string values to integers
			ftbl_path,ftbl_acc_int,ftbl_acc_enc,ftbl_acc_arp,ftbl_acc_unk,ftbl_group_id,ftbl_user_id,ftbl_vfs_id,ftbl_unk = ftbl_entry
			
			if ftbl_vfs_id == mfs_file_idx :
				mfs_parsed_idx.append(mfs_file_idx)
				
				# Remember to also adjust FTBL_Entry, param.mfs_ftbl & efs_anl
				ftbl_pt = ext_table(['Field', 'Value'], False, 1)
				ftbl_pt.title = col_y + 'File Table Entry' + col_e
				ftbl_pt.add_row(['Path', ftbl_path])
				ftbl_pt.add_row(['File ID', '0x%s' % ftbl_file_id])
				ftbl_pt.add_row(['Integrity', fvalue[ftbl_acc_int]])
				ftbl_pt.add_row(['Encryption', fvalue[ftbl_acc_enc]])
				ftbl_pt.add_row(['Anti-Replay', fvalue[ftbl_acc_arp]])
				ftbl_pt.add_row(['Access Unknown', '{0:013b}b'.format(ftbl_acc_unk)])
				ftbl_pt.add_row(['Group ID', '0x%0.4X' % ftbl_group_id])
				ftbl_pt.add_row(['User ID', '0x%0.4X' % ftbl_user_id])
				ftbl_pt.add_row(['VFS ID', '%0.4d' % ftbl_vfs_id])
				ftbl_pt.add_row(['Unknown', '{0:064b}b'.format(ftbl_unk)])
				
				rec_path = os.path.normpath(ftbl_path + ' (%0.4d)' % mfs_file_idx) # Get File local path from FTBL Dictionary
				sec_path = os.path.normpath(ftbl_path + ' (%0.4d)' % mfs_file_idx + '_integrity') # Create File Integrity local path
				rec_file = os.path.normpath(mfs_home13_dir + rec_path) # Set File actual path from FTBL Dictionary
				sec_file = os.path.normpath(mfs_home13_dir + sec_path) # Set File Integrity actual path from FTBL Dictionary
				rec_parent = os.path.normpath(os.path.dirname(rec_file)) # Adjust parent Folder actual path from FTBL Dictionary
				
				# Initialize Integrity related variables
				sec_hmac, sec_ar_random, sec_ar_counter, sec_svn, sec_ar_idx, sec_aes_nonce, sec_unk_flags = [''] * 7
				sec_unk0, sec_ar, sec_encr, sec_unk1, sec_unk2, sec_unk3, sec_unk4 = [0] * 7
				log_encr = ftbl_acc_enc
				log_arpl = ftbl_acc_arp
				sec_hdr = None
				file_sec = b''
				sec_unk = ''
				sec_extra_size = 0
				
				# Perform Integrity related actions
				if ftbl_acc_int :
					# Split MFS Home Directory Low Level File Contents & Integrity, if Integrity Protection is present
					file_data = mfs_file_data[:-sec_hdr_size] if mfs_file_data else b'' # MFS Home Directory Low Level File Contents without Integrity
					file_sec = mfs_file_data[-sec_hdr_size:] if mfs_file_data else b'' # MFS Home Directory Low Level File Integrity without Contents
					
					# Parse MFS Home Directory Low Level File Integrity Info
					if file_sec :
						
						if sec_hdr_size == 0x28 :
							sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size]) # MFS Home Directory Low Level File Integrity Structure
							
							# Some files have extra 0x10 Unknown data at the end of the 0x28 Integrity Structure (0x38).
							# We need to know the exact size of the full Integrity Structure in order to split the file.
							# For the life of me I cannot find any indicator at FTBL or VFS that those extra 0x10 exist.
							# The workaround below is stupid AF but should work until the proper indicator can be found.
							if sec_hdr.ARCounter > 0xFFFF : # The AR Counter should have small values, otherwise adjust
								sec_extra_size = 0x10
								file_data = mfs_file_data[:-(sec_hdr_size + sec_extra_size)] if mfs_file_data else b''
								file_sec = mfs_file_data[-(sec_hdr_size + sec_extra_size):] if mfs_file_data else b''
								sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size])
								sec_unk = '0x%0.*X' % (sec_extra_size * 2, int.from_bytes(file_sec[-sec_extra_size:], 'little'))
							
							sec_unk0, sec_ar, sec_unk1, sec_encr, sec_unk2, sec_ar_idx, sec_unk3, sec_svn, sec_unk4 = sec_hdr.get_flags()
							
							log_encr = sec_encr # Always prefer Integrity Info > Encryption value, if it exists
							log_arpl = sec_ar # Always prefer Integrity Info > Anti-Replay value, if it exists
							
							sec_unk_flags = '{0:01b}b'.format(sec_unk0) + ' {0:01b}b'.format(sec_unk1) + ' {0:07b}b'.format(sec_unk2) + ' {0:01b}b'.format(sec_unk3) + ' {0:02b}b'.format(sec_unk4)
							sec_hmac = '%0.*X' % (0x10 * 2, int.from_bytes(sec_hdr.HMACMD5, 'little'))
							sec_aes_nonce = '%0.*X' % (0xC * 2, int.from_bytes(sec_hdr.AESGCMNonce, 'little'))
							sec_ar_random = '0x%0.8X' % sec_hdr.ARRandom if sec_ar else ''
							sec_ar_counter = '0x%0.8X' % sec_hdr.ARCounter if sec_ar else ''
							if not sec_encr or sec_svn == 0 : sec_svn = ''
							if not sec_ar : sec_ar_idx = ''
							
							sec_hdr_pt = sec_hdr.mfs_print() # Save MFS Home Directory File Integrity Info
							if sec_extra_size : sec_hdr_pt.add_row(['Unknown', sec_unk]) # Append extra 0x10 Unknown data, if applicable
							
							mfs_write(os.path.normpath(os.path.join(rec_parent)), sec_file, file_sec) # Store MFS Home Directory File Integrity Contents
							mfs_txt(sec_hdr_pt, os.path.normpath(os.path.join(rec_parent)), sec_file, 'w', False) # Store/Print MFS Home Directory File Integrity Info
				
						elif sec_hdr_size == 0x34 :
							sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size]) # MFS Home Directory Low Level File Integrity Structure
							
							sec_unk0, sec_ar, sec_encr, sec_unk1, sec_ar_idx, sec_unk2, sec_svn, sec_unk3 = sec_hdr.get_flags()
							
							log_encr = sec_encr # Always prefer Integrity Info > Encryption value, if it exists
							log_arpl = sec_ar # Always prefer Integrity Info > Anti-Replay value, if it exists
							
							sec_unk_flags = '{0:01b}b'.format(sec_unk0) + ' {0:07b}b'.format(sec_unk1) + ' {0:03b}b'.format(sec_unk2) + ' {0:01b}b'.format(sec_unk3)
							sec_hmac = '%0.*X' % (0x20 * 2, int.from_bytes(sec_hdr.HMACSHA256, 'little'))
							sec_aes_nonce = '%0.*X' % (0x10 * 2, int.from_bytes(sec_hdr.ARValues_Nonce, 'little')) if sec_encr else ''
							sec_ar_random = '0x%0.8X' % struct.unpack_from('<I', sec_hdr.ARValues_Nonce)[0] if sec_ar else ''
							sec_ar_counter = '0x%0.8X' % struct.unpack_from('<I', sec_hdr.ARValues_Nonce, 4)[0] if sec_ar else ''
							if not sec_encr : sec_svn = ''
							if not sec_ar : sec_ar_idx = ''
							
							sec_hdr_pt = sec_hdr.mfs_print() # Save MFS Home Directory File Integrity Info
							if sec_extra_size : sec_hdr_pt.add_row(['Unknown', sec_unk]) # Append extra 0x10 Unknown data, if applicable
							
							mfs_write(os.path.normpath(os.path.join(rec_parent)), sec_file, file_sec) # Store MFS Home Directory File Integrity Contents
							mfs_txt(sec_hdr_pt, os.path.normpath(os.path.join(rec_parent)), sec_file, 'w', False) # Store/Print MFS Home Directory File Integrity Info
				
				mfs_write(rec_parent, rec_file, file_data) # Store File to currently working Folder
				mfs_txt(ftbl_pt, os.path.normpath(os.path.join(rec_parent)), rec_file, 'w', False) # Store/Print MFS Home Directory File Info
				
				# Append MFS Home Directory File Info to Log
				if sec_hdr_size == 0x28 :
					mfs_pt.add_row(['%0.4d' % ftbl_vfs_id, ftbl_path, '0x%s' % ftbl_file_id, '0x%X' % len(file_data), fvalue[ftbl_acc_int], fvalue[log_encr], sec_svn,
					fvalue[log_arpl], sec_ar_idx, sec_ar_random, sec_ar_counter, '0x%0.4X' % ftbl_user_id, '0x%0.4X' % ftbl_group_id, '{0:013b}b'.format(ftbl_acc_unk),
					'{0:064b}b'.format(ftbl_unk), sec_hmac, sec_aes_nonce, sec_unk_flags, sec_unk])
				
				elif sec_hdr_size == 0x34 :
					mfs_pt.add_row(['%0.4d' % ftbl_vfs_id, ftbl_path, '0x%s' % ftbl_file_id, '0x%X' % len(file_data), fvalue[ftbl_acc_int], fvalue[log_encr], sec_svn,
					fvalue[log_arpl], sec_ar_idx, sec_ar_random, sec_ar_counter, '0x%0.4X' % ftbl_user_id, '0x%0.4X' % ftbl_group_id, '{0:013b}b'.format(ftbl_acc_unk),
					'{0:064b}b'.format(ftbl_unk), sec_hmac, sec_aes_nonce, sec_unk_flags, sec_unk])
				
				break # Stop searching FTBL Dictionary at first VFS ID match
		else :
			if ftbl_dict : _ = mfs_anl_msg(col_m + 'Warning: File Table Dictionary %s > %s does not contain VFS ID %d!' % (ftbl_plat_id,ftbl_dict_id,mfs_file_idx) + col_e, '', False, False, False, [])
			rec_path = os.path.normpath(os.path.join('/Unknown', '%d.bin' % mfs_file_idx)) # Set generic/unknown File local path when warnings occur
			rec_file = os.path.normpath(mfs_home13_dir + rec_path) # Set generic/unknown File actual path when warnings occur
			rec_parent = os.path.normpath(os.path.join(mfs_home13_dir, 'Unknown')) # Set generic/unknown parent Folder actual path when warnings occur
			
			mfs_write(rec_parent, rec_file, file_data) # Store File to currently working Folder
			
			# Append MFS Home Directory File Info to Log
			if sec_hdr_size == 0x28 :
				mfs_pt.add_row(['%0.4d' % mfs_file_idx, rec_path, 'Unknown', '0x%X' % len(file_data), 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown',
				'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown'])
			
			elif sec_hdr_size == 0x34 :
				mfs_pt.add_row(['%0.4d' % mfs_file_idx, rec_path, 'Unknown', '0x%X' % len(file_data), 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown',
				'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown'])
			
	return mfs_parsed_idx
	
# Parse all MFS Configuration (Low Level Files 6 & 7) Records
# noinspection PyUnusedLocal
def mfs_cfg_anl(mfs_file, buffer, rec_folder, root_folder, config_rec_size, pch_init_info, vol_ftbl_id, vol_ftbl_pl) :
	mfs_pt = None
	ftbl_dict = {}
	ftbl_json = os.path.join(mea_dir, 'FileTable.dat')
	
	# Generate MFS Configuration Records Log
	if config_rec_size == 0x1C :
		mfs_pt = ext_table([col_y + 'Path' + col_e, col_y + 'Type' + col_e, col_y + 'Size' + col_e, col_y + 'Integrity' + col_e, col_y + 'Encryption' + col_e,
				 col_y + 'AntiReplay' + col_e, col_y + 'Rights' + col_e, col_y + 'User ID' + col_e, col_y + 'Group ID' + col_e, col_y + 'FIT' + col_e,
				 col_y + 'MCA' + col_e, col_y + 'Reserved' + col_e, col_y + 'Unknown Access' + col_e, col_y + 'Unknown Options' + col_e], True, 1)
	elif config_rec_size == 0xC :
		mfs_pt = ext_table([col_y + 'Path' + col_e, col_y + 'File ID' + col_e, col_y + 'Size' + col_e, col_y + 'FIT' + col_e, col_y + 'Reserved Flags' + col_e], True, 1)
		
		# Check if MFS File Table Dictionary file exists
		if os.path.isfile(ftbl_json) :
			with open(ftbl_json, 'r', encoding='utf-8') as json_file : ftbl_dict = json.load(json_file)
		else :
			_ = mfs_anl_msg(col_r + 'Error: MFS File Table Dictionary file is missing!' + col_e, 'error', True, False, False, [])
		
	mfs_pt.title = col_y + 'MFS %s Configuration Records' % ('006 Intel' if mfs_file == 6 else '007 OEM') + col_e
	
	rec_count = int.from_bytes(buffer[:4], 'little') # MFS Configuration Records Count
	for rec in range(rec_count) : # Parse all MFS Configuration Records
		rec_hdr = get_struct(buffer[4:], rec * config_rec_size, config_rec_struct[config_rec_size]) # MFS Configuration Record Structure
		rec_hdr_pt = rec_hdr.mfs_print() # MFS Configuration Record PLTable Object
		
		if config_rec_size == 0x1C :
			rec_name = rec_hdr.FileName.decode('utf-8') # File or Folder Name
			rec_size = rec_hdr.FileSize # File Size
			rec_res = '0x%0.4X' % rec_hdr.Reserved # Reserved
			rec_offset = rec_hdr.FileOffset # File Offset relative to MFS Low Level File start
			rec_user_id = '0x%0.4X' % rec_hdr.OwnerUserID # Owner User ID
			rec_group_id = '0x%0.4X' % rec_hdr.OwnerGroupID # Owner Group ID
			unix_rights,integrity,encryption,anti_replay,record_type,acc_unk,fitc_cfg,mca_upd,opt_unk = rec_hdr.get_flags() # Get Record Flags
			
			rec_size_p = '' if (record_type,rec_size) == (1,0) else '0x%X' % rec_size # Set Folder/File Size value for printing
			
			if record_type == 1 : # Set currently working Folder (Name or ..)
				rec_folder = os.path.normpath(os.path.join(rec_folder, rec_name, '')) # Add Folder name to path and adjust it automatically at ..
				local_mfs_path = os.path.relpath(rec_folder, start=root_folder) # Create Local MFS Folder Path
				rec_hdr_pt.add_row(['Path', local_mfs_path]) # Add Local MFS Folder Path to MFS Configuration Record Structure Info
				if rec_name not in ('.','..') : mfs_txt(rec_hdr_pt, rec_folder, rec_folder, 'w', False) # Store/Print MFS Configuration Record Info, skip folder markers
			else : # Set & Store currently working File (Name & Contents)
				rec_file = os.path.join(rec_folder, rec_name) # Add File name to currently working Folder path
				rec_data = buffer[rec_offset:rec_offset + rec_size] # Get File Contents from MFS Low Level File
				mfs_write(rec_folder, rec_file, rec_data) # Store File to currently working Folder
				local_mfs_path = os.path.relpath(rec_file, start=root_folder) # Create Local MFS File Path
				rec_hdr_pt.add_row(['Path', local_mfs_path]) # Add Local MFS File Path to MFS Configuration Record Structure Info
				mfs_txt(rec_hdr_pt, rec_folder, rec_file, 'w', False) # Store/Print MFS Configuration Record Info
				
				# Get PCH info via MFS Intel Configuration > PCH Initialization Table
				if mfs_file == 6 and rec_name.startswith('mphytbl') and rec_data : pch_init_info = mphytbl(mfs_file, rec_data, pch_init_info)
			
			if rec_name == '..' : continue # Parse but skip logging of Parent (..) directory
		
			# Append MFS Configuration Record Info to Log
			mfs_pt.add_row([local_mfs_path, ['File','Folder'][record_type], rec_size_p, ['No','Yes'][integrity], ['No','Yes'][encryption], ['No','Yes'][anti_replay],
			''.join(map(str, rec_hdr.get_rights(unix_rights))), rec_user_id, rec_group_id, ['No','Yes'][fitc_cfg], ['No','Yes'][mca_upd], rec_res,
			'{0:03b}b'.format(acc_unk), '{0:014b}b'.format(opt_unk)])
			
		elif config_rec_size == 0xC :
			rec_id = rec_hdr.FileID # File ID relative to MFS System Volume FTBL Dictionary
			rec_offset = rec_hdr.FileOffset # File Offset relative to MFS Low Level File start
			rec_size = rec_hdr.FileSize # File Size
			fitc_cfg,flag_unk = rec_hdr.get_flags() # Get Record Flags
			
			vol_ftbl_pl = check_ftbl_pl(vol_ftbl_pl, ftbl_dict) # Check if MFS Volume FTBL Platform exists
			vol_ftbl_id = check_ftbl_id(vol_ftbl_id, ftbl_dict, vol_ftbl_pl) # Check if MFS Volume FTBL Dictionary exists
			
			ftbl_dict_id = '%0.2X' % vol_ftbl_id # FTBL Dictionary ID Tag
			ftbl_plat_id = '%0.2X' % vol_ftbl_pl # FTBL Platform ID Tag
			ftbl_rec_id = '%0.8X' % rec_id # FTBL File/Record ID (10002000, 10046A39, 12090300 etc)
			
			if ftbl_plat_id not in ftbl_dict or ftbl_dict_id not in ftbl_dict[ftbl_plat_id] or 'FTBL' not in ftbl_dict[ftbl_plat_id][ftbl_dict_id] :
				if ftbl_dict : _ = mfs_anl_msg(col_m + 'Warning: File Table %s > %s does not exist!' % (ftbl_plat_id,ftbl_dict_id) + col_e, '', True, False, False, [])
				rec_path = os.path.normpath(os.path.join('/Unknown', '%s.bin' % ftbl_rec_id)) # Set generic/unknown File local path when warnings occur
				rec_file = os.path.normpath(rec_folder + rec_path) # Set generic/unknown File actual path when warnings occur
				rec_parent = os.path.normpath(os.path.join(rec_folder, 'Unknown')) # Set generic/unknown parent Folder actual path when warnings occur
			elif ftbl_rec_id not in ftbl_dict[ftbl_plat_id][ftbl_dict_id]['FTBL'] :
				if ftbl_dict : _ = mfs_anl_msg(col_m + 'Warning: File Table %s > %s does not contain ID %0.8X!' % (ftbl_plat_id,ftbl_dict_id,rec_id) + col_e, '', False, False, False, [])
				rec_path = os.path.normpath(os.path.join('/Unknown', '%s.bin' % ftbl_rec_id)) # Set generic/unknown File local path when warnings occur
				rec_file = os.path.normpath(rec_folder + rec_path) # Set generic/unknown File actual path when warnings occur
				rec_parent = os.path.normpath(os.path.join(rec_folder, 'Unknown')) # Set generic/unknown parent Folder actual path when warnings occur
			else :
				rec_path = os.path.normpath(ftbl_dict[ftbl_plat_id][ftbl_dict_id]['FTBL'][ftbl_rec_id].split(',')[0]) # Get File local path from FTBL Dictionary
				rec_file = os.path.normpath(rec_folder + rec_path) # Set File actual path from FTBL Dictionary
				rec_parent = os.path.normpath(os.path.dirname(rec_file)) # Adjust parent Folder actual path from FTBL Dictionary
			
			rec_name = os.path.basename(rec_file) # Get File Name
			rec_data = buffer[rec_offset:rec_offset + rec_size] # Get File Contents from MFS Low Level File
			mfs_write(rec_parent, rec_file, rec_data) # Store File to currently working Folder
			rec_hdr_pt.add_row(['Path', rec_path]) # Add Local MFS File Path to MFS Configuration Record Structure Info
			mfs_txt(rec_hdr_pt, rec_parent, rec_file, 'w', False) # Store/Print MFS Configuration Record Info
			
			# Get PCH info via MFS Intel Configuration > PCH Initialization Table
			if mfs_file == 6 and rec_name.startswith('mphytbl') and rec_data : pch_init_info = mphytbl(mfs_file, rec_data, pch_init_info)
			
			# Append MFS Configuration Record Info to Log
			mfs_pt.add_row([rec_path, '0x%s' % ftbl_rec_id, '0x%0.4X' % rec_size, ['No','Yes'][fitc_cfg], '{0:015b}b'.format(flag_unk)])
		
	mfs_txt(mfs_pt, root_folder, os.path.join(root_folder + 'home_records'), 'w', True) # Store/Print MFS Configuration Records Log
	
	return pch_init_info
	
# Analyze CSE FITC Partition > fitc.cfg OEM Configuration File 7
def fitc_anl(mod_f_path, part_start, part_end, config_rec_size, vol_ftbl_id, vol_ftbl_pl) :
	print(col_g + '\n    Analyzing MFS Low Level File 7 (OEM Configuration) ...' + col_e)
	
	fitc_part = reading[part_start:part_end]
	fitc_hdr = get_struct(fitc_part, 0, FITC_Header)
	fitc_rev = fitc_hdr.HeaderRevision
	
	if fitc_rev == 1 :
		fitc_hdr_data = fitc_part[:0x4] + b'\x00' * 4 + fitc_part[0x8:0xC]
		fitc_cfg_data = fitc_part[0x10:0x10 + fitc_hdr.DataLength]
		
		hdr_chk_int = fitc_hdr.HeaderChecksum
		hdr_chk_mea = crccheck.crc.Crc32.calc(fitc_hdr_data)
		if hdr_chk_int != hdr_chk_mea :
			if param.cse_pause :
				input_col(col_r + '\n    Error: Wrong FITC Header CRC-32 0x%0.8X, expected 0x%0.8X!' % (hdr_chk_int, hdr_chk_mea) + col_e) # Debug
			else :
				print(col_r + '\n    Error: Wrong FITC Header CRC-32 0x%0.8X, expected 0x%0.8X!' % (hdr_chk_int, hdr_chk_mea) + col_e)
				
		data_chk_int = fitc_hdr.DataChecksum
		data_chk_mea = crccheck.crc.Crc32.calc(fitc_cfg_data)
		if data_chk_int != data_chk_mea :
			if param.cse_pause :
				input_col(col_r + '\n    Error: Wrong FITC Data CRC-32 0x%0.8X, expected 0x%0.8X!' % (data_chk_int, data_chk_mea) + col_e) # Debug
			else :
				print(col_r + '\n    Error: Wrong FITC Data CRC-32 0x%0.8X, expected 0x%0.8X!' % (data_chk_int, data_chk_mea) + col_e)
	
	else : # CSME 15 (TGP) Alpha
		fitc_cfg_len = int.from_bytes(fitc_part[:0x4], 'little')
		fitc_cfg_data = fitc_part[0x4:0x4 + fitc_cfg_len]
		fitc_part_padd = fitc_part[0x4 + fitc_cfg_len:]
		
		if fitc_part_padd != len(fitc_part_padd) * b'\xFF' :
			if param.cse_pause :
				input_col(col_r + '\n    Error: Data at FITC padding, possibly unknown Header revision %d!' % fitc_rev + col_e) # Debug
			else :
				print(col_r + '\n    Error: Data at FITC padding, possibly unknown Header revision %d!' % fitc_rev + col_e)
	
	try :
		rec_folder = os.path.join(mea_dir, os.path.join(mod_f_path[:-4]), 'OEM Configuration', '')
		# noinspection PyUnusedLocal
		_ = mfs_cfg_anl(7, fitc_cfg_data, rec_folder, rec_folder, config_rec_size, [], vol_ftbl_id, vol_ftbl_pl) # Parse MFS Configuration Records
	except :
		if param.cse_pause :
			input_col(col_r + '\n    Error: Failed to analyze MFS Low Level File 7 (OEM Configuration)!' + col_e) # Debug
		else :
			print(col_r + '\n    Error: Failed to analyze MFS Low Level File 7 (OEM Configuration)!' + col_e)
			
# Analyze CSE EFS Partition
def efs_anl(mod_f_path, part_start, part_end, vol_ftbl_id, vol_ftbl_pl) :
	page_size = 0x1000
	meta_size = 0x4
	crc32_len = 0x4
	crc32_iv = 0x0
	idx_padd_len = 0x8
	sys_page_all = []
	dat_page_all = []
	emp_page_all = b''
	efs_data_all = b''
	file_data_all = b''
	fvalue = ['No','Yes']
	ftbl_dict = {}
	
	efs_part = reading[part_start:part_end]
	page_count = len(efs_part) // page_size
	page_hdr_size = ctypes.sizeof(EFS_Page_Header)
	page_ftr_size = ctypes.sizeof(EFS_Page_Footer)
	ftbl_json = os.path.join(mea_dir, 'FileTable.dat')
	efs_folder = os.path.join(mea_dir, os.path.join(mod_f_path[:-4]), '')
	
	# Verify that EFS Partition can be parsed by efs_anl
	if not re.compile(br'\x00.\x00.\x00{3}.{8}\x00\x01\x02\x03\x04\x05', re.DOTALL).search(efs_part[0x1:0x16]) :
		efs_anl_msg(col_r + 'Error: Skipped EFS partition at 0x%X, unrecognizable format!' % part_start + col_e, err_stor, True)
		
		return bool(file_data_all)
	
	# Initialize EFS Page Records Log
	efs_pt = ext_table([col_y + 'Type' + col_e, col_y + 'Unknown 0' + col_e, col_y + 'Table' + col_e, col_y + 'Revision' + col_e,
						col_y + 'Unknown 1' + col_e, col_y + 'Data Used' + col_e, col_y + 'Data Rest' + col_e,
						col_y + 'Table Revision' + col_e, col_y + 'CRC-32' + col_e], True, 1)
	efs_pt.title = col_y + 'EFS Page Records' + col_e
	
	# Parse EFS Pages to determine their Type (System, Data, Empty)
	for page_idx in range(page_count) :
		page_data = efs_part[page_idx * page_size:page_idx * page_size + page_size]
		page_hdr = get_struct(page_data[:page_hdr_size], 0, EFS_Page_Header)
		
		if page_hdr.Dictionary not in (0x0000,0xFFFF) :
			sys_page_all.append(page_data) # System Page
			page_type = 'System'
		elif page_hdr.Unknown0 != 0xFFFF :
			dat_page_all.append(page_data) # Data Page
			page_type = 'Data'
		else :
			emp_page_all += page_data # Empty/Scratch Page
			page_type = 'Scratch'
		
		if page_type == 'Scratch' : continue # Do not add Empty/Scratch Page(s) to Log
		
		# Append EFS Page Record Info to Log
		efs_pt.add_row([page_type, '0x%X' % page_hdr.Unknown0, '%0.2X' % page_hdr.Dictionary, page_hdr.Revision, '0x%X' % page_hdr.Unknown1,
						page_hdr.DataPagesCom, page_hdr.DataPagesRes, page_hdr.DictRevision, '0x%0.8X' % page_hdr.CRC32])
	
	# Process EFS Page Records Log
	if param.cse_unpack :
		if not param.cse_verbose : print('\n%s' % efs_pt) # Print EFS Page Records Log (already included in -ver86)
		
		mfs_txt(efs_pt, os.path.join(mod_f_path[:-4], ''), mod_f_path[:-4], 'a', True) # Store EFS Page Records Log
	
	sys_count = len(sys_page_all) # Count detected System Pages
	dat_count = len(dat_page_all) # Count detected Data Pages
	
	# EFS seems to use 1 System Page
	if sys_count != 1 :
		efs_anl_msg(col_r + 'Error: Detected %d EFS System Page(s), expected %d!' % (sys_count, 1) + col_e, err_stor, True)
	
	# EFS Empty/Scratch Page(s) should be empty (0xFF)
	if emp_page_all != b'\xFF' * len(emp_page_all) :
		efs_anl_msg(col_r + 'Error: Detected data in EFS Empty/Scratch Page(s)!' + col_e, err_stor, True)
	
	sys_page_data = sys_page_all[0] # System Page Contents (assuming only 1 exists)
	sys_hdr_data = sys_page_data[:page_hdr_size] # System Page Header Contents
	sys_hdr = get_struct(sys_hdr_data, 0, EFS_Page_Header) # System Page Header Structure
	
	sys_hdr_dict = sys_hdr.Dictionary # System Page Header Dictionary/Table (0A = CON, 0B = COR, 0C = SLM etc)
	
	# EFS & MFS Dictionary IDs should match
	if sys_hdr_dict != vol_ftbl_id :
		efs_anl_msg(col_r + 'Error: Detected EFS (%0.2X) & MFS (%0.2X) File Table Dictionary mismatch!' % (
					sys_hdr_dict, vol_ftbl_id) + col_e, err_stor, True)
				  
	sys_hdr_rev = sys_hdr.Revision # System Page Header EFS Revision
	sys_hdr_unk1 = sys_hdr.Unknown1 # System Page Header Unknown1 field
	
	# Report any new/unexpected EFS Revision & Unknown1 field values
	if (sys_hdr_rev,sys_hdr_unk1) != (1,2) :
		efs_anl_msg(col_r + 'Error: EFS System Page Header Revision,Unknown1 = 0x%X,0x%X, expected 0x1,0x2!' % (
					sys_hdr_rev, sys_hdr_unk1) + col_e, err_stor, True)
	
	sys_hdr_crc32_int = sys_hdr.CRC32 # System Page Header CRC-32 (Unknown0 - DictRevision, IV 0)
	sys_hdr_crc32_mea = ~crccheck.crc.Crc32.calc(sys_hdr_data[:-crc32_len], initvalue=crc32_iv) & 0xFFFFFFFF
	
	# Validate System Page Header CRC-32
	if sys_hdr_crc32_int != sys_hdr_crc32_mea :
		efs_anl_msg(col_r + 'Error: Wrong EFS System Page Header CRC-32 0x%0.8X, expected 0x%0.8X!' % (
					sys_hdr_crc32_int, sys_hdr_crc32_mea) + col_e, err_stor, True)
	elif param.cse_unpack :
		print(col_g + '\n    EFS System Page Header CRC-32 0x%0.8X is VALID' % sys_hdr_crc32_int + col_e)
	
	sys_dat_count = sys_hdr.DataPagesCom + sys_hdr.DataPagesRes # Count Total Data Pages reported by System Page
	
	# Data Pages Count from System Page Header & manual detection should match
	if dat_count != sys_dat_count :
		efs_anl_msg(col_r + 'Error: Detected %d EFS Data Pages, expected %d!' % (dat_count, sys_dat_count) + col_e, err_stor, True)

	sys_idx_padd = sys_page_data[page_hdr_size + sys_dat_count:page_hdr_size + sys_dat_count + idx_padd_len] # 1st Index Padding
	
	# Report any unexpected data in System Page 1st Index Area Padding
	if sys_idx_padd != b'\x00' * idx_padd_len :
		efs_anl_msg(col_r + 'Error: Detected data in EFS System Page 1st Index Area Padding!' + col_e, err_stor, True)
	
	sys_idx_size = sys_dat_count + idx_padd_len + crc32_len # System Page Index Area Size
	sys_idx_offset = sys_page_data.find(b'\xFF' * sys_idx_size) - sys_idx_size # System Page Last/Current Index Area Offset
	sys_idx_values = struct.unpack_from('<%dB' % sys_dat_count, sys_page_data, sys_idx_offset) # System Page Last/Current Index Area Values
	sys_idx_data = sys_page_data[sys_idx_offset:sys_idx_offset + sys_dat_count + idx_padd_len + crc32_len] # System Page Last/Current Index Area Data
	
	sys_idx_crc32_int = int.from_bytes(sys_idx_data[-crc32_len:], 'little') # System Page Indexes CRC-32 (Indexes + Padding, IV 0)
	sys_idx_crc32_mea = ~crccheck.crc.Crc32.calc(sys_idx_data[:-crc32_len], initvalue=crc32_iv) & 0xFFFFFFFF
	
	# Validate System Page Indexes CRC-32
	if sys_idx_crc32_int != sys_idx_crc32_mea :
		efs_anl_msg(col_r + 'Error: Wrong EFS System Page Indexes CRC-32 0x%0.8X, expected 0x%0.8X!' % (
					sys_idx_crc32_int, sys_idx_crc32_mea) + col_e, err_stor, True)
	
	# Sort Data Pages based on the order of the System Page Index Values
	# For example: 0C 01 07 03 00 [...] --> 0C = 1st Page, 07 = 3rd Page, 03 = 4th Page etc
	dat_pages_final = [dat_page_all[v] for v in sys_idx_values]
	
	# Parse the ordered Data Pages
	for page_idx in range(sys_dat_count) :
		page_data_all = dat_pages_final[page_idx] # Data Page Entire Contents
		page_data_dat = page_data_all[page_hdr_size:-page_ftr_size] # Data Page Data/File Contents
		page_data_crc = page_data_all[page_hdr_size:-crc32_len] # Data Page CRC-32 checked Contents
		
		dat_hdr_data = page_data_all[:page_hdr_size] # Data Page Header Contents
		dat_hdr = get_struct(dat_hdr_data, 0, EFS_Page_Header) # Data Page Header Structure
		dat_hdr_crc32_int = dat_hdr.CRC32 # Data Page Header CRC-32 (Unknown0 - DictRevision, IV 0)
		dat_hdr_crc32_mea = ~crccheck.crc.Crc32.calc(dat_hdr_data[:-crc32_len], initvalue=crc32_iv) & 0xFFFFFFFF
		
		# Validate Data Page Header CRC-32
		if dat_hdr_crc32_int != dat_hdr_crc32_mea :
			efs_anl_msg(col_r + 'Error: Wrong EFS Data Page %d Header CRC-32 0x%0.8X, expected 0x%0.8X!' % (
						page_idx, dat_hdr_crc32_int, dat_hdr_crc32_mea) + col_e, err_stor, True)
		elif param.cse_unpack :
			print(col_g + '\n    EFS Data Page %d Header CRC-32 0x%0.8X is VALID' % (page_idx, dat_hdr_crc32_int) + col_e)
		
		dat_ftr_data = page_data_all[-page_ftr_size:] # Data Page Footer Contents
		dat_ftr = get_struct(dat_ftr_data, 0, EFS_Page_Footer) # Data Page Footer Structure
		dat_ftr_crc32_int = dat_ftr.CRC32 # Data Page Footer CRC-32 (Header end - CRC32 start, IV 0)
		dat_ftr_crc32_mea = ~crccheck.crc.Crc32.calc(page_data_crc, initvalue=crc32_iv) & 0xFFFFFFFF
		dat_ftr_crc32_skip = bool(page_data_crc == b'\xFF' * len(page_data_crc) and dat_ftr_crc32_int == 0xFFFFFFFF)
		
		# Validate Data Page Footer CRC-32 (skip Reserved Data Pages)
		if not dat_ftr_crc32_skip and dat_ftr_crc32_int != dat_ftr_crc32_mea :
			efs_anl_msg(col_r + 'Error: Wrong EFS Data Page %d Footer CRC-32 0x%0.8X, expected 0x%0.8X!' % (
						page_idx, dat_ftr_crc32_int, dat_ftr_crc32_mea) + col_e, err_stor, True)
		elif param.cse_unpack :
			print(col_g + '\n    EFS Data Page %d Footer CRC-32 0x%0.8X is VALID' % (page_idx, dat_ftr_crc32_int) + col_e)
			
		efs_data_all += page_data_dat # Append Page/File Contents to Data Area Buffer
	
	efs_data_rest = bytearray(efs_data_all) # Initialize EFS Remaining Data Buffer to later detect wrong EFST
	
	# Check if EFS File Table Dictionary file exists
	if os.path.isfile(ftbl_json) :
		with open(ftbl_json, 'r', encoding='utf-8') as json_file : ftbl_dict = json.load(json_file)
	else :
		efs_anl_msg(col_r + 'Error: EFS File Table Dictionary file is missing!' + col_e, err_stor, True)
	
	vol_ftbl_pl = check_ftbl_pl(vol_ftbl_pl, ftbl_dict) # Get FTBL/EFST Platform from MFS Volume and check existence
	vol_ftbl_id = check_ftbl_id(vol_ftbl_id, ftbl_dict, vol_ftbl_pl) # Get FTBL/EFST Dictionary from MFS Volume and check existence
	
	plat_name = ftbl_efst_plat[vol_ftbl_pl] if vol_ftbl_pl in ftbl_efst_plat else 'Unknown' # Get FTBL/EFST Platform CodeName
	
	ftbl_dict_id = '%0.2X' % vol_ftbl_id # FTBL/EFST Dictionary ID Tag
	ftbl_plat_id = '%0.2X' % vol_ftbl_pl # FTBL/EFST Platform ID Tag
	efst_dict_rev = '%0.2X' % sys_hdr.DictRevision # FTBL/EFST Dictionary Revision Tag
	
	# Parse FTBL/EFST DB and extract EFS Files
	if 'EFST' in ftbl_dict[ftbl_plat_id][ftbl_dict_id] :
		if efst_dict_rev in ftbl_dict[ftbl_plat_id][ftbl_dict_id]['EFST'] :
			sec_hdr_size = get_sec_hdr_size(variant,major,minor,hotfix) # Get CSE File System Integrity Table Structure Size
			
			# Initialize EFS File Records Log
			if sec_hdr_size == 0x28 :
				efs_pt = ext_table([col_y + 'VFS ID' + col_e, col_y + 'EFS Name' + col_e, col_y + 'VFS Path' + col_e, col_y + 'File ID' + col_e,
									col_y + 'Size' + col_e, col_y + 'Metadata Unknown' + col_e, col_y + 'Reserved' + col_e, col_y + 'Integrity' + col_e,
									col_y + 'Encryption' + col_e, col_y + 'SVN' + col_e, col_y + 'Anti-Replay' + col_e, col_y + 'AR Index' + col_e,
									col_y + 'AR Random' + col_e, col_y + 'AR Counter' + col_e, col_y + 'User ID' + col_e, col_y + 'Group ID' + col_e,
									col_y + 'FTBL Unknown 1' + col_e, col_y + 'FTBL Unknown 2' + col_e, col_y + 'HMAC MD5' + col_e,
									col_y + 'AES-GCM Nonce' + col_e, col_y + 'Integrity Unknown 1' + col_e, col_y + 'Integrity Unknown 2' + col_e], True, 1)
				efs_pt.title = col_y + 'EFS File Records' + col_e
			else :
				efs_pt = None
			
			for offset_id in ftbl_dict[ftbl_plat_id][ftbl_dict_id]['EFST'][efst_dict_rev] :
				efst_entry = ftbl_dict[ftbl_plat_id][ftbl_dict_id]['EFST'][efst_dict_rev][offset_id].split(',') # Split EFST Entry string data
				efst_entry = [int(s) for s in efst_entry[:-1]] + [efst_entry[-1]] # Convert EFST Entry non-name string values to integers
				_,_,file_length,file_id,reserved,file_name = efst_entry # EFST > Entry/File info
				file_path = os.path.join(efs_folder, '%s (%0.4d)' % (file_name, file_id)) # Generate Entry/File path
				efs_offset = int(offset_id, 16) # Actual EFS Data Area Buffer File Offset from FTBL/EFST DB
				
				file_data_met = efs_data_all[efs_offset:efs_offset + meta_size] # Entry/File Metadata
				file_met = get_struct(file_data_met, 0, EFS_File_Metadata) # EFS Entry/File Metadata Structure
				file_met_size = file_met.Size # EFS Entry/File Size via its Metadata (always prefer over EFST Size)
				file_min_size = min(file_met_size, file_length) # EFS Entry/File Minimum Size from EFST or Metadata
				file_met_unk = file_met.Unknown # EFS Entry/File Unknown via its Metadata
				
				# Replace EFS Entry/File full data at the EFS Remaining Data Buffer to check for leftover data later
				efs_data_rest[efs_offset:efs_offset + meta_size + file_min_size] = b'\xFF' * (meta_size + file_min_size)
				
				# Check for empty EFS Entry/File via its Metadata Size
				if file_met_size == 0xFFFF :
					continue # Skip storing/recording of empty/unused EFS files
				
				# Check for wrong EFST via EFS Table & EFS Metadata File Size Mismatch
				if file_met_size > file_length :
					efs_anl_msg(col_m + 'Warning: Detected EFS Table & File Size mismatch at %s, wrong EFST!' % file_name + col_e, warn_stor, False)
					continue # No point in storing/recording EFS "files" when EFST is wrong
				
				file_data_all = efs_data_all[efs_offset + meta_size:efs_offset + meta_size + file_met_size] # EFS Entry/File Contents
				
				if not param.cse_unpack : continue # No need to further analyze EFS when not unpacking
				
				# EFS Files can be Integrity protected. Integrity/Security info can only be retrieved from FTBL, not EFST or EFS.
				# Without knowing the presence of Integrity, file size cannot be determined so FTBL parsing is necessary, not optional.
				for ftbl_file_id in ftbl_dict[ftbl_plat_id][ftbl_dict_id]['FTBL'] :
					ftbl_entry = ftbl_dict[ftbl_plat_id][ftbl_dict_id]['FTBL'][ftbl_file_id].split(',') # Split FTBL Entry string data
					ftbl_entry = [ftbl_entry[0]] + [int(s) for s in ftbl_entry[1:]] # Convert FTBL Entry non-path string values to integers
					ftbl_path,ftbl_acc_int,ftbl_acc_enc,ftbl_acc_arp,ftbl_acc_unk,ftbl_group_id,ftbl_user_id,ftbl_vfs_id,ftbl_unk = ftbl_entry
					
					if ftbl_vfs_id == file_id :
						# Remember to also adjust FTBL_Entry, param.mfs_ftbl & mfs_home13_anl
						ftbl_pt = ext_table(['Field', 'Value'], False, 1)
						ftbl_pt.title = col_y + 'File Table Entry' + col_e
						ftbl_pt.add_row(['EFS Name', file_name]) # Extra for EFS only
						ftbl_pt.add_row(['VFS Path', ftbl_path])
						ftbl_pt.add_row(['File ID', '0x%s' % ftbl_file_id])
						ftbl_pt.add_row(['Integrity', fvalue[ftbl_acc_int]])
						ftbl_pt.add_row(['Encryption', fvalue[ftbl_acc_enc]])
						ftbl_pt.add_row(['Anti-Replay', fvalue[ftbl_acc_arp]])
						ftbl_pt.add_row(['Access Unknown', '{0:013b}b'.format(ftbl_acc_unk)])
						ftbl_pt.add_row(['Group ID', '0x%0.4X' % ftbl_group_id])
						ftbl_pt.add_row(['User ID', '0x%0.4X' % ftbl_user_id])
						ftbl_pt.add_row(['VFS ID', '%0.4d' % ftbl_vfs_id])
						ftbl_pt.add_row(['Unknown', '{0:064b}b'.format(ftbl_unk)])
						
						# Initialize Integrity related variables
						sec_hmac, sec_ar_random, sec_ar_counter, sec_svn, sec_ar_idx, sec_aes_nonce, sec_unk_flags = [''] * 7
						log_encr = ftbl_acc_enc
						log_arpl = ftbl_acc_arp
						sec_unk = ''
						sec_extra_size = 0
						
						# Perform Integrity related actions
						if ftbl_acc_int :
							# Split EFS File Contents & Integrity, if Integrity Protection is present
							file_data = file_data_all[:-sec_hdr_size] if file_data_all else b'' # EFS File Contents without Integrity
							file_sec = file_data_all[-sec_hdr_size:] if file_data_all else b'' # EFS File Integrity without Contents
							
							# Parse EFS File Integrity Info
							if file_sec :
								if sec_hdr_size == 0x28 :
									sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size]) # EFS File Integrity Structure
									
									# Some files have extra 0x10 Unknown data at the end of the 0x28 Integrity Structure (0x38).
									# We need to know the exact size of the full Integrity Structure in order to split the file.
									# For the life of me I cannot find any indicator at FTBL or EFS that those extra 0x10 exist.
									# The workaround below is stupid AF but should work until the proper indicator can be found.
									if sec_hdr.ARCounter > 0xFFFF : # The AR Counter should have small values, otherwise adjust
										sec_extra_size = 0x10
										file_data = file_data_all[:-(sec_hdr_size + sec_extra_size)] if file_data_all else b''
										file_sec = file_data_all[-(sec_hdr_size + sec_extra_size):] if file_data_all else b''
										sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size])
										sec_unk = '0x%0.*X' % (sec_extra_size * 2, int.from_bytes(file_sec[-sec_extra_size:], 'little'))
									
									sec_unk0,sec_ar,sec_unk1,sec_encr,sec_unk2,sec_ar_idx,sec_unk3,sec_svn,sec_unk4 = sec_hdr.get_flags()
									
									log_encr = sec_encr # Always prefer Integrity Info > Encryption value, if it exists
									log_arpl = sec_ar # Always prefer Integrity Info > Anti-Replay value, if it exists
									
									sec_unk_flags = '{0:01b}b'.format(sec_unk0) + ' {0:01b}b'.format(sec_unk1) + ' {0:07b}b'.format(sec_unk2) + \
													' {0:01b}b'.format(sec_unk3) + ' {0:02b}b'.format(sec_unk4)
									sec_hmac = '%0.*X' % (0x10 * 2, int.from_bytes(sec_hdr.HMACMD5, 'little'))
									sec_aes_nonce = '%0.*X' % (0xC * 2, int.from_bytes(sec_hdr.AESGCMNonce, 'little'))
									sec_ar_random = '0x%0.8X' % sec_hdr.ARRandom if sec_ar else ''
									sec_ar_counter = '0x%0.8X' % sec_hdr.ARCounter if sec_ar else ''
									if not sec_encr or sec_svn == 0 : sec_svn = ''
									if not sec_ar : sec_ar_idx = ''
									
									sec_hdr_pt = sec_hdr.mfs_print() # Save EFS File Integrity Info
									sec_hdr_pt.title = col_y + 'EFS Integrity Table' + col_e # Adjust default title from MFS to EFS
									if sec_extra_size : sec_hdr_pt.add_row(['Unknown', sec_unk]) # Append extra 0x10 Unknown data, if applicable
									
									mfs_write(efs_folder, file_path + '_integrity', file_sec) # Store EFS File Integrity Contents
									mfs_txt(sec_hdr_pt, efs_folder, file_path + '_integrity', 'w', False) # Store EFS File Integrity Info
						else :
							file_data = file_data_all
						
						mfs_write(efs_folder, file_path, file_data) # Store EFS File Contents to currently working folder
						mfs_txt(ftbl_pt, efs_folder, file_path, 'w', False) # Store EFS File Metadata Info
						
						mfs_write(efs_folder, file_path + '_metadata', file_data_met) # Store EFS File Metadata to currently working folder
						mfs_txt(file_met.efs_print(), efs_folder, file_path + '_metadata', 'w', False) # Store EFS File Metadata Info
						
						if sec_hdr_size == 0x28 :
							# Append EFS File Record Info to Log
							efs_pt.add_row(['%0.4d' % file_id, file_name, ftbl_path, '0x%s' % ftbl_file_id, '0x%X' % len(file_data), '0x%0.4X' % file_met_unk,
											'0x%X' % reserved, fvalue[ftbl_acc_int], fvalue[log_encr], sec_svn, fvalue[log_arpl], sec_ar_idx, sec_ar_random,
											sec_ar_counter, '0x%0.4X' % ftbl_user_id, '0x%0.4X' % ftbl_group_id, '{0:013b}b'.format(ftbl_acc_unk),
											'{0:064b}b'.format(ftbl_unk), sec_hmac, sec_aes_nonce, sec_unk_flags, sec_unk])
						
						break # Stop searching FTBL Dictionary at first VFS ID match
				else :
					efs_anl_msg(col_r + 'Error: Could not find File System Platform 0x%s (%s) > Dictionary 0x%s > FTBL > VFS ID %0.4d!' % (
								ftbl_plat_id, plat_name, ftbl_dict_id, file_id) + col_e, err_stor, False)
			
			if file_data_all : # Perform actions depending on whether EFS Files exist or not
				mfs_txt(efs_pt, os.path.join(mod_f_path[:-4], ''), mod_f_path[:-4], 'a', True) # Store EFS File Records Log
			else :
				# Check if any uncharted EFS data remain after EFST analysis at Empty/Non-Initialized EFS only w/o Scratch data
				if param.cse_unpack and efs_data_rest != b'\xFF' * len(efs_data_rest) :
					efs_anl_msg(col_m + 'Warning: Detected additional EFS Data Buffer contents, wrong EFS Table!' + col_e, warn_stor, False)
		else :
			efs_anl_msg(col_r + 'Error: Could not find File System Platform 0x%s (%s) > Dictionary 0x%s > EFST > Revision 0x%s!' % (
						ftbl_plat_id, plat_name, ftbl_dict_id, efst_dict_rev) + col_e, err_stor, False)
	else :
		efs_anl_msg(col_r + 'Error: Could not find File System Platform 0x%s (%s) > Dictionary 0x%s > EFST!' % (
					ftbl_plat_id, plat_name, ftbl_dict_id) + col_e, err_stor, False)
	
	# Remember to also update any prior function return statements
	return bool(file_data_all)
	
# Analyze MFS Intel Configuration > Chipset Initialization Table
def mphytbl(mfs_file, rec_data, pch_init_info) :
	pch_stp_val = {0:'A',1:'B',2:'C',3:'D',4:'E',5:'F',6:'G',7:'H',8:'I',9:'J',10:'K',11:'L',12:'M',13:'N',14:'O',15:'P'}
	
	if rec_data[0x2:0x6] == b'\xFF' * 4 :
		pch_init_plt = pch_dict[rec_data[7]] if rec_data[7] in pch_dict else 'Unknown' # Actual Chipset SKU Platform (ICP-LP, TGP-H etc)
		pch_init_stp = rec_data[8] >> 4 # Raw Chipset Stepping(s), Absolute or Bitfield depending on firmware
		pch_init_rev = rec_data[6] # Chipset Initialization Table Revision
	else :
		pch_init_plt = pch_dict[rec_data[3] >> 4] if rec_data[3] >> 4 in pch_dict else 'Unknown' # Actual Chipset SKU Platform (SPT-H, CNP-LP etc)
		pch_init_stp = rec_data[3] & 0xF # Raw Chipset Stepping(s), Absolute or Bitfield depending on firmware
		pch_init_rev = rec_data[2] # Chipset Initialization Table Revision
	pch_true_stp = '' # Actual Chipset Stepping(s) (A, B, C etc)
	
	# Detect Actual Chipset Stepping(s) for CSSPS 4.4
	if (variant,major,minor) in [('CSSPS',4,4)] :
		pch_true_stp = pch_stp_val[pch_init_stp] # Absolute (0 = A, 1 = B, 2 = C, 3 = D etc)
		pch_init_plt = 'WTL' # Change from LBG-H to WTL (LBG-R)
	
	# Detect Actual Chipset Stepping(s) for CSME 11 & CSSPS 4
	elif (variant,major) in [('CSME',11),('CSSPS',4)] :
		if mn2_ftpr_hdr.Year > 0x2015 or (mn2_ftpr_hdr.Year == 0x2015 and mn2_ftpr_hdr.Month > 0x05) \
		or (mn2_ftpr_hdr.Year == 0x2015 and mn2_ftpr_hdr.Month == 0x05 and mn2_ftpr_hdr.Day >= 0x19) :
			# Absolute for CSME >=~ 11.0.0.1140 @ 2015-05-19 (0 = A, 1 = B, 2 = C, 3 = D etc)
			pch_true_stp = pch_stp_val[pch_init_stp]
		else :
			# Unreliable for CSME ~< 11.0.0.1140 @ 2015-05-19 (always 80 --> SPT/KBP-LP A)
			pass
	
	# Detect Actual Chipset Stepping(s) for CSME 12 & CSSPS 5
	elif (variant,major) in [('CSME',12),('CSSPS',5)] :
		if (mn2_ftpr_hdr.Year > 0x2018 or (mn2_ftpr_hdr.Year == 0x2018 and mn2_ftpr_hdr.Month > 0x01)
		or (mn2_ftpr_hdr.Year == 0x2018 and mn2_ftpr_hdr.Month == 0x01 and mn2_ftpr_hdr.Day >= 0x25)) :
			# Bitfield for CSME >=~ 12.0.0.1058 @ 2018-01-25 (0011 = --BA, 0110 = -CB-)
			for i in range(4) : pch_true_stp += 'DCBA'[i] if pch_init_stp & (1<<(4-1-i)) else ''
			if not pch_true_stp : pch_true_stp = 'A' # Fallback to A in case Bitfield is 0000
		else :
			# Absolute for CSME ~< 12.0.0.1058 @ 2018-01-25 (0 = A, 1 = B, 2 = C, 3 = D etc)
			pch_true_stp = pch_stp_val[pch_init_stp]
	
	# Detect Actual Chipset Stepping(s) for CSME 15.40
	elif (variant,major,minor) in [('CSME',15,40)] :
		if 7000 > build >= 1000 : pch_true_stp = pch_stp_val[(build // 1000) - 1] # Build Number Yxxx
		else : pch_true_stp = pch_stp_val[pch_init_stp] # Fallback to Absolute value
	
	# Detect Actual Chipset Stepping(s) for CSME 13, CSME 15 & CSSPS 6
	elif (variant,major) in [('CSME',13),('CSME',15),('CSME',16),('CSSPS',6)] :
		if rec_data[0x2:0x6] == b'\xFF' * 4 :
			# Absolute for CSME 13 >=~ 13.0.0.1061 (0 = A, 1 = B, 2 = C, 3 = D etc)
			pch_true_stp = pch_stp_val[pch_init_stp]
		else :
			# Bitfield for CSME ~< 13.0.0.1061 (0011 = --BA, 0110 = -CB-)
			for i in range(4) : pch_true_stp += 'DCBA'[i] if pch_init_stp & (1<<(4-1-i)) else ''
			if not pch_true_stp : pch_true_stp = 'A' # Fallback to A in case Bitfield is 0000
		
	# Detect Actual Chipset Stepping(s) for CSME 14.5
	elif (variant,major,minor) in [('CSME',14,5)] :
		# Absolute for CSME 14.5 (0 = A, 1 = B, 2 = C, 3 = D etc)
		pch_true_stp = pch_stp_val[pch_init_stp]
		pch_init_plt = 'CMP-V' # Change from KBP/BSF/GCF-H to CMP-V
	
	# Detect Actual Chipset Stepping(s) for CSME 14.0
	elif (variant,major) in [('CSME',14)] :
		# Bitfield for CSME 14.0 & maybe CSME 15 (0011 = --BA, 0110 = -CB-)
		for i in range(4) : pch_true_stp += 'DCBA'[i] if pch_init_stp & (1<<(4-1-i)) else ''
		if not pch_true_stp : pch_true_stp = 'A' # Fallback to A in case Bitfield is 0000
		
	pch_init_info.append([mfs_file, pch_init_plt, pch_true_stp, pch_init_rev]) # Output Chipset Initialization Table Info
	
	return pch_init_info
	
# MFS 14-bit CRC-16 for System Page Chunk Indexes (from parseMFS by Dmitry Sklyarov)
def Crc16_14(w, crc=0x3FFF) :
	CRC16tab = [0]*256
	for i in range(256):
		r = i << 8
		for _ in range(8): r = (r << 1) ^ (0x1021 if r & 0x8000 else 0)
		CRC16tab[i] = r & 0xFFFF
	
	for b in bytearray(struct.pack('<H', w)): crc = (CRC16tab[b ^ (crc >> 8)] ^ (crc << 8)) & 0x3FFF
	
	return crc
	
# Write/Print MFS Structures Information
def mfs_txt(struct_print, folder_path, file_path_wo_ext, mode, is_log) :
	if param.cse_unpack : # Write Text File during CSE Unpacking
		struct_txt = ansi_escape.sub('', str(struct_print)) # Ignore Colorama ANSI Escape Character Sequences
		
		os.makedirs(folder_path, exist_ok=True) # Create the Text File's parent Folder, if needed
		
		if param.cse_verbose and is_log : print('\n%s' % struct_txt) # Print Structure Info
		
		with open(file_path_wo_ext + '.txt', mode, encoding = 'utf-8') as txt : txt.write('\n%s' % struct_txt) # Store Structure Info Text File
		if param.write_html :
			with open(file_path_wo_ext + '.html', mode, encoding = 'utf-8') as html : html.write('\n<br/>\n%s' % pt_html(struct_print)) # Store Structure Info HTML File
		if param.write_json :
			with open(file_path_wo_ext + '.json', mode, encoding = 'utf-8') as html : html.write('\n%s' % pt_json(struct_print)) # Store Structure Info JSON File
	
# Write MFS File Contents
def mfs_write(folder_path, file_path, data) :
	if param.cse_unpack or param.cse_pause : # Write File during CSE Unpacking
		os.makedirs(folder_path, exist_ok=True) # Create the File's parent Folder, if needed
		
		with open(file_path, 'wb') as file : file.write(data)
		
# Store and show MFS Analysis Errors
def mfs_anl_msg(mfs_err_msg, msg_type, msg_copy, is_page, is_chunk_crc, mfs_tmp_page) :
	if msg_type == 'error' : err_stor.append([mfs_err_msg, msg_copy])
	
	if param.cse_unpack and not is_page :
		if msg_type == 'error' and param.cse_pause : input_col('\n    %s' % mfs_err_msg)
		else : print('\n    %s' % mfs_err_msg)
		
	if is_page :
		if is_chunk_crc : mfs_err_msg = '    ' + mfs_err_msg # Extra Tab at Page Chunk CRC messages for visual purposes (-unp86)
		mfs_tmp_page.append(('    ' + mfs_err_msg, msg_type)) # Pause on error (-bug86) handled by caller
		
	return mfs_tmp_page
	
# Store and show EFS Analysis Messages
def efs_anl_msg(efs_msg, msg_list, msg_copy) :
	msg_list.append([efs_msg, msg_copy])
	
	if param.cse_unpack and param.cse_pause : input_col('\n    %s' % efs_msg) # Debug
	elif param.cse_unpack : print('\n    %s' % efs_msg)
	
# Analyze CSE PCH Initialization Table Platforms/Steppings
def pch_init_anl(pch_init_info) :
	pch_init_final = []
	final_print = ''
	final_db = ''
	
	# pch_init_info = [[MFS File, Chipset, Stepping, Patch], etc]
	# pch_init_final = [[Chipset, Steppings], etc, [Total Platforms/Steppings, Total DB Steppings]]
	
	# Skip analysis if no Initialization Table or Stepping was detected
	if not pch_init_info or pch_init_info[0][2] == '' : return pch_init_final
	
	# Store each Chipset once
	for info in pch_init_info :
		skip = False
		for final in pch_init_final :
			if info[1] == final[0] : skip = True
		if not skip : pch_init_final.append([info[1], ''])
	
	# Store all Steppings for each Chipset
	for info in pch_init_info :
		for final in pch_init_final :
			if info[1] == final[0] :
				final[1] = final[1] + info[2]
		
	# Sort each Chipset Steppings in reverse order (e.g. DCBA) & build total Print values
	for final_idx in range(len(pch_init_final)) :
		pch_init_final[final_idx][1] = ''.join(sorted(list(dict.fromkeys(pch_init_final[final_idx][1])), reverse=True))
		final_print += '%s %s' % (pch_init_final[final_idx][0], ','.join(map(str, list(pch_init_final[final_idx][1]))))
		if final_idx < len(pch_init_final) - 1 : final_print += '\n' # No new line after last print
		final_db += pch_init_final[final_idx][1]
		
	# Add total Platforms/Steppings and Steppings for printing at last list cell, pch_init_final[-1]
	pch_init_final.append([final_print, ''.join(sorted(list(dict.fromkeys(final_db)), reverse=True))])
	
	return pch_init_final
	
# Analyze GSC Information (INFO) $FPT Partition
def info_anl(mod_f_path, part_start, part_end) :
	print(col_g + '\n    Analyzing GSC Information Partition ...' + col_e)
	
	fwi_size = ctypes.sizeof(GSC_Info_FWI)
	iup_size = ctypes.sizeof(GSC_Info_IUP)
	rev_size = 0x4
	
	info_rev = int.from_bytes(reading[part_start:part_start + rev_size], 'little')
	
	if info_rev != 1 :
		if param.cse_pause :
			input_col(col_r + '\n    Error: Unknown GSC Information Partition Revision %d!' % info_rev + col_e) # Debug
		else :
			print(col_r + '\n    Error: Unknown GSC Information Partition Revision %d!' % info_rev + col_e)
	
	info_data = reading[part_start + rev_size:part_end]
	fwi_data = info_data[:fwi_size]
	iup_data = info_data[fwi_size:]
	iup_count = len(iup_data) // iup_size
	
	fwi_hdr = get_struct(fwi_data, 0, GSC_Info_FWI)
	print('\n%s' % fwi_hdr.gsc_print())
	mfs_txt(fwi_hdr.gsc_print(), os.path.join(mod_f_path[:-4], ''), mod_f_path[:-4], 'a', False)
	
	for iup_idx in range(iup_count) :
		iup_hdr = get_struct(iup_data, iup_idx * iup_size, GSC_Info_IUP)
		if param.cse_verbose : print(iup_hdr.gsc_print())
		mfs_txt(iup_hdr.gsc_print(), os.path.join(mod_f_path[:-4], ''), mod_f_path[:-4], 'a', False)
	
# Analyze CSE PMC firmware before parsing
def pmc_anl(mn2_info) :
	pmc_pch_sku = 'Unknown'
	pmcp_upd_found = False
	pch_sku_val = {0:'SoC', 1:'LP', 2:'H', 3:'N'}
	pch_sku_old = {0:'H', 2:'LP'}
	pch_rev_val = {0:'A', 1:'B', 2:'C', 3:'D', 4:'E', 5:'F', 6:'G', 7:'H', 8:'I', 9:'J', 10:'K', 11:'L', 12:'M', 13:'N', 14:'O', 15:'P'}
	
	# mn2_info = [Major, Minor, Hotfix, Build, Release, RSA Key Hash, RSA Sig Hash, Date, SVN, PV bit, MEU Major, MEU Minor, MEU Hotfix,
	# 			  MEU Build, MN2 w/o RSA Hashes, MN2 Struct, MN2 Match Start, MN2 Match End]
	
	# $MN2 Manifest SVN = CSE_Ext_0F ARBSVN. The value is used for Anti-Rollback (ARB) and not Trusted Computing Base (TCB) purposes.
	
	pmc_year,pmc_month,pmc_day = list(map(int, mn2_info[7].split('-')))
	
	# Detect PMC Variant
	pmc_variant, _, _ = get_variant(reading, mn2_info[15], mn2_info[16], mn2_info[17], mn2_info[5], [pmc_year, pmc_month, pmc_day],
								 [mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3]])
	
	if not pmc_variant.startswith('PMC') : pmc_variant = 'Unknown'
	
	pmc_platform = pmc_variant[-3:]
	pmc_pch_rev = '%s%d' % (pch_rev_val[min(mn2_info[2] // 10, 0xF)], mn2_info[2] % 10) # 21 = PCH C PMC 1
	
	# Get/Set special PMC Platform, SKU and/or Steppings
	if pmc_variant == 'PMCCNP' and mn2_info[0] not in [300,30] :
		# CSME < 12.0.0.1033 --> 01.7.0.1022 = PCH Stepping A1 + PMC Hotfix 7 + PCH-H + PMC Build 1022 (Guess)
		# CSME < 12.0.0.1033 --> 10.0.2.1021 = PCH Stepping B0 + PMC Hotfix 0 + PCH-LP + PMC Build 1021 (Guess)
		if mn2_info[2] in pch_sku_old : pmc_pch_sku = pch_sku_old[mn2_info[2]] # 0 H, 2 LP
		pmc_pch_rev = '%s%d' % (pch_rev_val[min(mn2_info[0] // 10, 0xF)], mn2_info[0] % 10) # 21 = PCH C1
	
	elif pmc_variant == 'PMCCMPV' :
		# CSME 14.5 is H instead of V, PMC is 140 LP instead of 145 V = GREAT WORK INTEL...
		pmc_pch_sku = 'V' # Value instead of Halo or Low Power
		pmc_platform = 'CMP-V' # To differentiate CMP-V (KBP) from actual CMP
	
	elif pmc_variant == 'PMCWTL' :
		# Whitley is a royal f**k up, no further explanation required = GREAT WORK INTEL...
		pmc_pch_sku = 'H' # Based on target use cases
		pmc_pch_rev = 'B' # Based on CSSPS > VFS > mphytbl
		pmc_platform = 'WTL' # Whitley (a.k.a. LBG-R, a.k.a. SHI-T)
	
	elif pmc_variant.startswith(('PMCAPL','PMCBXT','PMCGLK')) :
		pmc_platform = pmc_variant[3:6]
		pmc_pch_rev = pmc_variant[-1]
	
	elif pmc_variant != 'Unknown' and mn2_info[1] in pch_sku_val :
		# 130.1.10.1003 = ICP + LP + PCH Compatibility B + PMC Maintenance 0 + PMC Revision 1003
		pmc_pch_sku = pch_sku_val[mn2_info[1]] # 0 SoC, 1 LP, 2 H, 3 N
	
	# Check PMC Latest status
	if pmc_variant == 'PMCWTL' :
		# WTL PMC version is weird/useless so use Latest Date instead
		db_year,db_month,db_day,_ = check_upd(('Latest_PMC%s_H_%s' % (pmc_platform[:3], pmc_pch_rev)))
		if pmc_year < db_year or (pmc_year == db_year and (pmc_month < db_month or (pmc_month == db_month and pmc_day < db_day))) : pmcp_upd_found = True
	else :
		_,_,db_rev,db_rel = check_upd(('Latest_PMC%s_%s_%s' % (pmc_platform[:3], pmc_pch_sku, pch_rev_val[mn2_info[2] // 10])))
		if mn2_info[2] < db_rev or (mn2_info[2] == db_rev and mn2_info[3] < db_rel) : pmcp_upd_found = True
	
	pmc_pch_rev_p = pmc_pch_rev[0] if pmc_pch_rev != 'Unknown' else pmc_pch_rev
	
	pmc_mn2_signed = 'Pre-Production' if mn2_info[4] == 'Debug' else 'Production'
	pmc_mn2_signed_db = 'PRD' if pmc_mn2_signed == 'Production' else 'PRE'
	
	# Fix Release of PRE firmware which are wrongly reported as PRD
	pmc_mn2_signed, pmc_mn2_signed_db = release_fix(pmc_mn2_signed, pmc_mn2_signed_db, mn2_info[5])
	
	if pmc_platform.startswith(('APL','GLK','BXT')) :
		pmc_fw_ver = '%s.%s.%s.%s' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
		pmc_meu_ver = '%d.%d.%d.%0.4d' % (mn2_info[10], mn2_info[11], mn2_info[12], mn2_info[13])
		pmc_name_db = '%s_%s_%s_%s_%s_%s' % (pmc_platform[:3], pmc_fw_ver, pmc_pch_rev_p, mn2_info[7], pmc_mn2_signed_db, mn2_info[6])
	elif pmc_platform.startswith(('CNP','WTL')) and mn2_info[0] not in [300,30] :
		pmc_fw_ver = '%0.2d.%s.%s.%s' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
		pmc_meu_ver = '%d.%d.%d.%0.4d' % (mn2_info[10], mn2_info[11], mn2_info[12], mn2_info[13])
		pmc_name_db = '%s_%s_%s_%s_%s_%s_%s' % (pmc_platform[:3], pmc_fw_ver, pmc_pch_sku, pmc_pch_rev_p, mn2_info[7], pmc_mn2_signed_db, mn2_info[6])
	elif pmc_platform.startswith('DG') :
		pmc_fw_ver = '%s.%s.%s.%s' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
		pmc_meu_ver = '%d.%d.%d.%0.4d' % (mn2_info[10], mn2_info[11], mn2_info[12], mn2_info[13])
		pmc_name_db = '%s_%s_%s_%s_%s' % (pmc_platform[:4], pmc_fw_ver, mn2_info[7], pmc_mn2_signed_db, mn2_info[6])
	else :
		pmc_fw_ver = '%s.%s.%0.2d.%0.4d' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
		pmc_meu_ver = '%d.%d.%d.%0.4d' % (mn2_info[10], mn2_info[11], mn2_info[12], mn2_info[13])
		pmc_name_db = '%s_%s_%s_%s_%s_%s' % (pmc_platform[:3], pmc_fw_ver, pmc_pch_sku, pmc_pch_rev_p, pmc_mn2_signed_db, mn2_info[6])
	
	# Search DB for PMC firmware
	for line in mea_db_lines :
		if pmc_name_db in line :
			break # Break loop at 1st name match
	else :
		note_new_fw('PMC %s' % pmc_platform)
	
	# Detect PMC RSA Public Key Recognition
	for line in mea_db_lines :
		if mn2_info[5] in line :
			break # Break loop at 1st hash match
	else :
		err_msg = [col_r + 'Error: Unknown %s %d.%d RSA Public Key!' % (pmc_variant, mn2_info[0], mn2_info[1]) + col_e, True]
		if err_msg not in err_stor : err_stor.append(err_msg) # Do not store message twice at bare/non-stitched PMC firmware
	
	return pmc_fw_ver, mn2_info[0], pmc_pch_sku, pmc_pch_rev, mn2_info[3], pmc_mn2_signed, pmc_mn2_signed_db, pmcp_upd_found, pmc_platform, \
		   mn2_info[7], mn2_info[8], mn2_info[9], pmc_meu_ver
		   
# Verify CSE FTPR/OPR & stitched PMC compatibility
def pmc_chk(pmc_mn2_signed, release, pmc_pch_gen, pmc_pch_sku, sku_result, sku_stp, pmc_pch_rev, pmc_platform) :
	if variant == 'CSSPS' : sku_result = 'H' # Manually adjust some fields at CSSPS
	elif variant == 'GSC' : pmc_pch_sku,sku_stp = ['Unknown'] * 2 # Manually adjust some fields at GSC
	elif variant == 'CSTXE' : pmc_pch_gen,pmc_pch_sku,sku_result = [-1,'N/A','N/A'] # Manually adjust some fields at CSTXE
	
	if (variant,major,minor) in pmc_dict :
		if (variant,major,minor,pmc_platform) == ('CSME',12,0,'CNP') and pmc_pch_gen != 300 : return # Ignore CSME 12.0 Alpha CNP PMC
		if (variant,major,minor,pmc_platform) == ('CSME',13,0,'ICP') and pmc_pch_gen != 130 : return # Ignore CSME 13.0 Alpha ICP PMC
		if (variant,major,minor,sku_result,pmc_pch_rev[0],sku_stp) == ('CSME',15,0,'H','B','A') : sku_stp = 'Unknown' # Skip CSME 15.0 H A w/ PMC B
		if (variant,major,minor,sku_result,pmc_pch_rev[0],sku_stp) == ('CSME',15,0,'LP','C','B') : sku_stp = 'Unknown' # Skip CSME 15.0 LP B w/ PMC C
		if (variant,major,minor,sku_result,pmc_pch_sku) in pmc_soc_dict : pmc_pch_sku = sku_result # Adjust known compatible PMC "SoC" SKU to CSE SKU
		
		if pmc_mn2_signed != release or pmc_pch_gen not in pmc_dict[(variant,major,minor)] or pmc_pch_sku != sku_result \
		or (sku_stp != 'Unknown' and pmc_pch_rev[0] not in sku_stp) :
			warn_stor.append([col_m + 'Warning: Incompatible PMC %s firmware detected!' % pmc_platform + col_e, False])
	else :
		err_stor.append([col_r + 'Error: Could not verify %s %d.%d & PMC %s firmware compatibility!' % (variant, major, minor, pmc_platform) + col_e, True])

# Parse CSE PMC firmware after analysis
def pmc_parse(pmc_all_init, pmc_all_anl) :
	for pmc in pmc_all_init :
		pmc_vcn,pmc_mn2_ver,pmc_ext15_info,pmc_size = pmc
		
		pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmc_mn2_signed_db,pmcp_upd_found,pmc_platform, \
		pmc_date,pmc_svn,pmc_pvbit,pmc_meu_ver = pmc_anl(pmc_mn2_ver)
		
		pmc_chk(pmc_mn2_signed, release, pmc_pch_gen, pmc_pch_sku, sku_result, sku_stp, pmc_pch_rev, pmc_platform)
		
		pmc_all_anl.append([pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmc_mn2_signed_db,pmcp_upd_found,
							pmc_platform,pmc_date,pmc_svn,pmc_pvbit,pmc_meu_ver,pmc_vcn,pmc_mn2_ver,pmc_ext15_info,pmc_size])
	
	return pmc_all_anl
	
# Analyze CSE PCHC firmware before parsing
def pchc_anl(mn2_info) :
	pchc_platform = 'Unknown'
	pchc_upd_found = False
	
	# mn2_info = [Major, Minor, Hotfix, Build, Release, RSA Key Hash, RSA Sig Hash, Date, SVN, PV bit, MEU Major, MEU Minor, MEU Hotfix,
	# 			  MEU Build, MN2 w/o RSA Hashes, MN2 Struct, MN2 Match Start, MN2 Match End]
	
	# $MN2 Manifest SVN = CSE_Ext_0F ARBSVN. The value is used for Anti-Rollback (ARB) and not Trusted Computing Base (TCB) purposes.
	
	pchc_year,pchc_month,pchc_day = list(map(int, mn2_info[7].split('-')))
	
	# Detect PCHC Variant
	pchc_variant, _, _ = get_variant(reading, mn2_info[15], mn2_info[16], mn2_info[17], mn2_info[5], [pchc_year, pchc_month, pchc_day],
								 [mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3]])
	
	if not pchc_variant.startswith('PCHC') : pchc_variant = 'Unknown'
	
	if pchc_variant != 'Unknown' : pchc_platform = 'CMP-V' if pchc_variant == 'PCHCCMPV' else pchc_variant[-3:]
	
	_,_,db_rev,db_rel = check_upd(('Latest_PCHC%s_%d%d' % (pchc_platform[:3], mn2_info[0], mn2_info[1])))
	if mn2_info[2] < db_rev or (mn2_info[2] == db_rev and mn2_info[3] < db_rel) : pchc_upd_found = True
	
	pchc_mn2_signed = 'Pre-Production' if mn2_info[4] == 'Debug' else 'Production'
	pchc_mn2_signed_db = 'PRD' if pchc_mn2_signed == 'Production' else 'PRE'
	
	# Fix Release of PRE firmware which are wrongly reported as PRD
	pchc_mn2_signed, pchc_mn2_signed_db = release_fix(pchc_mn2_signed, pchc_mn2_signed_db, mn2_info[5])
	
	pchc_fw_ver = '%d.%d.%d.%0.4d' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
	pchc_meu_ver = '%d.%d.%d.%0.4d' % (mn2_info[10], mn2_info[11], mn2_info[12], mn2_info[13])
	pchc_name_db = '%s_%s_%s_%s' % (pchc_platform[:3], pchc_fw_ver, pchc_mn2_signed_db, mn2_info[6])
	
	# Search DB for PCHC firmware
	for line in mea_db_lines :
		if pchc_name_db in line :
			break # Break loop at 1st name match
	else :
		note_new_fw('PCHC %s' % pchc_platform)
	
	# Detect PCHC RSA Public Key Recognition
	for line in mea_db_lines :
		if mn2_info[5] in line :
			break # Break loop at 1st hash match
	else :
		err_msg = [col_r + 'Error: Unknown %s %d.%d RSA Public Key!' % (pchc_variant, mn2_info[0], mn2_info[1]) + col_e, True]
		if err_msg not in err_stor : err_stor.append(err_msg) # Do not store message twice at bare/non-stitched PCHC firmware
	
	return pchc_fw_ver, mn2_info[0], mn2_info[1], mn2_info[3], pchc_mn2_signed, pchc_mn2_signed_db, pchc_upd_found, pchc_platform, mn2_info[7], \
		   mn2_info[8], mn2_info[9], pchc_meu_ver
		   
# Verify CSE FTPR/OPR & stitched PCHC compatibility
def pchc_chk(pchc_mn2_signed, release, pchc_fw_major, pchc_fw_minor, pchc_platform) :
	if (variant,major,minor) in pchc_dict :
		if pchc_mn2_signed != release or (pchc_fw_major,pchc_fw_minor) not in pchc_dict[(variant,major,minor)] :
			warn_stor.append([col_m + 'Warning: Incompatible PCHC %s firmware detected!' % pchc_platform + col_e, False])
	else :
		err_stor.append([col_r + 'Error: Could not verify %s %d.%d & PCHC %s firmware compatibility!' % (variant, major, minor, pchc_platform) + col_e, True])

# Parse CSE PCHC firmware after analysis
def pchc_parse(pchc_all_init, pchc_all_anl) :
	for pchc in pchc_all_init :
		pchc_vcn,pchc_mn2_ver,pchc_ext15_info,pchc_size = pchc
		
		pchc_fw_ver,pchc_fw_major,pchc_fw_minor,pchc_fw_rel,pchc_mn2_signed,pchc_mn2_signed_db,pchc_upd_found,pchc_platform,pchc_date,pchc_svn, \
		pchc_pvbit,pchc_meu_ver = pchc_anl(pchc_mn2_ver)
		
		pchc_chk(pchc_mn2_signed, release, pchc_fw_major, pchc_fw_minor, pchc_platform)
		
		pchc_all_anl.append([pchc_fw_ver,pchc_fw_major,pchc_fw_minor,pchc_fw_rel,pchc_mn2_signed,pchc_mn2_signed_db,pchc_upd_found,pchc_platform,
							 pchc_date,pchc_svn,pchc_pvbit,pchc_meu_ver,pchc_vcn,pchc_ext15_info,pchc_size])
	
	return pchc_all_anl

# Analyze CSE PHY firmware before parsing
def phy_anl(mn2_info) :
	phy_platform = 'Unknown'
	phy_sku = 'Unknown'
	phy_upd_found = False
	
	# mn2_info = [Major, Minor, Hotfix, Build, Release, RSA Key Hash, RSA Sig Hash, Date, SVN, PV bit, MEU Major, MEU Minor, MEU Hotfix,
	# 			  MEU Build, MN2 w/o RSA Hashes, MN2 Struct, MN2 Match Start, MN2 Match End]
	
	# $MN2 Manifest SVN = CSE_Ext_0F ARBSVN. The value is used for Anti-Rollback (ARB) and not Trusted Computing Base (TCB) purposes.
	
	phy_year,phy_month,phy_day = list(map(int, mn2_info[7].split('-')))
	
	# Detect PHY Variant
	phy_variant, _, _ = get_variant(reading, mn2_info[15], mn2_info[16], mn2_info[17], mn2_info[5], [phy_year, phy_month, phy_day],
								 [mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3]])

	if not phy_variant.startswith('PHY') : phy_variant = 'Unknown'
	
	if phy_variant != 'Unknown' :
		phy_platform = phy_variant[-3:]
		phy_sku = 'G' if phy_variant.startswith('PHYDG') else phy_variant[3] # Set "G" for GSC/GFX to match regular PHY SKU naming
	
	db_year,db_month,db_day,_ = check_upd(('Latest_%s_%d' % (phy_variant, mn2_info[0])))
	if phy_year < db_year or (phy_year == db_year and (phy_month < db_month or (phy_month == db_month and phy_day < db_day))) : phy_upd_found = True
	
	phy_mn2_signed = 'Pre-Production' if mn2_info[4] == 'Debug' else 'Production'
	phy_mn2_signed_db = 'PRD' if phy_mn2_signed == 'Production' else 'PRE'
	
	# Fix Release of PRE firmware which are wrongly reported as PRD
	phy_mn2_signed, phy_mn2_signed_db = release_fix(phy_mn2_signed, phy_mn2_signed_db, mn2_info[5])
	
	phy_fw_ver = '%d.%d.%d.%0.4d' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
	phy_meu_ver = '%d.%d.%d.%0.4d' % (mn2_info[10], mn2_info[11], mn2_info[12], mn2_info[13])
	if phy_variant.startswith('PHYDG') :
		phy_name_db = '%s_%s_%s_%s_%s_%s' % (phy_platform[:3], phy_sku, phy_fw_ver, mn2_info[7], phy_mn2_signed_db, mn2_info[6])
	else :
		phy_name_db = '%s_%s_%s_%s_%s' % (phy_platform[:3], phy_sku, phy_fw_ver, phy_mn2_signed_db, mn2_info[6])
	
	# Search DB for PHY firmware
	for line in mea_db_lines :
		if phy_name_db in line :
			break # Break loop at 1st name match
	else :
		note_new_fw('PHY %s %s' % (phy_platform, phy_sku))
	
	# Detect PHY RSA Public Key Recognition
	for line in mea_db_lines :
		if mn2_info[5] in line :
			break # Break loop at 1st hash match
	else :
		err_msg = [col_r + 'Error: Unknown %s %d.%d RSA Public Key!' % (phy_variant, mn2_info[0], mn2_info[1]) + col_e, True]
		if err_msg not in err_stor : err_stor.append(err_msg) # Do not store message twice at bare/non-stitched PHY firmware
	
	return phy_fw_ver, phy_sku, phy_mn2_signed, phy_mn2_signed_db, phy_upd_found, phy_platform, mn2_info[7], mn2_info[8], mn2_info[9], phy_meu_ver, mn2_info[3]
	
# Verify CSE FTPR/OPR & stitched PHY compatibility
def phy_chk(phy_mn2_signed, release, phy_platform, phy_sku) :
	if (variant,major,minor) in phy_dict :
		if phy_mn2_signed != release or phy_sku not in phy_dict[(variant,major,minor)] :
			warn_stor.append([col_m + 'Warning: Incompatible PHY %s (%s) firmware detected!' % (phy_sku, phy_platform) + col_e, False])
	else :
		err_stor.append([col_r + 'Error: Could not verify %s %d.%d & PHY %s (%s) firmware compatibility!' % (variant, major, minor, phy_sku, phy_platform) + col_e, True])

# Parse CSE PHY firmware after analysis
def phy_parse(phy_all_init, phy_all_anl) :
	for phy in phy_all_init :
		phy_vcn,phy_mn2_ver,phy_ext15_info,phy_size = phy
		
		phy_fw_ver,phy_sku,phy_mn2_signed,phy_mn2_signed_db,phy_upd_found,phy_platform,phy_date,phy_svn,phy_pvbit,phy_meu_ver,phy_fw_rel = phy_anl(phy_mn2_ver)
		
		phy_chk(phy_mn2_signed, release, phy_platform, phy_sku)
		
		phy_all_anl.append([phy_fw_ver,phy_sku,phy_mn2_signed,phy_mn2_signed_db,phy_upd_found,phy_platform,phy_date,phy_svn,phy_pvbit,phy_meu_ver,
							phy_fw_rel,phy_vcn,phy_ext15_info,phy_size])
			
	return phy_all_anl

# CSE Huffman Dictionary Loader by "IllegalArgument" (https://github.com/IllegalArgument)
# Dictionaries by "IllegalArgument", Dmitry Sklyarov, Mark Ermolov, Maxim Goryachy & me
def cse_huffman_dictionary_load(cse_variant, cse_major, cse_minor, verbosity) :
	HUFFMAN_SHAPE = []
	HUFFMAN_SYMBOLS = {}
	HUFFMAN_UNKNOWNS = {}
	mapping_types = {'code' : 0x20, 'data' : 0x60}
	huffman_dict = os.path.join(mea_dir, 'Huffman.dat')
	
	# Message Verbosity: All | Error | None
	
	# Check if a Huffman dictionary needs to be loaded and which version is required
	if cse_variant.startswith(('CSTXE','PMC','PCHC','PHY','OROM')) or (cse_variant,cse_major) == ('CSSPS',1) : return HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS
	dict_version = 11 if (cse_variant,cse_major) in [('CSME',11),('CSSPS',4)] or (cse_variant,cse_major,cse_minor) == ('CSME',14,5) else 12
	
	# Check if supported Huffman dictionary file exists
	if not os.path.isfile(huffman_dict) :
		if verbosity in ['all','error'] :
			if param.cse_pause : input_col(col_r + '\nHuffman dictionary file is missing!' + col_e)
			else : print(col_r + '\nHuffman dictionary file is missing!' + col_e)
		
		return HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS
	
	with open(huffman_dict, 'r', encoding='utf-8') as dict_file :
		dict_json = json.load(dict_file)
		
		dict_mappings = dict_json[str(dict_version)]
		mapping_codeword_ranges = {}
		
		for mapping_type_string, mapping in dict_mappings.items() :
			mapping_type = mapping_types[mapping_type_string]
			grouped_codeword_strings = itertools.groupby(sorted(list(mapping.keys()), key=len), key=len)
			# noinspection PyTypeChecker
			grouped_codewords = {codeword_len : [int(codeword, 2) for codeword in codewords] for codeword_len, codewords in grouped_codeword_strings}
			mapping_codeword_ranges[mapping_type] = {codeword_len : (min(codewords), max(codewords)) for codeword_len, codewords in grouped_codewords.items()}
		
		if len({frozenset(x.items()) for x in mapping_codeword_ranges.values()}) > 1 and verbosity in ['all','error'] :
			if param.cse_pause : input_col(col_r + '\n    Mismatched mappings in the same dictionary' + col_e)
			else : print(col_r + '\n    Mismatched mappings in the same dictionary' + col_e)
		
		codeword_ranges = list(mapping_codeword_ranges.values())[0]
		
		for i, j in zip(list(codeword_ranges.keys())[:-1], list(codeword_ranges.keys())[1:]) :
			if 2 * codeword_ranges[i][0] - 1 != codeword_ranges[j][1] and verbosity in ['all','error'] :
				if param.cse_pause : input_col(col_r + '\n    Discontinuity between codeword lengths {0} and {1}'.format(i, j) + col_e)
				else : print(col_r + '\n    Discontinuity between codeword lengths {0} and {1}'.format(i, j) + col_e)
				
		HUFFMAN_SHAPE = [(codeword_len, codeword_min << (32 - codeword_len), codeword_max) for codeword_len, (codeword_min, codeword_max) in codeword_ranges.items()]
		
		for mapping_type_string, mapping in dict_mappings.items() :
			mapping_type = mapping_types[mapping_type_string]
			
			HUFFMAN_SYMBOLS[mapping_type] = {}
			HUFFMAN_UNKNOWNS[mapping_type] = {}
			
			for codeword_len, (codeword_min, codeword_max) in codeword_ranges.items() :
				HUFFMAN_UNKNOWNS[mapping_type][codeword_len] = set()
				HUFFMAN_SYMBOLS[mapping_type][codeword_len] = []
				
				for codeword in range(codeword_max, codeword_min - 1, -1) :
					codeword_binary = format(codeword, '0' + str(codeword_len) + 'b')
					symbol = mapping[codeword_binary].strip()
					
					if symbol == '' :
						HUFFMAN_UNKNOWNS[mapping_type][codeword_len].add(codeword)
						HUFFMAN_SYMBOLS[mapping_type][codeword_len].append([0x7F])
					elif re.match(r'^(\?\?)+$', symbol) :
						HUFFMAN_UNKNOWNS[mapping_type][codeword_len].add(codeword)
						HUFFMAN_SYMBOLS[mapping_type][codeword_len].append(list(itertools.repeat(0x7F, int(len(symbol) / 2))))
					else :
						HUFFMAN_SYMBOLS[mapping_type][codeword_len].append(list(bytes.fromhex(symbol)))
	
	return HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS
	
# CSE Huffman Decompressor by "IllegalArgument" (https://github.com/IllegalArgument)
def cse_huffman_decompress(module_contents, compressed_size, decompressed_size, HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS, verbosity) :
	CHUNK_SIZE = 0x1000
	huff_error = False
	decompressed_array = []
	
	# Message Verbosity: All | Error | None
	
	if not HUFFMAN_SHAPE : return module_contents, huff_error # Failed to load required Huffman dictionary
	
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
				compressed_position += 1
				available_bits += 8
			
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
						huff_error = True
					decompressed_array.extend(symbol)
					decompressed_position += symbol_length
				else :
					if verbosity in ['all','error'] :
						print(col_r + '\n    Skipping overflowing codeword {: <15s} (dictionary 0x{:X}, codeword length {: >2d}, codeword {: >5s}, symbol length {:d}) at decompressed offset 0x{:X}'.format(
							('{:0>' + str(codeword_length) + 'b}').format(codeword), dictionary_type, codeword_length, '0x{:X}'.format(codeword), symbol_length, decompressed_position) + col_e)
						huff_error = True
					filler = itertools.repeat(0x7F, decompressed_limit - decompressed_position)
					decompressed_array.extend(filler)
					decompressed_position = decompressed_limit
			else :
				if verbosity in ['all','error'] :
					print(col_r + '\n    Reached end of compressed stream early at decompressed offset 0x{:X}'.format(decompressed_position) + col_e)
					huff_error = True
				filler = itertools.repeat(0x7F, decompressed_limit - decompressed_position)
				decompressed_array.extend(filler)
				decompressed_position = decompressed_limit
				
	return bytearray(decompressed_array), huff_error
	
# Detect CSE Partition Instance Identifier
def cse_part_inid(buffer, cpd_offset, ext_dictionary) :
	cpd_hdr_struct, cpd_hdr_size = get_cpd(buffer, cpd_offset)
	cpd_hdr = get_struct(buffer, cpd_offset, cpd_hdr_struct)
	cse_in_id = 0
	in_id_step = 0
	in_id_stop = 0
	cse_part_size = 0
	cse_part_name = ''
	
	if cpd_hdr.Tag == b'$CPD' : # Sanity check
		mn2_start = cpd_offset + cpd_hdr_size + cpd_entry_num_fix(buffer, cpd_offset, cpd_hdr.NumModules, cpd_hdr_size) * 0x18
		
		mn2_hdr = get_struct(buffer, mn2_start, get_manifest(buffer, mn2_start))
		
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
def cpd_entry_num_fix(buffer, cpd_offset, cpd_entry_count, cpd_hdr_size) :
	cpd_entry_empty = 0
	cpd_entry_end = cpd_offset + cpd_hdr_size + cpd_entry_count * 0x18
	
	# Some $CPD may have X entries + empty Y. Try to adjust counter a maximum of 5 times (GREAT WORK INTEL/OEMs...)
	while int.from_bytes(buffer[cpd_entry_end:cpd_entry_end + 0x18], 'little') == 0 :
		cpd_entry_end += 0x18
		cpd_entry_empty += 1
		if cpd_entry_empty > 5 :
			err_stor.append([col_r + 'Error: Failed to fix $CPD entry counter at 0x%X!' % cpd_offset + col_e, True])
			break
		
	return cpd_entry_count + cpd_entry_empty
	
# Calculate $CPD Partition size via its Entries
def cpd_size_calc(buffer, cpd_offset, align_size) :
	cpd_fw_end = 0
	cpd_offset_last = 0
	
	cpd_hdr_struct, cpd_hdr_size = get_cpd(buffer, cpd_offset)
	cpd_hdr = get_struct(buffer, cpd_offset, cpd_hdr_struct)
	cpd_num = cpd_entry_num_fix(buffer, cpd_offset, cpd_hdr.NumModules, cpd_hdr_size)
	
	for entry in range(cpd_num) : # Check all $CPD Entry Sizes (Manifest, Metadata, Modules)
		cpd_entry_hdr = get_struct(buffer, cpd_offset + cpd_hdr_size + entry * 0x18, CPD_Entry)
		cpd_entry_offset,_,_ = cpd_entry_hdr.get_flags()
		
		# Store last entry (max $CPD offset)
		if cpd_entry_offset > cpd_offset_last :
			cpd_offset_last = cpd_entry_offset
			cpd_fw_end = cpd_entry_offset + cpd_entry_hdr.Size
		
	cpd_align = (cpd_fw_end - cpd_offset) % align_size
	cpd_fw_end = cpd_fw_end + align_size - cpd_align
	
	return cpd_fw_end
	
# Validate $CPD Checksum
def cpd_chk(cpd_data, variant, major) :
	cpd_hdr_struct, _ = get_cpd(cpd_data, 0)
	
	if cpd_hdr_struct.__name__ == 'CPD_Header_R1' :
		cpd_chk_file = cpd_data[0xB]
		cpd_sum = sum(cpd_data) - cpd_chk_file
		cpd_chk_calc = (0x100 - cpd_sum & 0xFF) & 0xFF
	elif cpd_hdr_struct.__name__ == 'CPD_Header_R2' :
		cpd_chk_file = int.from_bytes(cpd_data[0x10:0x14], 'little')
		cpd_chk_calc = crccheck.crc.Crc32.calc(cpd_data[:0x10] + b'\x00' * 4 + cpd_data[0x14:])
	else :
		cpd_chk_file = int.from_bytes(cpd_data[0x10:0x14], 'little')
		cpd_chk_calc = crccheck.crc.Crc32.calc(cpd_data[:0x10] + b'\x00' * 4 + cpd_data[0x14:])
	
	# Store $CPD Checksum Values to check if they exist in the known bad CSE Hashes/Checksums list
	cpd_chk_rslt = ['$CPD_%s_%d_0x%0.8X' % (variant,major,cpd_chk_file),'$CPD_%s_%d_0x%0.8X' % (variant,major,cpd_chk_calc)]
	
	return cpd_chk_file == cpd_chk_calc, cpd_chk_file, cpd_chk_calc, cpd_chk_rslt

# Check CSE/GSC IUP firmware size
def chk_iup_size(eng_size_text, file_end, eng_fw_end, variant_p, platform) :
	if eng_fw_end > file_end :
		eng_size_text = [col_m + 'Warning: %s %s Firmware size exceeds File, possible data loss!' % (variant_p, platform) + col_e, True]
	elif eng_fw_end < file_end :
		padd_size_iup = file_end - eng_fw_end
		
		if reading[eng_fw_end:file_end] == padd_size_iup * b'\xFF' :
			eng_size_text = [col_y + 'Note: File has harmless unneeded %s %s Firmware end padding!' % (variant_p, platform) + col_e, False] # warn_stor
			if param.check : # Remove unneeded padding, when applicable (Debug/Research)
				with open('__RPADD__' + os.path.basename(file_in), 'wb') as o : o.write(reading[:-padd_size_iup])
		else :
			eng_size_text = [col_m + 'Warning: File size exceeds %s %s Firmware, data in padding!' % (variant_p, platform) + col_e, True]
	
	return eng_size_text

# Get Engine/Graphics/Independent Manifest Structure
def get_manifest(buffer, offset) :
	man_ver = int.from_bytes(buffer[offset + 0x8:offset + 0xC], 'little') # $MAN/$MN2 Version Tag
	num_info = int.from_bytes(buffer[offset + 0x20:offset + 0x24], 'little') # $MAN/$MN2 NumModules/BuildTag
	
	if man_ver == 0x10000 and (0x0 < num_info < 0x50) : return MN2_Manifest_R0
	if man_ver == 0x10000 : return MN2_Manifest_R1
	if man_ver == 0x21000 : return MN2_Manifest_R2
	
	return MN2_Manifest_R2
	
# Get Flash Partition Table Structure
def get_fpt(buffer, offset) :
	fpt_ver = buffer[offset + 0x8] # $FPT Version Tag
	fpt_crc = buffer[offset + 0x16:offset + 0x18] # $FPT v2.1 2nd word of CRC-32 for FIT Bug (v2.1 with v2.0 Version Tag)
	
	if fpt_ver == 0x21 : return FPT_Header_21, fpt_ver
	if fpt_ver == 0x20 and fpt_crc not in [b'\x00\x00',b'\xFF\xFF'] : return FPT_Header_21, 0x21
	if fpt_ver in (0x10,0x20) : return FPT_Header, fpt_ver
	
	return FPT_Header_21, fpt_ver
	
# Get Code Partition Directory Structure
def get_cpd(buffer, offset) :
	cpd_ver = buffer[offset + 0x8] # $CPD Version Tag
	
	if cpd_ver == 1 : return CPD_Header_R1, ctypes.sizeof(CPD_Header_R1)
	if cpd_ver == 2 : return CPD_Header_R2, ctypes.sizeof(CPD_Header_R2)
	
	return CPD_Header_R2, ctypes.sizeof(CPD_Header_R2)
	
# Get Code Partition Directory Structure
def get_bpdt(buffer, offset) :
	bpdt_ver = buffer[offset + 0x6] # BPDT Version Tag
	
	if bpdt_ver == 1 : return BPDT_Header_1
	if bpdt_ver == 2 : return BPDT_Header_2
	
	return BPDT_Header_2
	
# Get RBEP > rbe and/or FTPR > pm Module "Metadata"
def get_rbe_pm_met(rbe_pm_data_d, rbe_pm_met_hashes) :
	rbe_pm_patt_256_1 = re.compile(br'\x86\x80.{70}\x86\x80.{70}\x86\x80', re.DOTALL).search(rbe_pm_data_d) # Find SHA-256 "Metadata" pattern 1
	rbe_pm_patt_256_2 = re.compile(br'\x86\x80.{46}\x86\x80.{46}\x86\x80', re.DOTALL).search(rbe_pm_data_d) # Find SHA-256 "Metadata" pattern 2
	rbe_pm_patt_384_1 = re.compile(br'\x86\x80.{86}\x86\x80.{86}\x86\x80', re.DOTALL).search(rbe_pm_data_d) # Find SHA-384 "Metadata" pattern 1
	rbe_pm_patt_384_2 = re.compile(br'\x86\x80.{62}\x86\x80.{62}\x86\x80', re.DOTALL).search(rbe_pm_data_d) # Find SHA-384 "Metadata" pattern 2
	
	if rbe_pm_patt_256_1 :
		rbe_pm_patt_start = rbe_pm_patt_256_1.start()
		rbe_pm_struct_name = RBE_PM_Metadata
		rbe_pm_struct_size = ctypes.sizeof(RBE_PM_Metadata)
	elif rbe_pm_patt_256_2 :
		rbe_pm_patt_start = rbe_pm_patt_256_2.start()
		rbe_pm_struct_name = RBE_PM_Metadata_R2
		rbe_pm_struct_size = ctypes.sizeof(RBE_PM_Metadata_R2)
	elif rbe_pm_patt_384_1 :
		rbe_pm_patt_start = rbe_pm_patt_384_1.start()
		rbe_pm_struct_name = RBE_PM_Metadata_R3
		rbe_pm_struct_size = ctypes.sizeof(RBE_PM_Metadata_R3)
	elif rbe_pm_patt_384_2 :
		rbe_pm_patt_start = rbe_pm_patt_384_2.start()
		rbe_pm_struct_name = RBE_PM_Metadata_R4
		rbe_pm_struct_size = ctypes.sizeof(RBE_PM_Metadata_R4)
	else :
		return rbe_pm_met_hashes
	
	rbe_pm_met_start = rbe_pm_patt_start - 0x6 # "Metadata" entry starts 0x6 before VEN_ID 8086
	rbe_pm_met_end = rbe_pm_met_start # Initialize "Metadata" entries end
	while rbe_pm_data_d[rbe_pm_met_end + 0x6:rbe_pm_met_end + 0x8] == b'\x86\x80' : rbe_pm_met_end += rbe_pm_struct_size # Find end of "Metadata" entries
	rbe_pm_met_data = bytes(rbe_pm_data_d[rbe_pm_met_start:rbe_pm_met_end]) # Store "Metadata" entries
	rbe_pm_met_count = divmod(len(rbe_pm_met_data), rbe_pm_struct_size)[0] # Count "Metadata" entries
	
	for i in range(rbe_pm_met_count) :
		rbe_pm_met = get_struct(rbe_pm_met_data, i * rbe_pm_struct_size, rbe_pm_struct_name) # Parse "Metadata" entries
		rbe_pm_met_hash_len = len(rbe_pm_met.Hash) * 4 # Get "Metadata" entry Hash Length
		rbe_pm_met_hash = '%0.*X' % (rbe_pm_met_hash_len * 2, int.from_bytes(rbe_pm_met.Hash, 'little')) # Get "Metadata" entry Hash
		rbe_pm_met_hashes.append(rbe_pm_met_hash) # Store each "Metadata" entry Hash for Modules w/o Metadata Hash validation
	
	return rbe_pm_met_hashes

# https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
def get_struct(input_stream, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = input_stream[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= file_end) or (fit_len < struct_len) :
		err_stor.append([col_r + 'Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name.__name__) + col_e, True])
		
		for error in err_stor : print('\n' + error[0])
		
		copy_on_msg(err_stor + warn_stor + note_stor) # Close input and copy it in case of messages
		
		mea_exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure
	
# https://stackoverflow.com/a/34301571 by Sam P
# noinspection PyProtectedMember
def struct_json(structure) :
	result = {}
	
	def get_value(value) :
		if (type(value) not in [int, float, bool, str]) and not bool(value) :
			value = None # Null Pointer (not primitive type, is False)
		elif hasattr(value, '_length_') and hasattr(value, '_type_') :
			value = get_array(value) # Probably an Array
		elif isinstance(value, (bytes, bytearray)) :
			value = value.decode('utf-8') # Byte
		elif hasattr(value, '_fields_') :
			value = struct_json(value) # Probably nested struct
		
		return value
	
	def get_array(array) :
		ar = []
		for value in array :
			value = get_value(value)
			ar.append(value)
		
		return ar
	
	for field in structure._fields_ :
		value = get_value(getattr(structure, field[0]))
		result[field[0]] = value
	
	return json.dumps(result, indent=4)

# Initialize PLTable
def ext_table(row_col_names, header, padd) :
	pt = pltable.PrettyTable(row_col_names)
	pt.set_style(pltable.UNICODE_LINES)
	pt.xhtml = True
	pt.header = header # Boolean
	pt.left_padding_width = padd
	pt.right_padding_width = padd
	pt.hrules = pltable.ALL
	pt.vrules = pltable.ALL
	
	return pt
	
# Convert PLTable Object to HTML String
def pt_html(pt_obj) :
	return ansi_escape.sub('', str(pt_obj.get_html_string(format=True, attributes={})))
	
# Convert PLTable Object to JSON Dictionary
def pt_json(pt_obj) :
	return json.dumps(pt_obj.get_json_dict(re_pattern=ansi_escape), indent=4)
	
# Detect DB Revision
def mea_hdr_init() :
	mea_db_rev = 'Unknown'
	mea_db_rev_p = col_r + mea_db_rev + col_e
	
	for line in mea_db_lines :
		if 'Revision' in line :
			mea_db_list = line.split()
			if len(mea_db_list) >= 3 :
				mea_db_rev = mea_db_list[2]
				mea_db_rev_p = col_y + mea_db_rev + col_e
			
			break # Revision line found, skip rest of DB
	
	return mea_db_rev, mea_db_rev_p

# Print MEA Header
def mea_hdr(mea_db_rev_p) :
	hdr_pt = ext_table([], False, 1)
	hdr_pt.add_row([col_y + '        %s' % title + col_e + ' %s        ' % mea_db_rev_p])
	
	print(hdr_pt)

# https://stackoverflow.com/a/22881871 by jfs
def get_script_dir(follow_symlinks=True) :
	if getattr(sys, 'frozen', False) :
		path = os.path.abspath(sys.executable)
	else :
		path = inspect.getabsfile(get_script_dir)
	if follow_symlinks :
		path = os.path.realpath(path)

	return os.path.dirname(path)

# https://stackoverflow.com/a/781074 by Torsten Marek
def show_exception_and_exit(exc_type, exc_value, tb) :
	if exc_type is KeyboardInterrupt :
		print('\n')
	else :
		print(col_r + '\nError: %s crashed, please report the following:\n' % title)
		traceback.print_exception(exc_type, exc_value, tb)
		print(col_e)
	
	mea_exit(1)

# Execute final actions
def mea_exit(code) :
	try :
		# Before exiting, print output of MEA & DB update check Thread, if completed/dead
		if not thread_update.is_alive() and thread_update.result : print(thread_update.result)
	except :
		pass
	
	colorama.deinit() # Stop Colorama
	
	if not param.skip_pause : input('\nPress enter to exit')
	
	sys.exit(code)
	
# Input Colorama Workaround (Windows, Python 3.5+)
# https://github.com/tartley/colorama/issues/103#issuecomment-629816451
def input_col(message) :
	print(message, end = '')
	input()

# Calculate MD5 hash of data
def md5(data) :
	return hashlib.md5(data).hexdigest().upper()
	
# Calculate SHA-1 hash of data
def sha_1(data) :
	return hashlib.sha1(data).hexdigest().upper()
	
# Calculate SHA-256 hash of data
def sha_256(data) :
	return hashlib.sha256(data).hexdigest().upper()
	
# Calculate SHA-384 hash of data
def sha_384(data) :
	return hashlib.sha384(data).hexdigest().upper()

# Get Hash of data, digest size based
def get_hash(data, hash_size) :
	if hash_size == 0x10 : return md5(data)
	if hash_size == 0x14 : return sha_1(data)
	if hash_size == 0x20 : return sha_256(data)
	if hash_size == 0x30 : return sha_384(data)
	
	return sha_384(data)
	
# Validate CPU Microcode Checksum
def mc_chk32(data) :
	chk32 = 0
	
	for idx in range(0, len(data), 4) : # Move 4 bytes at a time
		chkbt = int.from_bytes(data[idx:idx + 4], 'little') # Convert to int, MSB at the end (LE)
		chk32 += chkbt
	
	return -chk32 & 0xFFFFFFFF # Return 0
	
# Copy input file if there are worthy Notes, Warnings or Errors
# Must be called at the end of analysis to gather any generated messages
def copy_on_msg(msg_all) :
	copy = False
	
	# Detect if any copy-worthy generated message exists
	for message in msg_all :
		if message[1] : copy = True
	
	if param.bypass and (err_stor or warn_stor or note_stor) : copy = True # Copy on any message (Debug/Research)
	
	# At least one message needs a file copy
	if copy :
		file_name = os.path.basename(file_in)
		check_dir = os.path.join(mea_dir, '__CHECK__', '')
		check_name = os.path.join(check_dir, file_name)
		
		if not os.path.isdir(check_dir) : os.mkdir(check_dir)
		
		# Check if same file already exists
		if os.path.isfile(check_name) :
			with open(file_in, 'rb') as input_file : input_sha1 = sha_1(input_file.read())
			with open(check_name, 'rb') as same_file : same_sha1 = sha_1(same_file.read())
			if input_sha1 == same_sha1 : return
			
			check_name += '_%d' % cur_count
		
		shutil.copyfile(file_in, check_name)

# Store/Show new firmware Note
def note_new_fw(variant_p) :
	note_stor.append([col_g + 'Note: This %s firmware is not in the database! You can help this project by\
	\n      quickly uploading it to https://mega.nz/megadrop/kgyWLLA10WY/. Thank you!' % variant_p + col_e, True])

# Check DB for latest version
def check_upd(key) :
	upd_key_found = False
	vlp = [0]*4
	
	for line in mea_db_lines :
		if key in line :
			upd_key_found = True
			wlp = line.strip().split('__') # whole line parts
			vlp = wlp[1].strip().split('.') # version line parts
			for i in range(len(vlp)) :
				# noinspection PyTypeChecker
				vlp[i] = int(vlp[i])
			break
	
	if upd_key_found : return vlp[0],vlp[1],vlp[2],vlp[3]
	
	return 0,0,0,0

# Get JSON Structure from DB
def get_db_json_obj(obj_name) :
	obj_bgn = mea_db_read.find(obj_name + '*BGN')
	obj_end = mea_db_read.find(obj_name + '*END')
	
	if obj_bgn == -1 or obj_end == -1 or obj_bgn >= obj_end : return None
	
	obj_data = mea_db_read[obj_bgn + len(obj_name + '*BGN'):obj_end]
	
	obj_data = ''.join([line.split(' # ')[0] for line in obj_data.split('\n')])
	
	return json.loads(obj_data)

# Detect Intel Flash Descriptor (FD)
def fd_anl_init(reading, file_end, start_man_match, end_man_match) :
	fd_match = list(fd_pat.finditer(reading)) # Flash Descriptor Pattern Match/Iteration ranges
	fd_count = len(fd_match) # Flash Descriptor Pattern Count
	reading_msg = '' # Input buffer new Flash Descriptor range message
	
	if not fd_match : return False, reading, file_end, start_man_match, end_man_match, 0, 0, 0, 0, False, False, reading_msg
	
	# Detected Flash Descriptor, use first but notify if more exist
	fd_start = fd_match[0].start()
	fd_end = fd_match[0].end()
	
	fd_flmap0_fcba = reading[fd_start + 0x4] * 0x10 # Component Base Address from FD start (ICH8-ICH10 = 1, IBX = 2, CPT+ = 3)
	
	# I/O Controller Hub (ICH)
	if fd_flmap0_fcba == 0x10 :
		fd_is_ich = True
		start_substruct = 0x0 # At ICH, Flash Descriptor starts at 0x0
		end_substruct = 0xBC # 0xBC for [0xAC] + 0xFF * 16 sanity check
	# Platform Controller Hub (PCH)
	else :
		fd_is_ich = False
		start_substruct = 0x10 # At PCH, Flash Descriptor starts at 0x10
		end_substruct = 0xBC # 0xBC for [0xAC] + 0xFF * 16 sanity check
	
	start_fd_match = fd_start - start_substruct # Flash Descriptor pattern Start Offset
	end_fd_match = fd_end - end_substruct # Flash Descriptor pattern End Offset
	
	# Calculate Flash Descriptor Flash Component Total Size
	fd_flmap0_nc = ((int.from_bytes(reading[end_fd_match:end_fd_match + 0x4], 'little') >> 8) & 3) + 1 # Component Count (00 = 1, 01 = 2)
	fd_flmap1_isl = reading[end_fd_match + 0x7] # PCH/ICH Strap Length (ME 2-8 & TXE 0-2 & SPS 1-2 <= 0x12, ME 9+ & TXE 3+ & SPS 3+ >= 0x13)
	fd_comp_den = reading[start_fd_match + fd_flmap0_fcba] # Component Density Byte (ME 2-8 & TXE 0-2 & SPS 1-2 = 0:5, ME 9+ & TXE 3+ & SPS 3+ = 0:7)
	fd_comp_1_bitwise = 0xF if fd_flmap1_isl >= 0x13 else 0x7 # Component 1 Density Bits (ME 2-8 & TXE 0-2 & SPS 1-2 = 3, ME 9+ & TXE 3+ & SPS 3+ = 4)
	fd_comp_2_bitwise = 0x4 if fd_flmap1_isl >= 0x13 else 0x3 # Component 2 Density Bits (ME 2-8 & TXE 0-2 & SPS 1-2 = 3, ME 9+ & TXE 3+ & SPS 3+ = 4)
	fd_comp_all_size = comp_dict[fd_comp_den & fd_comp_1_bitwise] # Component 1 Density (FCBA > C0DEN)
	if fd_flmap0_nc == 2 : fd_comp_all_size += comp_dict[fd_comp_den >> fd_comp_2_bitwise] # Component 2 Density (FCBA > C1DEN)
	
	# Update input file RAM buffer (reading) based on the actual Flash Descriptor Flash Component Total Size
	# Do not update reading if the initially detected Manifest pattern is outside the FD Component Total Data
	# Do not update reading if the input file starts with Download & Execute (DnX) $CPD RCIP Partition
	if start_man_match and (start_fd_match < start_man_match < start_fd_match + fd_comp_all_size) and file_end != fd_comp_all_size \
	and not (reading[0x0:0x4] == b'$CPD' and reading[0xC:0x10] == b'RCIP') :
		reading = reading[start_fd_match:start_fd_match + fd_comp_all_size] # Update input file buffer in RAM
		reading_msg = col_y + 'Note: Adjusted buffer to Flash Descriptor 0x%X - 0x%X!' % (start_fd_match,start_fd_match + fd_comp_all_size) + col_e
		note_stor.append([reading_msg, False]) # Inform user of the new input buffer FD range
		file_end = fd_comp_all_size # Update input file RAM buffer length, same as FD Flash Component Total Size
		start_man_match -= start_fd_match # Update Manifest Pattern Start Offset (before FD)
		end_man_match -= start_fd_match # Update Manifest Pattern End Offset (before FD)
		start_fd_match,end_fd_match = (0x0,0x4) if fd_is_ich else (0x0,0x14) # Update FD Pattern Start & End Offsets (after Manifest)
	
	# Do not notify for OEM Backup Flash Descriptors within the chosen/first Flash Descriptor
	for match in fd_match[1:] :
		if fd_start < match.start() <= fd_start + 0x1000 : fd_count -= 1
	
	# Check if the Flash Descriptor Flash Component Total Size fits within the input file
	fd_input_size = len(reading[start_fd_match:start_fd_match + fd_comp_all_size])
	if fd_input_size != fd_comp_all_size and not file_in.endswith('.scap') :
		fd_is_cut = True
		err_stor.append([col_r + 'Error: Firmware is incomplete/corrupted, expected 0x%X not 0x%X!' % (fd_comp_all_size, fd_input_size) + col_e, False])
	else :
		fd_is_cut = False
	
	return True, reading, file_end, start_man_match, end_man_match, start_fd_match, end_fd_match, fd_count, fd_comp_all_size, fd_is_ich, fd_is_cut, reading_msg

# Analyze Intel Flash Descriptor (FD) Regions
def fd_anl_rgn(start_fd_match, end_fd_match, fd_is_ich) :
	fd_reg_exist = [] # BIOS/IAFW + Engine/Graphics
	
	fd_rgn_base = end_fd_match + 0x3C if fd_is_ich else end_fd_match + 0x2C
	
	bios_fd_base = int.from_bytes(reading[fd_rgn_base + 0x4:fd_rgn_base + 0x6], 'little')
	bios_fd_limit = int.from_bytes(reading[fd_rgn_base + 0x6:fd_rgn_base + 0x8], 'little')
	me_fd_base = int.from_bytes(reading[fd_rgn_base + 0x8:fd_rgn_base + 0xA], 'little')
	me_fd_limit = int.from_bytes(reading[fd_rgn_base + 0xA:fd_rgn_base + 0x0C], 'little')
	pdr_fd_base = int.from_bytes(reading[fd_rgn_base + 0x10:fd_rgn_base + 0x12], 'little')
	pdr_fd_limit = int.from_bytes(reading[fd_rgn_base + 0x12:fd_rgn_base + 0x14], 'little')
	devexp_fd_base = int.from_bytes(reading[fd_rgn_base + 0x14:fd_rgn_base + 0x16], 'little')
	devexp_fd_limit = int.from_bytes(reading[fd_rgn_base + 0x16:fd_rgn_base + 0x18], 'little')
	
	if bios_fd_limit != 0 :
		bios_fd_start = bios_fd_base * 0x1000 + start_fd_match # fd_match required in case FD is not at the start of image
		bios_fd_size = (bios_fd_limit + 1 - bios_fd_base) * 0x1000 # The +1 is required to include last Region byte
		bios_fd_exist = bios_fd_start < file_end # Basic check that Region Start Offset is valid
		fd_reg_exist.extend((bios_fd_exist,bios_fd_start,bios_fd_size)) # BIOS/IAFW Region exists
	else :
		fd_reg_exist.extend((False,0,0)) # BIOS/IAFW Region missing
	
	if me_fd_limit != 0 :
		me_fd_start = me_fd_base * 0x1000 + start_fd_match
		me_fd_size = (me_fd_limit + 1 - me_fd_base) * 0x1000
		me_fd_exist = me_fd_start < file_end
		fd_reg_exist.extend((me_fd_exist,me_fd_start,me_fd_size)) # Engine/Graphics Region exists
	else :
		fd_reg_exist.extend((False,0,0)) # Engine/Graphics Region missing
	
	if pdr_fd_limit != 0 :
		pdr_fd_start = pdr_fd_base * 0x1000 + start_fd_match
		pdr_fd_size = (pdr_fd_limit + 1 - pdr_fd_base) * 0x1000
		pdr_fd_exist = pdr_fd_start < file_end
		fd_reg_exist.extend((pdr_fd_exist,pdr_fd_start,pdr_fd_size)) # Platform Data Region exists
	else :
		fd_reg_exist.extend((False,0,0)) # Engine/Graphics Region missing
	
	if devexp_fd_limit != 0 :
		devexp_fd_start = devexp_fd_base * 0x1000 + start_fd_match
		devexp_fd_size = (devexp_fd_limit + 1 - devexp_fd_base) * 0x1000
		devexp_fd_exist = devexp_fd_start < file_end
		fd_reg_exist.extend((devexp_fd_exist,devexp_fd_start,devexp_fd_size)) # Device Expansion Region exists
	else :
		fd_reg_exist.extend((False,0,0)) # Device Expansion Region missing
	
	return fd_reg_exist
	
# Format firmware version based on Variant
def get_fw_ver(variant, major, minor, hotfix, build) :
	if variant in ['SPS','CSSPS'] :
		version = '%s.%s.%s.%s' % ('{0:02d}'.format(major), '{0:02d}'.format(minor), '{0:02d}'.format(hotfix), '{0:03d}'.format(build)) # xx.xx.xx.xxx
	elif variant.startswith(('PMCAPL','PMCBXT','PMCGLK','PMCDG')) :
		version = '%s.%s.%s.%s' % (major, minor, hotfix, build)
	elif variant.startswith(('PMCCNP','PMCWTL')) and (major < 30 or major == 3232) :
		version = '%s.%s.%s.%s' % ('{0:02d}'.format(major), minor, hotfix, build)
	elif variant.startswith('PMC') :
		version = '%s.%s.%s.%s' % (major, minor, '{0:02d}'.format(hotfix), build)
	elif variant.startswith('PCHC') :
		version = '%s.%s.%s.%s' % (major, minor, hotfix, '{0:04d}'.format(build))
	elif variant.startswith('PHY') :
		version = '%s.%s.%s.%s' % (major, minor, hotfix, '{0:04d}'.format(build))
	else :
		version = '%s.%s.%s.%s' % (major, minor, hotfix, build)
	
	return version
	
# Check if Fixed Offset Variables (FOVD/NVKR) Partition is dirty
def fovd_clean(fovdtype) :	
	for part in fpt_part_all :
		if (fovdtype,part[0]) in [('new','FOVD'),('old','NVKR')] :
			if part[6] : return True # Empty = Clean
			
			if fovdtype == 'new' : return False # Non-Empty = Dirty
			
			if fovdtype == 'old' :
				nvkr_size = int.from_bytes(reading[part[1] + 0x19:part[1] + 0x1C], 'little')
				nvkr_data = reading[part[1] + 0x1C:part[1] + 0x1C + nvkr_size]
				
				return bool(nvkr_data == b'\xFF' * nvkr_size)
			
			break # FOVD/NVKR Partition found, skip the rest
	
	return True
	
# Calculate Hash Hex Digest of Message
def calc_hash_hex(message, hash_func) :
	msg_hash = hash_func()
	msg_hash.update(message)
	
	return msg_hash.hexdigest()
	
# Calculate Hash Digest of Message
def calc_hash(message, hash_func) :
	msg_hash = hash_func()
	msg_hash.update(message)
	
	return msg_hash.digest()

# SSA-PSS Mask Generation Function
def pss_mgf(seed, mask_len, hash_func) :
	mask = b''
	
	hash_len = hash_func().digest_size
	if mask_len > (hash_len << 32) : return '' # Mask length is invalid
	
	for i in range(-(-mask_len // hash_len)) : # math.ceil(x/y) = -(-x//y)
		mask += calc_hash(seed + i.to_bytes(4, 'big'), hash_func)
	
	return mask

# Apply SSA-PSS Mask to DB
def unmask_DB(masked_DB, mask) :
	return bytes([a ^ b for (a,b) in zip(masked_DB, mask[:len(masked_DB)])])

# Get SSA-PSS Hash & Mask DB
def parseSign(em_sign, hash_func) :
	TF = 0xBC
	
	digest_size = hash_func().digest_size
	sign = bytes.fromhex(em_sign)
	sig_hash = sign[-digest_size - 1:-1]
	if sign[-1] != TF : return '', None # TF is invalid
	masked_DB = sign[0:-digest_size - 1]
	
	return sig_hash, masked_DB

# Get SSA-PSS Salt from DB
def get_salt(unmasked_DB, mod_size) :
	PADDING_BYTE = b'\x00'
	SEPARATOR = b'\x01'
	
	z_bits = 8 - (mod_size - 1) % 8
	z_byte = unmasked_DB[0]
	for i in range(z_bits) :
		z_byte &= ~(0x80 >> i)
	
	index = unmasked_DB.find(SEPARATOR)
	if (index == -1) or (z_byte != 0) or (unmasked_DB[1:index] != PADDING_BYTE * (index-1)) : return '' # Invalid padding
	
	return unmasked_DB[index + 1:]

# Final SSA-PSS Signature validation
def pss_final_validate(message, salt_unmask, hash_func) :
	PADDING_BYTE = b'\x00'
	SALT_PADDING_COUNT = 8
	
	# Calculate hash of the message
	message_hash = calc_hash(message, hash_func)
	M_salt = PADDING_BYTE * SALT_PADDING_COUNT + message_hash + salt_unmask
	
	return calc_hash(M_salt, hash_func)

# Verify SSA-PSS Signature
def pss_verify(em_sign, message, sign_len, hash_func) :
	# Extract hash and Mask DB
	sig_hash, masked_DB = parseSign(em_sign, hash_func)
	if sig_hash == '' : return '', None
	
	# Calculate a mask
	mask = pss_mgf(sig_hash, len(masked_DB), hash_func)
	if mask == '' : return sig_hash, ''
	
	# Apply mask to DB
	unmasked_DB = unmask_DB(masked_DB, mask)
	
	# Extract salt from DB
	salt_unmask = get_salt(unmasked_DB, sign_len)
	if salt_unmask == '' : return sig_hash, ''
	
	return sig_hash, pss_final_validate(message, salt_unmask, hash_func)
	
# Validate Manifest RSA Signature
def rsa_sig_val(man_hdr_struct, buffer, check_start) :
	man_tag = man_hdr_struct.Tag.decode('utf-8')
	man_size = man_hdr_struct.Size * 4
	man_hdr_size = man_hdr_struct.HeaderLength * 4
	man_key_size = man_hdr_struct.PublicKeySize * 4
	man_pexp = man_hdr_struct.RSAExponent
	man_pkey = int.from_bytes(man_hdr_struct.RSAPublicKey, 'little')
	man_sign = int.from_bytes(man_hdr_struct.RSASignature, 'little')
	hash_data = buffer[check_start:check_start + 0x80] # First 0x80 before RSA block
	hash_data += buffer[check_start + man_hdr_size:check_start + man_size] # Manifest protected data
	
	# return [RSA Sig isValid, RSA Sig Decr Hash, RSA Sig Data Hash, RSA Validation isCrashed, $MN2 Offset, $MN2 Struct Object]
	
	try :
		dec_sign = '%0.*X' % (man_key_size * 2, pow(man_sign, man_pexp, man_pkey)) # Decrypted Signature
		
		if (man_tag,man_key_size) == ('$MAN',0x100) : # SHA-1
			rsa_hash = calc_hash_hex(hash_data, hashlib.sha1).upper()
			dec_hash = dec_sign[-40:] # 160-bit
		elif (man_tag,man_key_size) == ('$MN2',0x100) : # SHA-256
			rsa_hash = calc_hash_hex(hash_data, hashlib.sha256).upper()
			dec_hash = dec_sign[-64:] # 256-bit
		elif (man_tag,man_key_size) == ('$MN2',0x180) : # SHA-384
			rsa_hash, dec_hash = pss_verify(dec_sign, hash_data, 0x180, hashlib.sha384)
			rsa_hash, dec_hash = rsa_hash.hex().upper(), dec_hash.hex().upper()
		else :
			rsa_hash, dec_hash = pss_verify(dec_sign, hash_data, 0x180, hashlib.sha384)
			rsa_hash, dec_hash = rsa_hash.hex().upper(), dec_hash.hex().upper()
		
		return [dec_hash == rsa_hash, dec_hash, rsa_hash, False, check_start, man_hdr_struct] # RSA block validation check OK
	except :
		if (man_pexp,man_pkey,man_sign) == (0,0,0) : return [True, 0, 0, False, check_start, man_hdr_struct] # Valid/Empty RSA block, no validation crash
		
		return [False, 0, 0, True, check_start, man_hdr_struct] # RSA block validation check crashed, debugging required
	
# Fix early PRE firmware which are wrongly reported as PRD
def release_fix(release, rel_db, rsa_key_hash) :
	if release == 'Production' and rsa_key_hash in rsa_pre_keys :
		release = 'Pre-Production'
		rel_db = 'PRE'
	
	return release, rel_db
	
# Search DB for manual CSE SKU values
def get_cse_db(variant) :
	db_sku_chk = 'NaN'
	sku = 'NaN'
	sku_stp = 'Unknown'
	sku_pdm = 'UPDM'
	
	for line in mea_db_lines :
		if rsa_sig_hash in line :
			line_parts = line.strip().split('_')
			
			if variant == 'CSME' :
				db_sku_chk = line_parts[2] # Store the SKU from DB for latter use
				sku = sku_init + " " + line_parts[2] # Cell 2 is SKU
				if line_parts[3] not in ('X','XX') : sku_stp = line_parts[3] # Cell 3 is PCH/SoC Stepping
				if 'YPDM' in line_parts[4] or 'NPDM' in line_parts[4] or 'UPDM' in line_parts[4] : sku_pdm = line_parts[4] # Cell 4 is PDM
			elif variant == 'CSTXE' :
				if line_parts[1] not in ('X','XX') : sku_stp = line_parts[1] # Cell 1 is PCH/SoC Stepping
			elif variant == 'CSSPS' :
				if line_parts[-1] == 'EXTR' and line_parts[3] not in ('X','XX') : sku_stp = line_parts[3] # Cell 3 is PCH/SoC Stepping
			
			break # Break loop at 1st rsa_sig_hash match

	return db_sku_chk, sku, sku_stp, sku_pdm

# Get CSME 12+ Final SKU, SKU Platform, SKU Stepping
def get_csme12_sku(sku_init, fw_0C_sku0, fw_0C_sku2, sku, sku_result, sku_stp, db_sku_chk, pos_sku_tbl, pch_init_final) :
	if (variant,major) == ('CSME',11) : return sku, sku_result, sku_stp # CSME 11 has its own SKU Platform retrieval methodology
	
	if sku != 'NaN' :
		sku_result = db_sku_chk # SKU Platform retrieved from DB (Override)
	elif pos_sku_tbl != 'Unknown' :
		sku_result = pos_sku_tbl # SKU Platform retrieved from MFS (Best)
	elif (variant,major,minor,hotfix) == ('CSME',12,0,0) and build >= 7000 and year < 0x2018 and month < 0x8 : # CSME 12 Alpha only
		fw_0C_dict = {0: 'H', 1: 'LP'} # 00 = H, 01 = LP, 10 = N/A, 11 = N/A
		sku_result = fw_0C_dict[fw_0C_sku2] if fw_0C_sku2 in fw_0C_dict else 'Unknown' # SKU Platform retrieved from Extension 12 (Best)
	else :
		# SKU Platform retrieved from SKU Capabilities (2nd Best)
		if 'LP' in fw_0C_sku0 : sku_result = 'LP'
		elif 'H' in fw_0C_sku0 : sku_result = 'H'
		else : sku_result = 'Unknown'
		
		if (variant,major,minor,sku_result) == ('CSME',14,5,'H') : sku_result = 'V' # Adjust CSME 14.5 SKU Platform from H to V
		elif (variant,major,sku_init,sku_result) == ('CSME',13,'Slim','LP') : sku_result = 'N' # Adjust CSME 13 SLM SKU Platform from LP to N
	
	sku = '%s %s' % (sku_init, sku_result) # Adjust final SKU to add Platform
	
	if sku_stp == 'Unknown' and pch_init_final : sku_stp = pch_init_final[-1][1] # Set Chipset Stepping, if not found at DB
	
	return sku, sku_result, sku_stp

# Get CSE DB SKU and check for Latest status
def sku_db_upd_cse(sku_type, sku_plat, sku_stp, sku_db, upd_found, stp_only, skip_csme11) :
	if (variant,major,skip_csme11) == ('CSME',11,True) : return sku_db, upd_found
	
	if sku_stp == 'Unknown' : sku_db = '%s%sX' % (sku_type if stp_only else sku_type + '_', sku_plat if stp_only else sku_plat + '_')
	else : sku_db = '%s%s' % (sku_type if stp_only else sku_type + '_', sku_plat if stp_only else sku_plat + '_') + sku_stp
	
	_,_,db_hot,db_bld = check_upd(('Latest_%s_%s%s_%s%s' % (variant, major, minor, sku_type, sku_plat)))
	if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
	
	return sku_db, upd_found

# Detect Variant/Family
def get_variant(buffer, mn2_struct, mn2_match_start, mn2_match_end, mn2_rsa_hash, mn2_date, mn2_ver) :
	variant = 'Unknown'
	variant_p = 'Unknown'
	var_rsa_db = True
	year,month,_ = mn2_date
	major,minor,hotfix,build = mn2_ver
	
	# Detect Variant by unique DB RSA Public Key
	for line in mea_db_lines :
		if mn2_rsa_hash in line :
			line_parts = line.strip().split('_')
			variant = line_parts[1] # Store the Variant
			
			break # Break loop at 1st match
	
	if mn2_rsa_hash == '86C0E5EF0CFEFF6D810D68D83D8C6ECB68306A644C03C0446B646A3971D37894' and 6 <= major <= 10 : variant = 'ME'
	elif mn2_rsa_hash == '86C0E5EF0CFEFF6D810D68D83D8C6ECB68306A644C03C0446B646A3971D37894' and 0 <= major <= 2 : variant = 'TXE'
	
	if variant.startswith(('Unknown','TBD')) :
		if variant == 'Unknown' : var_rsa_db = False # TBD are multi-platform RSA Public Keys
		
		# Get CSE $CPD Module Names only for targeted variant detection via special ext_anl _Stage1 mode
		cpd_mod_names,_ = ext_anl(buffer, '$MN2_Stage1', mn2_match_start, file_end, ['CSME',major,minor,hotfix,build,year,month,variant_p], None, [[],''], [[],-1,-1,-1])
		
		if cpd_mod_names :
			is_meu = hasattr(mn2_struct, 'MEU_Minor') # Check if $MN2 has MEU fields
			
			for mod in cpd_mod_names :
				if mod == 'fwupdate' or is_pfu_img : variant = 'CSME' # CSME
				elif mod in ['bup_rcv', 'sku_mgr', 'manuf'] : variant = 'CSSPS' # REC, OPR, IGN
				elif mod.startswith('dkl') and major == 10 and is_meu and mn2_struct.MEU_Major == 13 : variant = 'PHYSLKF' # SPHY (LKF)
				elif mod.startswith('dkl') and major in (11,0) and is_meu and mn2_struct.MEU_Major == 100 : variant = 'PHYDG1' # PHYP (DG1)
				elif mod.startswith('PCIE') and major in (11,0) and is_meu and mn2_struct.MEU_Major == 101 : variant = 'PHYDG2' # PHYP (DG2)
				elif mod == 'gen4_i' and major == 13 and is_meu and mn2_struct.MEU_Major == 16 : variant = 'PHYNADP' # NPHY (ADP)
				elif mod == 'SNPMULTI' and major == 13 and is_meu and mn2_struct.MEU_Major == 16 : variant = 'PHYSADP' # SPHY (ADP)
				elif mod == 'nphy' and major in (9,7) and is_meu and mn2_struct.MEU_Major == 13 : variant = 'PHYNICP' # NPHY (ICP)
				elif mod == 'nphy' and major in (16,15,11) and is_meu and mn2_struct.MEU_Major == 15 : variant = 'PHYNTGP' # NPHY (TGP)
				elif mod == 'pphy' and major in (12,14,11) and is_meu and mn2_struct.MEU_Major == 15 : variant = 'PHYPTGP' # PPHY (TGP)
				elif mod == 'pphy' and major == 12 and is_meu and mn2_struct.MEU_Major == 0 : variant = 'PHYPEBG' # PPHY (EBG)
				elif mod == 'pphy' and major in (12,0) : variant = 'PHYPCMP' # PPHY (CMP)
				elif mod == 'IntelRec' and major == 16 : variant = 'PCHCADP' # ADP
				elif mod == 'IntelRec' and major == 15 and is_meu and mn2_struct.MEU_Minor == 40 : variant = 'PCHCMCC' # MCC
				elif mod == 'IntelRec' and major == 15 and is_meu and mn2_struct.MEU_Minor == 0 : variant = 'PCHCTGP' # TGP
				elif mod == 'IntelRec' and (major,minor) == (14,5) : variant = 'PCHCCMPV' # CMP-V
				elif mod == 'IntelRec' and (major,minor) == (14,0) : variant = 'PCHCCMP' # CMP
				elif mod == 'IntelRec' and (major,minor) == (13,30) : variant = 'PCHCLKF' # LKF
				elif mod == 'IntelRec' and (major,minor) == (13,5) : variant = 'PCHCJSP' # JSP
				elif mod == 'IntelRec' and (major,minor) == (13,0) : variant = 'PCHCICP' # ICP
				elif mod == 'PMCC000' and (major in (300,30,3232) or (major < 30 and year <= 0x2017)) : variant = 'PMCCNP' # 0 CNP
				elif mod == 'PMCC000' and major == 133 : variant = 'PMCLKF' # 0 LKF
				elif mod == 'PMCC000' and major in (135,130) and is_meu and mn2_struct.MEU_Minor == 50 : variant = 'PMCJSP' # JSP
				elif mod == 'PMCC000' and major in (400,130) : variant = 'PMCICP' # 0 ICP
				elif mod == 'PMCC000' and major == 140 and is_meu and mn2_struct.MEU_Minor == 5 : variant = 'PMCCMPV' # 0 CMP-V
				elif mod == 'PMCC000' and major == 140 : variant = 'PMCCMP' # 0 CMP (After CMP-V)
				elif mod == 'PMCC000' and major == 150 : variant = 'PMCTGP' # 0 TGP
				elif mod == 'PMCC000' and major == 154 : variant = 'PMCMCC' # 0 MCC
				elif mod == 'PMCC000' and major == 160 : variant = 'PMCADP' # 0 ADP
				elif mod == 'PMCC000' and major == 1 : variant = 'PMCWTL' # 0 WTL
				elif mod == 'PMCC002' : variant = 'PMCAPLA' # 2 APL A
				elif mod == 'PMCC003' : variant = 'PMCAPLB' # 3 APL B
				elif mod == 'PMCC004' : variant = 'PMCGLKA' # 4 GLK A
				elif mod == 'PMCC005' : variant = 'PMCBXTC' # 5 BXT C (Joule)
				elif mod == 'PMCC006' : variant = 'PMCGLKB' # 6 GLK B
				elif mod in ['gfx_srv','chassis'] : variant = 'GSC' # GSC
				elif mod.startswith('PCOD') and is_meu and mn2_struct.MEU_Major == 100 : variant = 'PMCDG1' # DG1
				elif mod.startswith('PCOD') and is_meu and (major == 4 or mn2_struct.MEU_Major == 101) : variant = 'PMCDG2' # DG2
				elif mod == 'VBT' and major == 19 : variant = 'OROMDG1' # DG1
				elif mod == 'VBT' and major == 20 : variant = 'OROMDG2' # DG2
				elif mod == 'VBT' : variant = 'OROM' # Unknown
			
			if variant.startswith(('Unknown','TBD')) : variant = 'CSTXE' # CSE fallback, no CSME/CSSPS/GSC/PMC/PCHC/PHY/OROM detected
		
		elif buffer[mn2_match_end + 0x270 + 0x80:mn2_match_end + 0x270 + 0x84] == b'$MME' :
			# $MME: ME2-5/SPS1 = 0x50, ME6-10/SPS2-3 = 0x60, TXE1-2 = 0x80
			variant = 'TXE'
		
		elif re.compile(br'\$SKU\x03\x00\x00\x00\x2F\xE4\x01\x00').search(buffer) or \
		re.compile(br'\$SKU\x03\x00\x00\x00\x08\x00\x00\x00').search(buffer) :
			variant = 'SPS'
		
		else :
			variant = 'ME' # Default fallback, no CSE/TXE/SPS/GSC/PMC/PCHC/PHY/OROM detected
	
	# Create Variant display-friendly text
	if variant == 'CSME' : variant_p = 'CSE ME'
	elif variant == 'CSTXE' : variant_p = 'CSE TXE'
	elif variant == 'CSSPS' : variant_p = 'CSE SPS'
	elif variant == 'GSC' : variant_p = 'GSC'
	elif variant.startswith('PHY') : variant_p = 'PHY'
	elif variant.startswith('PMC') : variant_p = 'PMC'
	elif variant.startswith('PCHC') : variant_p = 'PCHC'
	elif variant.startswith('OROM') : variant_p = 'OROM'
	elif variant in ['ME','TXE','SPS'] : variant_p = variant
	
	return variant, variant_p, var_rsa_db

# Check online for MEA & DB Updates
def mea_upd_check(db_path) :
	result = None
	
	try :
		with urllib.request.urlopen('https://raw.githubusercontent.com/platomav/MEAnalyzer/master/MEA.py') as gpy : git_py = gpy.read(0x100)
		git_py_utf = git_py.decode('utf-8','ignore')
		git_py_idx = git_py_utf.find('title = \'ME Analyzer v')
		if git_py_idx == -1 : raise Exception('BAD_PY_FORMAT')
		git_py_ver = git_py_utf[git_py_idx:][22:].split('\'')[0].split('_')[0]
		cur_py_ver = title[13:].split('_')[0]
		git_py_tup = git_py_ver.split('.')[:3]
		cur_py_tup = cur_py_ver.split('.')[:3]
		py_print = '(v%s --> v%s)' % (cur_py_ver, git_py_ver)
		py_is_upd = bool(int(cur_py_tup[0]) > int(git_py_tup[0]) or (int(cur_py_tup[0]) == int(git_py_tup[0]) and (int(cur_py_tup[1]) > int(git_py_tup[1])
					or (int(cur_py_tup[1]) == int(git_py_tup[1]) and int(cur_py_tup[2]) >= int(git_py_tup[2])))))
		
		with urllib.request.urlopen('https://raw.githubusercontent.com/platomav/MEAnalyzer/master/MEA.dat') as gdb : git_db = gdb.readlines(0x80)
		git_db_ver = git_db[1].decode('utf-8','ignore')[14:].split('_')[0].split(' ')[0]
		with open(db_path, 'r', encoding='utf-8') as db : cur_db_ver = db.readlines()[1][14:].split('_')[0].split(' ')[0]
		db_print = '(r%s --> r%s)' % (cur_db_ver, git_db_ver)
		db_is_upd = cur_db_ver >= git_db_ver
		
		git_link = '\n         Download the latest from https://github.com/platomav/MEAnalyzer/'
		if not py_is_upd and not db_is_upd : result = col_m + '\nWarning: Outdated ME Analyzer %s & Database %s!' % (py_print,db_print) + git_link + col_e
		elif not py_is_upd : result = col_m + '\nWarning: Outdated ME Analyzer %s!' % py_print + git_link + col_e
		elif not db_is_upd : result = col_m + '\nWarning: Outdated Database %s!' % db_print + git_link + col_e
	except :
		result = None
	
	return result

# Scan all files of a given directory
def mass_scan(f_path) :
	mass_files = []
	for root, _, files in os.walk(f_path):
		for name in files :
			mass_files.append(os.path.join(root, name))
			
	input('\nFound %s file(s)\n\nPress enter to start' % len(mass_files))
	
	return mass_files

# Colorama ANSI Color/Font Escape Character Sequences Regex
ansi_escape = re.compile(r'\x1b[^m]*m')

# CSE Extensions 0x00-0x1B, 0x1E-0x1F, 0x22, 0x23, 0x32, 0x544F4F46
ext_tag_all = list(range(0x1C)) + list(range(0x1E,0x20)) + [0x22,0x23,0x32,0x544F4F46]

# CSME 12-14 Revised Extensions
ext_tag_rev_hdr_csme12 = {0xF:'_R2', 0x14:'_R2'}

# CSME 12-14 Revised Extension Modules
ext_tag_rev_mod_csme12 = {0x1:'_R2', 0xD:'_R2'}

# CSME 15 Revised Extensions
ext_tag_rev_hdr_csme15 = {0x0:'_R2', 0x3:'_R2', 0xA:'_R2', 0xF:'_R2', 0x11:'_R2', 0x13:'_R2', 0x14:'_R3', 0x16:'_R2',
						  0x17:'_R2', 0x1B:'_R2'}

# CSME 15 Revised Extension Modules
ext_tag_rev_mod_csme15 = {0x1:'_R2', 0xD:'_R2', 0xE:'_R2', 0xF:'_R3', 0x10:'_R2', 0x18:'_R2', 0x19:'_R2', 0x1A:'_R2'}

# GSC/OROM 100 Revised Extensions
ext_tag_rev_hdr_gsc100 = {0x0:'_R2', 0x3:'_R2', 0xA:'_R2', 0xF:'_R2', 0x11:'_R2', 0x13:'_R2', 0x14:'_R3', 0x16:'_R2',
						  0x18:'_R2', 0x19:'_R2', 0x1A:'_R2'}

# GSC/OROM 100 Revised Extension Modules
ext_tag_rev_mod_gsc100 = {0x1:'_R2', 0x7:'_R2', 0xD:'_R2', 0xE:'_R2', 0xF:'_R2', 0x10:'_R2', 0x18:'_R3', 0x1A:'_R3'}

# CSSPS 5 Revised Extensions
ext_tag_rev_hdr_cssps5 = {0xF:'_R2'}

# CSSPS 5 Revised Extension Modules
ext_tag_rev_mod_cssps5 = {0x1:'_R2', 0x0:'_R2'}

# CSSPS 5.0.0-3 Revised Extensions
ext_tag_rev_hdr_cssps503 = {0xF:'_R2'}

# CSSPS 5.0.0-3 Revised Extension Modules
ext_tag_rev_mod_cssps503 = {0x0:'_R2'}

# CSE Extensions without Modules (exclude 0x1E, 0x1F, 0x544F4F46)
ext_tag_mod_none = [(0x4,''), (0xA,''), (0xA,'_R2'), (0xC,''), (0x11,''), (0x11,'_R2'), (0x13,''), (0x13,'_R2'),
					(0x16,''), (0x16,'_R2'), (0x17,''), (0x17,'_R2'), (0x1B,''), (0x1B,'_R2'), (0x32,'')]

# CSE Extensions with Module Count
ext_tag_mod_count = [(0x1,''), (0x2,''), (0x12,''), (0x22,''), (0x23,'')]

# CSE SPS SKU Type ID
cssps_type_fw = {'RC':'Recovery', 'OP':'Operational'}

# CSE File System ID
mfs_type = {0:'root', 1:'home', 2:'bin', 3:'susram', 4:'fpf', 5:'dev', 6:'umafs'}

# CSE Extension 0x0F NVM Compatibility
ext15_nvm_type = {0:'Undefined', 1:'UFS', 2:'SPI'}

# CSE Extension 0x0F Firmware Type
ext15_fw_type = {0:'Default', 1:'SPS', 2:'SPS EPO', 3:'Client', 4:'GFX'}

# GSC SKU Build Major to Stepping Dictionary
gsc_stp_dict = {0:'A', 1:'A', 2:'B', 3:'C', 4:'D', 5:'E', 6:'F', 7:'G', 8:'H', 9:'I'}

# CSE File System Home Directory Record Structures
home_rec_struct = {0x18:MFS_Home_Record_0x18, 0x1C:MFS_Home_Record_0x1C}

# CSE File System Configuration Record Structures
config_rec_struct = {0x1C:MFS_Config_Record_0x1C, 0xC:MFS_Config_Record_0xC}

# CSE File System Home Directory Integrity Structures
sec_hdr_struct = {0x28:MFS_Integrity_Table_0x28, 0x34:MFS_Integrity_Table_0x34}

# Flash Partition Table Partition Types
p_type_dict = {0:'Code', 1:'Data', 2:'GLUT', 3:'Generic', 4:'EFFS', 5:'ROM'}

# Flash Partition Table v2.0 Flags (Sector Types)
sector_types = {0:'4K', 2:'8K', 4:'64K', 8:'64K-8K Mixed'}

# GSC Option ROM PCI Register Code Types
pcir_code_types = {0x0: 'BIOS', 0x1: 'OpenBIOS', 0x2: 'PA-RISC', 0x3: 'UEFI', 0xF0: 'Data', 0xF1: 'Code', 0xFF: 'Reserved'}

# CSE Module Types
cse_mod_type = {0:'Process', 1:'Shared Library', 2:'Data', 3:'Independent'}

# CSE/GSC Hash Algorithms
cse_hash_alg = {0:'None', 1:'SHA-1', 2:'SHA-256', 3:'SHA-384'}

# CSE USB Type C Hash Algorithms
tcs_hash_alg = {0:'SHA-1', 1:'SHA-256', 2:'MD5'}

# CSE Extension 0x0C Firmware SKU
ext12_fw_sku = {
			0 : ('Corporate','COR'),
			1 : ('Consumer','CON'),
			2 : ('Slim','SLM'),
			3 : ('Server','SVR'),
			5 : ('Chrome','CHR'),
			}

# CSE Extension 0x0F Firmware SKU
ext15_fw_sku = {
			0 : ('Undefined','NA'),
			1 : ('Corporate','COR'),
			2 : ('Consumer','CON'),
			3 : ('Slim','SLM'),
			4 : ('Lite','LIT'),
			5 : ('Server','SVR'),
			6 : ('Atom','ATM'), # Guess/Placeholder (JSP)
			255 : ('All','ALL'),
			}

# CSE SPS SKU Platform ID
cssps_platform = {
			'GE' : 'Greenlow',
			'PU' : 'Purley',
			'HA' : 'Harrisonville',
			'PE' : 'Purley EPO',
			'BA' : 'Bakerville',
			'ME' : 'Mehlow',
			'WH' : 'Whitley',
			'ID' : 'Idaville',
			'TA' : 'Tatlow',
			}

# CSE Extension Structures
ext_dict = {
			'CSE_Ext_00' : CSE_Ext_00,
			'CSE_Ext_00_R2' : CSE_Ext_00_R2,
			'CSE_Ext_01' : CSE_Ext_01,
			'CSE_Ext_02' : CSE_Ext_02,
			'CSE_Ext_03' : CSE_Ext_03,
			'CSE_Ext_03_R2' : CSE_Ext_03_R2,
			'CSE_Ext_04' : CSE_Ext_04,
			'CSE_Ext_05' : CSE_Ext_05,
			'CSE_Ext_06' : CSE_Ext_06,
			'CSE_Ext_07' : CSE_Ext_07,
			'CSE_Ext_08' : CSE_Ext_08,
			'CSE_Ext_09' : CSE_Ext_09,
			'CSE_Ext_0A' : CSE_Ext_0A,
			'CSE_Ext_0A_R2' : CSE_Ext_0A_R2,
			'CSE_Ext_0B' : CSE_Ext_0B,
			'CSE_Ext_0C' : CSE_Ext_0C,
			'CSE_Ext_0D' : CSE_Ext_0D,
			'CSE_Ext_0E' : CSE_Ext_0E,
			'CSE_Ext_0F' : CSE_Ext_0F,
			'CSE_Ext_0F_R2' : CSE_Ext_0F_R2,
			'CSE_Ext_10' : CSE_Ext_10,
			'CSE_Ext_11' : CSE_Ext_11,
			'CSE_Ext_11_R2' : CSE_Ext_11_R2,
			'CSE_Ext_12' : CSE_Ext_12,
			'CSE_Ext_13' : CSE_Ext_13,
			'CSE_Ext_13_R2' : CSE_Ext_13_R2,
			'CSE_Ext_14' : CSE_Ext_14,
			'CSE_Ext_14_R2' : CSE_Ext_14_R2,
			'CSE_Ext_14_R3' : CSE_Ext_14_R3,
			'CSE_Ext_15' : CSE_Ext_15,
			'CSE_Ext_16' : CSE_Ext_16,
			'CSE_Ext_16_R2' : CSE_Ext_16_R2,
			'CSE_Ext_17' : CSE_Ext_17,
			'CSE_Ext_17_R2' : CSE_Ext_17_R2,
			'CSE_Ext_18' : CSE_Ext_18,
			'CSE_Ext_18_R2' : CSE_Ext_18_R2,
			'CSE_Ext_19' : CSE_Ext_19,
			'CSE_Ext_19_R2' : CSE_Ext_19_R2,
			'CSE_Ext_1A' : CSE_Ext_1A,
			'CSE_Ext_1A_R2' : CSE_Ext_1A_R2,
			'CSE_Ext_1B' : CSE_Ext_1B,
			'CSE_Ext_1B_R2' : CSE_Ext_1B_R2,
			'CSE_Ext_1E' : CSE_Ext_1E,
			'CSE_Ext_1F' : CSE_Ext_1F,
			'CSE_Ext_22' : CSE_Ext_22,
			'CSE_Ext_23' : CSE_Ext_23,
			'CSE_Ext_32' : CSE_Ext_32,
			'CSE_Ext_544F4F46' : CSE_Ext_544F4F46,
			'CSE_Ext_00_Mod' : CSE_Ext_00_Mod,
			'CSE_Ext_00_Mod_R2' : CSE_Ext_00_Mod_R2,
			'CSE_Ext_01_Mod' : CSE_Ext_01_Mod,
			'CSE_Ext_01_Mod_R2' : CSE_Ext_01_Mod_R2,
			'CSE_Ext_02_Mod' : CSE_Ext_02_Mod,
			'CSE_Ext_03_Mod' : CSE_Ext_03_Mod,
			'CSE_Ext_05_Mod' : CSE_Ext_05_Mod,
			'CSE_Ext_06_Mod' : CSE_Ext_06_Mod,
			'CSE_Ext_07_Mod' : CSE_Ext_07_Mod,
			'CSE_Ext_07_Mod_R2' : CSE_Ext_07_Mod_R2,
			'CSE_Ext_08_Mod' : CSE_Ext_08_Mod,
			'CSE_Ext_09_Mod' : CSE_Ext_09_Mod,
			'CSE_Ext_0B_Mod' : CSE_Ext_0B_Mod,
			'CSE_Ext_0D_Mod' : CSE_Ext_0D_Mod,
			'CSE_Ext_0D_Mod_R2' : CSE_Ext_0D_Mod_R2,
			'CSE_Ext_0E_Mod' : CSE_Ext_0E_Mod,
			'CSE_Ext_0E_Mod_R2' : CSE_Ext_0E_Mod_R2,
			'CSE_Ext_0F_Mod' : CSE_Ext_0F_Mod,
			'CSE_Ext_0F_Mod_R2' : CSE_Ext_0F_Mod_R2,
			'CSE_Ext_0F_Mod_R3' : CSE_Ext_0F_Mod_R3,
			'CSE_Ext_10_Mod' : CSE_Ext_10_Mod,
			'CSE_Ext_10_Mod_R2' : CSE_Ext_10_Mod_R2,
			'CSE_Ext_12_Mod' : CSE_Ext_12_Mod,
			'CSE_Ext_14_HashArray' : CSE_Ext_14_HashArray,
			'CSE_Ext_14_HashArray_R2' : CSE_Ext_14_HashArray_R2,
			'CSE_Ext_14_RegionMap' : CSE_Ext_14_RegionMap,
			'CSE_Ext_15_PartID' : CSE_Ext_15_PartID,
			'CSE_Ext_15_Payload' : CSE_Ext_15_Payload,
			'CSE_Ext_15_Payload_Knob' : CSE_Ext_15_Payload_Knob,
			'CSE_Ext_18_Mod' : CSE_Ext_18_Mod,
			'CSE_Ext_18_Mod_R2' : CSE_Ext_18_Mod_R2,
			'CSE_Ext_18_Mod_R3' : CSE_Ext_18_Mod_R3,
			'CSE_Ext_19_Mod' : CSE_Ext_19_Mod,
			'CSE_Ext_19_Mod_R2' : CSE_Ext_19_Mod_R2,
			'CSE_Ext_1A_Mod' : CSE_Ext_1A_Mod,
			'CSE_Ext_1A_Mod_R2' : CSE_Ext_1A_Mod_R2,
			'CSE_Ext_1A_Mod_R3' : CSE_Ext_1A_Mod_R3,
			'CSE_Ext_22_Mod' : CSE_Ext_22_Mod,
			'CSE_Ext_23_Mod' : CSE_Ext_23_Mod,
			}
			
# CSE Key Manifest Hash Usages
key_dict = {
			0 : 'CSE BUP', # Fault Tolerant Partition (FTPR)
			1 : 'CSE Main', # Non-Fault Tolerant Partition (NFTP)
			2 : 'PMCP', # Power Management Controller
			6 : 'USB Type C IOM', # USB Type C I/O Manageability
			7 : 'USB Type C PHY', # USB Type C Manageability, North
			8 : 'USB Type C TBT', # USB Type C Thunderbolt
			9 : 'WCOD', # Wireless Microcode
			10 : 'LOCL', # AMT Localization
			11 : 'Intel Unlock Token',
			13 : 'USB Type C PHY', # South
			14 : 'PCHC',
			16 : 'Intel ISI', # Intel Safety Island
			17 : 'SAMF',
			18 : 'PPHY',
			19 : 'GBST',
			32 : 'Boot Policy',
			33 : 'iUnit Boot Loader', # Imaging Unit (Camera)
			34 : 'iUnit Main Firmware',
			35 : 'cAVS Image 0', # Clear Audio Voice Speech
			36 : 'cAVS Image 1',
			37 : 'IFWI', # Integrated Firmware Image
			38 : 'OS Boot Loader',
			39 : 'OS Kernel',
			40 : 'SMIP', # Signed Master Image Profile
			41 : 'ISH Main', # Integrated Sensor Hub
			42 : 'ISH BUP',
			43 : 'OEM Unlock Token',
			44 : 'OEM Life Cycle',
			45 : 'OEM Key',
			46 : 'SilentLake VMM',
			47 : 'OEM Key Attestation',
			48 : 'OEM DAL', # Dynamic Application Loader
			49 : 'OEM DNX IFWI R1', # XML v1.0 (Download and Execute v1)
			53 : 'OEM DNX IFWI R2', # XML v2.4 (Download and Execute v2)
			57 : 'OEM Descriptor',
			58 : 'OEM ISI', # Intel Safety Island
			59 : 'PSE', # Programmable Services Engine
			96 : 'HBM IO',
			97 : 'OOB MSM',
			98 : 'GT GPU',
			99 : 'MDF IO',
			100 : 'GSC PMC',
			101 : 'GSC PHY',
			102 : 'USB Type C Controller',
			103 : 'OROM',
			104 : 'HUC Production',
			105 : 'HUC Debug',
			106 : 'IFR', # In Field Repair
			107 : 'GFX Data 0',
			108 : 'GFX Data 1',
			192 : 'ESE',
			193 : 'DMU',
			194 : 'PUnit',
			195 : 'SoC ESE',
			196 : 'SoC PMC',
			197 : 'SoC SoCC', # Configuration
			198 : 'SoC SPHY',
			}
	
# IFWI BPDT Entry Types ($CPD Partition Names)
bpdt_dict = {
			0 : 'SMIP', # OEM-SMIP Partition
			1 : 'RBEP', # ROM Boot Extensions Partition (CSE-RBE)
			2 : 'FTPR', # Fault Tolerant Partition (CSE-BUP/FTPR)
			3 : 'UCOD', # Microcode Partition
			4 : 'IBBP', # IBB Partition
			5 : 'S-BPDT', # Secondary BPDT
			6 : 'OBBP', # OBB Partition
			7 : 'NFTP', # Non-Fault Tolerant Partition (CSE-MAIN)
			8 : 'ISHC', # ISH Partition
			9 : 'DLMP', # Debug Launch Module Partition
			10 : 'UEPB', # IFP Override/Bypass Partition
			11 : 'UTOK', # Debug Tokens Partition
			12 : 'UFS PHY', # UFS PHY Partition
			13 : 'UFS GPP LUN', # UFS GPP LUN Partition
			14 : 'PMCP', # PMC Partition (a.k.a. PCOD)
			15 : 'IUNP', # IUnit Partition
			16 : 'NVMC', # NVM Configuration
			17 : 'UEP', # Unified Emulation Partition
			18 : 'WCOD', # CSE-WCOD Partition
			19 : 'LOCL', # CSE-LOCL Partition
			20 : 'OEMP', # OEM KM Partition
			21 : 'FITC', # OEM Configuration (fitc.cfg)
			22 : 'PAVP', # Protected Audio Video Path
			23 : 'IOMP', # USB Type C IO Manageability Partition (UIOM)
			24 : 'xPHY', # USB Type C MG Partition (a.k.a. MGPP)
			25 : 'TBTP', # USB Type C Thunderbolt Partition (TBT)
			26 : 'PLTS', # Platform Settings
			31 : 'DPHY', # USB Type C Dekel PHY
			32 : 'PCHC', # PCH Configuration
			33 : 'ISIF', # Intel Safety Island Firmware
			34 : 'ISIC', # Intel Safety Island Configuration (N/A)
			35 : 'HBMI', # HBM IO Partition
			36 : 'OMSM', # OOB MSM Partition
			37 : 'GTGP', # GT-GPU Partition
			38 : 'MDFI', # MDF IO Partition
			39 : 'PUNP', # PUnit Partition
			40 : 'PHYP', # GSC PHY Partition
			41 : 'SAMF', # SAM Firmware
			42 : 'PPHY', # PPHY Partition
			43 : 'GBST', # GBST Partition
			44 : 'TCCP', # USB Type C Controller Partition (a.k.a. TPCC)
			45 : 'PSEP', # Programmable Services Engine Partition
			}
			
# CSE Extension 12 SKU Capabilities (ConfigRuleSettings)
skuc_dict = {
			0 : 'MNG_FULL', # Full Manageability
			1 : 'MNG_STD', # Standard Manageability
			2 : 'AMT', # Active Management Technology
			3 : 'MNG_LOCAL', # Local Manageability
			4 : 'INT_TOUCH', # Integrated Precise Touch & Stylus
			6 : 'SOFTCREEK', # Manageability Upgrade Service
			7 : 'OUI',
			8 : 'H', # PCH-H/V
			9 : 'LP', # PCH-LP/N
			10 : 'ISH', # Integrated Sensor Hub
			12 : 'PAVP', # Protected Audio Video Path
			14 : 'RCA',
			15 : 'PRTCM', # Protected Real Time Clock
			16 : 'HAP', # High Assurance Platform
			17 : 'IPV6', # Internet Protocol v6
			18 : 'KVM', # Keyboard, Video and Mouse
			19 : 'OCH',
			20 : 'DAL', # Dynamic Application Loader
			21 : 'TLS', # Transport Layer Security
			22 : 'CILA', # Client Initiated Local Access
			23 : 'WLAN', # Wireless
			24 : 'WL_DISP', # Wireless Display
			25 : 'LH',
			26 : 'NAP', # Microsoft Network Access Point
			27 : 'ALARMCLK', # Local Wake and Update
			28 : 'SECUREBOOT', # Secure Boot
			29 : 'PTT', # Platform Trust Technology
			30 : 'MDNSPROXY', # Multicast DNS Proxy
			31 : 'NFC', # Near Field Communication
			}
	
# CSE PCH Platforms
pch_dict = {
			0x0 : 'LBG-H', # Lewisburg H
			0x3 : 'ICP-LP', # Ice Point LP
			0x4 : 'ICP-N', # Ice Point N
			0x5 : 'ICP-H', # Ice Point H
			0x6 : 'TGP-LP', # Tiger Point LP
			0x7 : 'TGP/EBG-H', # Tiger Point H, Tatlow H
			0x8 : 'SPT/KBP-LP', # Sunrise Point LP, Union Point LP
			0x9 : 'SPT-H', # Sunrise Point H
			0xB : 'KBP/BSF/GCF-H', # Union Point H, Basin Falls H, Glacier Falls H, Comet Point V
			0xC : 'CNP/CMP-LP', # Cannon Point LP, Comet Point LP
			0xD : 'CNP/CMP-H', # Cannon Point H, Comet Point H
			0xE : 'LKF-LP', # Lakefield LP
			0xF : 'MCC-LP', # Mule Creek Canyon (Elkhart Lake) LP
			0x10 : 'JSP-N', # Jasper Point N
			0x11 : 'EBG-H', # Emmitsburg H
			0x12 : 'ADP-LP', # Alder Point P (LP)
			}

# CSE MFS Low Level File Names
mfs_dict = {
			0 : 'Unknown',
			1 : 'Unknown',
			2 : 'Anti-Replay',
			3 : 'Anti-Replay',
			4 : 'SVN Migration',
			5 : 'Quota Storage',
			6 : 'Intel Configuration',
			7 : 'OEM Configuration',
			9 : 'Manifest Backup',
			}
			
# CSE & PMC Compatibility
pmc_dict = {
			('CSME',12,0) : [300],
			('CSME',13,0) : [130],
			('CSME',13,30) : [133],
			('CSME',13,50) : [135,130],
			('CSME',14,0) : [140],
			('CSME',14,1) : [140],
			('CSME',14,5) : [140],
			('CSME',15,0) : [150],
			('CSME',15,40) : [154],
			('CSME',16,0) : [160],
			('CSTXE',3,0) : [-1],
			('CSTXE',3,1) : [-1],
			('CSTXE',3,2) : [-1],
			('CSTXE',4,0) : [-1],
			('CSSPS',4,4) : [1],
			('CSSPS',5,0) : [300],
			('CSSPS',5,1) : [300],
			('CSSPS',6,0) : [150],
			('GSC',100,0) : [0,10],
			('GSC',101,0) : [0,4],
			}

# CSE & PMC SoC SKU Compatibility
pmc_soc_dict = {
			('CSME',16,0,'H','SoC'),
			('CSME',13,30,'LP','SoC'),
			}
			
# CSE & PCHC Compatibility
pchc_dict = {
			('CSME',13,0) : [(13,0)],
			('CSME',13,30) : [(13,30)],
			('CSME',13,50) : [(13,5)],
			('CSME',14,0) : [(14,0)],
			('CSME',14,1) : [(14,0)],
			('CSME',14,5) : [(14,5)],
			('CSME',15,0) : [(15,0)],
			('CSME',15,40) : [(15,40),(15,0)],
			('CSME',16,0) : [(16,0)],
			}
			
# CSE & PHY Compatibility
phy_dict = {
			('CSME',16,0) : ['S','N'],
			('CSME',15,0) : ['P','N'],
			('CSME',14,1) : ['P'],
			('CSME',14,0) : ['P'],
			('CSME',13,30) : ['S'],
			('CSME',13,0) : ['N'],
			('CSSPS',6,0) : ['P'],
			('GSC',101,0) : ['G'],
			('GSC',100,0) : ['G'],
			}
			
# FD Component Sizes
comp_dict = {
			0 : 0x80000, # 512 KB
			1 : 0x100000, # 1 MB
			2 : 0x200000, # 2 MB
			3 : 0x400000, # 4 MB
			4 : 0x800000, # 8 MB
			5 : 0x1000000, # 16 MB
			6 : 0x2000000, # 32 MB
			7 : 0x4000000, # 64 MB
			8 : 0x8000000, # 128 MB
			9 : 0x10000000, # 256 MB
			}

# FTBL/EFST Platforms
ftbl_efst_plat = {
			0x01 : 'ICP',
			0x02 : 'CMP',
			0x03 : 'LKF',
			0x04 : 'TGP',
			0x05 : 'CMP-V',
			0x08 : 'MCC',
			0x0A : 'IDV',
			0x0B : 'WTL',
			0x10 : 'ADP',
			0x11 : 'JSP',
			0x13 : 'EBG', # TGP-H (Tatlow)
			}

# Get MEA Parameters from input
param = MEA_Param(sys.argv)

# Get script location
mea_dir = get_script_dir()

# Enumerate parameter input
arg_num = len(sys.argv)

# Set dependencies paths
mea_db_path = os.path.join(mea_dir, 'MEA.dat')

# Initialize & Start background Thread for MEA & DB update check
thread_update = Thread_With_Result(target=mea_upd_check, args=(mea_db_path,), daemon=True)
if not param.upd_dis : thread_update.start() # Start as soon as possible (mea_dir, mea_db_path)

# Check if MEA DB exists
if os.path.isfile(mea_db_path) :
	with open(mea_db_path, 'r', encoding = 'utf-8') as db :
		mea_db_read = db.read()
		mea_db_lines = mea_db_read.splitlines()
else :
	mea_hdr('')
	print(col_r + '\nError: MEA.dat file is missing!' + col_e)
	mea_exit(1)

# Get Known Pre-Production RSA Public Key Hashes from DB
rsa_pre_keys = get_db_json_obj('rsa_pre_keys')

# Get CSE Known Bad Partition/Module Hashes from DB
cse_known_bad_hashes = get_db_json_obj('cse_known_bad_hashes')

# Get Known Duplicate File Name Hashes from DB
known_dup_name_hahes = get_db_json_obj('known_dup_name_hahes')

# Get Database Revision
mea_db_rev, mea_db_rev_p = mea_hdr_init()

# Pause after any unexpected python exception
sys.excepthook = show_exception_and_exit

# Set console/shell window title
mea_title = '%s %s' % (title, mea_db_rev)
if sys_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(mea_title)
elif sys_os.startswith('linux') or sys_os == 'darwin' : sys.stdout.write('\x1b]2;' + mea_title + '\x07')

if not param.skip_intro :
	mea_hdr(mea_db_rev_p)

	print("\nWelcome to Intel Engine & Graphics Firmware Analysis Tool\n")
	
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
	
	mea_hdr(mea_db_rev_p)
	
else :
	mea_hdr(mea_db_rev_p)
	
if (arg_num < 2 and not param.help_scr and not param.mass_scan) or param.help_scr :
	mea_help()

if param.mass_scan :
	in_path = input('\nEnter the full folder path : ')
	source = mass_scan(in_path)
else :
	source = sys.argv[1:] # Skip script/executable
	
# Initialize file input
file_in = ''
cur_count = 0
in_count = len(source)
for arg in source :
	if arg in param.val : in_count -= 1

# Intel Engine/Graphics/Independent firmware Manifest pattern ($MN2 or $MAN, VEN_ID 0x8086)
man_pat = re.compile(br'\x86\x80.{9}\x00\$((MN2)|(MAN))', re.DOTALL)

# Intel Engine/Graphics/Independent placeholder Manifest pattern ($MN2, VEN_ID 0xBCCB)
bccb_pat = re.compile(br'\xCB\xBC.{9}\x00\$MN2', re.DOTALL)

# Intel Engine/Graphics/Independent firmware Code Partition Directory pattern ($CPD)
cpd_pat = re.compile(br'\$CPD.\x00\x00\x00[\x01\x02]\x01[\x10\x14]', re.DOTALL)

# Intel Engine/Graphics firmware Flash Partition Table pattern ($FPT)
fpt_pat = re.compile(br'\$FPT[\x01-\x7F]\x00\x00\x00')

# Intel Engine/Graphics firmware Boot Partition Descriptor Table pattern (BPDT)
bpdt_pat = re.compile(br'\xAA\x55[\x00\xAA]\x00.\x00[\x01\x02][\x00\x01].{16}(.\x00.\x00.{3}\x00.{3}\x00){3}', re.DOTALL)

# Intel Graphics firmware Option ROM Header & PCI Register pattern (PCIR)
orom_pat = re.compile(br'\x55\xAA.{22}\x1C\x00.{2}PCIR\x86\x80.{4}[\x18\x1C]\x00', re.DOTALL)

# Intel Flash Descriptor pattern (FD)
fd_pat = re.compile(br'\x5A\xA5\xF0\x0F[\x01-\x10].{171}\xFF{16}', re.DOTALL)

# Intel Engine/Graphics firmware Manifest probable patterns ($CPD + IUP, FTPR/OROM.man)
pr_man_08_pat = re.compile(br'FTPR\.man\x00{4}.{2}\x00{2}.{2}\x00{6}.{19}\x00{5}', re.DOTALL)
pr_man_09_pat = re.compile(br'OROM\.man\x00{4}.{2}\x00{2}.{2}\x00{6}.{19}\x00{5}', re.DOTALL)

pr_cpd_parts    = ['LOCL', 'PMCP', 'PCOD', 'PCHC', 'SPHY', 'PPHY', 'PHYP', 'NPHY', 'WCOD']
pr_man_cpd_pats = {part: re.compile(cpd_pat.pattern + b'.' + part.encode(), re.DOTALL) for part in pr_cpd_parts}

for file_in in source :
	
	# Variable Initialization
	nvm_db = ''
	fw_type = ''
	upd_rslt = ''
	reading_msg = ''
	me2_type_fix = ''
	me2_type_exp = ''
	sku = 'NaN'
	sku_db = 'NaN'
	rel_db = 'NaN'
	type_db = 'NaN'
	platform = 'NaN'
	sku_init = 'NaN'
	sku_init_db = 'NaN'
	pdm_status = 'NaN'
	variant = 'Unknown'
	variant_p = 'Unknown'
	sku_result = 'Unknown'
	sku_stp = 'Unknown'
	phy_sku = 'Unknown'
	pmc_date = 'Unknown'
	phy_date = 'Unknown'
	pchc_date = 'Unknown'
	me7_blist_1 = 'Empty'
	me7_blist_2 = 'Empty'
	cse_in_id_str = '0000'
	pos_sku_ker = 'Invalid'
	pos_sku_ext = 'Unknown'
	pos_sku_tbl = 'Unknown'
	pmc_pch_sku = 'Unknown'
	pmc_pch_rev = 'Unknown'
	pmc_platform = 'Unknown'
	phy_platform = 'Unknown'
	pchc_platform = 'Unknown'
	pmc_mn2_signed = 'Unknown'
	phy_mn2_signed = 'Unknown'
	pchc_mn2_signed = 'Unknown'
	fwu_iup_result = 'Unknown'
	mfs_state = 'Unconfigured'
	mn2_meu_ver = '0.0.0.0000'
	pmc_meu_ver = '0.0.0.0000'
	phy_meu_ver = '0.0.0.0000'
	pchc_meu_ver = '0.0.0.0000'
	pvbit = None
	pt_dfpt = None
	fpt_hdr = None
	bpdt_hdr = None
	byp_match = None
	pmc_pvbit = None
	phy_pvbit = None
	pchc_pvbit = None
	old_mn2_hdr = None
	pmc_mn2_ver = None
	phy_mn2_ver = None
	pchc_mn2_ver = None
	cse_lt_struct = None
	start_man_match = None
	end_man_match = None
	mfs_parsed_idx = None
	uncharted_match = None
	intel_cfg_hash_mfs = None
	var_rsa_db = True
	efs_init = False
	efs_found = False
	mfs_found = False
	mfsb_found = False
	mfs_is_afs = False
	upd_found = False
	rgn_exist = False
	rbep_found = False
	fitc_found = False
	cdmd_found = False
	ifwi_exist = False
	utok_found = False
	oemp_found = False
	is_pfu_img = False
	is_orom_img = False
	fw_type_fix = False
	is_patsburg = False
	can_search_db = True
	fpt_chk_fail = False
	sps_extr_ignore = False
	sps_opr_found = False
	fwu_iup_exist = False
	fpt_romb_found = False
	fitc_ver_found = False
	pmcp_fwu_found = False
	pchc_fwu_found = False
	phy_fwu_found = False
	pmcp_upd_found = False
	phy_upd_found = False
	pchc_upd_found = False
	fw_in_db_found = False
	fd_me_rgn_exist = False
	cse_lt_chk_fail = False
	fd_pdr_rgn_exist = False
	fd_bios_rgn_exist = False
	fd_devexp_rgn_exist = False
	rgn_over_extr_found = False
	phy_all_anl = []
	phy_all_init = []
	pmc_all_anl = []
	pmc_all_init = []
	pchc_all_anl = []
	pchc_all_init = []
	gsc_info = []
	mfs_info = []
	err_stor = []
	note_stor = []
	warn_stor = []
	s_bpdt_all = []
	fpt_matches = []
	p_store_all = []
	fpt_part_all = []
	orom_hdr_all = []
	bpdt_matches = []
	bpdt_hdr_all = []
	bpdt_data_all = []
	bpdt_part_all = []
	pch_init_final = []
	cse_lt_part_all = []
	cse_lt_hdr_info = []
	init_man_match = [0,0]
	eng_size_text = ['', False]
	cse_red_info = [False, True, True]
	ext15_info = [0, '', ('',''), '']
	pmc_ext15_info = [0, '', ('',''), '']
	phy_ext15_info = [0, '', ('',''), '']
	pchc_ext15_info = [0, '', ('',''), '']
	fdv_status = [False, False, False, False, []]
	msg_set = set()
	msg_dict = {}
	msg_entries = {}
	ftbl_blob_dict = {}
	ftbl_entry_dict = {}
	vcn = -1
	svn = -1
	sku_me = -1
	pmc_svn = -1
	phy_svn = -1
	pchc_svn = -1
	pmc_vcn = -1
	phy_vcn = -1
	pchc_vcn = -1
	mod_size = 0
	fw_0C_lbg = 0
	sku_type = -1
	sku_size = -1
	sku_slim = 0
	fd_count = 0
	fpt_count = 0
	cse_in_id = 0
	fpt_start = 0
	efs_start = -1
	mfs_start = -1
	mfsb_start = -1
	efs_size = 0
	mfs_size = 0
	mfsb_size = 0
	pmcp_size = 0
	pchc_size = 0
	fitc_size = 0
	cdmd_size = 0
	phy_size = 0
	oem_signed = 0
	rbep_start = -1
	fpt_length = -1
	fpt_version = -1
	pmc_fw_ver = -1
	phy_fw_ver = -1
	pchc_fw_ver = -1
	fitc_major = -1
	fitc_minor = -1
	fitc_build = -1
	fitc_hotfix = -1
	p_end_last = 0
	old_mn2_off = 0
	mod_end_max = 0
	cse_lt_off = -1
	cse_lt_size = 0
	cpd_end_last = 0
	me_fd_start = -1
	me_fd_size = -1
	pdr_fd_size = -1
	bios_fd_size = -1
	bios_fd_start = -1
	pmc_fw_rel = -1
	phy_fw_rel = -1
	pchc_fw_rel = -1
	pmc_pch_gen = -1
	pchc_fw_major = -1
	pchc_fw_minor = -1
	vol_ftbl_id = -1
	vol_ftbl_pl = -1
	pdr_fd_start = -1
	fpt_part_num = -1
	p_offset_last = 0
	fpt_chk_int = 0
	fpt_chk_mea = 0
	fpt_pat_bgn = 0
	fpt_pat_end = 0
	bpdt_pat_bgn = 0
	cse_lt_dp_size = 0
	cse_lt_bp_size = 0
	cse_lt_dup_size = 0
	sps3_chk16_file = 0
	sps3_chk16_calc = 0
	devexp_fd_size = -1
	devexp_fd_start = -1
	p_end_last_back = -1
	cse_lt_flags_red = 0
	orom_pci_size = 0
	orom_cpd_size = 0
	check_fw_align = 0
	file_has_align = 0
	eng_fw_align = 0x1000
	mod_end = 0xFFFFFFFF
	p_max_size = 0xFFFFFFFF
	eng_fw_end = 0xFFFFFFFF
	p_offset_min = 0xFFFFFFFF
	cse_lt_entry_min = 0xFFFFFFFF
	cur_count += 1
	
	if not os.path.isfile(file_in) :
		if any(p in file_in for p in param.val) : continue # Next input file
		
		print(col_r + '\nError: File %s was not found!' % file_in + col_e)
		
		if not param.mass_scan : mea_exit(1)
		else : continue
	
	# Store input file buffer to RAM, will change if Flash Descriptor is detected
	with open(file_in, 'rb') as in_file : reading = in_file.read()
	file_end = len(reading) # Store the input file buffer Size/EOF
	reading_16 = reading[:0x10] # Store the first 16 input file buffer bytes
	
	# Detect & Skip AMI BIOS Guard (PFAT) protected images
	if reading[0x8:0x10] == b'_AMIPFAT' :
		msg_pt = ext_table([], False, 1)
		msg_pt.add_row([col_c + '%s (%d/%d)' % (os.path.basename(file_in)[:45], cur_count, in_count) + col_e])
		
		print('\n%s\n\nDetected' % msg_pt + col_y + ' AMI BIOS Guard (PFAT) ' + col_e + 'protected image, prior extraction'
			  ' required!\n\nUse "AMI BIOS Guard Extractor" from https://github.com/platomav/BIOSUtilities')
		
		copy_on_msg(['PFAT']) # Close input and copy it in case of messages
		
		continue # Next input file

	# Detect & Skip Intel (CS)SPS Capsule multi images
	if reading[:0x10] == b'\x34\x59\xEF\x99\x22\x78\xC4\x49\x83\xA4\x50\xC1\xAF\xBC\xBE\x00' :
		msg_pt = ext_table([], False, 1)
		msg_pt.add_row([col_c + '%s (%d/%d)' % (os.path.basename(file_in)[:45], cur_count, in_count) + col_e])
		
		print('\n%s\n\nDetected' % msg_pt + col_y + ' Intel (CS)SPS Capsule ' + col_e + 'multi image, format is not supported!')
		
		continue # Next input file
	
	# Parse VFS & EFS File Table Blobs
	if param.mfs_ftbl :
		ftbl = get_struct(reading, 0, FTBL_Header)
		
		if ftbl.Signature == b'FTBL' :
			for i in range(ftbl.TableCount) :
				tbl = get_struct(reading, 0x10 + i * 0x10, FTBL_Table)
				
				tbl_data = reading[tbl.Offset:tbl.Offset + tbl.Size]
				
				ftbl_pt = ext_table(['Path','File ID','Integrity','Encryption','Anti-Replay','Access Unknown','User ID','Group ID','VFS ID','Unknown'], True, 1)
				ftbl_pt.title = 'FTBL Table ' + '%0.2X' % tbl.Dictionary
				
				for j in range(tbl.EntryCount) :
					entry_data = tbl_data[j * 0x44:j * 0x44 + 0x44]
					
					entry = get_struct(entry_data, 0, FTBL_Entry)
					
					# Remember to also adjust FTBL_Entry, mfs_home13_anl & efs_anl
					
					f1,f2,f3,f4,f5 = entry.get_flags() # Integrity, Encryption, Anti-Replay, Access Unknown, Unknown
					
					path = entry.Path.decode('utf-8').strip() # Local Path (strip extra spaces, e.g. INTC_defpdt)
					file_id = '0x%0.8X' % entry.FileID # File ID
					access_int = ['No','Yes'][f1] # Access > Integrity
					access_enc = ['No','Yes'][f2] # Access > Encryption
					access_arp = ['No','Yes'][f3] # Access > Anti-Replay
					access_unk = '{0:013b}b'.format(f4) # Access > Unknown
					group_id = '0x%0.4X' % entry.GroudID # Group ID
					user_id = '0x%0.4X' % entry.UserID # User ID
					vfs_id = '%0.4d' % entry.VFSID # VFS ID (Low Level File)
					unknown = '{0:064b}b'.format(f5) # Unknown
					
					# Create File Table Entries Dictionary
					ftbl_entry_dict['%0.8X' % entry.FileID] = '%s,%d,%d,%d,%d,%d,%d,%d,%d' % (path,f1,f2,f3,f4,entry.GroudID,entry.UserID,entry.VFSID,f5)
					
					# Create File Table Entries Info
					ftbl_pt.add_row([path,file_id,access_int,access_enc,access_arp,access_unk,user_id,group_id,vfs_id,unknown])
					
				ftbl_blob_dict['%0.2X' % tbl.Dictionary] = {}
				ftbl_blob_dict['%0.2X' % tbl.Dictionary]['FTBL'] = ftbl_entry_dict # Create File Table Blob Dictionary
				
				with open('%s_FTBL_%0.2X.txt' % (os.path.basename(file_in), tbl.Dictionary), 'w', encoding='utf-8') as o : o.write(str(ftbl_pt))
				if param.write_html :
					with open('%s_FTBL_%0.2X.html' % (os.path.basename(file_in), tbl.Dictionary), 'w', encoding='utf-8') as o : o.write(pt_html(ftbl_pt))
				if param.write_json :
					with open('%s_FTBL_%0.2X.json' % (os.path.basename(file_in), tbl.Dictionary), 'w', encoding='utf-8') as o : o.write(pt_json(ftbl_pt))
		
		if reading[ftbl.HeaderSize:ftbl.HeaderSize + 0x4] == b'EFST' :
			efst = get_struct(reading, ftbl.HeaderSize, EFST_Header)
			
			e_pt = ext_table(['Dictionary','Offset','File Count','Size','Unknown 0','Data Pages Committed',
							  'Data Pages Reserved','Max Files','Unknown 1','Table Revision'], True, 1)
			e_pt.title = 'EFST Tables'
			
			for i in range(efst.TableCount) :
				tbl = get_struct(reading, ftbl.HeaderSize + 0x10 + i * 0x28, EFST_Table)
				
				e_pt.add_row(['0x%0.2X' % tbl.Dictionary,'0x%X' % tbl.Offset,tbl.EntryCount,'0x%X' % tbl.Size,'0x%X' % tbl.Unknown0,
				tbl.DataPagesCom,tbl.DataPagesRes,tbl.MaxEntries,'0x%X' % tbl.Unknown1,tbl.Revision])
				
				with open('%s_EFST.txt' % os.path.basename(file_in), 'w', encoding='utf-8') as o : o.write(str(e_pt))
				
				tbl_data = reading[tbl.Offset:tbl.Offset + tbl.Size]
				
				efst_pt = ext_table(['VFS ID','Name','Page','Offset','Size','Reserved'], True, 1)
				efst_pt.title = 'EFST Table ' + '%0.2X' % tbl.Dictionary
				
				file_info = []
				efst_entry_dict = {}
				for j in range(tbl.EntryCount) :
					entry_data = tbl_data[j * 0x3C:j * 0x3C + 0x3C]
					
					entry = get_struct(entry_data, 0, EFST_Entry)
					
					# Remember to also adjust EFST_Entry
					
					file_id = entry.FileID # File Count
					file_name = entry.FileName.decode('utf-8').strip() # File Name (strip extra spaces)
					if file_name.startswith('EFS_FILE_') : file_name = file_name[9:]
					file_page = entry.FilePage # EFS Page Number (0,1,2...)
					file_offset = entry.FileOffset # File Offset
					file_length = entry.FileSize # File Size
					reserved = entry.Reserved # Reserved
					file_info.append((file_page,file_offset,file_length,file_id,reserved,file_name))
					
					# Create EFS Table Entries Info
					efst_pt.add_row(['%0.4d' % file_id,file_name,file_page,'0x%X' % file_offset,'0x%X' % file_length,'0x%X' % reserved])
					
				file_info.sort() # Sort EFS Entries/Files based on File Page & File Offset
				
				# Determine actual EFS Data Area Buffer Offset for each Entry/File.
				# EFS Data Area Buffer consists of all Data Pages w/o Header & Footer.
				# EFS Files within the Data Area Buffer are sequential so we can use
				# each File Size to determine the next File Offset, starting from 0x0.
				dict_offset = [0] # First File starts at Data Area Buffer Offset 0x0
				for info_idx in range(len(file_info) - 1) : # Last File Size is not needed
					last_offset = dict_offset[info_idx] # Get previous File Offset
					dict_offset.append(last_offset + 0x4 + file_info[info_idx][2]) # Calculate current File Offset
				
				# Create EFS Table Entries/Files Dictionary
				for info_idx in range(len(file_info)) :
					efst_entry_dict['%0.8X' % dict_offset[info_idx]] = '%d,%d,%d,%d,%d,%s' % file_info[info_idx]
				
				# Create EFS Table Blob Dictionary
				if 'EFST' not in ftbl_blob_dict['%0.2X' % tbl.Dictionary] : ftbl_blob_dict['%0.2X' % tbl.Dictionary]['EFST'] = {}
				ftbl_blob_dict['%0.2X' % tbl.Dictionary]['EFST']['%0.2X' % tbl.Revision] = efst_entry_dict
				
				with open('%s_EFST_%0.2X.txt' % (os.path.basename(file_in), tbl.Dictionary), 'w', encoding='utf-8') as o : o.write(str(efst_pt))
				if param.write_html :
					with open('%s_EFST_%0.2X.html' % (os.path.basename(file_in), tbl.Dictionary), 'w', encoding='utf-8') as o : o.write(pt_html(efst_pt))
				if param.write_json :
					with open('%s_EFST_%0.2X.json' % (os.path.basename(file_in), tbl.Dictionary), 'w', encoding='utf-8') as o : o.write(pt_json(efst_pt))
				
		o_dict = json.dumps(ftbl_blob_dict, indent=4, sort_keys=True)
		with open('%s_FileTable.dat' % os.path.basename(file_in), 'w', encoding='utf-8') as o : o.write(o_dict)
		
		continue # Next input file
	
	# Detect Intel Engine/Graphics/Independent firmware
	for man_range in list(man_pat.finditer(reading)) :
		start_man_match = man_range.start() + 0xB # 8680.{9} sanity check before .$MN2 or .$MAN
		end_man_match = man_range.end()
		
		reading_4K = reading[max(0x0, end_man_match - 0x4020):max(0x0, end_man_match - 0x20)] # Based on MN2_Manifest Max Size
		
		pr_man_01 = reading[end_man_match + 0x264:end_man_match + 0x266] # FT,OP (ME 6 - 10 Part 1, TXE 0 - 2 Part 1, SPS 2 - 3 Part 1)
		pr_man_02 = reading[end_man_match + 0x266:end_man_match + 0x268] # PR,xx (ME 6 - 10 Part 2, TXE 0 - 2 Part 2)
		pr_man_03 = reading[end_man_match + 0x28C:end_man_match + 0x293] # BRINGUP (ME 2 - 5)
		pr_man_04 = reading[end_man_match + 0x2DC:end_man_match + 0x2E7] # EpsRecovery,EpsFirmware (SPS 1)
		pr_man_05 = reading[end_man_match + 0x270:end_man_match + 0x277] # $MMEBUP (ME 6 BYP Part 1, SPS 2 - 3 Part 2)
		pr_man_06 = reading[end_man_match + 0x33C:end_man_match + 0x340] # $MMX (ME 6 BYP Part 2)
		pr_man_07 = reading[0x290:0x299] == b'$MMEWCOD_' # $MMEWCOD_ (ME 8+ PFU)
		pr_man_08 = pr_man_08_pat.search(reading_4K) # FTPR.man (CSME 15.0.35 +)
		pr_man_09 = pr_man_09_pat.search(reading_4K) # OROM.man (GSC)
		
		pr_man_cpd = {name: pr_man_cpd_pats[name].search(reading_16) for name in pr_cpd_parts}

		if param.bypass : break # Force MEA to accept any $MAN/$MN2 (Debug/Research)
		
		# Break if a valid Recovery Manifest is found
		if pr_man_01 + pr_man_02 == b'FTPR' \
		or pr_man_01 + pr_man_05 + pr_man_06 == b'OP$MMEBUP\x00\x00\x00\x00' \
		or pr_man_03 == b'BRINGUP' \
		or pr_man_04 in (b'EpsRecovery', b'EpsFirmware') \
		or pr_man_05 + pr_man_06 == b'$MMEBUP$MMX' \
		or pr_man_07 or pr_man_08 or pr_man_09 \
		or any(pr_man_cpd.values()):
			if pr_man_07 or pr_man_cpd['LOCL'] or pr_man_cpd['WCOD'] : is_pfu_img = True # FWUpdate Partial Firmware Update (PFU)
			if pr_man_09 : is_orom_img = True # GSC Option ROM Image (OROM)
			break
		
	else :
		# Recovery Manifest not found (for > finish)
		msg_pt = ext_table([], False, 1)
		msg_pt.add_row([col_c + '%s (%d/%d)' % (os.path.basename(file_in)[:45], cur_count, in_count) + col_e])
		print('\n%s\n\nFile does not contain Intel Engine/Graphics Firmware' % msg_pt)
		
		continue # Next input file

	# Engine/Graphics/Independent firmware found (for > break), Manifest analysis
	
	# Detect Intel Flash Descriptor (FD)
	fd_exist,reading,file_end,start_man_match,end_man_match,start_fd_match,end_fd_match,fd_count,fd_comp_all_size,fd_is_ich,fd_is_cut,reading_msg = \
	fd_anl_init(reading,file_end,start_man_match,end_man_match)
	
	# Store Initial Manifest Offset for CSSPS EXTR RSA Signatures Hash
	init_man_match = [start_man_match,end_man_match]
	
	# Analyze Intel Flash Descriptor Regions
	if fd_exist :
		fd_bios_rgn_exist,bios_fd_start,bios_fd_size,fd_me_rgn_exist,me_fd_start,me_fd_size,fd_pdr_rgn_exist,pdr_fd_start,pdr_fd_size, \
		fd_devexp_rgn_exist,devexp_fd_start,devexp_fd_size = fd_anl_rgn(start_fd_match,end_fd_match,fd_is_ich)
		
		fd_data_all = reading[start_fd_match:start_fd_match + 0x1000] # Flash Descriptor Data
		fd_data_mn2 = fd_data_all[0x800:0xC00] # Flash Descriptor Manifest Data
		fd_is_rsa = bool(man_pat.search(fd_data_mn2[:0x20])) # Check if FD Manifest exists
		
		if fd_is_rsa : # Flash Descriptor is Hash protected
			ext_print,mn2_signs,fd_info = ext_anl(fd_data_mn2, '$MN2', 0x1B, file_end, ['CSME',0,0,0,0,0,0,'CSE ME'], 'FDV', [[],''], [[],-1,-1,-1])
			fd_rsa_valid = mn2_signs[0] # FDV RSA Signature validity
			fd_rsa_crash = mn2_signs[3] # FDV RSA Signature crashed
			fd_hash_int = fd_info[0] # FDV Extension 23 Hash value
			fd_hash_excl = fd_info[1] # FDV Extension 23 Exclusion Ranges
			fd_hash_data = bytearray(fd_data_all) # Flash Descriptor Hash Data
			ext_print[1][0].title = col_y + 'Flash Descriptor Manifest' + col_e # Adjust Manifest PLTable object's title
			
			# Check Flash Descriptor RSA Signature status
			if fd_rsa_crash : err_stor.append([col_r + 'Error: Could not validate Flash Descriptor RSA Signature!' + col_e, True])
			elif not fd_rsa_valid : err_stor.append([col_r + 'Error: Invalid Flash Descriptor RSA Signature!' + col_e, True])
			
			# Padd Excluded Ranges from Flash Descriptor Hash Data
			for excl_range in fd_hash_excl :
				range_size = excl_range[1] - excl_range[0]
				if range_size : fd_hash_data[excl_range[0]:excl_range[1]] = b'\xFF' * range_size
				
			fd_hash_mea = get_hash(fd_hash_data, len(fd_hash_int) // 2) # Calculate Flash Descriptor Hash value
			
			# Check Flash Descriptor Hash status
			if fd_hash_int != fd_hash_mea : err_stor.append([col_r + 'Error: Invalid Flash Descriptor Hash!' + col_e, True])
			
			# Store Flash Descriptor RSA Signature & Hash status and Manifest/Extension info
			fdv_status = [fd_is_rsa, fd_rsa_valid, fd_rsa_crash, fd_hash_int == fd_hash_mea, ext_print]
		
	# Detect CSE Layout Table, it unfortunately lacks a unique identifier (GREAT WORK INTEL...)
	if fd_me_rgn_exist :
		cse_lt_off = me_fd_start # If Flash Descriptor exists, use Engine/Graphics region offset (robust)
	else :
		cse_lt_pos_16 = reading[:0x1000].find(b'\x00' * 0x18 + b'\x22' + b'\x00' * 7 + b'\xFF' * 0xFB8) # At IFWI 1.6, try static "Checksum" field
		cse_lt_pos_17 = re.compile(br'\x40\x00[\x00\x01]\x00.{4}(.{3}\x00){14}', re.DOTALL).search(reading[:0x1000]) # At IFWI 1.7, try struct pattern
		if cse_lt_pos_16 != -1 : cse_lt_off = cse_lt_pos_16 - 0x28
		elif cse_lt_pos_17 : cse_lt_off = cse_lt_pos_17.start() - 0x10
		else : cse_lt_off = 0x0 # Assume 0x0 on cse_lt_pos_16/cse_lt_pos_17 miss (risky)
	
	cse_lt_size = 0x1000 # CSE LT Size is usually 0x1000 (4KB)
	cse_lt_bp = [b'\xAA\x55\x00\x00',b'\xAA\x55\xAA\x00'] # IFWI BPDT Signatures
	cse_lt_16 = get_struct(reading, cse_lt_off, CSE_Layout_Table_16) # IFWI 1.6 Structure
	cse_lt_17 = get_struct(reading, cse_lt_off, CSE_Layout_Table_17) # IFWI 1.7 Structure
	cse_lt_16_hdr_pad = reading[cse_lt_off + ctypes.sizeof(CSE_Layout_Table_16):cse_lt_off + cse_lt_size] # IFWI 1.6 Header Padding
	cse_lt_17_hdr_pad = reading[cse_lt_off + ctypes.sizeof(CSE_Layout_Table_17):cse_lt_off + cse_lt_size] # IFWI 1.7 Header Padding
	cse_lt_16_fpt_sig = reading[cse_lt_off + cse_lt_16.DataOffset:cse_lt_off + cse_lt_16.DataOffset + 0x4] # IFWI 1.6 FPT Signature
	cse_lt_17_fpt_sig = reading[cse_lt_off + cse_lt_17.DataOffset:cse_lt_off + cse_lt_17.DataOffset + 0x4] # IFWI 1.7 FPT Signature
	cse_lt_16_bp1_sig = reading[cse_lt_off + cse_lt_16.BP1Offset:cse_lt_off + cse_lt_16.BP1Offset + 0x4] # IFWI 1.6 BP1 Signature
	cse_lt_17_bp1_sig = reading[cse_lt_off + cse_lt_17.BP1Offset:cse_lt_off + cse_lt_17.BP1Offset + 0x4] # IFWI 1.7 BP1 Signature
	
	# If $FPT exists, verify CSE LT via Data, BP1 & Padding. Otherwise, only via BP1 & Padding (risky)
	if reading[cse_lt_off:cse_lt_off + 0x4] in cse_lt_bp :
		pass # Skip any CSE LT Structure "matches" which are actually IFWI 2.0 BPx (BPDT)
	elif cse_lt_16_fpt_sig == b'$FPT' and cse_lt_16_bp1_sig in cse_lt_bp and cse_lt_16_hdr_pad == len(cse_lt_16_hdr_pad) * b'\xFF' :
		cse_lt_struct = cse_lt_16 # CSE LT IFWI 1.6 with Data
		fpt_pat_bgn = cse_lt_off + cse_lt_16.DataOffset # Adjust $FPT Starting Offset based on CSE LT IFWI 1.6 Data
		fpt_pat_end = cse_lt_off + cse_lt_16.DataOffset + 0x4 # Adjust $FPT End Offset based on CSE LT IFWI 1.6 Data
	elif cse_lt_17_fpt_sig == b'$FPT' and cse_lt_17_bp1_sig in cse_lt_bp and cse_lt_17_hdr_pad == len(cse_lt_17_hdr_pad) * b'\xFF' :
		cse_lt_struct = cse_lt_17 # CSE LT IFWI 1.7 with Data
		fpt_pat_bgn = cse_lt_off + cse_lt_17.DataOffset # Adjust $FPT Starting Offset based on CSE LT IFWI 1.7 Data
		fpt_pat_end = cse_lt_off + cse_lt_17.DataOffset + 0x4 # Adjust $FPT End Offset based on CSE LT IFWI 1.7 Data
	elif cse_lt_16_bp1_sig in cse_lt_bp and cse_lt_16_hdr_pad == len(cse_lt_16_hdr_pad) * b'\xFF' :
		cse_lt_struct = cse_lt_16 # CSE LT IFWI 1.6 without Data
	elif cse_lt_17_bp1_sig in cse_lt_bp and cse_lt_17_hdr_pad == len(cse_lt_17_hdr_pad) * b'\xFF' :
		cse_lt_struct = cse_lt_17 # CSE LT IFWI 1.7 without Data
	
	# Analyze CSE Layout Table
	if cse_lt_struct :
		NA = [0,0xFFFFFFFF]
		
		cse_lt_hdr_info = [['Data',cse_lt_struct.DataOffset,cse_lt_struct.DataSize],['Boot 1',cse_lt_struct.BP1Offset,cse_lt_struct.BP1Size],
						   ['Boot 2',cse_lt_struct.BP2Offset,cse_lt_struct.BP2Size],['Boot 3',cse_lt_struct.BP3Offset,cse_lt_struct.BP3Size],
						   ['Boot 4',cse_lt_struct.BP4Offset,cse_lt_struct.BP4Size],['Boot 5',cse_lt_struct.BP5Offset,cse_lt_struct.BP5Size]]
		
		# Perform IFWI 1.7 specific CSE LT actions
		if cse_lt_struct == cse_lt_17 :
			# Validate IFWI 1.7 CSE LT CRC-32
			cse_lt_pointers = reading[cse_lt_off + 0x10:cse_lt_off + 0x14] + b'\x00' * 4 + reading[cse_lt_off + 0x18:cse_lt_off + 0x10 + cse_lt_struct.Size]
			cse_lt_chk_int = cse_lt_struct.Checksum
			cse_lt_chk_mea = crccheck.crc.Crc32.calc(cse_lt_pointers)
			if cse_lt_chk_mea != cse_lt_chk_int :
				cse_lt_chk_fail = True
				warn_stor.append([col_m + 'Warning: Wrong CSE Layout Table CRC 0x%0.8X, expected 0x%0.8X!' % (cse_lt_chk_int,cse_lt_chk_mea) + col_e, True])
				if param.check : # Fix CSE LT CRC-32, when applicable (Debug/Research)
					with open('__FCCLT__' + os.path.basename(file_in), 'wb') as o :
						o.write(reading[:cse_lt_off + 0x14] + struct.pack('<I', cse_lt_chk_mea) + reading[cse_lt_off + 0x18:])
			
			# Add IFWI 1.7 CSE LT Temp DRAM Cache Pages Offset & Size info
			cse_lt_hdr_info.append(['Temp',cse_lt_struct.TempPagesOffset,cse_lt_struct.TempPagesSize])
			
			# Add IFWI 1.7 CSE LT ELog Offset & Size info (0x58-0x5C at CSE_Layout_Table_17, Size field starts after ROMB at 0x10)
			if cse_lt_struct.Size >= 0x48 : cse_lt_hdr_info.append(['ELog',cse_lt_struct.ELogOffset,cse_lt_struct.ELogSize])
			
			# Get IFWI 1.7 CSE LT Flags Info (CSE Redundancy, Reserved)
			cse_lt_flags_red, _ = cse_lt_struct.get_flags()
		
		# Calculate CSE LT Data Partition Total Size (w/o Boot, Temp & ELog)
		cse_lt_dp_size = cse_lt_struct.DataSize
		
		# Calculate CSE LT Boot, Temp & ELog Partitions Total Size (w/o Data)
		cse_lt_bp_size = sum([info[2] for info in cse_lt_hdr_info[1:]])
		
		# Store CSE LT partition details
		for entry in cse_lt_hdr_info :
			cse_lt_entry_name = entry[0]
			cse_lt_entry_off = entry[1]
			cse_lt_entry_size = entry[2]
			
			cse_lt_entry_spi = cse_lt_off + cse_lt_entry_off
			cse_lt_entry_end = cse_lt_entry_spi + cse_lt_entry_size
			cse_lt_entry_data = reading[cse_lt_entry_spi:cse_lt_entry_end]
			cse_lt_entry_empty = bool(cse_lt_entry_off in NA or cse_lt_entry_size in NA or cse_lt_entry_data in [b'\x00' * cse_lt_entry_size,b'\xFF' * cse_lt_entry_size])
			if not cse_lt_entry_empty : cse_lt_entry_min = min(cse_lt_entry_off, cse_lt_entry_min)
			
			cse_lt_part_all.append([cse_lt_entry_name,cse_lt_entry_spi,cse_lt_entry_size,cse_lt_entry_end,cse_lt_entry_empty])
		
		if cse_lt_entry_min > cse_lt_size : cse_lt_size = cse_lt_entry_min # Adjust CSE LT Size when 1st Partition does not start at 0x1000
		
		pt_dcselt = ext_table([col_y + 'Name' + col_e, col_y + 'Start' + col_e, col_y + 'Size' + col_e, col_y + 'End' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt_dcselt.title = col_y + 'CSE Region Layout Table' + col_e
		
		# Detect CSE LT partition overlaps
		for part in cse_lt_part_all :
			pt_dcselt.add_row([part[0],'0x%0.6X' % part[1],'0x%0.6X' % part[2],'0x%0.6X' % part[3],part[4]]) # For -dfpt
			for all_part in cse_lt_part_all :
				# Partition A starts before B but ends after B start
				# Ignore partitions which have empty offset or size
				# Ignore FPTB Boot 4 within $FPT Data (CSSPS 4.4)
				if not part[4] and not all_part[4] and not any(s in [0,0xFFFFFFFF] for s in (part[1],part[2],all_part[1],all_part[2])) and (part[1] < all_part[1] < part[2]) \
				and not ((part[0],all_part[0],reading[all_part[1]:all_part[1] + 0x4]) == ('Data','Boot 4',b'$FPT') and all_part[1] >= part[1] and all_part[3] <= part[3]) :
					err_stor.append([col_r + 'Error: CSE LT partition %s (0x%0.6X - 0x%0.6X) overlaps with %s (0x%0.6X - 0x%0.6X)' % \
									(part[0],part[1],part[2],all_part[0],all_part[1],all_part[2]) + col_e, True])
					
		# Show CSE LT partition info on demand (-dfpt)
		if param.fpt_disp : print('%s\n' % pt_dcselt)
	
		# Detect ROMB code within CSE LT (IFWI 1.6 & 1.7, must be after cse_lt_size adjustment)
		if b'Non-Intel Root Key' in reading[cse_lt_off:cse_lt_off + cse_lt_size] :
			note_stor.append([col_y + 'Note: CSE LT seems to include ROM-Bypass code!' + col_e, True])
	
	# Detect all $FPT and/or BPDT starting offsets (both allowed/needed)
	if fd_me_rgn_exist :
		# $FPT detection based on FD with Engine/Graphics region (limits false positives from IE or CSTXE Engine/ROMB & DevExp1/Init)
		fpt_matches_init = list(fpt_pat.finditer(reading[me_fd_start:me_fd_start + me_fd_size]))
		
		# Detect ROMB code within FD > Engine/Graphics (IFWI 2.0, FD > DevExp & No CSE LT & CSE/UEFI in FD > BIOS & ROMB in FD > Engine)
		if fd_devexp_rgn_exist and not cse_lt_struct and fd_bios_rgn_exist and bpdt_pat.search(reading[bios_fd_start:bios_fd_start + 0x100]) \
		and b'Non-Intel Root Key' in reading[me_fd_start:me_fd_start + me_fd_size] :
			note_stor.append([col_y + 'Note: FD Engine/Graphics region seems to include ROM-Bypass code!' + col_e, True])
	else :
		# FD with Engine/Graphics region not found or multiple FD detected, scan entire file (could lead to false positives)
		fpt_matches_init = list(fpt_pat.finditer(reading))
		
	# No Variant known yet but, if possible, get CSE Stage 1 Info for false positive removal via special ext_anl _Stage1 mode
	man_mod_names,fptemp_info = ext_anl(reading, '$MN2_Stage1', start_man_match, file_end, ['CSME',0,0,0,0,0,0,'CSE ME'], None, [[],''], [[],-1,-1,-1])
	fptemp_exists = bool(man_mod_names and man_mod_names[0] == 'FTPR.man' and fptemp_info[0]) # Detect if CSE FTPR > fptemp module exists
	
	# Adjust $FPT matches, ignore known false positives
	for fpt_match in fpt_matches_init :
		fpt_match_start = me_fd_start + fpt_match.start() if fd_me_rgn_exist else fpt_match.start()
		if fptemp_exists and fptemp_info[2] > fpt_match_start >= fptemp_info[1] : pass # CSE FTPR > fptemp
		elif cse_lt_struct and cse_lt_off < fpt_match_start < fpt_pat_bgn : pass # CSE LT Padding > $FPT
		elif cse_lt_struct and cse_lt_flags_red and fpt_match_start == cse_lt_part_all[0][1] + 0x1000 : pass # CSE LT Data Redundancy > $FPT
		elif cse_lt_struct and not cse_lt_part_all[5][4] and fpt_match_start == cse_lt_part_all[5][1] : pass # CSE Default Data > $FPT
		elif cse_lt_struct and not cse_lt_part_all[5][4] and fpt_match_start == cse_lt_part_all[5][1] + 0x1000 : pass # CSE Default Data Redundancy > $FPT
		else : fpt_matches.append(fpt_match)
	
	# Detect $FPT Firmware Starting Offset
	if len(fpt_matches) :
		rgn_exist = True # Set $FPT detection boolean
		
		fpt_count = len(fpt_matches) # Count $FPT matches
		
		# Set $FPT Start & End when no CSE LT Data was found
		if fpt_pat_end == 0 :
			(fpt_pat_bgn, fpt_pat_end) = fpt_matches[0].span() # Select the 1st $FPT match by default
			
			# Adjust $FPT offset if FD with Engine/Graphics region exists
			if fd_me_rgn_exist :
				fpt_pat_bgn += me_fd_start
				fpt_pat_end += me_fd_start
		
		# Analyze $FPT header
		pt_dfpt = ext_table([col_y + 'Name' + col_e, col_y + 'Owner' + col_e, col_y + 'Start' + col_e, col_y + 'Size' + col_e, col_y + 'End' + col_e,
				  col_y + 'Type' + col_e, col_y + 'ID' + col_e, col_y + 'Valid' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt_dfpt.title = col_y + 'Flash Partition Table' + col_e
		
		fpt_get = get_fpt(reading, fpt_pat_bgn)
		fpt_hdr = get_struct(reading, fpt_pat_bgn, fpt_get[0])
		
		fpt_part_num = fpt_hdr.NumPartitions
		fpt_version = fpt_get[1]
		fpt_length = fpt_hdr.HeaderLength
		fpt_chk_int = fpt_hdr.HeaderChecksum
		
		fpt_start = fpt_pat_bgn if fpt_pat_bgn == 0 else fpt_pat_bgn - 0x10
		
		if (cse_lt_struct or (fd_devexp_rgn_exist and reading[devexp_fd_start:devexp_fd_start + 0x4] == b'$FPT')) \
		and fpt_version in [0x20,0x21] and fpt_length == 0x20 :
			fpt_start = fpt_pat_bgn
		elif reading[fpt_pat_bgn - 0x1000:fpt_pat_bgn - 0xFA8] == b'\x00' * 0x48 + b'\xFF' * 0x10 \
		or reading[fpt_pat_bgn - 0x1000:fpt_pat_bgn - 0xFA0] == b'\x00' * 0x50 + b'\xFF' * 0x10 :
			fpt_start = fpt_pat_bgn
		elif fpt_version == 0x10 and fpt_length == 0x20 :
			fpt_start = fpt_pat_bgn
		
		fpt_step = fpt_pat_bgn + 0x20 # 0x20 $FPT entry size
		
		for i in range(0, fpt_part_num):
			cse_in_id = 0
			cse_in_id_str = '0000'
			
			fpt_entry = get_struct(reading, fpt_step, FPT_Entry)
			
			p_type,_,_,_,_,_,p_valid = fpt_entry.get_flags()
			
			p_name = fpt_entry.Name
			p_owner = fpt_entry.Owner
			p_offset = fpt_entry.Offset
			p_offset_min = min(p_offset,p_offset_min)
			p_offset_spi = fpt_start + fpt_entry.Offset
			p_size = fpt_entry.Size
			p_valid_print = not p_valid == 0xFF
			p_type_print = p_type_dict[p_type] if p_type in p_type_dict else 'Unknown'
			is_cpd = reading[p_offset_spi:p_offset_spi + 0x4] == b'$CPD'
			cpd_name = reading[p_offset_spi + 0xC:p_offset_spi + 0x10].strip(b'\x00')
			
			if p_name in [b'\xFF\xFF\xFF\xFF', b''] : p_name = '' # If appears, wrong NumPartitions
			elif p_name == b'\xE0\x15' : p_name = 'E0150020' # ME8 (E0150020)
			elif is_cpd and p_name != b'FTUP' : p_name = cpd_name.decode('utf-8','ignore')
			else : p_name = p_name.decode('utf-8','ignore')
			
			p_empty = bool(p_offset in (0xFFFFFFFF, 0) or p_size == 0 or p_size != 0xFFFFFFFF and reading[p_offset_spi:p_offset_spi + p_size] in (b'', p_size * b'\xFF'))
			
			if not p_empty and p_offset_spi < file_end :
				# Get CSE Partition Instance ID
				cse_in_id,_,_ = cse_part_inid(reading, p_offset_spi, ext_dict)
				cse_in_id_str = '%0.4X' % cse_in_id
				
				# Get ME LOCL/WCOD Partition Instance ID
				mn2_hdr = get_struct(reading, p_offset_spi, get_manifest(reading, p_offset_spi))
				if mn2_hdr.Tag in [b'$MN2',b'$MAN'] : # Sanity check
					mn2_len = mn2_hdr.HeaderLength * 4
					mod_name = reading[p_offset_spi + mn2_len:p_offset_spi + mn2_len + 0x8].strip(b'\x00').decode('utf-8')
					if mod_name in ['LOCL','WCOD'] :
						cse_in_id = reading[p_offset_spi + mn2_len + 0x15:p_offset_spi + mn2_len + 0x15 + 0xB].strip(b'\x00').decode('utf-8')
						cse_in_id_str = cse_in_id
			
			fpt_part_all.append([p_name, p_offset_spi, p_offset_spi + p_size, cse_in_id, p_type_print, p_valid_print, p_empty])
			
			# Store $FPT Partition info for -dfpt
			if param.fpt_disp :
				if p_owner in [b'\xFF\xFF\xFF\xFF', b''] : p_owner = '' # Missing
				else : p_owner = p_owner.decode('utf-8','ignore')
				
				if p_offset in [0xFFFFFFFF, 0] : p_offset_print = ''
				else : p_offset_print = '0x%0.6X' % p_offset_spi
				
				if p_size in [0xFFFFFFFF, 0] : p_size_print = ''
				else : p_size_print = '0x%0.6X' % p_size
				
				if p_offset_print == '' or p_size_print == '' : p_end_print = ''
				else : p_end_print = '0x%0.6X' % (p_offset_spi + p_size)
				
				pt_dfpt.add_row([p_name,p_owner,p_offset_print,p_size_print,p_end_print,p_type_print,cse_in_id_str,p_valid_print,p_empty])
			
			p_store_all.append([p_name, p_offset_spi, p_size]) # For $FPT Recovery/Operational adjustment
			
			# Detect if firmware has ROM-Bypass (ROMB) partition
			if p_name == 'ROMB' and not p_empty : fpt_romb_found = True
			
			# Detect if firmware has (CS)SPS Operational (OPRx/COD1) partition
			if p_name.startswith(('OPR','COD1')) and not p_empty : sps_opr_found = True
			
			# Detect if firmware has ROM Boot Extensions (RBEP) partition
			if p_name == 'RBEP' and not p_empty :
				rbep_found = True
				rbep_start = p_offset_spi
				
			# Detect if firmware has CSE MFS File System Partition
			if p_name in ('MFS','AFSP') and not p_empty :
				mfs_found = True
				mfs_start = p_offset_spi
				mfs_size = p_size
				mfs_is_afs = p_name == 'AFSP'
				
			# Detect if firmware has CSE MFSB File System Backup Partition
			if p_name == 'MFSB' and not p_empty :
				mfsb_found = True
				mfsb_start = p_offset_spi
				mfsb_size = p_size
			
			# Detect if firmware has CSE EFS File System Partition
			if p_name == 'EFS' and not p_empty :
				efs_found = True
				efs_start = p_offset_spi
				efs_size = p_size
				
			# Detect if firmware has FITC File System Configuration Partition
			if p_name == 'FITC' :
				if not p_empty : fitc_found = True
				fitc_size = p_size
			
			# Detect if firmware has CDMD Partition
			if p_name == 'CDMD' :
				if not p_empty : cdmd_found = True
				cdmd_size = p_size
			
			# Detect if firmware has valid OEM Unlock/Security Token (UTOK/STKN)
			if p_name in ['UTOK','STKN'] and not p_empty and p_offset_spi < file_end and reading[p_offset_spi:p_offset_spi + 0x10] != b'\xFF' * 0x10 : utok_found = True
			
			# Detect if CSE firmware has valid and non-placeholder (VEN_ID BCCB) OEM Key Manager Partition (OEMP)
			if p_name == 'OEMP' and not p_empty and p_offset_spi < file_end and reading[p_offset_spi:p_offset_spi + 0x10] != b'\xFF' * 0x10 \
			and not bccb_pat.search(reading[p_offset_spi:p_offset_spi + 0x50]) : oemp_found = True
			
			if 0 < p_offset_spi < p_max_size and 0 < p_size < p_max_size : eng_fw_end = p_offset_spi + p_size
			else : eng_fw_end = p_max_size
			
			# Store last partition (max offset)
			if p_offset_last < p_offset_spi < p_max_size:
				p_offset_last = p_offset_spi
				p_end_last = eng_fw_end
			
			fpt_step += 0x20 # Next $FPT entry
		
		# Adjust Manifest to Recovery (ME/TXE) or Operational (SPS) partition based on $FPT
		if fpt_count <= 2 :
			# This does not work with Intel Engine Capsule images because they have multiple $FPT and Engine CODE
			# regions. It cannot be removed because MEA needs to jump to COD1/OPR1 for (CS)SPS parsing. The Intel
			# POR is to have at most two $FPT at normal (CS)SPS images, Main ($FPT) and Backup (FPTB), so MEA skips
			# this adjustment for images with more than two $FPT hits. The drawback is that MEA detects FTPR instead
			# of COD1/OPR1 at these Intel Capsule images. A proper detection/extractor could be added in the future.
			for p_rec_fix in p_store_all :
				# For ME 2-5 & SPS 1, pick CODE if RCVY or COD1 are not present
				# For SPS, pick Operational (COD1/OPR1) instead of Recovery (CODE/FTPR)
				if p_rec_fix[0] in ['FTPR', 'RCVY', 'OPR1', 'OPR', 'COD1'] or (p_rec_fix[0] == 'CODE' and not any(p in ('RCVY', 'COD1') for p in p_store_all)) :
					# Only if partition exists at file (counter-example: sole $FPT etc)
					if p_rec_fix[1] + p_rec_fix[2] <= file_end :
						rec_man_match = man_pat.search(reading[p_rec_fix[1]:p_rec_fix[1] + p_rec_fix[2]])
						
						if rec_man_match :
							# Store the old/initial SPS Manifest (i.e. Recovery instead of Operational) for RSA Signature validation
							old_mn2_off = start_man_match - 0x1B
							old_mn2_hdr = get_struct(reading, old_mn2_off, get_manifest(reading, old_mn2_off))
							
							# Adjust new/correct Manifest match range (start, end)
							(start_man_match, end_man_match) = rec_man_match.span()
							start_man_match += p_rec_fix[1] + 0xB # Add Recovery/Operational offset and 8680.{9} sanity check before .$MN2 or .$MAN
							end_man_match += p_rec_fix[1]
		else :
			# More than two $FPT detected, probably Intel Engine Capsule image
			mfs_found = False
			mfsb_found = False
	
	# Check CSE Redundancy (Boot & Data)
	if cse_lt_struct and cse_lt_flags_red :
		cse_red_info[0] = True # CSE Redundancy is enabled
		data_part_data = reading[cse_lt_part_all[0][1]:cse_lt_part_all[0][3]]
		boot1_part_data = reading[cse_lt_part_all[1][1]:cse_lt_part_all[1][3]]
		boot2_part_data = reading[cse_lt_part_all[2][1]:cse_lt_part_all[2][3]]
		data_fpt_size = p_offset_min - 0x1000 if p_offset_min > 0x1000 else p_offset_min
		
		# Boot Partition 2 must be a copy of Boot Partition 1
		if boot1_part_data != boot2_part_data :
			cse_red_info[1] = False # Boot Partition CSE Redundancy check failed
			err_stor.append([col_r + 'Error: CSE Redundancy check failed, Boot 1 != Boot 2!' + col_e, True])
		
		# Data Partition, when present, must have a copy of its $FPT at 0x1000
		# The backup $FPT may not be 0x1000, compare data up until 1st partition
		if not cse_lt_part_all[0][4] and data_part_data[:data_fpt_size] != data_part_data[0x1000:0x1000 + data_fpt_size] :
			cse_red_info[2] = False # Data Partition $FPT Redundancy check failed
			err_stor.append([col_r + 'Error: CSE Redundancy check failed, Data $FPT != Data $FPT Backup!' + col_e, True])
	
	# Scan for IFWI/BPDT Ranges
	if cse_lt_struct :
		# Search Boot Partitions only when CSE LT exists (fast & robust)
		for part in cse_lt_part_all :
			if part[0].startswith('Boot') and not part[4] : # Non-Empty CSE LT Boot Partition (skip Data/MFS)
				bpdt_match = bpdt_pat.search(reading[part[1]:part[3]]) # BPDT detection
				if bpdt_match : bpdt_matches.append((bpdt_match.start() + part[1], bpdt_match.end() + part[1])) # Store BPDT range, relative to 0x0
	else :
		# Search entire image when no CSE LT exists (slower & false positive prone)
		bpdt_match = list(bpdt_pat.finditer(reading)) # BPDT detection
		for match in bpdt_match :
			if mfs_found and mfs_start <= match.start() < mfs_start + mfs_size : continue # Skip BPDT within MFS (e.g. 008 > fwupdate> fwubpdtinfo)
			if mfsb_found and mfsb_start <= match.start() < mfsb_start + mfsb_size : continue # Skip BPDT within MFSB (e.g. 008 > fwupdate> fwubpdtinfo)
			bpdt_matches.append(match.span()) # Store all BPDT ranges, already relative to 0x0
	
	# Parse IFWI/BPDT Ranges
	for ifwi_bpdt in range(len(bpdt_matches)):
		
		ifwi_exist = True # Set IFWI/BPDT detection boolean
		
		bpdt_pat_bgn = bpdt_matches[ifwi_bpdt][0] # Get BPDT Start Offset via bpdt_matches index
		
		if bpdt_pat_bgn in s_bpdt_all : continue # Skip already parsed S-BPDT (Type 5)
		
		bpdt_hdr = get_struct(reading, bpdt_pat_bgn, get_bpdt(reading, bpdt_pat_bgn))
		
		# Store Primary BPDT info to show at CSE unpacking
		if param.cse_unpack :
			bpdt_hdr_all.append(bpdt_hdr.hdr_print())
			bpdt_data_all.append(reading[bpdt_pat_bgn:bpdt_pat_bgn + 0x200]) # Min size 0x200 (no size at Header, min is enough though)
		
		# Analyze BPDT header
		bpdt_step = bpdt_pat_bgn + 0x18 # 0x18 BPDT Header size
		bpdt_part_num = bpdt_hdr.DescCount
		
		pt_dbpdt = ext_table([col_y + 'Name' + col_e, col_y + 'Type' + col_e, col_y + 'Partition' + col_e, col_y + 'Start' + col_e,
				  col_y + 'Size' + col_e, col_y + 'End' + col_e, col_y + 'ID' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt_dbpdt.title = col_y + 'Boot Partition Descriptor Table' + col_e
		
		for i in range(0, bpdt_part_num):
			cse_in_id = 0
			
			bpdt_entry = get_struct(reading, bpdt_step, BPDT_Entry)
			
			p_type = bpdt_entry.Type
			p_offset = bpdt_entry.Offset
			p_offset_spi = bpdt_pat_bgn + p_offset
			p_size = bpdt_entry.Size
			is_cpd = reading[p_offset_spi:p_offset_spi + 0x4] == b'$CPD'
			cpd_name = reading[p_offset_spi + 0xC:p_offset_spi + 0x10].strip(b'\x00').decode('utf-8','ignore')
			
			p_empty = bool(p_offset in (0xFFFFFFFF, 0) or p_size in (0xFFFFFFFF, 0) or reading[p_offset_spi:p_offset_spi + p_size] in (b'', p_size * b'\xFF'))
			
			if is_cpd : p_name = cpd_name
			elif p_type in bpdt_dict : p_name = bpdt_dict[p_type]
			else : p_name = 'Unknown'
			
			if not p_empty and p_offset_spi < file_end :
				# Get CSE Partition Instance ID
				cse_in_id,_,_ = cse_part_inid(reading, p_offset_spi, ext_dict)
			
			# Store BPDT Partition info for -dfpt
			if param.fpt_disp :
				if p_offset in [0xFFFFFFFF, 0] : p_offset_print = ''
				else : p_offset_print = '0x%0.6X' % p_offset_spi
				
				if p_size in [0xFFFFFFFF, 0] : p_size_print = ''
				else : p_size_print = '0x%0.6X' % p_size
				
				if p_offset_print == '' or p_size_print == '' : p_end_print = ''
				else : p_end_print = '0x%0.6X' % (p_offset_spi + p_size)
				
				pt_dbpdt.add_row([p_name,'%0.2d' % p_type,'Primary',p_offset_print,p_size_print,p_end_print,'%0.4X' % cse_in_id,p_empty])
			
			# Detect if IFWI Primary includes ROM Boot Extensions (RBEP) partition
			if p_name == 'RBEP' and not p_empty :
				rbep_found = True
				rbep_start = p_offset_spi
			
			# Detect if IFWI Primary includes Power Management Controller (PMCP/PCOD) partition
			if p_name in ('PMCP','PCOD') and not p_empty :
				pmcp_fwu_found = False
				pmcp_size = p_size
				
				_,_,_,pmc_vcn,_,_,_,_,_,_,_,_,pmc_mn2_ver,_,pmc_ext15_info,_,_,_,_ = \
				ext_anl(reading, '$CPD', p_offset_spi, file_end, ['PMC',-1,-1,-1,-1,-1,-1,'PMC'], None, [[],''], [[],-1,-1,-1])
				
				pmc_all_init.append([pmc_vcn,pmc_mn2_ver,pmc_ext15_info,pmcp_size])
				
			# Detect if IFWI Primary includes Platform Controller Hub Configuration (PCHC) partition
			if p_name == 'PCHC' and not p_empty :
				pchc_fwu_found = False
				pchc_size = p_size
				
				_,_,_,pchc_vcn,_,_,_,_,_,_,_,_,pchc_mn2_ver,_,pchc_ext15_info,_,_,_,_ = \
				ext_anl(reading, '$CPD', p_offset_spi, file_end, ['PCHC',-1,-1,-1,-1,-1,-1,'PCHC'], None, [[],''], [[],-1,-1,-1])
				
				pchc_all_init.append([pchc_vcn,pchc_mn2_ver,pchc_ext15_info,pchc_size])
				
			# Detect if IFWI Primary includes USB Type C Physical (PHY) partition
			if p_name in ('PPHY','NPHY','SPHY','PHYP') and not p_empty :
				phy_fwu_found = False
				phy_size = p_size
				
				_,_,_,phy_vcn,_,_,_,_,_,_,_,_,phy_mn2_ver,_,phy_ext15_info,_,_,_,_ = \
				ext_anl(reading, '$CPD', p_offset_spi, file_end, ['PHY',-1,-1,-1,-1,-1,-1,'PHY'], None, [[],''], [[],-1,-1,-1])
				
				phy_all_init.append([phy_vcn,phy_mn2_ver,phy_ext15_info,phy_size])
				
			# Detect if IFWI Primary includes CSE MFS File System partition (Not POR, just in case)
			if p_name in ('MFS','AFSP') and not p_empty :
				mfs_found = True
				mfs_start = p_offset_spi
				mfs_size = p_size
				mfs_is_afs = p_name == 'AFSP'
				
			# Detect if IFWI Primary includes CSE File System Backup partition (Not POR, just in case)
			if p_name == 'MFSB' and not p_empty :
				mfsb_found = True
				mfsb_start = p_offset_spi
				mfsb_size = p_size
				
			# Detect if IFWI Primary includes CSE EFS File System partition (Not POR, just in case)
			if p_name == 'EFS' and not p_empty :
				efs_found = True
				efs_start = p_offset_spi
				efs_size = p_size
				
			# Detect if IFWI Primary includes FITC File System Configuration partition (Not POR, just in case)
			if p_name == 'FITC' :
				if not p_empty : fitc_found = True
				fitc_size = p_size
			
			# Detect if IFWI Primary includes CDMD partition (Not POR, just in case)
			if p_name == 'CDMD' :
				if not p_empty : cdmd_found = True
				cdmd_size = p_size
			
			if p_type == 5 and not p_empty and p_offset_spi < file_end and reading[p_offset_spi:p_offset_spi + 0x2] == b'\xAA\x55' : # Secondary BPDT (S-BPDT)
				s_bpdt_hdr = get_struct(reading, p_offset_spi, get_bpdt(reading, p_offset_spi))
				
				# Store Secondary BPDT info to show at CSE unpacking
				if param.cse_unpack :
					bpdt_hdr_all.append(s_bpdt_hdr.hdr_print())
					bpdt_data_all.append(reading[bpdt_pat_bgn:bpdt_pat_bgn + 0x200]) # Min size 0x200 (no size at Header, min is enough though)
				
				s_bpdt_all.append(p_offset_spi) # Store parsed S-BPDT offset to skip at IFWI/BPDT Starting Offsets
				
				s_bpdt_step = p_offset_spi + 0x18 # 0x18 S-BPDT Header size
				s_bpdt_part_num = s_bpdt_hdr.DescCount
				
				for j in range(0, s_bpdt_part_num):
					cse_in_id = 0
					
					s_bpdt_entry = get_struct(reading, s_bpdt_step, BPDT_Entry)
					
					s_p_type = s_bpdt_entry.Type
					s_p_offset = s_bpdt_entry.Offset
					s_p_offset_spi = bpdt_pat_bgn + s_p_offset
					s_p_size = s_bpdt_entry.Size
					s_is_cpd = reading[s_p_offset_spi:s_p_offset_spi + 0x4] == b'$CPD'
					s_cpd_name = reading[s_p_offset_spi + 0xC:s_p_offset_spi + 0x10].strip(b'\x00').decode('utf-8','ignore')
					
					s_p_empty = bool(s_p_offset in (0xFFFFFFFF, 0) or s_p_size in (0xFFFFFFFF, 0) or reading[s_p_offset_spi:s_p_offset_spi + s_p_size] in (b'', s_p_size * b'\xFF'))
					
					if s_is_cpd : s_p_name = s_cpd_name
					elif s_p_type in bpdt_dict : s_p_name = bpdt_dict[s_p_type]
					else : s_p_name = 'Unknown'
					
					if not s_p_empty and s_p_offset_spi < file_end :
						cse_in_id,_,_ = cse_part_inid(reading, s_p_offset_spi, ext_dict)
					
					# Store BPDT Partition info for -dfpt
					if param.fpt_disp :
						if s_p_offset in [0xFFFFFFFF, 0] : s_p_offset_print = ''
						else : s_p_offset_print = '0x%0.6X' % s_p_offset_spi
						
						if s_p_size in [0xFFFFFFFF, 0] : s_p_size_print = ''
						else : s_p_size_print = '0x%0.6X' % s_p_size
						
						if s_p_offset_print == '' or s_p_size_print == '' : s_p_end_print = ''
						else : s_p_end_print = '0x%0.6X' % (s_p_offset_spi + s_p_size)
						
						pt_dbpdt.add_row([s_p_name,'%0.2d' % s_p_type,'Secondary',s_p_offset_print,s_p_size_print,s_p_end_print,'%0.4X' % cse_in_id,s_p_empty])
						
					# Detect if IFWI Secondary includes ROM Boot Extensions (RBEP) partition
					if s_p_name == 'RBEP' and not s_p_empty :
						rbep_found = True
						rbep_start = s_p_offset_spi
					
					# Detect if IFWI Secondary includes Power Management Controller (PMCP/PCOD) partition
					if s_p_name in ('PMCP','PCOD') and not s_p_empty :
						pmcp_fwu_found = False
						pmcp_size = s_p_size
						
						_,_,_,pmc_vcn,_,_,_,_,_,_,_,_,pmc_mn2_ver,_,pmc_ext15_info,_,_,_,_ = \
						ext_anl(reading, '$CPD', s_p_offset_spi, file_end, ['PMC',-1,-1,-1,-1,-1,-1,'PMC'], None, [[],''], [[],-1,-1,-1])
						
						pmc_all_init.append([pmc_vcn,pmc_mn2_ver,pmc_ext15_info,pmcp_size])
					
					# Detect if IFWI Secondary includes Platform Controller Hub Configuration (PCHC) partition
					if s_p_name == 'PCHC' and not s_p_empty :
						pchc_fwu_found = False
						pchc_size = s_p_size
						
						_,_,_,pchc_vcn,_,_,_,_,_,_,_,_,pchc_mn2_ver,_,pchc_ext15_info,_,_,_,_ = \
						ext_anl(reading, '$CPD', s_p_offset_spi, file_end, ['PCHC',-1,-1,-1,-1,-1,-1,'PCHC'], None, [[],''], [[],-1,-1,-1])
						
						pchc_all_init.append([pchc_vcn,pchc_mn2_ver,pchc_ext15_info,pchc_size])
						
					# Detect if IFWI Secondary includes USB Type C Physical firmware (PHY) partition
					if s_p_name in ('PPHY','NPHY','SPHY','PHYP') and not s_p_empty :
						phy_fwu_found = False
						phy_size = s_p_size
						
						_,_,_,phy_vcn,_,_,_,_,_,_,_,_,phy_mn2_ver,_,phy_ext15_info,_,_,_,_ = \
						ext_anl(reading, '$CPD', s_p_offset_spi, file_end, ['PHY',-1,-1,-1,-1,-1,-1,'PHY'], None, [[],''], [[],-1,-1,-1])
						
						phy_all_init.append([phy_vcn,phy_mn2_ver,phy_ext15_info,phy_size])
					
					# Detect if IFWI Secondary includes CSE MFS File System partition (Not POR, just in case)
					if s_p_name in ('MFS','AFSP') and not s_p_empty :
						mfs_found = True
						mfs_start = s_p_offset_spi
						mfs_size = s_p_size
						mfs_is_afs = s_p_name == 'AFSP'
						
					# Detect if IFWI Secondary includes CSE File System Backup partition (Not POR, just in case)
					if s_p_name == 'MFSB' and not s_p_empty :
						mfsb_found = True
						mfsb_start = s_p_offset_spi
						mfsb_size = s_p_size
					
					# Detect if IFWI Secondary includes CSE EFS File System partition (Not POR, just in case)
					if s_p_name == 'EFS' and not s_p_empty :
						efs_found = True
						efs_start = s_p_offset_spi
						efs_size = s_p_size
						
					# Detect if IFWI Secondary includes FITC File System Configuration partition (Not POR, just in case)
					if s_p_name == 'FITC' :
						if not s_p_empty : fitc_found = True
						fitc_size = s_p_size
					
					# Detect if IFWI Secondary includes CDMD partition (Not POR, just in case)
					if s_p_name == 'CDMD' :
						if not s_p_empty : cdmd_found = True
						cdmd_size = s_p_size
					
					# Store all Secondary BPDT entries for extraction
					bpdt_part_all.append([s_p_name,s_p_offset_spi,s_p_offset_spi + s_p_size,s_p_type,s_p_empty,'Secondary',cse_in_id])
					
					s_bpdt_step += 0xC # 0xC BPDT Entry size
			
			# Store all Primary BPDT entries for extraction
			bpdt_part_all.append([p_name,p_offset_spi,p_offset_spi + p_size,p_type,p_empty,'Primary',cse_in_id])
			
			bpdt_step += 0xC # 0xC BPDT Entry size
		
		# Show BPDT Partition info on demand (-dfpt)
		if param.fpt_disp : print('%s\n' % pt_dbpdt)
	
	# Perform actions on total stored BPDT entries
	for part in bpdt_part_all :
		# Detect if IFWI includes CSSPS Operational (OPRx) partition
		if part[3] == 2 and not part[4] and reading[part[1] + 0xC:part[1] + 0xF] == b'OPR' : sps_opr_found = True
		
		# Adjust Manifest to Recovery (CSME/CSTXE) or Operational (CSSPS) partition based on BPDT
		if part[3] == 2 and not part[4] and part[1] < file_end : # Type = CSE_BUP, non-Empty, Start < EOF
			# Only if partition exists at file (counter-example: sole IFWI etc)
			if part[1] + (part[2] - part[1]) <= file_end :
				rec_man_match = man_pat.search(reading[part[1]:part[1] + (part[2] - part[1])])
				
				if rec_man_match :
					(start_man_match, end_man_match) = rec_man_match.span()
					start_man_match += part[1] + 0xB # Add CSE_BUP offset and 8680.{9} sanity check before .$MN2
					end_man_match += part[1]
	
		# Detect if CSE firmware has valid OEM Unlock/Security Token (UTOK/STKN)
		if part[0] in ['UTOK','STKN'] and not part[4] and part[1] < file_end and reading[part[1]:part[1] + 0x10] != b'\xFF' * 0x10 : utok_found = True
		
		# Detect if CSE firmware has valid and non-placeholder (VEN_ID BCCB) OEM Key Manager Partition (OEMP)
		if part[0] == 'OEMP' and not part[4] and part[1] < file_end and reading[part[1]:part[1] + 0x10] != b'\xFF' * 0x10 \
		and not bccb_pat.search(reading[part[1]:part[1] + 0x50]) : oemp_found = True
	
		# Detect BPDT partition overlaps
		for all_part in bpdt_part_all :
			# Partition A starts before B but ends after B start
			# Ignore partitions which have empty offset or size
			# Ignore DLMP partition which overlaps by Intel design
			if not part[4] and not all_part[4] and not any(s in [0,0xFFFFFFFF] for s in (part[1],part[2],all_part[1],all_part[2])) \
			and part[0] not in ['S-BPDT','DLMP'] and all_part[0] not in ['S-BPDT','DLMP'] and (part[1] < all_part[1] < part[2]) :
				err_stor.append([col_r + 'Error: BPDT partition %s (0x%0.6X - 0x%0.6X) overlaps with %s (0x%0.6X - 0x%0.6X)' % \
								(part[0],part[1],part[2],all_part[0],all_part[1],all_part[2]) + col_e, True])
	
		# Ignore Flash Descriptor OEM backup at BPDT > OBBP > NvCommon (HP)
		if part[0] == 'OBBP' and not part[4] and fd_pat.search(reading[part[1]:part[2]]) : fd_count -= 1
	
	# Parse OROM/PCIR Images, only if GSC OROM firmware is detected
	orom_match = list(orom_pat.finditer(reading)) if is_orom_img else [] # OROM/PCIR detection
	for match in orom_match :
		orom_pat_bgn = match.start() # Get OROM start offset
		
		orom_struct_size = ctypes.sizeof(GSC_OROM_Header) # Get OROM Header Structure Size
		orom_hdr_data = reading[orom_pat_bgn:orom_pat_bgn + orom_struct_size] # Store OROM Header Structure Contents
		orom_hdr = get_struct(orom_hdr_data, 0, GSC_OROM_Header) # Get OROM Header Structure
		orom_hdr_p = orom_hdr.gsc_print() # Get OROM Header Structure Info
		
		pcir_off = orom_pat_bgn + orom_hdr.PCIDataHdrOff # Get PCIR offset via OROM Header
		pcir_struct_size = ctypes.sizeof(GSC_OROM_PCI_Data) # Get MEA OROM PCI Data Structure Size
		pcir_hdr_size = int.from_bytes(reading[pcir_off + 0xA:pcir_off + 0xC], 'little') # Get Image OROM PCI Data Size
		pcir_hdr_data = reading[pcir_off:pcir_off + pcir_hdr_size] # Store OROM PCI Data Structure Contents
		if pcir_hdr_size < pcir_struct_size : pcir_hdr_data += b'\x00' * (pcir_struct_size - pcir_hdr_size) # Adjust shorter PCIR
		pcir_hdr = get_struct(pcir_hdr_data, 0, GSC_OROM_PCI_Data) # Get OROM PCI Data Structure
		pcir_hdr_p = pcir_hdr.gsc_print() # Get OROM PCI Data Structure Info
		
		orom_pci_size += orom_hdr.ImageSize * 512 # Calculate OROM IUP Size by appending all OROM/PCIR Image Sizes
		
		# Calculate OROM IUP Size by appending all $CPD Partition and OROM/PCIR Structure Sizes
		data_off = max(orom_hdr.PCIDataHdrOff + pcir_hdr.PCIDataHdrLen, orom_hdr.EFIImageOffset, orom_hdr.OROMPayloadOff) # Data Offset
		if reading[orom_pat_bgn + data_off:orom_pat_bgn + data_off + 0x4] == b'$CPD' : # Check if Data is actually an OROM $CPD Partition
			orom_cpd_size += orom_pat_bgn - orom_match[0].start() - orom_cpd_size # Append Size between current & previous OROM $CPD Partitions
			orom_cpd_size += data_off # Append Size between current OROM/PCIR Headers & Data Payload (OROM $CPD Partition)
			orom_cpd_size += cpd_size_calc(reading[data_off + orom_pat_bgn:], 0, 0x1000) # Append Size of current OROM $CPD Partition
		
		# Show OROM/PCIR Image info on demand (-dfpt)
		if param.fpt_disp : print('%s\n%s\n' % (orom_hdr_p, pcir_hdr_p))
		
		# Store OROM/PCIR Image info to show at OROM unpacking
		if param.cse_unpack : orom_hdr_all.extend([orom_hdr_p, pcir_hdr_p])
	
	# Scan $MAN/$MN2 Manifest, for basic info only
	mn2_ftpr_hdr = get_struct(reading, start_man_match - 0x1B, get_manifest(reading, start_man_match - 0x1B))
	
	major = mn2_ftpr_hdr.Major
	minor = mn2_ftpr_hdr.Minor
	hotfix = mn2_ftpr_hdr.Hotfix
	build = mn2_ftpr_hdr.Build
	svn = mn2_ftpr_hdr.SVN
	if hasattr(mn2_ftpr_hdr, 'VCN') : vcn = mn2_ftpr_hdr.VCN
	day = mn2_ftpr_hdr.Day
	month = mn2_ftpr_hdr.Month
	year = mn2_ftpr_hdr.Year
	date = '%0.4X-%0.2X-%0.2X' % (year, month, day)
	
	# Get & Hash the Manifest RSA Public Key and Signature
	rsa_block_off = end_man_match + 0x60 # RSA Block Offset
	rsa_key_len = mn2_ftpr_hdr.PublicKeySize * 4 # RSA Key/Signature Length
	rsa_exp_len = mn2_ftpr_hdr.ExponentSize * 4 # RSA Exponent Length
	rsa_key = reading[rsa_block_off:rsa_block_off + rsa_key_len] # RSA Public Key
	rsa_key_hash = get_hash(rsa_key, 0x20) # SHA-256 of RSA Public Key
	rsa_sig = reading[rsa_block_off + rsa_key_len + rsa_exp_len:rsa_block_off + rsa_key_len * 2 + rsa_exp_len] # RSA Signature
	rsa_sig_hash = get_hash(rsa_sig, 0x20) # SHA-256 of RSA Signature
	
	# Detect Variant/Family
	variant, variant_p, var_rsa_db = get_variant(reading, mn2_ftpr_hdr, start_man_match, end_man_match, rsa_key_hash,
												 [year, month, day], [major, minor, hotfix, build])
	
	# Get the Proper + Initial Manifest Info for (CS)SPS EXTR (FTPR + OPR1)
	if variant in ('SPS','CSSPS') and sps_opr_found :
		# Hash the merger of the FTPR & OPR RSA Signatures at EXTR
		rsa_block_off_i = init_man_match[1] + 0x60 # Initial (FTPR) RSA Block Offset
		rsa_sig_i = reading[rsa_block_off_i + rsa_key_len + rsa_exp_len:rsa_block_off_i + rsa_key_len * 2 + rsa_exp_len] # Initial (FTPR) RSA Signature
		rsa_sig_i_hash = get_hash(rsa_sig_i, 0x20) # SHA-256 of Initial (FTPR) RSA Signature
		rsa_sig_s = rsa_sig_i + rsa_sig if rsa_sig != rsa_sig_i else rsa_sig # Proper (OPR1) + Initial (FTPR) RSA Signatures
		
		# Ignore the EXTR at FTPR & OPR Firmware Version mismatch (must be before new/merged EXTR rsa_sig_hash)
		sps_ver_rec = reading[init_man_match[1] + 0x4:init_man_match[1] + 0xC] # Initial/Recovery (FTPR) Firmware Version
		sps_ver_opr = reading[end_man_match + 0x4:end_man_match + 0xC] # Proper/Operational (OPR1) Firmware Version
		if (sps_ver_rec != sps_ver_opr) and rsa_sig_i_hash in mea_db_read and rsa_sig_hash in mea_db_read : sps_extr_ignore = True
		
		rsa_sig_hash = get_hash(rsa_sig_s, 0x20) # SHA-256 of Proper (OPR1) + Initial (FTPR) RSA Signatures
	
	# Detect & Scan $MAN/$MN2 Manifest via Variant, for accurate info
	mn2_ftpr_hdr = get_struct(reading, start_man_match - 0x1B, get_manifest(reading, start_man_match - 0x1B))
	
	# Detect $MN2 Manifest Manifest Extension Utility version, if applicable
	if hasattr(mn2_ftpr_hdr, 'MEU_Major') and mn2_ftpr_hdr.MEU_Major not in (0,0xFFFF) :
		# noinspection PyStringFormat
		mn2_meu_ver = '%d.%d.%d.%0.4d' % (mn2_ftpr_hdr.MEU_Major,mn2_ftpr_hdr.MEU_Minor,mn2_ftpr_hdr.MEU_Hotfix,mn2_ftpr_hdr.MEU_Build)
	
	# Detect RSA Public Key Recognition
	if not var_rsa_db : err_stor.append([col_r + 'Error: Unknown %s %d.%d RSA Public Key!' % (variant, major, minor) + col_e, True])
	
	# Detect (CS)SPS Old/Initial RSA Signature Validity
	if variant.endswith('SPS') and old_mn2_hdr :
		old_man_valid = rsa_sig_val(old_mn2_hdr, reading, old_mn2_off)
		if not old_man_valid[0] :
			rsa_check = bool([old_man_valid[1],old_man_valid[2]] not in cse_known_bad_hashes) # Ignore known bad RSA Signatures
			err_stor.append([col_r + 'Error: Invalid %s %d.%d RSA Signature (Recovery)!' % (variant, major, minor) + col_e, rsa_check])
	
	# Detect RSA Signature Validity
	man_valid = rsa_sig_val(mn2_ftpr_hdr, reading, start_man_match - 0x1B)
	if not man_valid[0] :
		rsa_check = bool([man_valid[1],man_valid[2]] not in cse_known_bad_hashes) # Ignore known bad RSA Signatures
		err_stor.append([col_r + 'Error: Invalid %s %d.%d RSA Signature!' % (variant, major, minor) + col_e, rsa_check])
	
	if rgn_exist :
		
		# Multiple Backup $FPT header bypass at SPS1/SPS4 (DFLT/FPTB)
		if variant == 'CSSPS' or (variant,major) == ('SPS',1) and fpt_count % 2 == 0 : fpt_count /= 2
		
		# Last/Uncharted partition scanning inspired by Lordkag's UEFIStrip
		# ME2-ME6 don't have size for last partition, scan its submodules
		if p_end_last == p_max_size :
			mn2_hdr = get_struct(reading, p_offset_last, get_manifest(reading, p_offset_last))
			mod_start = p_offset_last + mn2_hdr.HeaderLength * 4 + 0xC
			
			# ME 6
			if mn2_hdr.Tag == b'$MN2' :
				for _ in range(mn2_hdr.NumModules) :
					mme_mod = get_struct(reading, mod_start, MME_Header_New)
					
					if mme_mod.Tag != b'$MME' : break # Sanity check
					
					mod_size = mme_mod.SizeComp if mme_mod.SizeComp else mme_mod.SizeUncomp
					
					mod_end = p_offset_last + mme_mod.Offset_MN2 + mod_size
					
					if mod_end > mod_end_max : mod_end_max = mod_end # In case modules are not offset sorted
					
					mod_start += 0x60
			
			# ME 2-5
			elif mn2_hdr.Tag == b'$MAN' :
				mod_size_all = 0
				
				for _ in range(mn2_hdr.NumModules) :
					mme_mod = get_struct(reading, mod_start, MME_Header_Old)
					
					if mme_mod.Tag != b'$MME' : break # Sanity check
					
					mod_size_all += mme_mod.Size
					
					mod_start += 0x50
				
				mod_end_max = mod_start + 0x50 + 0xC + mod_size_all # Last $MME + $MME size + $SKU size + all $MOD sizes
			
			# For Engine/Graphics alignment & size, remove fpt_start (included in mod_end_max < mod_end < p_offset_last)
			eng_fw_align -= (mod_end_max - fpt_start) % 0x1000 # 4K alignment Size of entire Engine/Graphics firmware
			
			if eng_fw_align != 0x1000 :
				eng_fw_end = mod_end_max + eng_fw_align - fpt_start
				
				file_has_align = min(eng_fw_align, file_end - mod_end_max) # Check whatever alignment padding is actually available in file
				file_bad_align = reading[mod_end_max:mod_end_max + file_has_align] not in [b'', b'\xFF' * file_has_align] # Data in alignment padding bool
				if fpt_start == 0 and file_has_align > 0 and file_bad_align :
					warn_stor.append([col_m + 'Warning: File has data in firmware 4K alignment padding!' + col_e, param.check])
				
				check_fw_align = 0x0 if mod_end_max > file_end else eng_fw_align - file_has_align
			else :
				eng_fw_end = mod_end_max - fpt_start
		
		# Last $FPT entry has size, scan for uncharted partitions
		else :
			# Due to 4K $FPT Partition alignment, Uncharted can start after 0x0 to 0x1000 bytes
			if not fd_exist and not cse_lt_struct and reading[p_end_last:p_end_last + 0x4] != b'$CPD' :
				p_end_last_back = p_end_last # Store $FPT-based p_end_last offset for CSME 12+ FWUpdate Support detection
				uncharted_match = cpd_pat.search(reading[p_end_last:p_end_last + 0x200B]) # Should be within the next 4-8K bytes
				if uncharted_match : p_end_last += uncharted_match.start() # Adjust p_end_last to actual Uncharted start
			
			# ME8-10 WCOD/LOCL but works for ME7, TXE1-2, SPS2-3 even though these end at last $FPT entry
			while reading[p_end_last + 0x1C:p_end_last + 0x20] == b'$MN2' :
				mod_in_id = '0000'
				
				mn2_hdr = get_struct(reading, p_end_last, get_manifest(reading, p_end_last))
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
				
				mn2_hdr = get_struct(reading, p_end_last, get_manifest(reading, p_end_last))
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
			
			# CSE WCOD/LOCL/DNXP
			while reading[p_end_last:p_end_last + 0x4] == b'$CPD' :
				cpd_hdr_struct, cpd_hdr_size = get_cpd(reading, p_end_last)
				cpd_hdr = get_struct(reading, p_end_last, cpd_hdr_struct)
				cpd_num = cpd_entry_num_fix(reading, p_end_last, cpd_hdr.NumModules, cpd_hdr_size)
				cpd_tag = cpd_hdr.PartitionName.strip(b'\x00').decode('utf-8','ignore')
				
				# Calculate partition size by the CSE Extension 03 or 16 (CSE_Ext_03 or CSE_Ext_16)
				# PartitionSize of CSE_Ext_03/16 is always 0x0A at CSTXE so check $CPD entries instead
				cse_in_id,_,cse_ext_part_size = cse_part_inid(reading, p_end_last, ext_dict)
				
				# Last charted $FPT region size can be larger than CSE_Ext_03/16.PartitionSize because of 4K pre-alignment by Intel
				# Calculate partition size by the $CPD entries (Needed for CSTXE, 2nd check for CSME/CSSPS)
				cpd_offset_last = 0 # Reset Last Module Offset at each $CPD
				for entry in range(cpd_num) : # Check all $CPD Entry Sizes (Manifest, Metadata, Modules)
					cpd_entry_hdr = get_struct(reading, p_end_last + cpd_hdr_size + entry * 0x18, CPD_Entry)
					cpd_entry_offset,_,_ = cpd_entry_hdr.get_flags()
					
					# Store last entry (max $CPD offset)
					if cpd_entry_offset > cpd_offset_last :
						cpd_offset_last = cpd_entry_offset
						cpd_end_last = cpd_entry_offset + cpd_entry_hdr.Size
				
				fpt_off_start = p_end_last # Store starting offset of current $FPT Partition for fpt_part_all
				
				# Take the largest partition size from the two checks
				# Add previous $CPD start for next size calculation
				p_end_last += max(cse_ext_part_size,cpd_end_last)
				
				# Store all $FPT Partitions, uncharted (Type Code, Valid, Not Empty)
				fpt_part_all.append([cpd_tag,fpt_off_start,p_end_last,cse_in_id,'Code',True,False])
				
				# Store $FPT Partition info for -dfpt
				if param.fpt_disp :
					pt_dfpt.add_row([cpd_tag,'','0x%0.6X' % fpt_off_start,'0x%0.6X' % (p_end_last - fpt_off_start),
					        '0x%0.6X' % p_end_last,'Code','%0.4X' % cse_in_id,True,False])
		
		# Show $FPT Partition info on demand (-dfpt)
		if param.fpt_disp : print('%s\n' % pt_dfpt)
		
		# Detect if uncharted $FPT partitions (IUPs) exist
		if len(fpt_part_all) > fpt_part_num : fwu_iup_exist = True
		
		# Detect $FPT partition overlaps
		for part in fpt_part_all :
			for all_part in fpt_part_all :
				# Partition A starts before B but ends after B start
				# Ignore partitions which have empty offset or size
				# Ignore FTUP combo partition (NFTP + WCOD + LOCL)
				# Ignore DLMP partition which overlaps by Intel design
				if not part[6] and not all_part[6] and not any(s in [0,0xFFFFFFFF] for s in (part[1],part[2],all_part[1],all_part[2])) \
				and part[0] not in ['FTUP','DLMP'] and all_part[0] not in ['FTUP','DLMP'] and (part[1] < all_part[1] < part[2]) :
					err_stor.append([col_r + 'Error: $FPT partition %s (0x%0.6X - 0x%0.6X) overlaps with %s (0x%0.6X - 0x%0.6X)' % \
									(part[0],part[1],part[2],all_part[0],all_part[1],all_part[2]) + col_e, True])
		
		# Detect CSE IUP required by FWUpdate at $FPT Charted & Uncharted to avoid FIT bug
		for part in fpt_part_all :
			# Detect if firmware has Power Management Controller (PMCP/PCOD) partition
			if part[0] in ('PMCP','PCOD') and not part[6] :
				pmcp_fwu_found = True
				pmcp_size = part[2] - part[1]
				
				_,_,_,pmc_vcn,_,_,_,_,_,_,_,_,pmc_mn2_ver,_,pmc_ext15_info,_,_,_,_ = \
				ext_anl(reading, '$CPD', part[1], file_end, ['PMC',-1,-1,-1,-1,-1,-1,'PMC'], None, [[],''], [[],-1,-1,-1])
				
				pmc_all_init.append([pmc_vcn,pmc_mn2_ver,pmc_ext15_info,pmcp_size])
				
			# Detect if firmware has Platform Controller Hub Configuration (PCHC) partition
			if part[0] == 'PCHC' and not part[6] :
				pchc_fwu_found = True
				pchc_size = part[2] - part[1]
				
				_,_,_,pchc_vcn,_,_,_,_,_,_,_,_,pchc_mn2_ver,_,pchc_ext15_info,_,_,_,_ = \
				ext_anl(reading, '$CPD', part[1], file_end, ['PCHC',-1,-1,-1,-1,-1,-1,'PCHC'], None, [[],''], [[],-1,-1,-1])
				
				pchc_all_init.append([pchc_vcn,pchc_mn2_ver,pchc_ext15_info,pchc_size])
				
			# Detect if firmware has USB Type C Physical (PHY) partition
			if part[0] in ('PPHY','NPHY','SPHY','PHYP') and not part[6] :
				phy_fwu_found = True
				phy_size = part[2] - part[1]
				
				_,_,_,phy_vcn,_,_,_,_,_,_,_,_,phy_mn2_ver,_,phy_ext15_info,_,_,_,_ = \
				ext_anl(reading, '$CPD', part[1], file_end, ['PHY',-1,-1,-1,-1,-1,-1,'PHY'], None, [[],''], [[],-1,-1,-1])
				
				phy_all_init.append([phy_vcn,phy_mn2_ver,phy_ext15_info,phy_size])
		
	# Calculate Firmware Size based on $FPT and/or IFWI LT
	if (cse_lt_struct and not rgn_exist) or (rgn_exist and p_end_last != p_max_size) :
		if cse_lt_struct :
			# Check for duplicate/nested CSE LT entries
			for entry_c in cse_lt_hdr_info :
				for entry_o in cse_lt_hdr_info :
					if entry_c[0] != entry_o[0] and entry_c[1] >= entry_o[1] and entry_c[1] + entry_c[2] <= entry_o[1] + entry_o[2] :
						cse_lt_dup_size += entry_c[2] # If entry_c different than entry_o and entry_c within entry_o, duplicated/nested
			
			# CSME 12+ consists of Layout Table (0x1000) + Data (MEA or LT size) + Boot/Temp/ELog (LT size) - Duplicates/Nested (LT size)
			p_end_last = cse_lt_size + max(p_end_last,cse_lt_dp_size) + cse_lt_bp_size - cse_lt_dup_size
		
		# For Engine/Graphics alignment & size, remove fpt_start (included in p_end_last < eng_fw_end < p_offset_spi)
		eng_fw_align -= (p_end_last - fpt_start) % 0x1000 # 4K alignment Size of entire Engine/Graphics firmware
		
		if eng_fw_align != 0x1000 :
			file_has_align = min(eng_fw_align, file_end - p_end_last) # Check whatever alignment padding is actually available in file
			file_bad_align = reading[p_end_last:p_end_last + file_has_align] not in [b'', b'\xFF' * file_has_align] # Data in alignment padding bool
			if (fpt_start == 0 or (cse_lt_struct and cse_lt_off == 0)) and file_has_align > 0 and file_bad_align :
				warn_stor.append([col_m + 'Warning: File has data in Firmware 4K alignment padding!' + col_e, param.check])
			
			# Ignore 4K alignment at CSME 16+ for FWUpdate image creation via MFIT (seriously Intel ?)
			if variant == 'CSME' and major >= 16 :
				eng_fw_end = p_end_last - fpt_start
			else :
				eng_fw_end = p_end_last + eng_fw_align - fpt_start
				check_fw_align = 0x0 if p_end_last > file_end else eng_fw_align - file_has_align
		else :
			eng_fw_end = p_end_last - fpt_start
	
	# Detect Firmware Data inconsistency (eng_fw_end dependent)
	if rgn_exist or cse_lt_struct :
		# SPI image with FD
		if fd_me_rgn_exist :
			if eng_fw_end > me_fd_size :
				eng_size_text = [col_m + 'Warning: Firmware size exceeds Engine/Graphics region, possible data loss!' + col_e, False]
			elif eng_fw_end < me_fd_size and fd_is_cut :
				eng_size_text = [col_m + 'Warning: Firmware size exceeds Engine/Graphics region, possible data loss!' + col_e, False]
			elif eng_fw_end < me_fd_size :
				# Extra data at Engine/Graphics FD region padding
				padd_size_fd = me_fd_size - eng_fw_end
				padd_start_fd = (cse_lt_off if cse_lt_struct else fpt_start) + eng_fw_end
				padd_end_fd = (cse_lt_off if cse_lt_struct else fpt_start) + eng_fw_end + padd_size_fd
				padd_data_fd = reading[padd_start_fd:padd_end_fd]
				
				if padd_data_fd != padd_size_fd * b'\xFF' :
					# Detect CSSPS 4, sometimes uncharted/empty, $BIS partition
					sps4_bis_match = b'$BIS\x00' in padd_data_fd if (variant,major) == ('CSSPS',4) else None
					
					if sps4_bis_match is not None : eng_size_text = ['', False]
					else : eng_size_text = [col_m + 'Warning: Data in Engine/Graphics region padding, possible data corruption!' + col_e, True]
		
		# Bare Engine/Graphics Region
		elif fpt_start == 0 or (cse_lt_struct and cse_lt_off == 0) :
			padd_size_file = file_end - eng_fw_end
			
			if eng_fw_end > file_end :
				if eng_fw_end <= file_end + check_fw_align :
					# Firmware ends at last $FPT entry but is not 4K aligned, can/must be ignored (CSME 12-15/16+)
					eng_size_text = [col_y + 'Note: File is missing optional Firmware 4K alignment padding!' + col_e, False] # warn_stor
					if param.check : # Add alignment padding, when missing (Debug/Research)
						with open('__APADD__' + os.path.basename(file_in), 'wb') as o : o.write(reading + b'\xFF' * check_fw_align)
				else :
					eng_size_text = [col_m + 'Warning: Firmware size exceeds File, possible data loss!' + col_e, True]
			elif eng_fw_end < file_end :
				padd_data_file = reading[eng_fw_end:eng_fw_end + padd_size_file]
				
				if padd_data_file == padd_size_file * b'\xFF' :
					# Extra padding is clear
					eng_size_text = [col_y + 'Note: File has harmless unneeded Firmware end padding!' + col_e, False] # warn_stor
					if param.check : # Remove unneeded padding, when applicable (Debug/Research)
						with open('__RPADD__' + os.path.basename(file_in), 'wb') as o : o.write(reading[:-padd_size_file])
				else :
					# Detect CSSPS 4, sometimes uncharted/empty, $BIS partition
					sps4_bis_match = b'$BIS\x00' in padd_data_file if (variant,major) == ('CSSPS',4) else None
					
					# Extra padding has data
					if sps4_bis_match is not None : eng_size_text = ['', False]
					else : eng_size_text = [col_m + 'Warning: File size exceeds Firmware, data in padding!' + col_e, True]
	
	# Firmware Type detection (Stock, Extracted, Update)
	if ifwi_exist : # IFWI
		fitc_ver_found = True
		fw_type = 'Extracted'
		fitc_major = bpdt_hdr.FitMajor
		fitc_minor = bpdt_hdr.FitMinor
		fitc_hotfix = bpdt_hdr.FitHotfix
		fitc_build = bpdt_hdr.FitBuild
	elif rgn_exist : # SPS 1-3 have their own firmware Types
		if variant == 'SPS' : fw_type = 'Extracted' # SPS is built manually so EXTR
		elif variant == 'ME' and (2 <= major <= 7) :
			# Check 1, FOVD partition
			if (major >= 3 and not fovd_clean('new')) or (major == 2 and not fovd_clean('old')) : fw_type = 'Extracted'
			else :
				# Check 2, EFFS/NVKR strings
				fitc_match = re.compile(br'KRND\x00').search(reading) # KRND. detection = FITC, 0x00 adds old ME RGN support
				if fitc_match is not None :
					if major == 4 : fw_type_fix = True # ME4-Only Fix 3
					else : fw_type = 'Extracted'
				elif major in [2,3] : fw_type_fix = True # ME2-Only Fix 1, ME3-Only Fix 1
				else : fw_type = 'Stock'
		elif (variant == 'ME' and major >= 8) or variant in ['CSME','CSTXE','CSSPS','TXE','GSC'] :
			fpt_upd_only = [] # Initialize $FPT w/ Update partitions only list
			_ = [fpt_upd_only.append(part[0]) for part in fpt_part_all if not part[6]]
			
			# Check 1, $FPT Update image
			if sorted(fpt_upd_only) == ['FTPR','FTUP','NFTP'] :
				fw_type = 'Update' # $FPT exists but includes FTPR & FTUP/NFTP only, Update
			# Check 2, FITC Version
			elif fpt_hdr.FitBuild in [0x0,0xFFFF] : # 0000/FFFF --> clean (CS)ME/(CS)TXE
				fw_type = 'Stock'
				
				# Check 3, FOVD partition
				if not fovd_clean('new') : fw_type = 'Extracted'
				
				# Check 4, CSTXE FIT placeholder $FPT Header entries
				if reading[fpt_start:fpt_start + 0x10] + reading[fpt_start + 0x1C:fpt_start + 0x30] == b'\xFF' * 0x24 : fw_type = 'Extracted'
				
				# Check 5, CSME 13+ FWUpdate EXTR has placeholder $FPT ROM-Bypass Vectors 0-3 (0xFF instead of 0x00 padding)
				# If not enough (should be OK), MEA could further check if FTUP is empty and/or if PMCP/PCOD, PCHC & PHY exist or not
				if variant == 'CSME' and major >= 13 and reading[fpt_start:fpt_start + 0x10] == b'\xFF' * 0x10 : fw_type = 'Extracted'
			else :
				# Get FIT/FITC version used to build the image
				fitc_ver_found = True
				fw_type = 'Extracted'
				fitc_major = fpt_hdr.FitMajor
				fitc_minor = fpt_hdr.FitMinor
				fitc_hotfix = fpt_hdr.FitHotfix
				fitc_build = fpt_hdr.FitBuild
	elif is_pfu_img :
		fw_type = 'Partial Update' # FWUpdate LOCL/WCOD
	else :
		fw_type = 'Update' # No Region detected, Update
	
	# Verify $FPT Checksums (must be after Firmware Type detection)
	if rgn_exist :
		fpt_chk_bgn = fpt_pat_bgn if fpt_length <= 0x20 else fpt_start
		fpt_ver_byte = struct.pack('<B', fpt_version)
		fpt_ver_end = fpt_pat_end + 0x1
		
		# Check $FPT Checksum
		if fpt_version <= 0x20 :
			fpt_chk_sum = sum(reading[fpt_chk_bgn:fpt_chk_bgn + fpt_length]) - fpt_chk_int
			fpt_chk_mea = (0x100 - fpt_chk_sum & 0xFF) & 0xFF
			fpt_fixes = [fpt_pat_end, fpt_ver_byte, fpt_ver_end, fpt_pat_end + 0x3, struct.pack('<B', fpt_chk_mea), fpt_pat_end + 0x4]
			fpt_chk_int, fpt_chk_mea = '0x%0.2X' % fpt_chk_int, '0x%0.2X' % fpt_chk_mea
		else :
			fpt_21_data = bytearray(reading[fpt_chk_bgn:fpt_chk_bgn + 0x14] + b'\x00' * 4 + reading[fpt_chk_bgn + 0x18:fpt_chk_bgn + 0x20 + fpt_part_num * 0x20])
			fpt_21_data[0x8:0x9] = fpt_ver_byte # Fix FPT v21 with v20 Version Tag
			fpt_chk_mea = crccheck.crc.Crc32.calc(fpt_21_data)
			fpt_fixes = [fpt_pat_end, fpt_ver_byte, fpt_ver_end, fpt_pat_end + 0xC, struct.pack('<I', fpt_chk_mea), fpt_pat_end + 0x10]
			fpt_chk_int, fpt_chk_mea = '0x%0.8X' % fpt_chk_int, '0x%0.8X' % fpt_chk_mea
		
		if fpt_chk_mea != fpt_chk_int: fpt_chk_fail = True
		
		# Fix $FPT Checksum, when applicable (Debug/Research)
		if param.check and fpt_chk_fail :
			with open('__FCFPT__' + os.path.basename(file_in), 'wb') as o :
				o.write(reading[:fpt_fixes[0]] + fpt_fixes[1] + reading[fpt_fixes[2]:fpt_fixes[3]] + fpt_fixes[4] + reading[fpt_fixes[5]:])
		
		# CSME 12+, CSTXE 3+ and CSSPS 5+ EXTR $FPT Checksum is usually wrong (0x00 placeholder or same as in RGN), ignore
		if fw_type == 'Extracted' and ((variant == 'CSME' and major >= 12) or (variant == 'CSTXE' and major >= 3) or (variant == 'CSSPS' and major >= 5)) :
			fpt_chk_fail = False
		
		# Warn when $FPT Checksum is wrong
		if fpt_chk_fail : warn_stor.append([col_m + 'Warning: Wrong $FPT Checksum %s, expected %s!' % (fpt_chk_int,fpt_chk_mea) + col_e, True])
		
		# Check SPS 3 extra $FPT Checksum-16 (from Lordkag's UEFIStrip)
		if variant == 'SPS' and major == 3 :
			sps3_chk_start = fpt_start + 0x30
			sps3_chk_end = sps3_chk_start + fpt_part_num * 0x20
			sps3_chk16_file = '0x%0.4X' % int.from_bytes(reading[sps3_chk_end:sps3_chk_end + 0x2], 'little')
			sps3_chk16_sum = sum(bytearray(reading[sps3_chk_start:sps3_chk_end])) & 0xFFFF
			sps3_chk16_calc = '0x%0.4X' % (~sps3_chk16_sum & 0xFFFF)
			if sps3_chk16_calc != sps3_chk16_file:
				warn_stor.append([col_m + 'Warning: Wrong $FPT SPS3 Checksum %s, expected %s!' % (sps3_chk16_file,sps3_chk16_calc) + col_e, True])
	
	# Check for Fujitsu UMEM ME Region (RGN/$FPT or UPD/$MN2)
	if (fd_me_rgn_exist and reading[me_fd_start:me_fd_start + 0x4] == b'\x55\x4D\xC9\x4D') or (reading[:0x4] == b'\x55\x4D\xC9\x4D') :
		warn_stor.append([col_m + 'Warning: Fujitsu Intel Engine/Graphics firmware detected!' + col_e, False])
	
	# Detect Firmware Release (Production, Pre-Production, ROM-Bypass)
	mn2_flags_pvbit,_,_,_,mn2_flags_debug = mn2_ftpr_hdr.get_flags()
	rel_signed = ['Production', 'Debug'][mn2_flags_debug]
	
	if fpt_romb_found :
		release = 'ROM-Bypass'
		rel_db = 'BYP'
	elif rel_signed == 'Production' :
		release = 'Production'
		rel_db = 'PRD'
	else :
		release = 'Pre-Production'
		rel_db = 'PRE'
		
	# Fix Release of PRE firmware which are wrongly reported as PRD
	release, rel_db = release_fix(release, rel_db, rsa_key_hash)
	
	# Detect PV/PC bit (0 or 1)
	if (variant == 'ME' and major >= 8) or variant == 'TXE' :
		pvbit_match = (re.compile(br'\$DAT.{20}IFRP', re.DOTALL)).search(reading[start_man_match:]) # $DAT + [0x14] + IFRP detection
		if pvbit_match : pvbit = reading[start_man_match + pvbit_match.start() + 0x10]
	elif variant in ['CSME','CSTXE','CSSPS','GSC'] or variant.startswith(('PMC','PCHC','PHY','OROM')) :
		pvbit = mn2_flags_pvbit
	
	if variant == 'ME' : # Management Engine
		
		# Detect SKU Attributes
		sku_match = re.compile(br'\$SKU[\x03-\x04]\x00\x00\x00').search(reading[start_man_match:]) # $SKU detection
		if sku_match is not None :
			start_sku_match = sku_match.start() + start_man_match
			
			if 2 <= major <= 6 :
				# https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/WordDocuments/instanceidandversionstringformats.htm
				# https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/WordDocuments/vproverificationtableparameterdefinitions.htm
				sku_me = int.from_bytes(reading[start_sku_match + 8:start_sku_match + 0xC], 'big')
			elif 7 <= major <= 10 :
				sku_attrib = get_struct(reading, start_sku_match, SKU_Attributes)
				_,sku_slim,_,_,_,_,_,_,_,is_patsburg,sku_type,sku_size,_ = sku_attrib.get_flags()
		
		if major == 2 : # ICH8 2.0 - 2.2 or ICH8M 2.5 - 2.6
			sku_byte = {0: 'AMT + ASF + QST', 1: 'ASF + QST', 2: 'QST'}
			
			if sku_me == 0x00000000 : # AMT + ASF + QST
				sku = 'AMT'
				sku_db = 'AMT'
				if minor <= 2 : sku_db_check = 'AMTD'
				else : sku_db_check = 'AMTM'
			elif sku_me == 0x02000000 : # QST
				sku = 'QST'
				sku_db = 'QST'
				sku_db_check = 'QST'
			else :
				sku = col_r + 'Unknown' + col_e
				sku_db_check = 'UNK'
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
			
			_,db_min,db_hot,db_bld = check_upd('Latest_ME_2_%s' % sku_db_check)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME2-Only Fix 1 : The usual method to detect EXTR vs RGN does not work for ME2
			if fw_type_fix :
				if sku == 'QST' or (sku == 'AMT' and minor >= 5) :
					nvkr_match = (re.compile(br'NVKRKRID')).search(reading) # NVKRKRID detection
					if nvkr_match is not None :
						(start_nvkr_match, end_nvkr_match) = nvkr_match.span()
						nvkr_start = int.from_bytes(reading[end_nvkr_match:end_nvkr_match + 0x4], 'little')
						nvkr_size = int.from_bytes(reading[end_nvkr_match + 0x4:end_nvkr_match + 0x8], 'little')
						nvkr_data = reading[fpt_start + nvkr_start:fpt_start + nvkr_start + nvkr_size]
						# NVKR sections : Name[0xC] + Size[0x3] + Data[Size]
						prat_match = (re.compile(br'Pra Table\xFF\xFF\xFF')).search(nvkr_data) # "Pra Table" detection (2.5/2.6)
						maxk_match = (re.compile(br'MaxUsedKerMem\xFF\xFF\xFF')).search(nvkr_data) # "MaxUsedKerMem" detection
						if prat_match is not None :
							(start_prat_match, end_prat_match) = prat_match.span()
							prat_start = fpt_start + nvkr_start + end_prat_match + 0x3
							prat_end = fpt_start + nvkr_start + end_prat_match + 0x13
							me2_type_fix = int.from_bytes(reading[prat_start:prat_end], 'big')
							me2_type_exp = 0x7F45DBA3E65424458CB09A6E608812B1
						elif maxk_match is not None :
							(start_maxk_match, end_maxk_match) = maxk_match.span()
							qstpat_start = fpt_start + nvkr_start + end_maxk_match + 0x68
							qstpat_end = fpt_start + nvkr_start + end_maxk_match + 0x78
							me2_type_fix = int.from_bytes(reading[qstpat_start:qstpat_end], 'big')
							me2_type_exp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
				elif sku == 'AMT' and minor < 5 :
					nvsh_match = (re.compile(br'NVSHOSID')).search(reading) # NVSHOSID detection
					if nvsh_match is not None :
						netip_match = (re.compile(br'net\.ip\xFF\xFF\xFF')).search(reading) # "net.ip" detection (2.0-2.2)
						if netip_match is not None :
							(start_netip_match, end_netip_match) = netip_match.span()
							netip_size = int.from_bytes(reading[end_netip_match + 0x0:end_netip_match + 0x3], 'little')
							netip_start = fpt_start + end_netip_match + 0x4 # 0x4 always 03 so after that byte for 00 search
							netip_end = fpt_start + end_netip_match + netip_size + 0x3 # (+ 0x4 - 0x1)
							me2_type_fix = int.from_bytes(reading[netip_start:netip_end], 'big')
							me2_type_exp = int.from_bytes(b'\x00' * (netip_size - 0x1), 'big')
							
				if me2_type_fix != me2_type_exp : fw_type = 'Extracted'
				else : fw_type = 'Stock'
			
			# ME2-Only Fix 2 : Identify ICH Revision B0 firmware SKUs
			me2_sku_fix = ['FF4DAEACF679A7A82269C1C722669D473F7D76AD3DFDE12B082A0860E212CD93',
			'345F39266670F432FCFF3B6DA899C7B7E0137ED3A8A6ABAD4B44FB403E9BB3BB',
			'8310BA06D7B9687FC18847991F9B1D747B55EF30E5E0E5C7B48E1A13A5BEE5FA']
			if rsa_sig_hash in me2_sku_fix :
				sku = 'AMT B0'
				sku_db = 'AMT_B0'
			
			# ME2-Only Fix 3 : Detect ROMB RGN/EXTR image correctly (at $FPT v1 ROMB was before $FPT)
			if rgn_exist and release == 'Pre-Production' :
				byp_pat = re.compile(br'\$VER\x02\x00\x00\x00') # $VER2... detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				
				if byp_match :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
					byp_size = fpt_start - (byp_match.start() - 0x80)
					eng_fw_end += byp_size
					eng_size_text = ['', False]
					
			if minor >= 5 : platform = 'ICH8M'
			else : platform = 'ICH8'
	
		elif major == 3 : # ICH9 or ICH9DO
			sku_bits = {1: 'IDT', 2: 'TPM', 3: 'AMT Lite', 4: 'AMT', 5: 'ASF', 6: 'QST'}
			
			if sku_me in [0x0E000000,0x00000000] : # AMT + ASF + QST (00000000 for Pre-Alpha ROMB)
				sku = 'AMT' # Q35 only
				sku_db = 'AMT'
			elif sku_me == 0x06000000 : # ASF + QST
				sku = 'ASF' # Q33 (HP dc5800)
				sku_db = 'ASF'
			elif sku_me == 0x02000000 : # QST
				sku = 'QST'
				sku_db = 'QST'
			else :
				sku = col_r + 'Unknown' + col_e
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
				
			_,db_min,db_hot,db_bld = check_upd('Latest_ME_3_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True

			# ME3-Only Fix 1 : The usual method to detect EXTR vs RGN does not work for ME3
			if fw_type_fix :
				me3_type_fix1 = []
				me3_type_fix2a = 0x10 * 0xFF
				me3_type_fix2b = 0x10 * 0xFF
				me3_type_fix3 = 0x10 * 0xFF
				effs_match = (re.compile(br'EFFSOSID')).search(reading) # EFFSOSID detection
				if effs_match is not None :
					(start_effs_match, end_effs_match) = effs_match.span()
					effs_start = int.from_bytes(reading[end_effs_match:end_effs_match + 0x4], 'little')
					effs_size = int.from_bytes(reading[end_effs_match + 0x4:end_effs_match + 0x8], 'little')
					effs_data = reading[fpt_start + effs_start:fpt_start + effs_start + effs_size]
					
					me3_type_fix1 = (re.compile(br'ME_CFG_DEF\x04NVKR')).findall(effs_data) # ME_CFG_DEF.NVKR detection (RGN have <= 2)
					me3_type_fix2 = (re.compile(br'MaxUsedKerMem\x04NVKR\x7Fx\x01')).search(effs_data) # MaxUsedKerMem.NVKR.x. detection
					me3_type_fix3 = int.from_bytes(reading[fpt_start + effs_start + effs_size - 0x20:fpt_start + effs_start + effs_size - 0x10], 'big')
					
					if me3_type_fix2 is not None :
						(start_me3f2_match, end_me3f2_match) = me3_type_fix2.span()
						me3_type_fix2a = int.from_bytes(reading[fpt_start + effs_start + end_me3f2_match - 0x30:fpt_start + effs_start + end_me3f2_match - 0x20], 'big')
						me3_type_fix2b = int.from_bytes(reading[fpt_start + effs_start + end_me3f2_match + 0x30:fpt_start + effs_start + end_me3f2_match + 0x40], 'big')

				if len(me3_type_fix1) > 2 or me3_type_fix3 != 0x10 * 0xFF or me3_type_fix2a != 0x10 * 0xFF or me3_type_fix2b != 0x10 * 0xFF : fw_type = 'Extracted'
				else : fw_type = 'Stock'
			
			# ME3-Only Fix 2 : Detect AMT ROMB UPD image correctly (very vague, may not always work)
			if fw_type == 'Update' and release == 'Pre-Production' : # Debug Flag detected at $MAN but PRE vs BYP is needed for UPD (not RGN)
				# It seems that ROMB UPD is smaller than equivalent PRE UPD
				# min size(ASF, UPD) is 0xB0904 so 0x100000 safe min AMT ROMB
				# min size(AMT, UPD) is 0x190904 so 0x185000 safe max AMT ROMB
				# min size(QST, UPD) is 0x2B8CC so 0x40000 safe min for ASF ROMB
				# min size(ASF, UPD) is 0xB0904 so 0xAF000 safe max for ASF ROMB
				# min size(QST, UPD) is 0x2B8CC so 0x2B000 safe max for QST ROMB
				if (sku == 'AMT' and 0x100000 < file_end < 0x185000) or (sku == 'ASF' and 0x40000 < file_end < 0xAF000) or (sku == 'QST' and file_end < 0x2B000) :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			# ME3-Only Fix 3 : Detect Pre-Alpha ($FPT v1) ROMB RGN/EXTR image correctly
			if rgn_exist and fpt_version == 16 and release == 'Pre-Production' :
				byp_pat = re.compile(br'\$VER\x03\x00\x00\x00') # $VER3... detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				
				if byp_match :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
					byp_size = fpt_start - (byp_match.start() - 0x80)
					eng_fw_end += byp_size
					eng_size_text = ['', False]
			
			platform = 'ICH9'
	
		elif major == 4 : # ICH9M or ICH9M-E (AMT or TPM+AMT): 4.0 - 4.2 , xx00xx --> 4.0 , xx20xx --> 4.1 or 4.2
			sku_bits = {0: 'Reserved', 1: 'IDT', 2: 'TPM', 3: 'AMT Lite', 4: 'AMT', 5: 'ASF', 6: 'QST', 7: 'Reserved'}
			
			if sku_me in [0xAC200000,0xAC000000,0x04000000] : # 040000 for Pre-Alpha ROMB
				sku = 'AMT + TPM' # CA_ICH9_REL_ALL_SKUs_ (TPM + AMT)
				sku_db = 'ALL'
			elif sku_me in [0x8C200000,0x8C000000,0x0C000000] : # 0C000000 for Pre-Alpha ROMB
				sku = 'AMT' # CA_ICH9_REL_IAMT_ (AMT)
				sku_db = 'AMT'
			elif sku_me in [0xA0200000,0xA0000000] :
				sku = 'TPM' # CA_ICH9_REL_NOAMT_ (TPM)
				sku_db = 'TPM'
			else :
				sku = col_r + 'Unknown' + col_e
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
			
			# ME4-Only Fix 1 : Detect ROMB UPD image correctly
			if fw_type == "Update" :
				byp_pat = re.compile(br'ROMB') # ROMB detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				if byp_match :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			# ME4-Only Fix 2 : Detect SKUs correctly, only for Pre-Alpha firmware
			if minor == 0 and hotfix == 0 :
				if fw_type == 'Update' :
					tpm_tag = (re.compile(br'\$MME.{24}TPM', re.DOTALL)).search(reading) # $MME + [0x18] + TPM
					amt_tag = (re.compile(br'\$MME.{24}MOFFM1_OVL', re.DOTALL)).search(reading) # $MME + [0x18] + MOFFM1_OVL
				else :
					tpm_tag = (re.compile(br'NVTPTPID')).search(reading) # NVTPTPID partition found at ALL or TPM
					amt_tag = (re.compile(br'NVCMAMTC')).search(reading) # NVCMAMTC partition found at ALL or AMT
				
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
				effs_match = (re.compile(br'EFFSOSID')).search(reading) # EFFSOSID detection
				if effs_match is not None :
					(start_effs_match, end_effs_match) = effs_match.span()
					effs_start = int.from_bytes(reading[end_effs_match:end_effs_match + 0x4], 'little')
					effs_size = int.from_bytes(reading[end_effs_match + 0x4:end_effs_match + 0x8], 'little')
					effs_data = reading[fpt_start + effs_start:fpt_start + effs_start + effs_size]
				
					me4_type_fix1 = (re.compile(br'ME_CFG_DEF')).findall(effs_data) # ME_CFG_DEF detection (RGN have 2-4)
					me4_type_fix2 = (re.compile(br'GPIO10Owner')).search(effs_data) # GPIO10Owner detection
					me4_type_fix3 = (re.compile(br'AppRule\.03\.000000')).search(effs_data) # AppRule.03.000000 detection
				
					if len(me4_type_fix1) > 5 or me4_type_fix2 is not None or me4_type_fix3 is not None : fw_type = "Extracted"
					else : fw_type = 'Stock'
			
			# Placed here in order to comply with Fix 2 above in case it is triggered
			_,db_min,db_hot,db_bld = check_upd('Latest_ME_4_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			platform = 'ICH9M'
			
		elif major == 5 : # ICH10D or ICH10DO
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 5: 'ASF', 6: 'QST', 8: 'Level III Manageability Upgrade', 9: 'Corporate', 10: 'Anti-Theft', 15: 'Remote PC Assist'}
			
			if sku_me == 0x3E080000 : # EL_ICH10_SKU1
				sku = 'Digital Office' # AMT
				sku_db = 'DO'
			elif sku_me == 0x060D0000 : # EL_ICH10_SKU4
				sku = 'Base Consumer' # NoAMT
				sku_db = 'BC'
			elif sku_me == 0x06080000 : # EL_ICH10_SKU2 or EL_ICH10_SKU3
				sku = 'Digital Home or Base Corporate (?)'
				sku_db = 'DHBC'
			else :
				sku = col_r + 'Unknown' + col_e
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
				
			_,db_min,db_hot,db_bld = check_upd('Latest_ME_5_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME5-Only Fix : Detect ROMB UPD image correctly
			if fw_type == 'Update' :
				byp_pat = re.compile(br'ROMB') # ROMB detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				if byp_match :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			platform = 'ICH10'
	
		elif major == 6 :
			platform = 'IBX'
			
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 6: 'QST', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist'}
			
			if sku_me == 0x00000000 : # Ignition (128KB, 2MB)
				if hotfix == 50 : # 89xx (Cave/Coleto Creek)
					ign_pch = 'CCK'
					platform = 'CCK'
				else : # P55, PM55, 34xx (Ibex Peak)
					ign_pch = 'IBX'
				sku_db = 'IGN_' + ign_pch
				sku = 'Ignition ' + ign_pch
			elif sku_me == 0x701C0000 : # Home IT (1.5MB, 4MB)
				sku = '1.5MB'
				sku_db = '1.5MB'
			# xxDCxx = 6.x, xxFCxx = 6.0, xxxxEE = Mobile, xxxx6E = Desktop, F7xxxx = Old Alpha/Beta Releases
			elif sku_me in [0x77DCEE00,0x77FCEE00,0xF7FEFE00] : # vPro (5MB, 8MB)
				sku = '5MB MB'
				sku_db = '5MB_MB'
			elif sku_me in [0x77DC6E00,0x77FC6E00,0xF7FE7E00] : # vPro (5MB, 8MB)
				sku = '5MB DT'
				sku_db = '5MB_DT'
			else :
				sku = col_r + 'Unknown' + col_e
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
				
			_,db_min,db_hot,db_bld = check_upd('Latest_ME_6_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME6-Only Fix 1 : ME6 Ignition does not work with KRND
			if 'Ignition' in sku and rgn_exist :
				ign_pat = (re.compile(br'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6D\x3C\x75\x6D')).findall(reading) # Clean $MINIFAD checksum
				if len(ign_pat) < 2 : fw_type = "Extracted" # 2 before NFTP & IGRT
				else : fw_type = "Stock"
			
			# ME6-Only Fix 2 : Ignore errors at ROMB (Region present, FTPR tag & size missing)
			if release == 'ROM-Bypass' : eng_size_text = ['', False]
			
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
			
			_,db_min,db_hot,db_bld = check_upd('Latest_ME_7_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME7-Only Fix: ROMB UPD detection
			if fw_type == 'Update' :
				me7_mn2_hdr_len = mn2_ftpr_hdr.HeaderLength * 4
				me7_mn2_mod_len = (mn2_ftpr_hdr.NumModules + 1) * 0x60
				me7_mcp = get_struct(reading, start_man_match - 0x1B + me7_mn2_hdr_len + 0xC + me7_mn2_mod_len, MCP_Header) # Goto $MCP
				
				if me7_mcp.CodeSize in [374928,419984] : # 1.5/5MB ROMB Code Sizes
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			# ME7 Blacklist Table Detection
			me7_blist_1_minor = int.from_bytes(reading[start_man_match + 0x6DF:start_man_match + 0x6E1], 'little')
			me7_blist_1_hotfix = int.from_bytes(reading[start_man_match + 0x6E1:start_man_match + 0x6E3], 'little')
			me7_blist_1_build = int.from_bytes(reading[start_man_match + 0x6E3:start_man_match + 0x6E5], 'little')
			if me7_blist_1_build != 0 : me7_blist_1 = '<= 7.%d.%d.%d' % (me7_blist_1_minor, me7_blist_1_hotfix, me7_blist_1_build)
			me7_blist_2_minor = int.from_bytes(reading[start_man_match + 0x6EB:start_man_match + 0x6ED], 'little')
			me7_blist_2_hotfix = int.from_bytes(reading[start_man_match + 0x6ED:start_man_match + 0x6EF], 'little')
			me7_blist_2_build = int.from_bytes(reading[start_man_match + 0x6EF:start_man_match + 0x6F1], 'little')
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
			
			_,db_min,db_hot,db_bld = check_upd('Latest_ME_8_%s' % sku_db)
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
			
			_,db_min,db_hot,db_bld = check_upd('Latest_ME_9%d_%s' % (minor, sku_db))
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
			
			_,db_min,db_hot,db_bld = check_upd('Latest_ME_10%d_%s' % (minor, sku_db))
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			if minor == 0 : platform = 'WPT-LP'
	
	elif variant == 'CSME' : # Converged Security Management Engine
		
		# Firmware Unpacking for all CSME
		if param.cse_unpack :
			cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail, cse_lt_chk_fail,
			cse_red_info, fdv_status, reading_msg, orom_hdr_all)
			continue # Next input file
		
		# Get CSE MFS File System Attributes & Configuration State (invokes mfs_anl, must be before ext_anl)
		mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final,vol_ftbl_id,config_rec_size,vol_ftbl_pl \
		= get_mfs_anl(mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final)
		
		# Get CSE EFS File System Attributes & Configuration State (must be after mfs_anl)
		if efs_found : efs_init = efs_anl(mea_dir, efs_start, efs_start + efs_size, vol_ftbl_id, vol_ftbl_pl)
		
		# Get CSE Firmware Attributes (must be after mfs_anl)
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext50_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info, \
		ext_iunit_val,ext15_info,pch_init_final,gmf_blob_info,fwi_iup_hashes,gsc_info \
		= ext_anl(reading, '$MN2', start_man_match, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], None, [mfs_parsed_idx,intel_cfg_hash_mfs],
		[pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl])
		
		# MFS missing, determine state via FTPR > fitc.cfg, FITC, MFSB or EFS (must be after mfs_anl, efs_anl & ext_anl)
		if mfs_state != 'Initialized' and efs_init : mfs_state = 'Initialized'
		elif mfs_state == 'Unconfigured' and (oem_config or fitc_found or mfsb_found or cdmd_found) : mfs_state = 'Configured'
		
		fw_0C_sku0,fw_0C_sku1,fw_0C_lbg,fw_0C_sku2 = ext12_info # Get SKU Capabilities, SKU Type, HEDT Support, SKU Platform
		
		# Set SKU Type via Extension 12 or 15 or 35 (CSME logic)
		# When CSE_Ext_0F_R2 was introduced, Firmware SKU field was reserved to the meaningless value 1. After some time, Firmware SKU
		# was adjusted with actual values 0+ and 1 now means Corporate (COR). To avoid confusion when comparing against the SKU value
		# from CSE_Ext_0C, MEA should ignore the placeholder "Corporate" SKU at CSE_Ext_0F_R2 and use the actual value from CSE_Ext_0C.
		# Generally, due to CSE_Ext_0F_R2 confusion, CSE_Ext_0C should be prefered when CSE_Ext_0F_R2 SKU is CON,COR,ALL,NA or missing.
		# There are plans for another (seriously ?) SKU Type extension, CSE_Ext_23. Support for CSE_Ext_23 can be added once it's used.
		if fw_0C_sku1[1] != 'UNK' and ext15_info[2][1] in ['','NA','ALL','CON','COR'] :
			sku_init = fw_0C_sku1[0]
			sku_init_db = fw_0C_sku1[1]
		elif ext15_info[2][1] not in ['','NA','ALL'] :
			sku_init = ext15_info[2][0]
			sku_init_db = ext15_info[2][1]
		else :
			sku_init = 'Unknown'
			sku_init_db = 'UNK'
		
		# Detect SKU Platform via MFS Intel PCH Initialization Table
		if pch_init_final and '-LP' in pch_init_final[-1][0] : pos_sku_tbl = 'LP'
		elif pch_init_final and '-H' in pch_init_final[-1][0] : pos_sku_tbl = 'H'
		elif pch_init_final and '-N' in pch_init_final[-1][0] : pos_sku_tbl = 'N'
		elif pch_init_final and '-V' in pch_init_final[-1][0] : pos_sku_tbl = 'V'
		
		db_sku_chk,sku,sku_stp,sku_pdm = get_cse_db(variant) # Get CSE SKU info from DB
		
		# Get CSME 12+ Final SKU, SKU Platform, SKU Stepping
		sku,sku_result,sku_stp = get_csme12_sku(sku_init, fw_0C_sku0, fw_0C_sku2, sku, sku_result, sku_stp, db_sku_chk, pos_sku_tbl, pch_init_final)
		
		# Parse all detected stitched PMC firmware
		pmc_all_anl = pmc_parse(pmc_all_init, pmc_all_anl)
		
		# Parse all detected stitched PCHC firmware
		pchc_all_anl = pchc_parse(pchc_all_init, pchc_all_anl)
		
		# Parse all detected stitched PHY firmware
		phy_all_anl = phy_parse(phy_all_init, phy_all_anl)
		
		if major == 11 :
			
			# Set SKU Platform via Extension 12 Attributes
			if minor > 0 or (minor == 0 and (hotfix > 0 or (hotfix == 0 and build >= 1205 and build != 7101))) :
				if fw_0C_sku2 == 0 : pos_sku_ext = 'H' # Halo
				elif fw_0C_sku2 == 1 : pos_sku_ext = 'LP' # Low Power
			else :
				pos_sku_ext = 'Invalid' # Only for CSME >= 11.0.0.1205
			
			# SKU not in Extension 12 and not in DB, scan decompressed Huffman module FTPR > kernel
			if pos_sku_ext == 'Invalid' and sku == 'NaN' :
				for mod in cpd_mod_attr :
					if mod[0] == 'kernel' :
						huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, minor, 'error')
						ker_decomp, huff_error = cse_huffman_decompress(reading[mod[3]:mod[3] + mod[4]], mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none')
						
						# 0F22D88D65F85B5E5DC355B8 (56AA|36AA for H, 60A0|004D|9C64 for LP)
						sku_pat = re.compile(br'\x0F\x22\xD8\x8D\x65\xF8\x5B\x5E\x5D\xC3\x55\xB8').search(ker_decomp)
						
						if sku_pat :
							sku_bytes = int.from_bytes(ker_decomp[sku_pat.end():sku_pat.end() + 0x1] + ker_decomp[sku_pat.end() + 0x17:sku_pat.end() + 0x18], 'big')
							if sku_bytes in (0x56AA,0x36AA) : pos_sku_ker = 'H' # 0x36AA for 11.0.0.1126
							elif sku_bytes in (0x60A0,0x004D,0x9C64) : pos_sku_ker = 'LP' # 0x004D,0x9C64 for 11.0.0.1100,11.0.0.1109
						
						break # Skip rest of FTPR modules
			
			if pos_sku_ext in ['Unknown','Invalid'] : # SKU not retrieved from Extension 12
				if pos_sku_ker == 'Invalid' : # SKU not retrieved from Kernel
					if sku == 'NaN' and not is_pfu_img : # SKU not retrieved from manual MEA DB entry
						sku = col_r + 'Unknown' + col_e
						err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
					else :
						pass # SKU retrieved from manual MEA DB entry or PFU image
				else :
					sku = sku_init + ' ' + pos_sku_ker # SKU retrieved from Kernel
			else :
				sku = sku_init + ' ' + pos_sku_ext # SKU retrieved from Extension 12
			
			# Store final SKU result (CSME 11 only)
			if ' LP' in sku : sku_result = 'LP'
			elif ' H' in sku : sku_result = 'H'
			
			# Set PCH/SoC Stepping, if not found at DB
			if sku_stp == 'Unknown' and pch_init_final : sku_stp = pch_init_final[-1][1]
			
			# Adjust PCH Platform via Minor version
			if minor == 0 and not pch_init_final : platform = 'SPT' # Sunrise Point
			elif minor in [5,6,7,8] and not pch_init_final : platform = 'SPT/KBP' # Sunrise Point, Union Point
			elif minor in [10,11,12] and not pch_init_final : platform = 'BSF/GCF' # Basin Falls, Glacier Falls
			elif minor in [20,21,22] and not pch_init_final : platform = 'LBG' # Lewisburg
			
			# Get CSME 11 DB SKU and check for Latest status (must be before sku_pdm)
			sku_db,upd_found = sku_db_upd_cse(sku_init_db, sku_result, sku_stp, sku_db, upd_found, False, False)
			
			if minor in [0,5,6,7,10,11,20,21] : upd_found = True # Superseded minor versions
			
			# Power Down Mitigation (PDM) is a SPT-LP C erratum, first fixed at ~11.0.0.1183
			# Hardcoded in FTPR > BUP, Huffman decompression required to detect NPDM or YPDM
			# Hardfixed at KBP-LP A but 11.5-8 have PDM firmware for SPT-LP C with KBL(R)
			if sku_result == 'LP' :
				# PDM not in DB, scan decompressed Huffman module FTPR > bup
				if sku_pdm not in ['NPDM','YPDM'] :
					for mod in cpd_mod_attr :
						if mod[0] == 'bup' :
							huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, minor, 'error')
							bup_decomp, huff_error = cse_huffman_decompress(reading[mod[3]:mod[3] + mod[4]], mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none')
							
							if bup_decomp != b'' :
								# 55B00189E55DC3
								pdm_pat = re.compile(br'\x55\xB0\x01\x89\xE5\x5D\xC3').search(bup_decomp)
							
								if pdm_pat : sku_pdm = 'YPDM'
								else : sku_pdm = 'NPDM'
							
							break # Skip rest of FTPR modules
				
				if sku_pdm == 'YPDM' : pdm_status = 'Yes'
				elif sku_pdm == 'NPDM' : pdm_status = 'No'
				elif sku_pdm == 'UPDM1' : pdm_status = 'Unknown 1'
				elif sku_pdm == 'UPDM2' : pdm_status = 'Unknown 2'
				else : pdm_status = 'Unknown'
				
				sku_db += '_%s' % sku_pdm # Must be after sku_db_upd_cse
		
		elif major == 12 :
			
			if minor == 0 and not pch_init_final : platform = 'CNP' # Cannon Point
			
		elif major == 13 :
			
			if minor == 0 and not pch_init_final : platform = 'ICP' # Ice Point
			elif minor == 30 and not pch_init_final : platform = 'LKF' # Lakefield
			elif minor == 50 and not pch_init_final : platform = 'JSP' # Jasper Point
			
		elif major == 14 :
			
			if minor == 0 : upd_found = True # Superseded minor version
			
			if minor in [0,1] and not pch_init_final : platform = 'CMP-H/LP' # Comet Point H/LP
			elif minor == 5 and not pch_init_final : platform = 'CMP-V' # Comet Point V
			
		elif major == 15 :
			
			if minor == 0 and not pch_init_final : platform = 'TGP' # Tiger Point
			elif minor == 40 and not pch_init_final : platform = 'MCC' # Mule Creek Canyon (Elkhart Lake)
		
		elif major == 16 :
			
			if minor == 0 and not pch_init_final : platform = 'ADP' # Alder Point
			
		# Get CSME 12+ DB SKU and check for Latest status
		sku_db,upd_found = sku_db_upd_cse(sku_init_db, sku_result, sku_stp, sku_db, upd_found, False, True)
	
	elif variant == 'TXE' : # Trusted Execution Engine
		
		# Detect SKU Attributes
		sku_match = re.compile(br'\$SKU[\x03-\x04]\x00\x00\x00').search(reading[start_man_match:]) # $SKU detection
		if sku_match is not None :
			start_sku_match = sku_match.start() + start_man_match
			
			sku_attrib = get_struct(reading, start_sku_match, SKU_Attributes)
			_,_,_,_,_,_,_,_,_,_,_,sku_size,_ = sku_attrib.get_flags()
			
		if major in [0,1] :
			
			if sku_size * 0.5 == 1.0 :
				sku = '1MB N/W'
				sku_db = '1MB_NW'
				platform = 'CGM'
			elif sku_size * 0.5 in (1.5,2.0) :
				sku = '1.25MB' if minor == 0 else '1.375MB'
				sku_db = '1.25MB' if minor == 0 else '1.375MB'
				platform = 'BYT'
			elif sku_size * 0.5 in (2.5,3.0) :
				sku = '3MB'
				sku_db = '3MB'
				platform = 'BYT'
			else :
				sku = col_r + 'Unknown' + col_e
			
			if rsa_key_hash == '6B8B10107E20DFD45F6C521100B950B78969B4AC9245D90DE3833E0A082DF374' :
				sku += ' M/D'
				sku_db += '_MD'
			elif rsa_key_hash == '613421A156443F1C038DDE342FF6564513A1818E8CC23B0E1D7D7FB0612E04AC' :
				sku += ' I/T'
				sku_db += '_IT'
				
		elif major == 2 :
			if sku_size * 0.5 == 1.5 :
				sku = '1.375MB'
				sku_db = '1.375MB'
			else :
				sku = col_r + 'Unknown' + col_e
			
			platform = 'BSW/CHT'
			
		_,db_min,db_hot,db_bld = check_upd('Latest_TXE_%d%d_%s' % (major, minor, sku_db))
		if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
	
	elif variant == 'CSTXE' : # Converged Security Trusted Execution Engine
		
		# Firmware Unpacking for all CSTXE
		if param.cse_unpack :
			cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail, cse_lt_chk_fail,
			cse_red_info, fdv_status, reading_msg, orom_hdr_all)
			continue # Next input file
		
		# Get CSE MFS File System Attributes & Configuration State (invokes mfs_anl, must be before ext_anl)
		mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final,vol_ftbl_id,config_rec_size,vol_ftbl_pl \
		= get_mfs_anl(mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final)
		
		# Detect CSE Firmware Attributes (must be after mfs_anl)
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext50_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info, \
		ext_iunit_val,ext15_info,pch_init_final,gmf_blob_info,fwi_iup_hashes,gsc_info \
		= ext_anl(reading, '$MN2', start_man_match, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], None, [mfs_parsed_idx,intel_cfg_hash_mfs],
		[pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl])
		
		# MFS missing, determine state via FTPR > fitc.cfg, FITC, MFSB or EFS (must be after mfs_anl, efs_anl & ext_anl)
		if mfs_state != 'Initialized' and efs_init : mfs_state = 'Initialized'
		elif mfs_state == 'Unconfigured' and (oem_config or fitc_found or mfsb_found or cdmd_found) : mfs_state = 'Configured'
		
		fw_0C_sku0,fw_0C_sku1,fw_0C_lbg,fw_0C_sku2 = ext12_info # Get SKU Capabilities, SKU Type, HEDT Support, SKU Platform
		
		db_sku_chk,sku,sku_stp,sku_pdm = get_cse_db(variant) # Get CSE SKU info from DB
		
		if major == 3 :
			
			if minor in [0,1] :
				
				# Adjust SoC Stepping if not from DB
				if sku_stp == 'Unknown' :
					if release == 'Production' : sku_stp = 'B' # PRD
					else : sku_stp = 'A' # PRE, BYP
					
				platform = 'APL' # Apollo Lake
				
			elif minor == 2 :
				
				# Adjust SoC Stepping if not from DB
				if sku_stp == 'Unknown' :
					if release == 'Production' : sku_stp = 'C' # PRD (Joule_C0-X64-Release)
					else : sku_stp = 'A' # PRE, BYP
					
				platform = 'BXT' # Broxton (Joule)
				
			if minor == 0 : upd_found = True # Superseded minor version
			
		elif major == 4 :
			
			if minor == 0 :
				
				# Adjust SoC Stepping if not from DB
				if sku_stp == 'Unknown' :
					if release == 'Production' : sku_stp = 'B' # PRD
					else : sku_stp = 'A' # PRE, BYP
			
				platform = 'GLK'
		
		# Parse all detected stitched PMC firmware (must be at the end due to SKU Stepping adjustments)
		pmc_all_anl = pmc_parse(pmc_all_init, pmc_all_anl)
		
		# Get DB SKU and check for Latest status (must be at the end due to superseded minor versions)
		sku_db,upd_found = sku_db_upd_cse('', '', sku_stp, sku_db, upd_found, True, True)
		
	elif variant == 'SPS' : # Server Platform Services
		
		if major == 1 and not rgn_exist :
			sps1_rec_match = re.compile(br'EpsRecovery').search(reading[start_man_match:]) # EpsRecovery detection
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
				rec_sku_match = re.compile(br'R2OP.{6}OP', re.DOTALL).search(reading[start_man_match:start_man_match + 0x2000]) # R2OP.{6}OP detection
				if rec_sku_match :
					sku = (reading[start_man_match + rec_sku_match.start() + 0x8:start_man_match + rec_sku_match.start() + 0xA]).decode('utf-8')
					sku_db = sku
					platform = sps_platform[sku] if sku in sps_platform else 'Unknown ' + sku

	elif variant == 'CSSPS' : # Converged Security Server Platform Services
		
		# Firmware Unpacking for all CSSPS
		if param.cse_unpack :
			cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail, cse_lt_chk_fail,
			cse_red_info, fdv_status, reading_msg, orom_hdr_all)
			continue # Next input file
		
		# Get CSE MFS File System Attributes & Configuration State (invokes mfs_anl, must be before ext_anl)
		mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final,vol_ftbl_id,config_rec_size,vol_ftbl_pl = get_mfs_anl(mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final)
		
		# Get CSE EFS File System Attributes & Configuration State (must be after mfs_anl)
		if efs_found : efs_init = efs_anl(mea_dir, efs_start, efs_start + efs_size, vol_ftbl_id, vol_ftbl_pl)
		
		# Detect CSE Firmware Attributes (must be after mfs_anl)
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext50_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info, \
		ext_iunit_val,ext15_info,pch_init_final,gmf_blob_info,fwi_iup_hashes,gsc_info \
		= ext_anl(reading, '$MN2', start_man_match, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], None, [mfs_parsed_idx,intel_cfg_hash_mfs],
		[pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl])
		
		# MFS missing, determine state via FTPR > fitc.cfg, FITC, MFSB or EFS (must be after mfs_anl, efs_anl & ext_anl)
		if mfs_state != 'Initialized' and efs_init : mfs_state = 'Initialized'
		elif mfs_state == 'Unconfigured' and (oem_config or fitc_found or mfsb_found or cdmd_found) : mfs_state = 'Configured'
		
		fw_0C_sku0,fw_0C_sku1,fw_0C_lbg,fw_0C_sku2 = ext12_info # Get SKU Capabilities, SKU Type, HEDT Support, SKU Platform
		
		db_sku_chk,sku,sku_stp,sku_pdm = get_cse_db(variant) # Get CSE SKU info from DB
		
		# Set PCH/SoC Stepping, if not found at DB
		if sku_stp == 'Unknown' and pch_init_final : sku_stp = pch_init_final[-1][1]
		
		# Set Recovery or Operational Region Type
		if not rgn_exist :
			# Intel releases OPR as partition ($CPD) but REC as region ($FPT)
			if ext_pname == 'FTPR' : fw_type = 'Recovery' # Non-Intel POR for REC
			elif ext_pname == 'OPR' : fw_type = 'Operational' # Intel POR for OPR
		elif not ifwi_exist and not sps_opr_found :
			fw_type = 'Recovery' # Intel POR for REC ($FPT + FTPR)
		
		# Set SKU Type via Extension 12 or 15 (CSSPS logic)
		if not fw_0C_sku0 and ext15_info[0] == 0 : # CSE_Ext_0C > FWSKUCaps and CSE_Ext_0F_R2 > ARBSVN cannot be empty/0
			sku = 'Unknown'
			sku_init_db = 'UNK'
		elif fw_0C_sku0 : # SKU in CSE_Ext_0C, prefer over CSE_Ext_0F
			sku = fw_0C_sku1[0]
			sku_init_db = fw_0C_sku1[1]
		elif ext15_info[0] != 0 and ext15_info[1] == '' : # SKU in CSE_Ext_0F_R2 but empty
			sku = 'Ignition'
			sku_init_db = 'IGN'
		else : # SKU in non-empty CSE_Ext_0F_R2, fallback if CSE_Ext_0C not used and not IGN
			sku = ext15_info[2][0]
			sku_init_db = ext15_info[2][1]
		
		sku_plat = ext50_info[1]
		sku_db = '%s_%s' % (sku_plat, sku_init_db)
		if sku_stp != 'Unknown' : sku_db += '_%s' % sku_stp
		
		if sku_plat in cssps_platform : platform = cssps_platform[sku_plat] # Chipset Platform via SKU Platform
		elif pch_init_final : platform = pch_init_final[0][0] # Chipset Platform via MFS Intel PCH Initialization Table
		else : platform = 'Unknown' # Chipset Platform is Unknown
		
		# Parse all detected stitched PMC firmware
		pmc_all_anl = pmc_parse(pmc_all_init, pmc_all_anl)
		
		# Parse all detected stitched PCHC firmware
		pchc_all_anl = pchc_parse(pchc_all_init, pchc_all_anl)
		
		# Parse all detected stitched PHY firmware
		phy_all_anl = phy_parse(phy_all_init, phy_all_anl)
		
		if major == 4 :
			
			if minor in [4,2] : warn_stor.append([col_m + 'Warning: CSE SPS 4.%d (Whitley %s) is partially supported only, errors are expected!' % (minor,sku) + col_e, False])
			
			if platform == 'Unknown' : platform = 'SPT-H' # Sunrise Point
		
		elif major == 5 :
			
			if platform == 'Unknown' : platform = 'CNP-H' # Cannon Point
		
		elif major == 6 :
			
			if platform == 'Unknown' : platform = 'TGP-H' # Tiger Point
	
	elif variant == 'GSC' : # Graphics System Controller
		
		# Firmware Unpacking for all GSC
		if param.cse_unpack :
			cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail, cse_lt_chk_fail,
			cse_red_info, fdv_status, reading_msg, orom_hdr_all)
			continue # Next input file
		
		# Get GSC MFS File System Attributes & Configuration State (invokes mfs_anl, must be before ext_anl)
		mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final,vol_ftbl_id,config_rec_size,vol_ftbl_pl \
		= get_mfs_anl(mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final)
		
		# Get GSC EFS File System Attributes & Configuration State (must be after mfs_anl)
		if efs_found : efs_init = efs_anl(mea_dir, efs_start, efs_start + efs_size, vol_ftbl_id, vol_ftbl_pl)
		
		# Get GSC Firmware Attributes (must be after mfs_anl)
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext50_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info, \
		ext_iunit_val,ext15_info,pch_init_final,gmf_blob_info,fwi_iup_hashes,_ \
		= ext_anl(reading, '$MN2', start_man_match, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], None, [mfs_parsed_idx,intel_cfg_hash_mfs],
		[pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl])
		
		if rbep_found :
			_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,gsc_info \
			= ext_anl(reading, '$CPD', rbep_start, file_end, [variant,major,minor,hotfix,build,year,month,variant_p], None, [mfs_parsed_idx,intel_cfg_hash_mfs],
			[pch_init_final,config_rec_size,vol_ftbl_id,vol_ftbl_pl])
		
		# MFS missing, determine state via FTPR > fitc.cfg, FITC, MFSB or EFS (must be after mfs_anl, efs_anl & ext_anl)
		if mfs_state != 'Initialized' and efs_init : mfs_state = 'Initialized'
		elif mfs_state == 'Unconfigured' and (oem_config or fitc_found or mfsb_found or cdmd_found) : mfs_state = 'Configured'
		
		# Get GSC Project Info
		if gsc_info :
			sku = '%s SOC%d %0.4d' % (gsc_info[0], gsc_info[1], gsc_info[2])
			sku_stp = 'A' if gsc_info[0] == 'DG01' else gsc_stp_dict[gsc_info[2] // 1000]
			sku_db = '%s_SOC%s_%s_%0.4d' % (gsc_info[0], gsc_info[1], sku_stp, gsc_info[2])
		
		# Parse all detected stitched PMC firmware
		pmc_all_anl = pmc_parse(pmc_all_init, pmc_all_anl)
		
		# Parse all detected stitched PHY firmware
		phy_all_anl = phy_parse(phy_all_init, phy_all_anl)
		
		# TODO: GSC information should be taken by RBEP, not FTPR
		
		if major == 100 :
			
			if minor == 0 and not gsc_info and not pch_init_final : sku,sku_db,platform = ['DG01'] * 3 # Dedicated Xe Graphics 1
		
		elif major == 101 :
			
			if minor == 0 and not gsc_info and not pch_init_final : sku,sku_db,platform = ['DG02'] * 3 # Dedicated Xe Graphics 2
			
		# Check for Latest GSC status
		if gsc_info :
			db_bld,_,_,_ = check_upd(('Latest_%s_%s_%d_%s' % (variant, gsc_info[0], gsc_info[1], sku_stp)))
			if gsc_info[2] < db_bld : upd_found = True
		else :
			_,_,db_hot,db_bld = check_upd(('Latest_%s_%s' % (variant, sku)))
			if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
	
	elif variant.startswith('OROM') : # Graphics System Controller Option ROM
		
		# Firmware Unpacking for all OROM
		if param.cse_unpack :
			cse_unpack('OROM', fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail, cse_lt_chk_fail,
			cse_red_info, fdv_status, reading_msg, orom_hdr_all)
			continue # Next input file
		
		# Detect IUP Firmware Attributes (must be after mfs_anl)
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext50_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info, \
		ext_iunit_val,ext15_info,pch_init_final,gmf_blob_info,fwi_iup_hashes,gsc_info \
		= ext_anl(reading, '$MN2', start_man_match, file_end, ['OROM',-1,-1,-1,-1,-1,-1,'OROM'], None, [[],''], [[],-1,-1,-1])
		
		platform = variant[4:] if len(variant) > 4 else 'Unknown'
		
		orom_all_size = max(orom_pci_size, orom_cpd_size) # Get total OROM IUP Size ($CPD Size may exceed PCIR)
		eng_fw_end = orom_all_size + 0x1000 - (orom_all_size % 0x1000) # Calculate 4K aligned OROM IUP Size
		
		if orom_match and orom_match[0].start() == 0x0 : # OROM 1st Image POR Start Offset is 0x0
			eng_size_text = chk_iup_size(eng_size_text, file_end, eng_fw_end, variant_p, platform) # Check OROM IUP Size
	
	elif variant.startswith('PMC') : # Power Management Controller
		
		# Firmware Unpacking for all PMC
		if param.cse_unpack :
			cse_unpack('PMC', fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail, cse_lt_chk_fail,
			cse_red_info, fdv_status, reading_msg, orom_hdr_all)
			continue # Next input file
		
		# Detect IUP Firmware Attributes
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext50_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info, \
		ext_iunit_val,ext15_info,pch_init_final,gmf_blob_info,fwi_iup_hashes,gsc_info \
		= ext_anl(reading, '$CPD', 0, file_end, ['PMC',-1,-1,-1,-1,-1,-1,'PMC'], None, [[],''], [[],-1,-1,-1])
		
		pmc_fw_ver,pmc_pch_gen,sku,sku_stp,pmc_fw_rel,release,rel_db,upd_found,platform,date,svn,pvbit,mn2_meu_ver = pmc_anl(cpd_mn2_info)
		
		if sku_stp != 'Unknown' : sku_stp = sku_stp[0]
		sku_db = '%s_%s' % (sku, sku_stp)
		
		eng_fw_end = cpd_size_calc(reading, 0, 0x1000) # Get PMC firmware size
		
		eng_size_text = chk_iup_size(eng_size_text, file_end, eng_fw_end, variant_p, platform) # Check PMC firmware size
				
	elif variant.startswith('PCHC') : # Platform Controller Hub Configuration
		
		# Firmware Unpacking for all PCHC
		if param.cse_unpack :
			cse_unpack('PCHC', fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail, cse_lt_chk_fail,
			cse_red_info, fdv_status, reading_msg, orom_hdr_all)
			continue # Next input file
		
		# Detect IUP Firmware Attributes
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext50_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info, \
		ext_iunit_val,ext15_info,pch_init_final,gmf_blob_info,fwi_iup_hashes,gsc_info \
		= ext_anl(reading, '$CPD', 0, file_end, ['PCHC',-1,-1,-1,-1,-1,-1,'PCHC'], None, [[],''], [[],-1,-1,-1])
		
		pchc_fw_ver,pchc_fw_major,pchc_fw_minor,pchc_fw_rel,release,rel_db,upd_found,platform,date,svn,pvbit,mn2_meu_ver = pchc_anl(cpd_mn2_info)
		
		eng_fw_end = cpd_size_calc(reading, 0, 0x1000) # Get PCHC firmware size
		
		eng_size_text = chk_iup_size(eng_size_text, file_end, eng_fw_end, variant_p, platform) # Check PCHC firmware size
				
	elif variant.startswith('PHY') : # USB Type C Physical
		
		# Firmware Unpacking for all PHY
		if param.cse_unpack :
			cse_unpack('PHY', fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail, cse_lt_chk_fail,
			cse_red_info, fdv_status, reading_msg, orom_hdr_all)
			continue # Next input file
		
		# Detect IUP Firmware Attributes
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext50_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info, \
		ext_iunit_val,ext15_info,pch_init_final,gmf_blob_info,fwi_iup_hashes,gsc_info \
		= ext_anl(reading, '$CPD', 0, file_end, ['PHY',-1,-1,-1,-1,-1,-1,'PHY'], None, [[],''], [[],-1,-1,-1])
		
		phy_fw_ver,sku,release,rel_db,upd_found,platform,date,svn,pvbit,mn2_meu_ver,phy_fw_rel = phy_anl(cpd_mn2_info)
		
		eng_fw_end = cpd_size_calc(reading, 0, 0x1000) # Get PHY firmware size
		
		eng_size_text = chk_iup_size(eng_size_text, file_end, eng_fw_end, variant_p, platform) # Check PHY firmware size
	
	# Create Firmware Type DB entry
	if variant.startswith(('PMC','PCHC','PHY','OROM')) : fw_type = 'Independent'
	
	if fw_type == 'Extracted' : type_db = 'EXTR'
	elif fw_type == 'Stock' : type_db = 'RGN'
	elif fw_type == 'Update' : type_db = 'UPD'
	elif fw_type == 'Operational' : type_db = 'OPR'
	elif fw_type == 'Recovery' : type_db = 'REC'
	elif fw_type == 'Partial Update' : type_db = 'PFU'
	elif fw_type == 'Independent' and variant.startswith('PMC') : type_db = 'PMC'
	elif fw_type == 'Independent' and variant.startswith('PHY') : type_db = 'PHY'
	elif fw_type == 'Independent' and variant.startswith('PCHC') : type_db = 'PCHC'
	elif fw_type == 'Independent' and variant.startswith('OROM') : type_db = 'OROM'
	elif fw_type == 'Unknown' : type_db = 'UNK'
	
	# Check for CSME 12+ FWUpdate Support/Compatibility
	fwu_iup_check = (variant,major >= 12,type_db,sku_db[:3],is_pfu_img) == ('CSME',True,'EXTR','COR',False)
	if fwu_iup_check and (uncharted_match or not fwu_iup_exist) : fwu_iup_result = 'Impossible'
	if variant == 'CSME' and major >= 16 and not is_pfu_img and file_has_align > 0x0 and fpt_start == 0x0 : fwu_iup_result = 'Impossible'
	if fwu_iup_result != 'Impossible' :
		if major == 12 :
			fwu_iup_result = ['No','Yes'][int(pmcp_fwu_found)]
		elif (major,minor) in [(13,0),(13,50),(14,0),(14,5),(15,40),(16,0)] or (major,minor,sku_result) == (15,0,'LP') :
			fwu_iup_result = ['No','Yes'][int(pmcp_fwu_found and pchc_fwu_found)]
		elif (major,minor) in [(13,30),(14,1)] or (major,minor,sku_result) == (15,0,'H') :
			fwu_iup_result = ['No','Yes'][int(pmcp_fwu_found and pchc_fwu_found and phy_fwu_found)]
		else :
			fwu_iup_result = ['No','Yes'][int(pmcp_fwu_found and pchc_fwu_found and phy_fwu_found)]
		
	# Check for CSE Extension 15 R2 NVM Compatibility
	if ext15_info[3] not in ['', 'Undefined'] : nvm_db = '_%s' % ext15_info[3]
	
	# Format Firmware Version Tag based on Variant
	fw_ver = get_fw_ver(variant, major, minor, hotfix, build)
	
	# Create Firmware File Name
	if variant.endswith('SPS') and sku == 'NaN' : # (CS)SPS w/o SKU
		name_fw = '%s_%s_%s' % (fw_ver, rel_db, type_db)
	elif variant.startswith(('PMCAPL','PMCBXT','PMCGLK')) : # PMC APL A/B, BXT C, GLK A/B
		name_fw = '%s_%s_%s_%s_%s' % (platform[:3], fw_ver, sku_stp[0], date, rel_db)
	elif variant.startswith(('PMCCNP','PMCWTL')) and (major < 30 or major == 3232) : # PMC CNP A, WTL
		name_fw = '%s_%s_%s_%s_%s' % (platform[:3], fw_ver, sku_db, date, rel_db)
	elif variant.startswith('PMCDG') : # PMC DG
		name_fw = '%s_%s_%s_%s' % (platform[:4], fw_ver, date, rel_db)
	elif variant.startswith('PMC') : # PMC CNP A/B, ICP, LKF, CMP, TGP, ADP, DG1
		name_fw = '%s_%s_%s_%s' % (platform[:3], fw_ver, sku_db, rel_db)
	elif variant.startswith('PCHC') : # PCHC ICP, LKF, CMP, TGP, ADP
		name_fw = '%s_%s_%s' % (platform[:3], fw_ver, rel_db)
	elif variant.startswith('PHYDG') : # PHY DG
		name_fw = '%s_%s_%s_%s_%s' % (platform[:3], sku, fw_ver, date, rel_db)
	elif variant.startswith('PHY') : # PHY S, P
		name_fw = '%s_%s_%s_%s' % (platform[:3], sku, fw_ver, rel_db)
	elif variant.startswith('OROM') : # OROM
		name_fw = '%s_%s_%s' % (platform, fw_ver, rel_db)
	elif fw_type == 'Partial Update' : # PFU/LMS
		name_fw = '%s_%s_%s' % (fw_ver, rel_db, type_db)
	else : # (CS)ME, (CS)TXE, (CS)SPS, GSC
		name_fw = '%s_%s%s_%s_%s' % (fw_ver, sku_db, nvm_db, rel_db, type_db)
	
	# CSME 12+ Corporate Extracted must include IUP existence state as well for FWUpdate tool compatibility & usage
	if fwu_iup_check : name_fw += ['-N','-Y'][int(fwu_iup_exist)]
	
	# Create Firmware Database Name/Entry
	name_db = name_fw + '_' + rsa_sig_hash
	
	# Append part of RSA Signature Hash to known Firmware with duplicate Names
	# All CSME 15.0 LP must have RSA Signature appended due to Bx & Cx Stepping
	if rsa_sig_hash in known_dup_name_hahes or (variant,major,minor,sku_result) == ('CSME',15,0,'LP') :
		name_fw += '_%s' % rsa_sig_hash[:8]
	
	# Store Firmware DB entry to file
	if param.db_print_new :
		with open(os.path.join(mea_dir, 'MEA_PDB.txt'), 'a', encoding = 'utf-8') as db_file : db_file.write(name_db + '\n')
		continue # Next input file
	
	# Search Database for Firmware
	if not variant.startswith(('PMC','PCHC','PHY')) and not is_pfu_img : # Not PMC, PCHC, PHY or Partial Update
		for line in mea_db_lines :
			# Search the re-created file name without extension at the database
			if name_db in line : fw_in_db_found = True # Known firmware, nothing new
			if rsa_sig_hash in line and '_%s_' % rel_db in line and type_db == 'EXTR' and ('_RGN' in line or '_EXTR-Y' in line) :
				rgn_over_extr_found = True # Same firmware found but of preferred type (RGN > EXTR, EXTR-Y > EXTR-N), nothing new
				fw_in_db_found = True
			# For ME 6.0 IGN, (CS)ME 7+, (CS)TXE
			if rsa_sig_hash in line and type_db == 'UPD' and ((variant in ['ME','CSME'] and (major >= 7 or
			(major == 6 and 'Ignition' in sku))) or variant in ['TXE','CSTXE']) and ('_RGN' in line or '_EXTR' in line) :
				rgn_over_extr_found = True # Same RGN/EXTR firmware found at database, UPD disregarded
			if rsa_sig_hash in line and (variant,type_db,sku_stp) == ('CSSPS','REC','Unknown') :
				fw_in_db_found = True # REC w/o $FPT are not POR for CSSPS, notify only if REC w/ $FPT does not exist
	else :
		can_search_db = False # Do not search DB for PMC, PCHC, PHY or Partial Update
	
	if can_search_db and not rgn_over_extr_found and not fw_in_db_found and not sps_extr_ignore : note_new_fw(variant_p)
	
	# Check if firmware is updated, Production only
	if release == 'Production' and not is_pfu_img : # Does not display if firmware is non-Production or Partial Update
		if not variant.startswith(('SPS','CSSPS','PMCAPL','PMCBXT','PMCGLK')) : # (CS)SPS and old PMC excluded
			upd_rslt = col_r + 'No' + col_e if upd_found else col_g + 'Yes' + col_e
	
	# Rename input file based on the DB structured name
	if param.give_db_name :
		old_file_name = file_in
		new_file_name = os.path.join(os.path.dirname(file_in), name_fw + '.bin')
		
		if not os.path.isfile(new_file_name) : os.replace(old_file_name, new_file_name)
		elif os.path.basename(file_in) == name_fw + '.bin' : pass
		else : print(col_r + 'Error: A file with the same name already exists!' + col_e)
		
		continue # Next input file
	
	# Print Firmware Info
	msg_pt = ext_table(['Field', 'Value'], False, 1)
	msg_pt.title = col_c + '%s (%d/%d)' % (os.path.basename(file_in)[:45], cur_count, in_count) + col_e
	
	msg_pt.add_row(['Family', variant_p])
	msg_pt.add_row(['Version', fw_ver])
	msg_pt.add_row(['Release', release + ', Engineering ' if build >= 7000 else release])
	msg_pt.add_row(['Type', fw_type])
	
	if (variant == 'CSTXE' and 'Unknown' not in sku) or (variant,sku) == ('SPS','NaN') or is_pfu_img \
	or variant.startswith(('PMCAPL','PMCBXT','PMCGLK','PCHC','PMCDG','OROM')) :
		pass
	else :
		msg_pt.add_row(['SKU', sku])
	
	if variant.startswith(('CS','PMC','GSC')) and not variant.startswith('PMCDG') and not is_pfu_img :
		if pch_init_final : msg_pt.add_row(['Chipset', pch_init_final[-1][0]])
		elif sku_stp == 'Unknown' : msg_pt.add_row(['Chipset', 'Unknown'])
		else : msg_pt.add_row(['Chipset Stepping', ', '.join(map(str, list(sku_stp)))])
	
	if nvm_db : msg_pt.add_row(['NVM Compatibility', ext15_info[3]])
	
	if ((variant == 'ME' and major >= 8) or variant.startswith(('TXE','CS','GSC','PMC','PCHC','PHY','OROM'))) and not is_pfu_img :
		msg_pt.add_row(['TCB Security Version Number', svn])
		
	if ((variant == 'CSME' and major >= 12) or variant.startswith(('CSTXE','CSSPS','GSC','PMC','PCHC','PHY','OROM'))) and not is_pfu_img :
		msg_pt.add_row(['ARB Security Version Number', ext15_info[0]])
	
	if ((variant == 'ME' and major >= 8) or variant.startswith(('TXE','CS','GSC','PMC','PCHC','PHY','OROM'))) and not is_pfu_img :
		msg_pt.add_row(['Version Control Number', vcn])
	
	if pvbit is not None and not is_pfu_img : msg_pt.add_row(['Production Ready', ['No','Yes'][pvbit]]) # Always check against None
	
	if [variant,major,is_pfu_img] == ['CSME',11,False] :
		if pdm_status != 'NaN' : msg_pt.add_row(['Power Down Mitigation', pdm_status])
		msg_pt.add_row(['Workstation Support', ['No','Yes'][fw_0C_lbg]])
		
	if variant == 'ME' and major == 7 : msg_pt.add_row(['Patsburg Support', ['No','Yes'][is_patsburg]])
	
	if variant in ('CSME','CSTXE','CSSPS','TXE','GSC') and not is_pfu_img :
		msg_pt.add_row(['OEM Configuration', ['No','Yes'][int(oem_signed or oemp_found or utok_found)]])
	
	if variant == 'CSME' and major >= 12 and not is_pfu_img : msg_pt.add_row(['FWUpdate Support', fwu_iup_result])
	
	msg_pt.add_row(['Date', date])

	if variant in ('CSME','CSTXE','CSSPS','GSC') and not is_pfu_img : msg_pt.add_row(['File System State', mfs_state])
	
	if rgn_exist or cse_lt_struct or variant.startswith(('PMC','PCHC','PHY','OROM')) :
		if (variant,major,release) == ('ME',6,'ROM-Bypass') : msg_pt.add_row(['Size', 'Unknown'])
		elif (variant,fd_devexp_rgn_exist) == ('CSTXE',True) : pass
		else : msg_pt.add_row(['Size', '0x%X' % eng_fw_end])
	
	if fitc_ver_found :
		msg_pt.add_row(['Flash Image Tool', get_fw_ver(variant,fitc_major,fitc_minor,fitc_hotfix,fitc_build)])
		
	if mn2_meu_ver != '0.0.0.0000' :
		msg_pt.add_row(['Manifest Extension Utility', mn2_meu_ver])
	
	if (variant,major) == ('ME',7) :
		msg_pt.add_row(['Downgrade Blacklist 7.0', me7_blist_1])
		msg_pt.add_row(['Downgrade Blacklist 7.1', me7_blist_2])
	
	if platform != 'NaN' : msg_pt.add_row(['Chipset Support', platform])
	
	if not variant.startswith(('SPS','CSSPS','OROM')) and upd_rslt != '' : msg_pt.add_row(['Latest', upd_rslt])
	
	print('\n%s' % msg_pt)
	
	if param.check : # Debug/Research
		if mfs_state != 'Unconfigured' or oem_signed or oemp_found or utok_found or fitc_size or cdmd_size : input('\nCFG_PRESENT!\n')
		if pmc_all_init or pchc_all_init or phy_all_init : input('\nIUP_PRESENT!\n')
	
	if param.write_html :
		with open('%s.html' % os.path.basename(file_in), 'w', encoding='utf-8') as o : o.write('\n<br/>\n%s' % pt_html(msg_pt))
	
	if param.write_json :
		with open('%s.json' % os.path.basename(file_in), 'w', encoding='utf-8') as o : o.write('\n%s' % pt_json(msg_pt))
	
	for pmc in pmc_all_anl :
		msg_pmc_pt = ext_table(['Field', 'Value'], False, 1)
		msg_pmc_pt.title = 'Power Management Controller'
		
		pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmc_mn2_signed_db,pmcp_upd_found,pmc_platform, \
		pmc_date,pmc_svn,pmc_pvbit,pmc_meu_ver,pmc_vcn,pmc_mn2_ver,pmc_ext15_info,pmc_size = pmc
		
		msg_pmc_pt.add_row(['Family', 'PMC'])
		msg_pmc_pt.add_row(['Version', pmc_fw_ver])
		msg_pmc_pt.add_row(['Release', pmc_mn2_signed + ', Engineering ' if pmc_fw_rel >= 7000 else pmc_mn2_signed])
		msg_pmc_pt.add_row(['Type', 'Independent'])
		if (variant == 'CSME' and major >= 12) or (variant == 'CSSPS' and major >= 5) or not pmc_platform.startswith(('APL','BXT','GLK','DG')) :
			msg_pmc_pt.add_row(['Chipset SKU', pmc_pch_sku])
		if not pmc_platform.startswith('DG') : msg_pmc_pt.add_row(['Chipset Stepping', 'Unknown' if pmc_pch_rev[0] == 'U' else pmc_pch_rev[0]])
		msg_pmc_pt.add_row(['TCB Security Version Number', pmc_svn])
		msg_pmc_pt.add_row(['ARB Security Version Number', pmc_ext15_info[0]])
		msg_pmc_pt.add_row(['Version Control Number', pmc_vcn])
		if pmc_pvbit is not None : msg_pmc_pt.add_row(['Production Ready', ['No','Yes'][pmc_pvbit]]) # Always check against None
		msg_pmc_pt.add_row(['Date', pmc_date])
		msg_pmc_pt.add_row(['Size', '0x%X' % pmc_size])
		if pmc_meu_ver != '0.0.0.0000' : msg_pmc_pt.add_row(['Manifest Extension Utility', pmc_meu_ver])
		msg_pmc_pt.add_row(['Chipset Support', pmc_platform])
		if pmc_mn2_signed == 'Production' and ((variant == 'CSME' and major >= 12) or variant == 'GSC') :
			msg_pmc_pt.add_row(['Latest', [col_g + 'Yes' + col_e, col_r + 'No' + col_e][pmcp_upd_found]])
		
		print(msg_pmc_pt)
		
		if param.write_html :
			with open('%s.html' % os.path.basename(file_in), 'a', encoding='utf-8') as o : o.write('\n<br/>\n%s' % pt_html(msg_pmc_pt))
			
		if param.write_json :
			with open('%s.json' % os.path.basename(file_in), 'a', encoding='utf-8') as o : o.write('\n%s' % pt_json(msg_pmc_pt))
			
	for pchc in pchc_all_anl :
		msg_pchc_pt = ext_table(['Field', 'Value'], False, 1)
		msg_pchc_pt.title = 'Platform Controller Hub Configuration'
		
		pchc_fw_ver,pchc_fw_major,pchc_fw_minor,pchc_fw_rel,pchc_mn2_signed,pchc_mn2_signed_db,pchc_upd_found,pchc_platform, \
		pchc_date,pchc_svn,pchc_pvbit,pchc_meu_ver,pchc_vcn,pchc_ext15_info,pchc_size = pchc
		
		msg_pchc_pt.add_row(['Family', 'PCHC'])
		msg_pchc_pt.add_row(['Version', pchc_fw_ver])
		msg_pchc_pt.add_row(['Release', pchc_mn2_signed + ', Engineering ' if pchc_fw_rel >= 7000 else pchc_mn2_signed])
		msg_pchc_pt.add_row(['Type', 'Independent'])
		msg_pchc_pt.add_row(['TCB Security Version Number', pchc_svn])
		msg_pchc_pt.add_row(['ARB Security Version Number', pchc_ext15_info[0]])
		msg_pchc_pt.add_row(['Version Control Number', pchc_vcn])
		if pchc_pvbit is not None : msg_pchc_pt.add_row(['Production Ready', ['No','Yes'][pchc_pvbit]]) # Always check against None
		msg_pchc_pt.add_row(['Date', pchc_date])
		msg_pchc_pt.add_row(['Size', '0x%X' % pchc_size])
		if pchc_meu_ver != '0.0.0.0000' : msg_pchc_pt.add_row(['Manifest Extension Utility', pchc_meu_ver])
		msg_pchc_pt.add_row(['Chipset Support', pchc_platform])
		if pchc_mn2_signed == 'Production' and (variant == 'CSME' and major >= 13) :
			msg_pchc_pt.add_row(['Latest', [col_g + 'Yes' + col_e, col_r + 'No' + col_e][pchc_upd_found]])
		
		print(msg_pchc_pt)
		
		if param.write_html :
			with open('%s.html' % os.path.basename(file_in), 'a', encoding='utf-8') as o : o.write('\n<br/>\n%s' % pt_html(msg_pchc_pt))
			
		if param.write_json :
			with open('%s.json' % os.path.basename(file_in), 'a', encoding='utf-8') as o : o.write('\n%s' % pt_json(msg_pchc_pt))
			
	for phy in phy_all_anl :
		msg_phy_pt = ext_table(['Field', 'Value'], False, 1)
		msg_phy_pt.title = 'USB Type C Physical'
		
		phy_fw_ver,phy_sku,phy_mn2_signed,phy_mn2_signed_db,phy_upd_found,phy_platform,phy_date,phy_svn,phy_pvbit,phy_meu_ver, \
		phy_fw_rel,phy_vcn,phy_ext15_info,phy_size = phy
		
		msg_phy_pt.add_row(['Family', 'PHY'])
		msg_phy_pt.add_row(['Version', phy_fw_ver])
		msg_phy_pt.add_row(['Release', phy_mn2_signed + ', Engineering ' if phy_fw_rel >= 7000 else phy_mn2_signed])
		msg_phy_pt.add_row(['Type', 'Independent'])
		msg_phy_pt.add_row(['SKU', phy_sku])
		msg_phy_pt.add_row(['TCB Security Version Number', phy_svn])
		msg_phy_pt.add_row(['ARB Security Version Number', phy_ext15_info[0]])
		msg_phy_pt.add_row(['Version Control Number', phy_vcn])
		if phy_pvbit is not None : msg_phy_pt.add_row(['Production Ready', ['No','Yes'][phy_pvbit]]) # Always check against None
		msg_phy_pt.add_row(['Date', phy_date])
		msg_phy_pt.add_row(['Size', '0x%X' % phy_size])
		if phy_meu_ver != '0.0.0.0000' : msg_phy_pt.add_row(['Manifest Extension Utility', phy_meu_ver])
		msg_phy_pt.add_row(['Chipset Support', phy_platform])
		if phy_mn2_signed == 'Production' and ((variant == 'CSME' and major >= 13) or variant == 'GSC') :
			msg_phy_pt.add_row(['Latest', [col_g + 'Yes' + col_e, col_r + 'No' + col_e][phy_upd_found]])
		
		print(msg_phy_pt)
		
		if param.write_html :
			with open('%s.html' % os.path.basename(file_in), 'a', encoding='utf-8') as o : o.write('\n<br/>\n%s' % pt_html(msg_phy_pt))
		
		if param.write_json :
			with open('%s.json' % os.path.basename(file_in), 'a', encoding='utf-8') as o : o.write('\n%s' % pt_json(msg_phy_pt))
	
	# Print Messages which must be at the end of analysis
	if eng_size_text != ['', False] : warn_stor.append(['%s' % eng_size_text[0], eng_size_text[1]])
	
	if fwu_iup_result == 'Impossible' and uncharted_match :
		fwu_iup_msg = (uncharted_match.start(),p_end_last_back,p_end_last_back + uncharted_match.start())
		warn_stor.append([col_m + 'Warning: Remove 0x%X padding from 0x%X - 0x%X for FWUpdate Support!' % fwu_iup_msg + col_e, False])
	
	if variant == 'CSME' and major >= 16 and fwu_iup_result == 'Impossible' and file_has_align :
		warn_stor.append([col_m + 'Warning: Remove 0x%X padding from image end for FWUpdate Support!' % file_has_align + col_e, False])
	
	if fpt_count > 1 : note_stor.append([col_y + 'Note: Multiple (%d) Intel Flash Partition Tables detected!' % fpt_count + col_e, True])
	
	if fd_count > 1 : note_stor.append([col_y + 'Note: Multiple (%d) Intel Flash Descriptors detected!' % fd_count + col_e, True])
	
	msg_all = err_stor + warn_stor + note_stor
	for msg_idx in range(len(msg_all)) :
		msg_tuple = tuple(msg_all[msg_idx])
		if msg_tuple not in msg_set:
			msg_set.add(msg_tuple)
			print('\n' + msg_all[msg_idx][0])
			if param.write_html :
				with open('%s.html' % os.path.basename(file_in), 'a', encoding='utf-8') as o : o.write('\n<p>%s</p>' % ansi_escape.sub('', str(msg_all[msg_idx][0])))
			if param.write_json :
				msg_entries['Entry %0.4d' % msg_idx] = ansi_escape.sub('', str(msg_all[msg_idx][0]))
	
	if param.write_json :
		msg_dict['Messages'] = msg_entries
		with open('%s.json' % os.path.basename(file_in), 'a', encoding='utf-8') as o : o.write('\n%s' % json.dumps(msg_dict, indent=4))
	
	# Close input and copy it in case of messages
	copy_on_msg(msg_all)
	
	# Show MEA help screen only once
	if param.help_scr : mea_exit(0)

mea_exit(0)