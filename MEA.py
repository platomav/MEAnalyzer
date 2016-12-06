"""
ME Analyzer
Intel Engine Firmware Analysis Tool
Copyright (C) 2014-2016 Plato Mavropoulos
"""

title = 'ME Analyzer v1.7.0_9'

import sys
import re
import os
import io
import binascii
import hashlib
import struct
import tempfile
import subprocess
import traceback
import fileinput
import inspect
import colorama
import win32console

# Initialize and setup Colorama
colorama.init()
col_red = colorama.Fore.RED + colorama.Style.BRIGHT
col_green = colorama.Fore.GREEN + colorama.Style.BRIGHT
col_yellow = colorama.Fore.YELLOW + colorama.Style.BRIGHT
col_magenta = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
col_end = colorama.Fore.RESET + colorama.Style.RESET_ALL

class MEA_Param :

	def __init__(self,source) :
	
		self.all = ['-?','-skip','-multi','-ubupre','-ubu','-extr','-msg','-adir','-hid','-aecho','-eker',
					'-dker','-pwdb','-pdb','-enuf','-rbume','-dbname','-utf8','-exc','-mass','-fptchk','-disuf']
		
		# -disuf is removed, temporarily ignored via param.all until UEFIStrip adjusts
		
		self.help_scr = False
		self.skip_intro = False
		self.multi = False
		self.ubu_mea_pre = False
		self.ubu_mea = False
		self.extr_mea = False
		self.print_msg = False
		self.alt_dir = False
		self.hid_find = False
		self.alt_msg_echo = False
		self.me11_ker_extr = False
		self.me11_ker_disp = False
		self.db_print_clean = False
		self.db_print_new = False
		self.enable_uf = False
		self.rbu_me_extr = False
		self.give_db_name = False
		self.unicode_fix = False
		self.exc_pause = False
		self.mass_scan = False
		self.fpt_chk_print = False
		
		for i in source :
			if i == '-?' : self.help_scr = True # Displays MEA help text for end-users.
			if i == '-skip' : self.skip_intro = True # Skips the MEA options intro screen.
			if i == '-multi' : self.multi = True # Checks multiple files, keeps those with messages and renames everything else.
			if i == '-ubupre' : self.ubu_mea_pre = True # UBU Pre-Menu mode, 9 --> Engine FW found, 8 --> Engine FW not found.
			if i == '-ubu' : self.ubu_mea = True # UBU mode, prints everything without some headers.
			if i == '-extr' : self.extr_mea = True # UEFI Strip mode, prints special one-line outputs.
			if i == '-msg' : self.print_msg = True # Prints all messages without any headers.
			if i == '-adir' : self.alt_dir = True # Sets UEFIFind.exe to the previous directory.
			if i == '-hid' : self.hid_find = True # Forces MEA to display any firmware found. Works with -msg.
			if i == '-aecho' : self.alt_msg_echo = True # Enables an alternative display of empty lines. Works with -msg and -hid.
			if i == '-eker' : self.me11_ker_extr = True # Extraction of post-SKL FTPR > Kernel region.
			if i == '-dker' : self.me11_ker_disp = True # Forces MEA to print post-SKL Kernel/FIT SKU analysis even when firmware is hash-known.
			if i == '-pwdb' : self.db_print_clean = True # Prints the whole DB without SHA1 hashes.
			if i == '-pdb' : self.db_print_new = True # Writes input firmware's DB entries to file.
			if i == '-enuf' : self.enable_uf = True # Enables UEFIFind Engine GUID Detection.
			if i == '-rbume' : self.rbu_me_extr = True # Extraction of Dell HDR RBU ImagME Regions.
			if i == '-dbname' : self.give_db_name = True # Rename input file based on DB structured name.
			if i == '-utf8' : self.unicode_fix = True # Encode all output to Unicode for strange characters.
			if i == '-exc' : self.exc_pause = True # Pauses after any unexpected python exception, for debugging.
			if i == '-mass' : self.mass_scan = True # Scans all files of a given directory, no limit.
			if i == '-fptchk' : self.fpt_chk_print = True # Displays detected & expected $FPT header Checksum.
			
		if self.ubu_mea_pre or self.ubu_mea or self.extr_mea or self.print_msg or self.mass_scan \
		or self.db_print_clean or self.db_print_new : self.skip_intro = True

# MEA Version Header
def mea_hdr_init() :
	if not param.extr_mea and not param.print_msg :
		db_rev = "None"
		try :
			fw_db = db_open()
			for line in fw_db :
				if 'Revision' in line :
					db_line = line.split()
					db_rev = db_line[2]
			fw_db.close()
		except :
			pass
			
		return db_rev

def mea_hdr(db_rev) :	
	print("\n-------[ %s ]-------" % title)
	print("            Database %s" % db_rev)
		
def mea_help() :
	print("\n\
Usage: MEA.exe [FilePath] {Options}\n\n\
{Options}\n\n\
	-? : Displays MEA's help & usage screen\n\
	-skip : Skips MEA's options intro screen\n\
	-multi : Scans multiple files and renames on messages\n\
	-mass : Scans all files of a given directory\n\
	-ubu : SoniX/LS_29's UEFI BIOS Updater mode\n\
	-ubupre : SoniX/LS_29's UEFI BIOS Updater Pre-Menu mode\n\
	-extr : Lordkag's UEFI Strip mode\n\
	-adir : Sets UEFIFind to the previous directory\n\
	-msg : Prints only messages without headers\n\
	-hid : Displays all firmware even without messages (-msg)\n\
	-aecho : Alternative display of empty lines (-msg, -hid)\n\
	-enuf : Enables UEFIFind Engine GUID detection\n\
	-dbname : Renames input file based on DB name\n\
	-rbume : Extracts Dell HDR RBU ImagME regions\n\
	-pwdb : Prints the DB without SHA1 hashes to file\n\
	-pdb : Writes input firmware's DB entries to file\n\
	-dker : Prints Kernel/FIT analysis for post-SKL firmware\n\
	-eker : Extracts post-SKL FTPR > Kernel region (research)\n\
    -fptchk : Displays detected & expected $FPT header Checksum\n\
	-exc : Pauses after unexpected python exceptions (debugging)\n\
	-utf8 : Encodes output to Unicode (only in case of crash)\
	")

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
	traceback.print_exception(exc_type, exc_value, tb)
	input("\nPress enter key to exit")
	sys.exit(-1)
	
# Calculate SHA-1 Hash of File
def sha1_file(filepath) :
	with open(filepath, 'rb') as f : return hashlib.sha1(f.read()).hexdigest()
	
def sha1_text(text) :
	return hashlib.sha1(text).hexdigest()

def mea_exit(code) :
	colorama.deinit() # Stop Colorama
	if param.ubu_mea_pre or param.ubu_mea or param.extr_mea or param.print_msg : sys.exit(code)
	input("\nPress enter to exit")
	sys.exit(code)

# Must be called at the end of analysis to gather all available messages, if any
def multi_drop() :
	if err_stor or warn_stor or note_stor : # Any note, warning or error renames the file
		f.close()
		new_multi_name = os.path.dirname(file_in) + "\__CHECK__" + os.path.basename(file_in)
		os.rename(file_in, new_multi_name)

def db_open() :
	fw_db = open(db_path, "r")
	return fw_db
		
def db_print() :
	fw_db = db_open()
	for line in fw_db :
		if (line[:3] == "***") or ('Latest' in line) :
			continue # Skip comments or "Latest"
		else :
			if len(line) < 2 :
				with open(mea_dir + "\\" + "MEA_DB.txt", "a") as pdb_file : pdb_file.write('\n') # Keep empty lines for easier copying
			elif 'SHA1' in line :
				wlp = line.strip().split('_') # whole line parts
				plp = wlp[0] # printable line parts
				for i in range(1, len(wlp) - 2, 1) : plp = plp + "_" + wlp[i]
				with open(mea_dir + "\\" + "MEA_DB.txt", "a") as pdb_file : pdb_file.write(plp + '\n')
			else :
				with open(mea_dir + "\\" + "MEA_DB.txt", "a") as pdb_file : pdb_file.write(line.strip() + '\n')
	fw_db.close()
		
	mea_exit(0)

def db_repl(file,f_find,f_replace) :
	for line in fileinput.input(file, inplace=1):
		if f_find in line :
			line = line.replace(f_find,f_replace)
		sys.stdout.write(line)
		
	mea_exit(0)
	
def check_upd(key) :
	upd_key_found = False
	vlp = [0]*4
	fw_db = db_open()
	for line in fw_db :
		if len(line) < 2 or line[:3] == "***" :
			continue # Skip empty lines or comments
		elif key in line :
			upd_key_found = True
			wlp = line.strip().split('__') # whole line parts
			vlp = wlp[1].strip().split('.') # version line parts
			for i in range(len(vlp)) : vlp[i] = int(vlp[i])
			break
	fw_db.close()
	if upd_key_found : return vlp[0],vlp[1],vlp[2],vlp[3]
	else : return 0,0,0,0
		
def str_reverse_as_bytes(input_var) :
	# Splits the string into pairs, reverses them and then merge it back together (ABCD --> AB CD --> CD AB --> CDAB)
	return "".join(reversed([input_var[i:i+2] for i in range(0, len(input_var), 2)]))
		
# General MEA Messages
def gen_msg(msg, value) :
	if msg == "uefifind_guid" :
		if not param.print_msg : 
			print("")
			print(col_yellow + "Note: Detected Engine GUID %s!" % value + col_end)
			
		if (not err_stor) and (not warn_stor) and (not note_stor) :
			note_stor.append(col_yellow + "Note: Detected Engine GUID %s!" % value + col_end)
		else :
			note_stor.append(col_yellow + "\nNote: Detected Engine GUID %s!" % value + col_end)

# Detect SPI with Intel Flash Descriptor
def spi_fd_init() :
	fd_match = (re.compile(br'\xFF\xFF\xFF\xFF\x5A\xA5\xF0\x0F')).search(reading) # 16xFF + Z¥π. detection (Intel Flash Descriptor)
	if fd_match is None :
		fd_match = (re.compile(br'\x5A\xA5\xF0\x0F')).search(reading) # Z¥π. only fallback (ICH, Pre-PCH)
		start_substruct = 0x0
	else :
		start_substruct = 0xC
	
	if fd_match is not None :
		(start_fd_match, end_fd_match) = fd_match.span()
		return True, start_fd_match - start_substruct, end_fd_match
	else :
		return False, 0, 0

# Analyze Intel FD after Reading, Major, Variant
def spi_fd(action,start_fd_match,end_fd_match) :
	if action == 'unlocked' :
		# 0xh FF FF = 0b 1111 1111 1111 1111 --> All 8 (0-7) regions Read/Write unlocked by CPU/BIOS
		if (variant == "ME" and major <= 10) or variant == "TXE" : # CPU/BIOS, ME, GBE check
			fd_bytes = reading[end_fd_match + 0x4E:end_fd_match + 0x50] + reading[end_fd_match + 0x52:end_fd_match + 0x54] \
					   + reading[end_fd_match + 0x56:end_fd_match + 0x58]
			fd_bytes = binascii.b2a_hex(fd_bytes).decode('utf-8').upper() # Hex value with Little Endianess
			if fd_bytes == "FFFFFFFFFFFF" : return 2 # Unlocked FD
			else : return 1 # Locked FD
		elif variant == "ME" and major > 10 : # CPU/BIOS, ME, GBE, EC check
			fd_bytes = reading[end_fd_match + 0x6D:end_fd_match + 0x70] + reading[end_fd_match + 0x71:end_fd_match + 0x74] \
					   + reading[end_fd_match + 0x75:end_fd_match + 0x78] + reading[end_fd_match + 0x7D:end_fd_match + 0x80]
			fd_bytes = binascii.b2a_hex(fd_bytes).decode('utf-8').upper() # Hex value with Little Endianess
			if fd_bytes == "FFFFFFFFFFFFFFFFFFFFFFFF" : return 2 # Unlocked FD
			else : return 1 # Locked FD
	elif action == 'region' :
		me_base = int.from_bytes(reading[end_fd_match + 0x34:end_fd_match + 0x36], 'little')
		me_limit = int.from_bytes(reading[end_fd_match + 0x36:end_fd_match + 0x38], 'little')
		if me_limit != 0 :
			me_start = me_base * 0x1000 + start_fd_match # fd_match required in case FD is not at the start of image
			#me_size = hex((me_limit + 1 - me_base) * 0x1000) # The +1 is required to include last Region byte
			return True,me_start # FD found, ME Region exists
		else :
			return False,0 # FD found, ME Region missing
		
def fw_ver() :
	if variant == "SPS" :
		if sub_sku != "NaN" : version = "%s.%s.%s.%s.%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), sub_sku) # xx.xx.xx.xxx.y
		else : version = "%s.%s.%s.%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build)) # xx.xx.xx.xxx
	else :
		version = "%s.%s.%s.%s" % (major, minor, hotfix, build)
	
	return version
	
def fuj_umem_ver(me_start) :
	rgn_fuj_hdr = reading[me_start:me_start + 0x4]
	rgn_fuj_hdr = binascii.b2a_hex(rgn_fuj_hdr).decode('utf-8').upper()
	version = "NaN"
	if rgn_fuj_hdr == "554DC94D" : # Futjitsu Compressed ME Region with header UMEM
		major = int(binascii.b2a_hex(reading[me_start + 0xB:me_start + 0xD][::-1]), 16)
		minor = int(binascii.b2a_hex(reading[me_start + 0xD:me_start + 0xF][::-1]), 16)
		hotfix = int(binascii.b2a_hex(reading[me_start + 0xF:me_start + 0x11][::-1]), 16)
		build = int(binascii.b2a_hex(reading[me_start + 0x11:me_start + 0x13][::-1]), 16)
		version = "%s.%s.%s.%s" % (major, minor, hotfix, build)
	
	return version

# Taken directly from Lordkag's UEFI Strip!
def switch_guid (guid, transform) :
	vol = ''

	if transform == "GUID2HEX" :
		vol = guid[6:8] + guid[4:6] + guid[2:4] + guid[:2] + guid[11:13] + guid[9:11] + guid[16:18]
		vol += guid[14:16] + guid[19:23] + guid[24:]
	elif transform == "HEX2GUID" :
		vol = guid[6:8] + guid[4:6] + guid[2:4] + guid[:2] + "-" + guid[10:12] + guid[8:10] + "-"
		vol += guid[14:16] + guid[12:14] + "-" + guid[16:20] + "-" + guid[20:]
	
	return vol.upper()
	
# Check if Fixed Offset Variables (FOVD/NVKR) section is dirty
def fovd_clean (fovdtype) :
	fovd_match = None
	fovd_data = b''
	if fovdtype == "new" : fovd_match = (re.compile(br'\x46\x4F\x56\x44\x4B\x52\x49\x44')).search(reading) # FOVDKRID detection
	elif fovdtype == "old" : fovd_match = (re.compile(br'\x4E\x56\x4B\x52\x4B\x52\x49\x44')).search(reading) # NVKRKRID detection
	if fovd_match is not None :
		(start_fovd_match, end_fovd_match) = fovd_match.span()
		fovd_start = int.from_bytes(reading[end_fovd_match:end_fovd_match + 0x4], 'little')
		fovd_size = int.from_bytes(reading[end_fovd_match + 0x4:end_fovd_match + 0x8], 'little')
		if fovdtype == "new" : fovd_data = reading[fpt_start + fovd_start:fpt_start + fovd_start + fovd_size]
		elif fovdtype == "old" :
			fovd_size = int.from_bytes(reading[fovd_start + 0x19:fovd_start + 0x1C], 'little')
			fovd_data = reading[fpt_start + fovd_start + 0x1C:fpt_start + fovd_start + 0x1C + fovd_size]
		if fovd_data == b'\xFF' * fovd_size : return True
		else : return False
	else : return True
	
def vcn_skl(start_man_match, variant) :
	me11_vcn_pat = re.compile(br'\xFF\xFF\xFF\xFF........................................\x46\x54\x50\x52') # FF*4 + [0x28] + FTPR detection
	me11_vcn_match = me11_vcn_pat.search(reading[start_man_match:]) # After FTPR $MN2 for performance and to avoid $CPD FTPR
	if me11_vcn_match is not None :
		(start_vcn_match, end_vcn_match) = me11_vcn_match.span()
		
		if variant == "TXE" : vcn = reading[start_man_match + end_vcn_match:start_man_match + end_vcn_match + 0x1] # TXE 3.x
		else : vcn = reading[start_man_match + end_vcn_match + 0x24:start_man_match + end_vcn_match + 0x25] # ME 11.x & SPS 4.x
		vcn = int(binascii.b2a_hex(vcn[::-1]), 16)
		
		return vcn

def ker_anl(fw_type) :
	ftpr_match = (re.compile(br'\x24\x43\x50\x44........\x46\x54\x50\x52', re.DOTALL)).search(reading) # "$CPD [0x8] FTPR" detection
	
	ker_start = 0x0
	ker_end = 0x0
	rel_db = "NaN"
	ker_name = "NaN"
	
	if ftpr_match is not None :
		(start_ftpr_match, end_ftpr_match) = ftpr_match.span()
		ker_start = int.from_bytes(reading[end_ftpr_match + 0x54:end_ftpr_match + 0x57], 'little') + start_ftpr_match # 5,B (Kernel,BUP)
		ker_end = int.from_bytes(reading[end_ftpr_match + 0x84:end_ftpr_match + 0x87], 'little') + start_ftpr_match # 8,E (Kernel,BUP)
		if release == "Production" : rel_db = "PRD"
		elif release == "Pre-Production" : rel_db = "PRE"
		elif release == "ROM-Bypass" : rel_db = "BYP"
		if variant == "SPS" : ker_name = "%s.%s.%s.%s_%s.bin" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), rel_db)
		else : ker_name = "%s.%s.%s.%s_%s_%s.bin" % (major, minor, hotfix, build, sku_db, rel_db)
	
	if fw_type == "extr" :
		ker_data = reading[ker_start:ker_end]
		try :
			with open(mea_dir + "\\" + 'ker_temp.bin', 'w+b') as ker_temp : ker_temp.write(ker_data)
			if os.path.isfile(mea_dir + "\\" + ker_name) : os.remove(mea_dir + "\\" + ker_name)
			os.rename(mea_dir + "\\" + 'ker_temp.bin', mea_dir + "\\" + ker_name)
			print(col_yellow + "Extracted Kernel from %s to %s" % (hex(ker_start), hex(ker_end - 0x1)) + col_end)
		except :
			print(col_red + "Error, could not extract Kernel from %s to %s" % (hex(ker_start), hex(ker_end - 0x1)) + col_end)
			if os.path.isfile(mea_dir + "\\" + 'ker_temp.bin') : os.remove(mea_dir + "\\" + 'ker_temp.bin')
		
		return 'continue'
		
	return ker_start, ker_end, rel_db
		
def krod_anl() :
	me11_sku_match = (re.compile(br'\x4B\x52\x4F\x44')).finditer(reading) # KROD detection

	uuid_found = ""
	sku_check = "NaN"
	me11_sku_ranges = []
	
	if me11_sku_match is not None and fw_type != "Update" :
		for m in me11_sku_match : me11_sku_ranges.append(m.span()) # Find and store all KROD starting offsets and spans (SKU history)
		
		if me11_sku_ranges :
			(start_sku_match, end_sku_match) = me11_sku_ranges[-1] # Set last KROD starting & ending offsets
			
			# OEMID: Checks only first two parts to avoid some unknown data before the other three parts
			oemid_p1a = reading[start_sku_match + 0x1D : start_sku_match + 0x21] # 4 bytes in LE
			oemid_p1b = reading[start_sku_match + 0x15 : start_sku_match + 0x19] # 4 bytes in LE
			oemid_p2a = reading[start_sku_match + 0x21 : start_sku_match + 0x23] # 2 bytes in LE
			oemid_p2b = reading[start_sku_match + 0x19 : start_sku_match + 0x1B] # 2 bytes in LE
			oemid_p1a = str_reverse_as_bytes(binascii.b2a_hex(oemid_p1a).decode('utf-8').upper())
			oemid_p1b = str_reverse_as_bytes(binascii.b2a_hex(oemid_p1b).decode('utf-8').upper())
			oemid_p2a = str_reverse_as_bytes(binascii.b2a_hex(oemid_p2a).decode('utf-8').upper())
			oemid_p2b = str_reverse_as_bytes(binascii.b2a_hex(oemid_p2b).decode('utf-8').upper())
			#oemid_p3 = reading[start_sku_match + 0x23 : start_sku_match + 0x25] # 2 bytes in LE
			#oemid_p4 = reading[start_sku_match + 0x25 : start_sku_match + 0x27] # 2 bytes
			#oemid_p5 = reading[start_sku_match + 0x27 : start_sku_match + 0x2D] # 6 bytes
			#oemid_p3 = str_reverse_as_bytes(binascii.b2a_hex(oemid_p3).decode('utf-8').upper())
			#oemid_p4 = binascii.b2a_hex(oemid_p4).decode('utf-8').upper()
			#oemid_p5 = binascii.b2a_hex(oemid_p5).decode('utf-8').upper()
			oemid_a = "%s-%s" % (oemid_p1a, oemid_p2a)
			oemid_b = "%s-%s" % (oemid_p1b, oemid_p2b)
			if oemid_a == "4C656E6F-766F" or oemid_b == "4C656E6F-766F" : uuid_found = "Lenovo" # 4C656E6F-766F-0000-0000-000000000000
			elif oemid_a == "00000406-0000" or oemid_b == "00000406-0000" : uuid_found = "Lenovo" # 00000406-0000-0000-0000-000000000000
			elif oemid_a == "00000405-0000" or oemid_b == "00000405-0000" : uuid_found = "Lenovo" # 00000405-0000-0000-0000-000000000000
			elif oemid_a == "68853622-EED3" or oemid_b == "68853622-EED3" : uuid_found = "Dell" # 68853622-EED3-4E83-8A86-6CDE315F6B78
			#elif oemid != "00000000-0000" : uuid_found = "Unknown" # 00000000-0000-0000-0000-000000000000
			
			sku_check = krod_fit_sku(start_sku_match)
			me11_sku_ranges.pop(len(me11_sku_ranges)-1)

	return uuid_found, sku_check, me11_sku_ranges

def krod_fit_sku(start_sku_match) :
	sku_check = reading[start_sku_match - 0x100 : start_sku_match]
	sku_check = binascii.b2a_hex(sku_check).decode('utf-8').upper()
	sku_check = ' '.join([sku_check[i:i+2] for i in range(0, len(sku_check), 2)]) # Split every 2 characters (like Bytes)
	
	return sku_check
	
def db_skl(variant) :
	fw_db = db_open()

	db_sku_chk = "NaN"
	sku = "NaN"
	sku_stp = "NaN"
	sku_pdm = "UKPDM"
	
	for line in fw_db :
		if len(line) < 2 or line[:3] == "***" :
			continue # Skip empty lines or comments
		elif rsa_hash in line :
			line_parts = line.strip().split('_')
			if variant == 'ME' :
				db_sku_chk = line_parts[2] # Store the SKU from DB for latter use
				sku = sku_init + " " + line_parts[2] # Cel 2 is SKU
				if line_parts[3] != "XX" : sku_stp = line_parts[3] # Cel 3 is PCH Stepping
				if line_parts[4] in ['PDM','NOPDM','UKPDM'] : sku_pdm = line_parts[4] # Cel 4 is PDM
			elif variant == 'TXE' :
				if line_parts[1] != "X" : sku_stp = line_parts[1] # Cel 1 is PCH Stepping
			break # Break loop at 1st rsa_hash match
	fw_db.close()

	return db_sku_chk, sku, sku_stp, sku_pdm
	
def db_pkey() :
	fw_db = db_open()

	pkey_var = "NaN"
	
	for line in fw_db :
		if len(line) < 2 or line[:3] == "***" :
			continue # Skip empty lines or comments
		elif rsa_pkey in line :
			line_parts = line.strip().split('_')
			pkey_var = line_parts[1] # Store the Variant
			break # Break loop at 1st rsa_pkey match
	fw_db.close()

	return pkey_var

def intel_id() :
	intel_id = reading[start_man_match - 0xB:start_man_match - 0x9]
	intel_id = binascii.b2a_hex(intel_id[::-1]).decode('utf-8')
	if intel_id != "8086" : # Initial Manifest is a false positive
		print(col_red + "Error" + col_end + ", file does not contain Intel Engine firmware!")
					
		if param.multi : multi_drop() # Error Message not kept in array to allow param.multi detection
		else: f.close()
		
		if found_guid != "" : gen_msg('uefifind_guid', found_guid)
		
		if param.ubu_mea_pre : mea_exit(8)
		else : return 'continue'
	
	return 'OK'
	
def rsa_anl() :
	rsa_sig = reading[end_man_match + 0x164:end_man_match + 0x264] # Read RSA Signature of Recovery
	rsa_hash = sha1_text(rsa_sig).upper() # SHA-1 hash of RSA Signature
	
	rsa_pkey = reading[end_man_match + 0x60:end_man_match + 0x70] # Read RSA Public Key of Recovery
	rsa_pkey = binascii.b2a_hex(rsa_pkey).decode('utf-8').upper() # First 0x10 of RSA Public Key
	
	return rsa_hash, rsa_pkey
	
# Print all Errors, Warnings & Notes (must be Errors > Warnings > Notes)
# Rule 1: If -msg -hid or -msg only: none at the beginning & one empty line at the end (only when messages exist)
# Rule 2: If -msg -aecho: one empty line at the beginning & none at the end (only when messages exist)
# Note: Does not work properly with Partial Update images. Ignored due to irrelevance.
# Note: In case of changes, remember to also change the copied lines at the DB existance check below
def msg_rep() :
	global name_db # Must be global to avoid python error
	
	if (err_stor or warn_stor or note_stor) and param.alt_msg_echo : print("") # Rule 2
	elif param.alt_msg_echo and param.hid_find : print("") # When both -hid and -aecho, aecho prefered due to Rule 2
	
	if param.hid_find : # Parameter -hid always prints a message whether the error/warning/note arrays are empty or not
		if me_rec_ffs : print(col_yellow + "MEA: Found Intel %s Recovery Module %s_NaN_REC in file!" % (variant, fw_ver()) + col_end)
		elif jhi_warn : print(col_yellow + "MEA: Found Intel %s IPT-DAL Module %s_NaN_IPT in file!" % (variant, fw_ver()) + col_end)
		else : print(col_yellow + "MEA: Found Intel %s Firmware %s in file!" % (variant, name_db) + col_end)
		
		if err_stor or warn_stor or note_stor : print("") # Separates -hid from -msg output (only when messages exist, Rule 1 compliant)
		
	for i in range(len(err_stor)) : print(err_stor[i])
	for i in range(len(warn_stor)) : print(warn_stor[i])
	for i in range(len(note_stor)) : print(note_stor[i])
	
	if (err_stor or warn_stor or note_stor) and not param.alt_msg_echo : print("") # Rule 1
	elif not param.alt_msg_echo and param.hid_find : print("") # Rule 1, -hid without any other messages

# Force string to be printed as ASCII, ignore errors
def force_ascii(string) :
	# Input string is bare and only for printing (no open(), no Colorama etc)
	ascii_str = (str(string.encode('ascii', 'ignore'))).strip("b'")
	return ascii_str
	
def mass_scan(f_path) :
	mass_files = []
	for root, dirs, files in os.walk(f_path, topdown=False):
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
db_path = mea_dir + "\\" + "MEA.dat"
if param.alt_dir :
	top_dir = os.path.dirname(mea_dir) # Get parent dir of mea_dir -> UBU folder or UEFI_Strip folder
	uf_path = top_dir + "\\" + "UEFIFind.exe"
else : uf_path = mea_dir + "\\" + "UEFIFind.exe"

if not param.skip_intro :
	db_rev = mea_hdr_init()
	mea_hdr(db_rev)

	print("\nWelcome to Intel Engine Firmware Analysis Tool\n")
	
	if arg_num == 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFile:       " + col_green + "%s" % force_ascii(os.path.basename(sys.argv[1])) + col_end)
	elif arg_num > 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFiles:       " + col_yellow + "Multiple" + col_end)
	else :
		print('Input a filename or "filepath" or press Enter to list options\n')
		print("\nFile:       " + col_magenta + "None" + col_end)

	input_var = input('\nOption(s):  ')
	
	# Anything quoted ("") is taken as one (file paths etc)
	input_var = re.split(''' (?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', input_var.strip())
	
	# Get MEA Parameters based on given Options
	param = MEA_Param(input_var)
	
	# Non valid parameters are treated as files
	if input_var[0] != "" :
		for i in input_var:
			if i not in param.all :
				sys.argv.append(i.strip('"'))
	
	# Re-enumerate parameter input
	arg_num = len(sys.argv)
	
	os.system('cls')
	
	mea_hdr(db_rev)

if param.db_print_clean : db_print()
	
if (arg_num < 2 and not param.help_scr and not param.db_print_clean and not param.mass_scan) or param.help_scr :
	mea_help()
	mea_exit(5)

# http://www.macfreek.nl/memory/Encoding_of_Python_stdout
if param.unicode_fix :
	def write(line): print(line.encode('utf-8'))
	if sys.stdin.encoding != 'UTF-8': sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')
	if sys.stdout.encoding != 'UTF-8': sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
	if sys.stderr.encoding != 'UTF-8': sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Pause after any unexpected python exception
if param.exc_pause : sys.excepthook = show_exception_and_exit

# Actions for MEA but not UBU or UEFIStrip
if param.ubu_mea_pre or param.ubu_mea or param.extr_mea or param.print_msg : pass
else : win32console.SetConsoleTitle(title) # Set console window title

if param.mass_scan :
	in_path = input('\nType the full folder path : ')
	source = mass_scan(in_path)
else :
	source = sys.argv[1:] # Skip script/executable

# Check if dependencies exist
depend_db = os.path.isfile(db_path)
depend_uf = os.path.isfile(uf_path)

if not depend_db:
	if not param.print_msg : print(col_red + "\nError, MEA.dat file is missing!" + col_end)
	mea_exit(1)
	
if param.enable_uf and not depend_uf :
	if not param.print_msg : print(col_red + "\nError, UEFIFind.exe file is missing!" + col_end)
	mea_exit(1)
	
for file_in in source :
	
	# Variable Init
	fw_type = ""
	sku_me = ""
	sku_txe = ""
	upd_rslt = ""
	found_guid = ""
	sku = "NaN"
	pvpc = "NaN"
	me2_type_fix = ""
	me2_type_exp = ""
	no_man_text = "NaN"
	sku_db = "NaN"
	sub_sku = "NaN"
	rel_db = "NaN"
	type_db = "NaN"
	platform = "NaN"
	fit_platform = "NaN"
	text_ubu_pre = "NaN"
	sku_init = "NaN"
	sku_stp = "NaN"
	sps_serv = "NaN"
	opr_mode = "NaN"
	txe_sub = "NaN"
	txe_sub_db = "NaN"
	fw_in_db_found = "No"
	pos_sku_ker = "Unknown"
	pos_sku_fit = "Unknown"
	me11_vcn_match = None
	byp_match = None
	err_sps_sku = ""
	fuj_version = "NaN"
	fuj_rgn_exist = False
	fpt_chk_fail = False
	me_rec_ffs = False
	jhi_warn = False
	uuid_found = ""
	wcod_found = False
	can_search_db = True
	sku_missing = False
	rec_missing = False
	upd_found = False
	unk_major = False
	rgn_exist = False
	err_stor = []
	note_stor = []
	warn_stor = []
	err_rep = 0
	fpt_count = 0
	rel_byte = 0
	rel_bit = 0
	vcn = -1
	svn = -1
	pvbit = -1
	me11_vcn_ranges = []
	me11_sku_ranges = []
	err_stor_ker = []
	fitc_ver_found = False
	rgn_over_extr_found = False
	multi_rgn = False
	me11_ker_anl = False
	me11_ker_msg = False
	apl_warn = False
	uf_error = False
	fd_rgn_exist = False
	fd_lock_state = 0
	
	if not os.path.isfile(file_in) :
		if any(p in file_in for p in param.all) : continue # Next input file
		
		print(col_red + "\nError" + col_end + ", file %s was not found!" % file_in)
		
		if not param.mass_scan : mea_exit(0)
		else : continue
	
	f = open(file_in, 'rb')
	reading = f.read()
	
	# Show file name & extension
	if not param.ubu_mea and not param.ubu_mea_pre and not param.extr_mea and not param.print_msg :
		print("\nFile:     %s" % force_ascii(os.path.basename(file_in)))
		print("")
	elif param.ubu_mea :
		print(col_magenta + "\nMEA shows the Intel Engine firmware of the BIOS/SPI\n\
image that you opened with UBU. It does NOT show the\n\
current Intel Engine firmware running on your system!\n" + col_end)
		
	# UEFIFind Engine GUID Detection
	if param.enable_uf : # UEFI Strip is expected to call MEA without UEFIFind
		
		uefi_pat = "\
						header count 533A14F1EBCB3348A4DC0826E063EC08 {0}\n\
						header count A8FF90DE85B97545AB8DADE52C362CA3 {0}\n\
						header count A9A41FFC4E03D54693EEE6ECC6C7945E {0}\n\
						header count FC9137C45BE0A04A84B1F14547885C70 {0}\n\
						header count 89068D094542654F80C97F3202C5F44E {0}\n\
						header count F0D505D07598EA4A8F3996FC50DAEB94 {0}\n\
						header count 9BD5B898BAE8EE4898DDC295392F1EDB {0}\n\
						header count 390716B36513A748AECB038652E2B528 {0}\n\
						header count 0C111D82A3D0F74CAEF3E28088491704 {0}\n\
						header count 6E1F582C87B1AA4696E72081098D6413 {0}\n\
						header count 8226C7591C5C22479F25B26F4275BFEF {0}\n\
					".format(file_in).replace('	', '')
		
		try :
			with tempfile.NamedTemporaryFile(mode='w+', encoding='utf-8', delete=False) as temp_ufpat : temp_ufpat.write(uefi_pat)
			
			uf_subp = subprocess.check_output([uf_path, "file", temp_ufpat.name, file_in])
			uf_subp = uf_subp.replace(b'\x0D\x0D\x0A', b'\x0D\x0A').replace(b'\x0D\x0A\x0D\x0A', b'\x0D\x0A').decode('utf-8')
			
			with tempfile.NamedTemporaryFile(mode='w+', encoding='utf-8', delete=False) as temp_ufout : temp_ufout.write(uf_subp)
			
			with open(temp_ufout.name, "r+") as out_file :
				lines = out_file.readlines()
				for i in range(2, len(lines), 4) : # Start from 3rd line with a 4 line step until eof
					if 'nothing found' not in lines[i] :
						rslt = lines[i-2].strip().split()
						found_guid = switch_guid(rslt[2], "HEX2GUID")
			
		except subprocess.CalledProcessError : pass
		except : uf_error = True
		
		try :
			# noinspection PyUnboundLocalVariable
			os.remove(temp_ufpat.name)
			# noinspection PyUnboundLocalVariable
			os.remove(temp_ufout.name)
		except : pass
	
	# Detect if file is Engine firmware
	man_pat = re.compile(br'\x00\x24\x4D((\x4E\x32)|(\x41\x4E))') # .$MN2 or .$MAN detection, 0x00 adds old ME RGN support
	man_match = man_pat.search(reading)
	me1_match = (re.compile(br'\x54\x65\x6B\x6F\x61\x41\x70\x70')).search(reading) # TekoaApp detection, AMT 1.x only
	if me1_match is not None : man_match = (re.compile(br'\x50\x72\x6F\x76\x69\x73\x69\x6F\x6E\x53\x65\x72\x76\x65\x72')).search(reading) # ProvisionServer detection
	
	if man_match is None :
	
		# Determine if FD exists and if Engine Region is present
		fd_exist,start_fd_match,end_fd_match = spi_fd_init()
		if fd_exist : fd_rgn_exist,me_start = spi_fd('region',start_fd_match,end_fd_match)
		
		# Engine Region exists but cannot be identified
		if fd_rgn_exist :
			param.multi = False # Disable param.multi to keep such compressed ME Regions
			fuj_version = fuj_umem_ver(me_start) # Check if ME Region is Fujitsu UMEM compressed (me_start from spi_fd function)
			
			# ME Region is Fujitsu UMEM compressed
			if fuj_version != "NaN" :
				no_man_text = "Found" + col_yellow + " Fujitsu Compressed " + col_end + ("Intel Engine Firmware v%s" % fuj_version)
				text_ubu_pre = "Found" + col_yellow + " Fujitsu Compressed " + col_end + ("Intel Engine Firmware v%s" % fuj_version)
				
				if param.extr_mea : no_man_text = "NaN %s_NaN_UMEM %s NaN NaN" % (fuj_version, fuj_version)
			
			# ME Region is Unknown
			else :
				no_man_text = "Found" + col_yellow + " unidentifiable " + col_end + "Intel Engine Firmware\n\n" + col_red + "Please report this issue!" + col_end
				text_ubu_pre = "Found" + col_yellow + " unidentifiable " + col_end + "Intel Engine Firmware"
				
				if param.extr_mea : no_man_text = "NaN NaN_NaN_UNK NaN NaN NaN" # For UEFI Strip (-extr)
		
		# Engine Region does not exist	
		else :
			me_rec_guid = binascii.b2a_hex(reading[:0x10]).decode('utf-8').upper()
			fuj_version = fuj_umem_ver(0) # Check if ME Region is Fujitsu UMEM compressed (me_start is 0x0, no SPI FD)
			fw_start_match = (re.compile(br'\x24\x46\x50\x54.\x00\x00\x00', re.DOTALL)).search(reading) # $FPT detection
			
			# Image is a ME Recovery Module of GUID 821D110C
			if me_rec_guid == "0C111D82A3D0F74CAEF3E28088491704" :
				param.multi = False # Disable param.multi to keep such compressed Engine Regions
			
				if param.extr_mea :
					no_man_text = "NaN NaN_NaN_REC NaN NaN NaN" # For UEFI Strip (-extr)
				elif param.print_msg :
					no_man_text = col_magenta + "\n\nWarning, this is NOT a flashable Intel Engine Firmware image!" + col_end + \
					col_yellow + "\n\nNote, further analysis not possible without manifest header." + col_end
				elif param.ubu_mea_pre :
					no_man_text = "File does not contain Intel Engine Firmware"
				else :
					no_man_text = "Release:  MERecovery Module\nGUID:     821D110C-D0A3-4CF7-AEF3-E28088491704" + \
					col_magenta + "\n\nWarning, this is NOT a flashable Intel Engine Firmware image!" + col_end + \
					col_yellow + "\n\nNote, further analysis not possible without manifest header." + col_end
			
			# Image is ME Fujitsu UMEM compressed
			elif fuj_version != "NaN" :
				param.multi = False # Disable param.multi to keep such compressed Engine Regions
				no_man_text = "Found" + col_yellow + " Fujitsu Compressed " + col_end + ("Intel Engine Firmware v%s" % fuj_version)
				text_ubu_pre = "Found" + col_yellow + " Fujitsu Compressed " + col_end + ("Intel Engine Firmware v%s" % fuj_version)
				
				if param.extr_mea : no_man_text = "NaN %s_NaN_UMEM %s NaN NaN" % (fuj_version, fuj_version)
			
			# Image contains some Engine Flash Partition Table ($FPT)
			elif fw_start_match is not None :
				param.multi = False # Disable param.multi to keep such compressed Engine Regions
				(start_fw_start_match, end_fw_start_match) = fw_start_match.span()
				fpt_start = start_fw_start_match - 0x10 # Starting offset of firmware image
				fitc_exist = binascii.b2a_hex(reading[fpt_start + 0x28 : fpt_start + 0x30]).decode('utf-8').upper()
				
				if fitc_exist != "0000000000000000" and fitc_exist != "FFFFFFFFFFFFFFFF" :
					fitc_major  = int(binascii.b2a_hex( (reading[fpt_start + 0x28:fpt_start + 0x2A]) [::-1]), 16)
					fitc_minor  = int(binascii.b2a_hex( (reading[fpt_start + 0x2A:fpt_start + 0x2C]) [::-1]), 16)
					fitc_hotfix = int(binascii.b2a_hex( (reading[fpt_start + 0x2C:fpt_start + 0x2E]) [::-1]), 16)
					fitc_build  = int(binascii.b2a_hex( (reading[fpt_start + 0x2E:fpt_start + 0x30]) [::-1]), 16)
					fitc_ver = "%s.%s.%s.%s" % (fitc_major, fitc_minor, fitc_hotfix, fitc_build)
					no_man_text = "Found" + col_yellow + " Unknown " + col_end + ("Intel Engine Flash Partition Table v%s\n\n" % fitc_ver) + col_red + \
					"Please report this issue!" + col_end
					text_ubu_pre = "Found" + col_yellow + " Unknown " + col_end + ("Intel Engine Flash Partition Table v%s" % fitc_ver)
					
					if param.extr_mea : no_man_text = "NaN %s_NaN_FPT %s NaN NaN" % (fitc_ver, fitc_ver) # For UEFI Strip (-extr)
				
				else :
					no_man_text = "Found" + col_yellow + " Unknown " + col_end + "Intel Engine Flash Partition Table\n\n" + col_red + \
					"Please report this issue!" + col_end
					text_ubu_pre = "Found" + col_yellow + " Unknown " + col_end + "Intel Engine Flash Partition Table"
					
					if param.extr_mea : no_man_text = "NaN NaN_NaN_FPT NaN NaN NaN" # For UEFI Strip (-extr)
				
			# Image does not contain any kind of Intel Engine firmware
			else :
				no_man_text = "File does not contain Intel Engine Firmware"

		if param.extr_mea :
			if no_man_text != "NaN" : print(no_man_text)
			else : pass
		elif param.print_msg :
			if param.alt_msg_echo : print("\nMEA: %s" % no_man_text) # Rule 2, one empty line at the end
			else : print("MEA: %s\n" % no_man_text) # Rule 1, one empty line at the beginning
			if found_guid != "" :
				gen_msg('uefifind_guid', found_guid)
				for i in range(len(note_stor)) : print(note_stor[i])
				print("")
		elif param.ubu_mea_pre : # Must be before param.ubu_mea
			if 'File does not contain Intel Engine Firmware' not in no_man_text :
				print(text_ubu_pre + ', use ME Analyzer for details!')
			else : pass
		elif param.ubu_mea :
			print("%s" % no_man_text)
			if found_guid != "" : gen_msg('uefifind_guid', found_guid)
			print("")
		else :
			print("%s" % no_man_text)
			if found_guid != "" : gen_msg('uefifind_guid', found_guid)
			
		if param.multi : multi_drop() # All Messages here are not kept in arrays to allow param.multi deletion
		else: f.close()
		
		continue # Next input file

	else : # Engine firmware found, Manifest Header ($MAN or $MN2) Analysis
		
		if binascii.b2a_hex(reading[:0x10]).decode('utf-8').upper() == "0C111D82A3D0F74CAEF3E28088491704" : me_rec_ffs = True
		
		if param.multi and param.me11_ker_disp : param.me11_ker_disp = False # dker not allowed with param.multi unless actual SKU error occurs
		
		if me1_match is None : # All except AMT 1.x
			(start_man_match, end_man_match) = man_match.span()
			
			# Adjust Manifest Header to the Recovery section
			pr_man_1 = (reading[end_man_match + 0x274:end_man_match + 0x278]).decode('utf-8', 'ignore') # FTPR (ME >= 11, TXE >= 3, SPS >= 4)
			pr_man_2 = (reading[end_man_match + 0x264:end_man_match + 0x268]).decode('utf-8', 'ignore') # FTPR (6 <= ME <= 10, TXE <= 2, SPS <= 3)
			pr_man_3 = (reading[end_man_match + 0x28C:end_man_match + 0x290]).decode('utf-8', 'ignore') # BRIN (ME <= 5)
			pr_man_4 = (reading[end_man_match + 0x2DC:end_man_match + 0x2E0]).decode('utf-8', 'ignore') # EpsR (SPS 1)
			pr_man_5 = (reading[end_man_match + 0x264:end_man_match + 0x268]).decode('utf-8', 'ignore') # IGRT (ME 6 IGN)
			
			if ("FTPR" not in [pr_man_1,pr_man_2]) and ("BRIN" not in pr_man_3) and ("EpsR" not in pr_man_4) and ("IGRT" not in pr_man_5) :
				# Initial Manifest Header was not from Recovery section
				man_count = man_pat.findall(reading)
				
				if len(man_count) > 1 : # Extra searches only if multiple manifest exist
					pr_man = (re.compile(br'\x00\x24\x4D\x4E\x32.{628}\x46\x54\x50\x52', re.DOTALL)).search(reading) # .$MN2 + [0x274] + FTPR
					if pr_man is None : pr_man = (re.compile(br'\x00\x24\x4D\x4E\x32.{612}\x49\x47\x52\x54', re.DOTALL)).search(reading) # .$MN2 + [0x264] + IGRT
					if pr_man is None : pr_man = (re.compile(br'\x00\x24\x4D\x4E\x32.{612}\x46\x54\x50\x52', re.DOTALL)).search(reading) # .$MN2 + [0x264] + FTPR
					if pr_man is None : pr_man = (re.compile(br'\x00\x24\x4D\x41\x4E.{652}\x42\x52\x49\x4E', re.DOTALL)).search(reading) # .$MAN + [0x28C] + BRIN
					if pr_man is None : pr_man = (re.compile(br'\x00\x24\x4D\x41\x4E.{732}\x45\x70\x73\x52', re.DOTALL)).search(reading) # .$MAN + [0x2DC] + EpsR
				
					if pr_man is not None :
						# Found proper Manifest Header from Recovery section
						(start_man_match, end_man_match) = pr_man.span()
						end_man_match = start_man_match + 0x5 # .$MAN/.$MN2
					else :
						# Fallback to initial Manifest, check Intel ID 8086 validity
						if intel_id() == 'continue' : continue # Next input file
						err_rep += 1
						rec_missing = True
				else :
					# Only one (initial) Manifest found, check Intel ID 8086 validity
					if intel_id() == 'continue' : continue # Next input file
			
			# Detect RSA Signature and Public Key
			rsa_hash,rsa_pkey = rsa_anl()
			
			major = int(binascii.b2a_hex( (reading[start_man_match + 0x9:start_man_match + 0xB]) [::-1]), 16)
			minor = int(binascii.b2a_hex( (reading[start_man_match + 0xB:start_man_match + 0xD]) [::-1]), 16)
			hotfix = int(binascii.b2a_hex( (reading[start_man_match + 0xD:start_man_match + 0xF]) [::-1]), 16)
			build = int(binascii.b2a_hex( (reading[start_man_match + 0xF:start_man_match + 0x11]) [::-1]), 16)
			svn = int(binascii.b2a_hex( (reading[start_man_match + 0x11:start_man_match + 0x12]) [::-1]), 16)
			vcn = int(binascii.b2a_hex( (reading[start_man_match + 0x19:start_man_match + 0x1A]) [::-1]), 16)
			date = binascii.b2a_hex( (reading[start_man_match - 0x7:start_man_match - 0x3]) [::-1]).decode('utf-8')
			date_print = "%s/%s/%s" % (date[-2:], date[4:6], date[:4]) # format is dd/mm/yyyy
			
			# Detect Firmware Variant (ME, TXE or SPS)
			variant = db_pkey()
			
			if variant == "NaN" : # Variant detection by RSA Public Key in DB failed
				# 5FB2D04BC4D8B4E90AECB5C708458F95 = RSA PKEY used at both ME & TXE PRE-BYP
				
				# ME2-5/SPS1 --> $MME = 0x50, ME6-10 & SPS2-3 --> $MME = 0x60, TXE1-2 --> $MME = 0x80
				txe3_match = (re.compile(br'\x52\x42\x45\x50\x72\x62\x65\x00\x00\x00\x00\x00')).search(reading) # RBEPrbe.....
				txe1_match = reading[end_man_match + 0x270 + 0x80:end_man_match + 0x270 + 0x84].decode('utf-8', 'ignore') # Go to 2nd $MME module
				if txe3_match is not None or txe1_match == '$MME' : variant = "TXE"
				else :
					sps_match = (re.compile(br'\x24\x43\x50\x44........\x4F\x50\x52\x00', re.DOTALL)).search(reading) # $CPD + [0x8] + OPR. detection for SPS 4 OPR
					if sps_match is None : sps_match = (re.compile(br'\x62\x75\x70\x5F\x72\x63\x76\x2E\x6D\x65\x74')).search(reading) # bup_rcv.met detection for SPS 4 REC
					if sps_match is None : sps_match = (re.compile(br'\x24\x53\x4B\x55\x03\x00\x00\x00\x2F\xE4\x01\x00')).search(reading) # $SKU of SPS 2 & 3
					if sps_match is None : sps_match = (re.compile(br'\x24\x53\x4B\x55\x03\x00\x00\x00\x08\x00\x00\x00')).search(reading) # $SKU of SPS 1
					if sps_match is not None : variant = "SPS"
					else : variant = "ME" # Default, no TXE/SPS detected
			
			# Detect Firmware Starting Offset
			fw_start_pat = re.compile(br'\x24\x46\x50\x54.\x00\x00\x00', re.DOTALL)
			
			fpt_count = len(fw_start_pat.findall(reading)) # Detect multiple Engine Regions
			if fpt_count > 1 : multi_rgn = True
			
			fw_start_match = fw_start_pat.search(reading)
			if fw_start_match is not None :
				rgn_exist = True # Region detected, depends on Variant and thus must be executed afterwards
				(start_fw_start_match, end_fw_start_match) = fw_start_match.span()
				if variant == "ME" and major == 2 :
					fpt_start = start_fw_start_match
					fpt_chk_byte = 0xB
					fpt_chk_size = 0x20
				else :
					fpt_start = start_fw_start_match - 0x10
					fpt_chk_byte = 0x1B
					fpt_chk_size = 0x30
				fpt_end = fpt_start + 0x1000 # 4KB size

				# Check $FPT Checksum validity
				fpt_chk_file = struct.pack("B", reading[fpt_start + fpt_chk_byte])
				fpt_chk_calc = struct.pack("B", (0x100 - (sum(reading[fpt_start:fpt_start+fpt_chk_size]) - reading[fpt_start + fpt_chk_byte]) & 0xFF) & 0xFF)
				if param.fpt_chk_print :
					print("Detected $FPT Checksum: 0x%0.2X" % struct.unpack("b" , fpt_chk_file))
					print("Expected $FPT Checksum: 0x%0.2X" % struct.unpack("b" , fpt_chk_calc))
					continue
				if fpt_chk_calc != fpt_chk_file : fpt_chk_fail = True

				# Additional $FPT header at SPS 1.x firmware at DFLT section
				if variant == "SPS" and (major == 1 or major == 4) :
					if fpt_count == 2 : multi_rgn = False
					fpt_count -= 1
				
				# Double $FPT header detection (Clevo MERecovery, 2nd $FPT = 1st $FPT + 0x110)
				while True :
					next_is_fpt = reading[fpt_start + 0x110:fpt_start + 0x110 + 4].decode('utf-8', 'ignore') # Check (offset + 0x110) -> (offset + 0x114) content
					if next_is_fpt == "$FPT" : # Check if there is more than one $FPT headers
						fpt_start += 0x100  # Adjust offset to the latter found $FPT header
						if fpt_count > 1 :
							fpt_count -= 1 # Clevo MERecovery $FPT is ignored when reporting multiple firmware (multi_rgn boolean)
							if fpt_count <= 1 : multi_rgn = False # Only when 2 $FPT exist (Clevo MERecovery + Normal)
					else :
						break
			else :
				fw_type = "Update" # No Region detected, Update
			
			# Detect Intel Flash Descriptor
			fd_exist,start_fd_match,end_fd_match = spi_fd_init()
			if fd_exist :
				fd_rgn_exist,me_start = spi_fd('region',start_fd_match,end_fd_match)
				fd_lock_state = spi_fd('unlocked',start_fd_match,end_fd_match)
			
			# Check for Fujitsu UMEM ME Region (RGN/$FPT or UPD/$MN2)
			if fd_rgn_exist :
				fuj_umem_spi = reading[me_start:me_start + 0x4]
				fuj_umem_spi = binascii.b2a_hex(fuj_umem_spi).decode('utf-8').upper()
				if fuj_umem_spi == "554DC94D" : fuj_rgn_exist = True # Futjitsu ME Region (RGN or UPD) with header UMEM
			else :
				fuj_umem_spi = reading[0x0:0x4]
				fuj_umem_spi = binascii.b2a_hex(fuj_umem_spi).decode('utf-8').upper()
				if fuj_umem_spi == "554DC94D" : fuj_rgn_exist = True
			
			# Detect Firmware Release (Production, Pre-Production, ROM-Bypass, Other)
			rel_byte = ord(chr(int((binascii.b2a_hex(reading[start_man_match - 0xC:start_man_match - 0xB])), 16))) # MSB of Release Byte
			rel_bit = rel_byte & 0x80 # Int from only the same bits between two bytes (C0 = 1100 0000, 80 = 1000 0000 ==> 80 = 1000 0000 ==> PRE/BYP)
			if rgn_exist : # Check for ROM-Bypass entry at $FPT
				if (variant == "ME" and major >= 11) or (variant == "TXE" and major >= 3) or (variant == "SPS" and major >= 4) :
					byp_match = binascii.b2a_hex(reading[fpt_start:fpt_start + 0x4]).decode('utf-8').upper() # 0x0 - 0x4 = ROMB Address
				else :
					# noinspection PyUnboundLocalVariable
					byp_match = (re.compile(br'\x52\x4F\x4D\x42')).search(reading[fpt_start:fpt_end]) # ROMB detection
			jhi_medal_match = (re.compile(br'\x24\x4D\x44\x4C\x4D\x65\x64\x61\x6C')).search(reading) # TXE IPT-DAL Applet Module Detection
			if jhi_medal_match is not None :
				variant = "TXE" # Only TXE? Who cares...
				can_search_db = False
				jhi_warn = True
			
			# PRD/PRE/BYP must be after ME-REC/IPT-DAL Module Release Detection
			if me_rec_ffs : release = "ME Recovery Module"
			elif jhi_warn : release = "IPT-DAL Applet Module"
			elif byp_match not in [None,'00000000'] : release = "ROM-Bypass"
			elif rel_bit == 0 : release = "Production"
			elif rel_bit != 0 : release = "Pre-Production"
			
			if rel_byte not in [0,64,128,192] : # 0x00 --> 0, 0x40 --> 64, 0x80 --> 128, 0xC0 --> 192 in ASCII
				release = col_red + "Error" + col_end + ", unknown firmware release!" + col_red + " *" + col_end
				err_rep += 1
				err_stor.append(release)
			
			# Detect Firmware $SKU (Variant, Major & Minor dependant)
			sku_pat = re.compile(br'\x24\x53\x4B\x55[\x03-\x04]\x00\x00\x00') # $SKU detection, pattern used later as well
			sku_match = sku_pat.search(reading[start_man_match:]) # Search $SKU after proper $MAN/$MN2 Manifest
			if sku_match is not None :
				(start_sku_match, end_sku_match) = sku_match.span()
				start_sku_match += start_man_match
				end_sku_match += start_man_match
			
			# Detect PV/PC bit (0 or 1)
			if (variant == "ME" and major > 7) or variant == "TXE" :
				pvbit_match = (re.compile(br'\x24\x44\x41\x54....................\x49\x46\x52\x50', re.DOTALL)).search(reading) # $DAT + [0x14] + IFRP detection
				if pvbit_match is not None :
					(start_pvbit_match, end_pvbit_match) = pvbit_match.span()
					pvbit = int(binascii.b2a_hex( (reading[start_pvbit_match + 0x10:start_pvbit_match + 0x11]) ), 16)
				elif (variant == "ME" and major > 10) or (variant == "TXE" and major > 2) :
					pvbit = int(binascii.b2a_hex( (reading[start_man_match - 0xF:start_man_match - 0xE]) ), 16)
				
				if pvbit == 0 : pvpc = "No"
				elif pvbit == 1 : pvpc = "Yes"
				else :
					pvpc = col_red + "Error" + col_end + ", unknown PV bit!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(pvpc)
		
		else : # AMT 1.x
			variant = "ME"
			(start_man_match, end_man_match) = man_match.span()
			major = int(binascii.b2a_hex( (reading[start_man_match - 0x260:start_man_match - 0x25F]) [::-1]).decode('utf-8'))
			minor = int(binascii.b2a_hex( (reading[start_man_match - 0x25F:start_man_match - 0x25E]) [::-1]).decode('utf-8'))
			hotfix = int(binascii.b2a_hex( (reading[start_man_match - 0x25E:start_man_match - 0x25D]) [::-1]).decode('utf-8'))
		
		if variant == "ME" : # Management Engine
			
			if me1_match is None and sku_match is not None : # Found $SKU entry
			
				# Number of $SKU entries per firmware generation :
				# ME3 --> 1 x QST RGN , 2 x QST UPD , 2 x AMT/ASF RGN , 3 x AMT/ASF UPD
				# ME2,4,5,6 --> 2 x RGN , 3 x UPD
				# ME7 - ME10 --> 1 x RGN/UPD
			
				if 1 < major < 7:
					sku_me = reading[start_sku_match + 8:start_sku_match + 0xC]
					sku_me = binascii.b2a_hex(sku_me).decode('utf-8').upper()
				elif 6 < major < 11:
					sku_me = reading[start_sku_match + 8:start_sku_match + 0x10]
					sku_me = binascii.b2a_hex(sku_me).decode('utf-8').upper()
			
			if major == 1 and me1_match is not None : # Desktop ICH7: Tekoa 82573E only
				db_maj,db_min,db_hot,db_bld = check_upd('Latest_AMT_1_TEKOA')
				if minor < db_min or (minor == db_min and hotfix < db_hot) : upd_found = True
				
				name_db = "%s.%s.%s_AMT1" % (major, minor, hotfix) # AMT1 is required to avoid false positives
			
				fw_db = db_open()
				for line in fw_db :
					if name_db in line : fw_in_db_found = "Yes" # Known firmware, nothing new
				fw_db.close()
			
				print("Firmware: Intel AMT")
				print("Version:  %s.%s.%s" % (major, minor, hotfix))
				print("Platform: GbE 82573E")

				if upd_found : print("Latest:   " + col_red + "No" + col_end)
				else : print("Latest:   " + col_green + "Yes" + col_end)
			
				if fw_in_db_found == "No" :
					print("")
					print(col_yellow + "Note: This firmware was not found at the database, please report it!" + col_end)
					note_stor.append(col_yellow + "Note: This firmware was not found at the database, please report it!" + col_end)
				
				if param.multi : multi_drop() # Some (not all) Messages here are not kept in arrays to allow param.multi deletion
				
				if found_guid != "" : gen_msg('uefifind_guid', found_guid)
				
				f.close()
				continue # Next input file
			
			if major == 2 : # Desktop ICH8: 2.0 & 2.1 & 2.2 or Mobile ICH8M: 2.5 & 2.6
				if sku_me == "00000000" :
					sku = "AMT"
					sku_db = "AMT"
					if minor >= 5 : db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_2_AMTM')
					else : db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_2_AMTD')
					if minor < 2 or (minor == 2 and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
					elif minor == 5 or (minor == 6 and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				elif sku_me == "02000000" :
					sku = "QST" # Name is either QST or ASF, probably QST based on size and RGN modules
					sku_db = "QST"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_2_QST')
					if minor == 0 and (hotfix < db_hot or (hotfix == db_hot and build < db_bld)) : upd_found = True
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 2 SKU!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)
				
				# ME2-Only Fix 1 : The usual method to detect EXTR vs RGN does not work for ME2
				if sku == "QST" or (sku == "AMT" and minor >= 5) :
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
							me2_type_exp = "7F45DBA3E65424458CB09A6E608812B1"
						elif maxk_match is not None :
							(start_maxk_match, end_maxk_match) = maxk_match.span()
							qstpat_start = fpt_start + nvkr_start + end_maxk_match + 0x68
							qstpat_end = fpt_start + nvkr_start + end_maxk_match + 0x78
							me2_type_fix = (binascii.b2a_hex(reading[qstpat_start:qstpat_end])).decode('utf-8').upper()
							me2_type_exp = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
				elif sku == "AMT" and minor < 5 :
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
				
				# ME2-Only Fix 2 : Identify ICH Revision B0 firmware SKUs
				me2_sku_fix = ['1C3FA8F0B5B9738E717F74F1F01D023D58085298','AB5B010215DFBEA511C12F350522E672AD8C3345','92983C962AC0FD2636B5B958A28CFA42FB430529']
				if rsa_hash in me2_sku_fix :
					sku = "AMT B0"
					sku_db = "AMT_B0"
				
				if minor >= 5 : platform = "Mobile"
				else : platform = "Desktop"
		
			if major == 3 : # Desktop ICH9x (All-Optional, QST) or ICH9DO (Q35, AMT): 3.0 & 3.1 & 3.2
				if sku_me == "0E000000" :
					sku = "AMT" # Active Management Technology --> Remote Control (Q35 only)
					sku_db = "AMT"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_3_AMT')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				elif sku_me == "06000000" :
					sku = "ASF" # Alert Standard Format --> Message Report (Q33, ex: HP dc5800)
					sku_db = "ASF"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_3_ASF')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				elif sku_me == "02000000" :
					sku = "QST" # Quiet System Technology --> Fan Control (All but optional)
					sku_db = "QST"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_3_QST')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 3 SKU!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)

				# ME3-Only Fix 1 : The usual method to detect EXTR vs RGN does not work for ME3
				me3_type_fix1 = 0
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
					
				# ME3-Only Fix 2 : Detect AMT ROMB UPD image correctly (very vague, may not always work)
				if fw_type == "Update" and release == "Pre-Production" : # Debug Flag detected at $MAN but PRE vs BYP is needed for UPD (not RGN)
					f.seek(0, 2)
					position = f.tell()
					# It seems that ROMB UPD is smaller than equivalent PRE UPD
					# min size(ASF, UPD) is 0xB0904 so 0x100000 safe min AMT ROMB
					# min size(AMT, UPD) is 0x190904 so 0x185000 safe max AMT ROMB
					# min size(QST, UPD) is 0x2B8CC so 0x40000 safe min for ASF ROMB
					# min size(ASF, UPD) is 0xB0904 so 0xAF000 safe max for ASF ROMB
					# min size(QST, UPD) is 0x2B8CC so 0x2B000 safe max for QST ROMB
					if sku == "AMT" and int(0x100000) < position < int(0x185000): release = "ROM-Bypass"
					elif sku == "ASF" and int(0x40000) < position < int(0xAF000): release = "ROM-Bypass"
					elif sku == "QST" and position < int(0x2B000) : release = "ROM-Bypass"
				
				platform = "Desktop"
		
			if major == 4 : # Mobile ICH9M or ICH9M-E (AMT or TPM+AMT): 4.0 & 4.1 & 4.2 , xx00xx --> 4.0 , xx20xx --> 4.1 or 4.2
				if sku_me == "AC200000" or sku_me == "AC000000" or sku_me == "04000000" : # 040000 for Pre-Alpha ROMB
					sku = "AMT + TPM" # CA_ICH9_REL_ALL_SKUs_ (TPM + AMT)
					sku_db = "ALL"
				elif sku_me == "8C200000" or sku_me == "8C000000" or sku_me == "0C000000" : # 0C0000 for Pre-Alpha ROMB
					sku = "AMT" # CA_ICH9_REL_IAMT_ (AMT)
					sku_db = "AMT"
				elif sku_me == "A0200000" or sku_me == "A0000000" :
					sku = "TPM" # CA_ICH9_REL_NOAMT_ (TPM)
					sku_db = "TPM"
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 4 SKU!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)
				
				# ME4-Only Fix 1 : Detect ROMB UPD image correctly
				if fw_type == "Update" :
					byp_pat = re.compile(br'\x52\x4F\x4D\x42') # ROMB detection (ROM-Bypass)
					byp_match = byp_pat.search(reading)
					if byp_match is not None : release = "ROM-Bypass"
				
				# ME4-Only Fix 2 : Detect SKUs correctly, only for Pre-Alpha firmware
				if minor == 0 and hotfix == 0 :
					if fw_type == "Update" :
						tpm_tag = (re.compile(br'\x24\x4D\x4D\x45........................\x54\x50\x4D', re.DOTALL)).search(reading) # $MME + [0x18] + TPM
						amt_tag = (re.compile(br'\x24\x4D\x4D\x45........................\x4D\x4F\x46\x46\x4D\x31\x5F\x4F\x56\x4C', re.DOTALL)).search(reading) # $MME + [0x18] + MOFFM1_OVL
					else :
						tpm_tag = (re.compile(br'\x4E\x56\x54\x50\x54\x50\x49\x44')).search(reading) # NVTPTPID partition found at ALL or TPM
						amt_tag = (re.compile(br'\x4E\x56\x43\x4D\x41\x4D\x54\x43')).search(reading) # NVCMAMTC partition found at ALL or AMT
					
					if tpm_tag is not None and amt_tag is not None :
						sku = "AMT + TPM" # CA_ICH9_REL_ALL_SKUs_
						sku_db = "ALL"
					elif tpm_tag is not None :
						sku = "TPM" # CA_ICH9_REL_NOAMT_
						sku_db = "TPM"
					else :
						sku = "AMT" # CA_ICH9_REL_IAMT_
						sku_db = "AMT"
				
				# ME4-Only Fix 3 : The usual method to detect EXTR vs RGN does not work for ME4
				effs_match = (re.compile(br'\x45\x46\x46\x53\x4F\x53\x49\x44')).search(reading) # EFFSOSID detection
				if effs_match is not None :
					(start_effs_match, end_effs_match) = effs_match.span()
					effs_start = int.from_bytes(reading[end_effs_match:end_effs_match + 0x4], 'little')
					effs_size = int.from_bytes(reading[end_effs_match + 0x4:end_effs_match + 0x8], 'little')
					effs_data = reading[fpt_start + effs_start:fpt_start + effs_start + effs_size]
					
					me4_type_fix1 = (re.compile(br'\x4D\x45\x5F\x43\x46\x47\x5F\x44\x45\x46')).findall(effs_data) # ME_CFG_DEF detection (RGN have 2-4)
					me4_type_fix2 = (re.compile(br'\x47\x50\x49\x4F\x31\x30\x4F\x77\x6E\x65\x72')).search(effs_data) # GPIO10Owner detection
					me4_type_fix3 = (re.compile(br'\x41\x70\x70\x52\x75\x6C\x65\x2E\x30\x33\x2E\x30\x30\x30\x30\x30\x30')).search(effs_data) # AppRule.03.000000 detection
				
				# Placed here in order to comply with Fix 2 above in case it is triggered
				if sku_db == "ALL" :
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_4_ALL')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				elif sku_db == "AMT" :
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_4_AMT')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				elif sku_db == "TPM" :
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_4_TPM')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
					
				platform = "Mobile"
					
			if major == 5 : # Desktop ICH10D: Basic or ICH10DO: Professional SKUs
				if sku_me == "3E080000" : # EL_ICH10_SKU1
					sku = "Digital Office" # AMT
					sku_db = "DO"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_5_DO')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				elif sku_me == "060D0000" : # EL_ICH10_SKU4
					sku = "Base Consumer" # NoAMT
					sku_db = "BC"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_5_BC')
					if minor < db_min or (minor == db_min and hotfix == db_hot and build < db_bld) : upd_found = True
				elif sku_me == "06080000" : # EL_ICH10_SKU2 or EL_ICH10_SKU3
					sku = "Digital Home or Base Corporate (?)"
					sku_db = "DHBC"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_5_DHBC')
					if minor < db_min or (minor == db_min and hotfix == db_hot and build < db_bld) : upd_found = True
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 5 SKU!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)
					
				# ME5-Only Fix: Detect ROMB UPD image correctly
				if fw_type == "Update" :
					byp_pat = re.compile(br'\x52\x4F\x4D\x42') # ROMB detection (ROM-Bypass)
					byp_match = byp_pat.search(reading)
					if byp_match is not None : release = "ROM-Bypass"
				
				platform = "Desktop"
		
			if major == 6 :
				if sku_me == "00000000" : # Ignition (128KB, 2MB)
					sku = "Ignition"
					if hotfix != 50 : # P55, PM55, 34xx (Ibex Peak)
						sku_db = "IGN_IP"
						platform = "Ibex Peak"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_6_IGNIP')
						if minor == db_min and hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					elif hotfix == 50 : # 89xx (Cave/Coleto Creek)
						sku_db = "IGN_CC"
						platform = "Cave/Coleto Creek"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_6_IGNCC')
						if minor == db_min and hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
				elif sku_me == "701C0000" : # Home IT (1.5MB, 4MB)
					sku = "1.5MB"
					sku_db = "1.5MB"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_6_15MB')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				# xxDCxx = 6.x, xxFCxx = 6.0, xxxxEE = Mobile, xxxx6E = Desktop, F7xxxx = Old Alpha/Beta Releases
				elif sku_me == "77DCEE00" or sku_me == "77FCEE00" or sku_me == "F7FEFE00" : # vPro (5MB, 8MB)
					sku = "5MB MB"
					sku_db = "5MB_MB"
					platform = "Mobile"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_6_5MBMB')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				elif sku_me == "77DC6E00" or sku_me == "77FC6E00" or sku_me == "F7FE7E00" : # vPro (5MB, 8MB)
					sku = "5MB DT"
					sku_db = "5MB_DT"
					platform = "Desktop"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_6_5MBDT')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 6 SKU!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)
				
				# ME6-Only Fix: Ignore FTPR missing error at ROMB (Region present, tag missing)
				if release == "ROM-Bypass" :
					err_rep -= 1
					rec_missing = False
				
			if major == 7 :
			
				# ME7.1 firmware had two SKUs (1.5MB or 5MB) for each platform: Cougar Point (6-series) or Patsburg (C600,X79)
				# For each firmware we are interested in SKU, Minor version & Platform. SKU: 1.5MB is 701C , 5MB is 775C
				# Minor version for 1.5MB: 7.0.x is 0001 , 7.1.x is 1001 & Minor version for 5MB: 7.0.x is EF0D , 7.1.x is FF0D
				# For Apple MAC, Minor version for 1.5MB: 7.0.x is 0081 & 5MB is unknown
				# Platform for 1.5MB: CPT is 0322 , PBG is 8322 & Platform for 5MB: CPT is 0A43 , PBG is 8A43
				# After 7.1.50.1172 both platforms were merged into one firmware with the PBG SKUs so 1.5MB --> 8322 , 5MB --> 8A43
				# Firmware 7.1.21.1134 is PBG-exclusive according to documentation. All 7.1.21.x releases, if any more exist, seem to be PBG-only
				# All firmware between 7.1.20.x and 7.1.41.x (excluding 7.1.21.x, 7.1.22.x & 7.1.20.1056) are CPT-only BUT with the PBG SKU
				# So basically every firmware after 7.1.20.x has the PBG SKU but only after 7.1.50.x are the platforms truly merged (CPT+PBG)
				# All firmware between 7.1.22.x (last PBG) and 7.1.30.x ("new_SKU_based_on_PBG" CPT) need to be investigated manually if they exist
				# All firmware between 7.1.41.x (last I found) and 7.1.50.x (first merged) need to be investigated manually if they exist
			
				if sku_me == "701C000103220000" or sku_me == "701C100103220000" : # 1.5MB (701C), 7.0.x (0001) or 7.1.x (1001) , CPT (0322)
					sku = "1.5MB"
					sku_db = "1.5MB_CPT"
					platform = "CPT"
				elif sku_me == "701C000183220000" or sku_me == "701C100183220000" : # 1.5MB (701C), 7.0.x (0001) or 7.1.x (1001) , PBG (8322)
					sku = "1.5MB"
					sku_db = "1.5MB_PBG"
					platform = "PBG"
				elif sku_me == "701C008103220000" : # 1.5MB (701C), Apple MAC 7.0.x (0081), CPT (0322)
					sku = "1.5MB Apple MAC" # Special Apple MAC SKU v7.0.1.1205
					sku_db = "1.5MB_MAC"
					platform = "CPT"
				elif sku_me == "775CEF0D0A430000" or sku_me == "775CFF0D0A430000" or sku_me == "77DCFF0101000000" : # 5MB (775C), 7.0.x (EF0D) or 7.1.x (FF0D) , CPT (0A43)
					# Special SKU for 5MB ROMB Alpha2 firmware v7.0.0.1041 --> 77DCFF010100
					sku = "5MB"
					sku_db = "5MB_CPT"
					platform = "CPT"
				elif sku_me == "775CEF0D8A430000" or sku_me == "775CFF0D8A430000" : # 5MB (775C), 7.0.x (EF0D) or 7.1.x (FF0D) , PBG (8A43)
					sku = "5MB"
					sku_db = "5MB_PBG"
					platform = "PBG"
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 7 SKU!" + col_red + " *" + col_end
					platform = col_red + "Error" + col_end + ", this firmware requires investigation!" + col_red + " *" + col_end
					if minor != 1 and hotfix != 20 and build != 1056 : # Exception for firmware 7.1.20.1056 Alpha (check below)
						err_rep += 1
						err_stor.append(sku)
						err_stor.append(platform)
				
				if sku_me == "701C100103220000" or sku_me == "701C100183220000": # 1.5MB (701C) , 7.1.x (1001) , CPT or PBG (0322 or 8322)
					if (20 < hotfix < 30 and hotfix != 21 and build != 1056) or (41 < hotfix < 50) : # Versions that, if exist, require manual investigation
						sku = "1.5MB"
						sku_db = "NaN"
						platform = col_red + "Error" + col_end + ", this firmware requires investigation!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(platform)
					elif 20 <= hotfix <= 41 and hotfix != 21 and build != 1056 : # CPT firmware but with PBG SKU (during the "transition" period)
						sku = "1.5MB"
						sku_db = "1.5MB_CPT"
						platform = "CPT"
					elif hotfix >= 50 : # Firmware after 7.1.50.1172 are merged CPT + PBG images with PBG SKU
						sku = "1.5MB"
						sku_db = "1.5MB_ALL"
						platform = "CPT/PBG"
				if sku_me == "775CFF0D0A430000" or sku_me == "775CFF0D8A430000": # 5MB (775C) , 7.1.x (FF0D) , CPT or PBG (0A43 or 8A43)
					if (20 < hotfix < 30 and hotfix != 21 and build != 1056 and build != 1165) or (41 < hotfix < 50) : # Versions that, if exist, require manual investigation
						sku = "5MB"
						sku_db = "NaN"
						platform = col_red + "Error" + col_end + ", this firmware requires investigation!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(platform)
					elif 20 <= hotfix <= 41 and hotfix != 21 and build != 1056 and build != 1165 : # CPT firmware but with PBG SKU (during the "transition" period)
						sku = "5MB"
						sku_db = "5MB_CPT"
						platform = "CPT"
					elif hotfix >= 50 : # Firmware after 7.1.50.1172 are merged CPT + PBG images with PBG SKU
						sku = "5MB"
						sku_db = "5MB_ALL"
						platform = "CPT/PBG"
				
				# Firmware 7.1.20.1056 Alpha is PBG with CPT SKU at PRD and unique SKU at BYP, hardcoded values
				if build == 1056 and hotfix == 20 and minor == 1 :
					sku_me7a = reading[start_sku_match + 8:start_sku_match + 0xA]
					sku_me7a = binascii.b2a_hex(sku_me7a).decode('utf-8').upper()
					if sku_me7a == "701C" :
						sku = "1.5MB"
						sku_db = "1.5MB_PBG"
						platform = "PBG"
					elif sku_me7a == "775C" :
						sku = "5MB"
						sku_db = "5MB_PBG"
						platform = "PBG"
					else :
						sku = col_red + "Error" + col_end + ", unknown ME 7 SKU!" + col_red + " *" + col_end
						platform = col_red + "Error" + col_end + ", this firmware requires investigation!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(sku)
						err_stor.append(platform)
				
				if sku == "1.5MB" :
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_7_15MB')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				elif sku == "5MB" :
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_7_5MB')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				if sku_db == "1.5MB_MAC" :
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_7_MAC')
					if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
				
				# ME7 Blacklist Table Detection
				me7_blist_1_minor  = int(binascii.b2a_hex( (reading[start_man_match + 0x6DF:start_man_match + 0x6E1]) [::-1]), 16)
				me7_blist_1_hotfix = int(binascii.b2a_hex( (reading[start_man_match + 0x6E1:start_man_match + 0x6E3]) [::-1]), 16)
				me7_blist_1_build  = int(binascii.b2a_hex( (reading[start_man_match + 0x6E3:start_man_match + 0x6E5]) [::-1]), 16)
				me7_blist_2_minor  = int(binascii.b2a_hex( (reading[start_man_match + 0x6EB:start_man_match + 0x6ED]) [::-1]), 16)
				me7_blist_2_hotfix = int(binascii.b2a_hex( (reading[start_man_match + 0x6ED:start_man_match + 0x6EF]) [::-1]), 16)
				me7_blist_2_build  = int(binascii.b2a_hex( (reading[start_man_match + 0x6EF:start_man_match + 0x6F1]) [::-1]), 16)
				
				# ME7-Only Fix: ROMB UPD detection
				if fw_type == "Update" :
					me7_romb_upd  = reading[start_man_match + 0x63E:start_man_match + 0x640] # Goto $MCP region
					me7_romb_upd  = binascii.b2a_hex(me7_romb_upd).decode('utf-8').upper() # Hex value with Little Endianess
					if me7_romb_upd != "9806" and me7_romb_upd != "5807" : # 9806 is 1.5MB and 5807 is 5MB (Production, Pre-Production)
						if me7_romb_upd == "B805" : release = "ROM-Bypass" # B805 is 1.5MB ROM-Bypass
						elif me7_romb_upd == "6806" : release = "ROM-Bypass" # 6806 is 5MB ROM-Bypass
						else : # Unknown ROM-Bypass $MCP entry
							release = col_red + "Error" + col_end + ", unknown ME 7 ROM-Bypass SKU!" + col_red + " *" + col_end
							err_rep += 1
							err_stor.append(release)
			
			if major == 8 :
				if sku_me == "E01C11C103220000" or sku_me == "E01C114103220000" or sku_me == "601C114103220000" :
					sku = "1.5MB"
					sku_db = "1.5MB"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_8_15MB')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				elif sku_me == "FF5CFFCD0A430000" or sku_me == "FF5CFF4D0A430000" or sku_me == "7F5CFF0D0A430000" or sku_me == "7F5CFF8D0A430000" :
					# SKU for 8.1.0.1035 Alpha firmware --> 7F5CFF8D0A430000
					sku = "5MB"
					sku_db = "5MB"
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_8_5MB')
					if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 8 SKU!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)
					
				# ME8-Only Fix: SVN location
				svn = int(binascii.b2a_hex( (reading[start_man_match + 0x15:start_man_match + 0x16]) [::-1]), 16)
			
			if major == 9 :
				if minor == 0 :
					if sku_me == "E09911C113220000" :
						sku = "1.5MB"
						sku_db = "1.5MB"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_90_15MB')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					elif sku_me == "EFD9FFCD0A430000" :
						sku = "5MB"
						sku_db = "5MB"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_90_5MB')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					else :
						sku = col_red + "Error" + col_end + ", unknown ME 9.0 SKU!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(sku)
					
					# Ignore: 9.0.50.x (9.1 Alpha)
					if hotfix == 50 : upd_found = True
					
					platform = "LynxPoint"
					
				elif minor == 1 :
					if sku_me == "E09911D113220000" :
						sku = "1.5MB"
						sku_db = "1.5MB"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_91_15MB')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					elif sku_me == "EFD9FFDD0A430000" :
						sku = "5MB"
						sku_db = "5MB"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_91_5MB')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					else :
						sku = col_red + "Error" + col_end + ", unknown ME 9.1 SKU!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(sku)
					platform = "LynxPoint"
					
				elif minor == 5 or minor == 6 :
					if sku_me == "609A11B113220000" :
						sku = "1.5MB"
						sku_db = "1.5MB"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_95_15MB')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					elif sku_me == "6FDAFFBD0A430000" or sku_me == "EFDAFFED0A430000" : # 2nd SKU is for old Pre-Alpha releases (ex: v9.5.0.1225)
						sku = "5MB"
						sku_db = "5MB"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_95_5MB')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					elif sku_me == "401A001123220000" : # Special Apple MAC SKU
						sku = "1.5MB Apple Mac"
						sku_db = "1.5MB_MAC"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_95_MAC')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True 
					else :
						sku = col_red + "Error" + col_end + ", unknown ME 9.5 SKU!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(sku)
					
					# Ignore: 9.6.x (10.0 Alpha)
					if minor == 6 : upd_found = True
					
					platform = "LynxPoint LP"
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 9.x Minor version!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)
				
			if major == 10 :
				if minor == 0 :
					if sku_me == "C0BA11F113220000" or sku_me == "C0BA11F114220000" : # 2nd SKU is BYP
						sku = "1.5MB"
						sku_db = "1.5MB"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_100_15MB')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					elif sku_me == "CFFAFFFF0A430000" or sku_me == "CFFAFFFF0A430000" :
						sku = "5MB"
						sku_db = "5MB"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_100_5MB')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					elif sku_me == "401A001122220000" : # Special Apple MAC SKU
						sku = "1.5MB Apple Mac"
						sku_db = "1.5MB_MAC"
						db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_100_MAC')
						if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					else :
						sku = col_red + "Error" + col_end + ", unknown ME 10.0 SKU!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(sku)
					platform = "Broadwell LP"
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 10.x Minor version!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)
			
			if major == 11 :
				
				me11_sku_init_match = (re.compile(br'\x4C\x4F\x43\x4C\x6D\x65\x62\x78')).search(reading) # LOCLmebx detection
				if me11_sku_init_match is not None :
					sku_init = "Corporate"
					sku_init_db = "COR"
				else :
					sku_init = "Consumer"
					sku_init_db = "CON"
				
				uuid_found,sku_check,me11_sku_ranges = krod_anl() # Detect OEMID and FIT SKU
				
				vcn = vcn_skl(start_man_match, variant) # Detect VCN
				
				ker_start,ker_end,rel_db = ker_anl('anl') # Kernel Analysis for all 11.x
				
				db_sku_chk,sku,sku_stp,sku_pdm = db_skl(variant) # Retreive SKU & Rev from DB
				
				# Some early firmware are reported as PRD even though they are PRE
				if release == "Production" and rsa_pkey == "5FB2D04BC4D8B4E90AECB5C708458F95" :
					release = "Pre-Production"
					rel_db = "PRE"
				
				# Kernel Analysis for all 11.x
				ker_sku = reading[ker_start + 0x700:ker_start + 0x900] # Actual range is 0x780 - 0x840
						
				match_1_h = (re.compile(br'\x56\xA6\xF5\x9A\xC4\xA6\xDB\x69\x3C\x7A\x15')).search(ker_sku)
				match_1_lp = (re.compile(br'\x56\xA6\xF5\x9A\xC4\xA6\xDB\x69\x3C\x7A\x11')).search(ker_sku)
						
				match_2_h = (re.compile(br'\x6A\x6F\x59\xAC\x4A\x6D\xB6\x93\xC7\xA1\x50')).search(ker_sku)
				match_2_lp = (re.compile(br'\x6A\x6F\x59\xAC\x4A\x6D\xB6\x93\xC7\xA1\x11')).search(ker_sku)
						
				match_3_h = (re.compile(br'\xAB\x53\x7A\xCD\x62\x53\x6D\xB4\x9E\x3D\x0A')).search(ker_sku)
				match_3_lp = (re.compile(br'\xAB\x53\x7A\xCD\x62\x53\x6D\xB4\x9E\x3D\x08')).search(ker_sku)
						
				match_4_h = (re.compile(br'\xB5\x37\xAC\xD6\x25\x36\xDB\x49\xE3\xD0\xA8')).search(ker_sku)
				match_4_lp = (re.compile(br'\xB5\x37\xAC\xD6\x25\x36\xDB\x49\xE3\xD0\x88')).search(ker_sku)
					
				match_5_h = (re.compile(br'\x5A\x9B\xD6\x6B\x12\x9B\x6D\xA4\xF1\xE8\x54')).search(ker_sku)
				match_5_lp = (re.compile(br'\x5A\x9B\xD6\x6B\x12\x9B\x6D\xA4\xF1\xE8\x44')).search(ker_sku)
					
				match_6_h = (re.compile(br'\xA9\xBD\x66\xB1\x29\xB6\xDA\x4F\x1E\x85\x42')).search(ker_sku)
				#match_6_lp = (re.compile(br'\xA9\xBD\x66\xB1\x29\xB6\xDA\x4F\x1E\x85\xXX')).search(ker_sku)

				#match_7_h = (re.compile(br'\xA9\xBD\x66\xB1\x29\xB6\xDA\x4F\x1E\x84\xXX')).search(ker_sku)
				match_7_lp = (re.compile(br'\xA9\xBD\x66\xB1\x29\xB6\xDA\x4F\x1E\x84\x46')).search(ker_sku)
					
				match_8_h = (re.compile(br'\xAD\x4D\xEB\x35\x89\x4D\xB6\xD2\x78\xF4\x2A')).search(ker_sku)
				#match_8_lp = (re.compile(br'\xAD\x4D\xEB\x35\x89\x4D\xB6\xD2\x78\xF4\xXX')).search(ker_sku)
						
				match_9_h = (re.compile(br'\xD4\xDE\xB3\x58\x94\xDB\x6D\x27\x8F\x42\xA1')).search(ker_sku)
				match_9_lp = (re.compile(br'\xD4\xDE\xB3\x58\x94\xDB\x6D\x27\x8F\x42\x23')).search(ker_sku)
							
				if any(m is not None for m in (match_1_h,match_2_h,match_3_h,match_4_h,match_5_h,match_6_h,match_8_h,match_9_h)) : pos_sku_ker = "H"
				elif any(m is not None for m in (match_1_lp,match_2_lp,match_3_lp,match_4_lp,match_5_lp,match_7_lp,match_9_lp)) : pos_sku_ker = "LP"
				
				# FIT Platform SKU for all 11.x
				if sku_check != "NaN" :
						
					while fit_platform == "NaN" :
						
						if any(s in sku_check for s in (' 64 00 01 80 00 ',' 02 D1 02 64 ')) : fit_platform = "SPT-H Q170"
						elif any(s in sku_check for s in (' 65 00 01 80 00 ',' 02 D1 02 65 ')) : fit_platform = "SPT-H Q150"
						elif any(s in sku_check for s in (' 66 00 01 80 00 ',' 02 D1 02 66 ')) : fit_platform = "SPT-H B150"
						elif any(s in sku_check for s in (' 67 00 01 80 00 ',' 02 D1 02 67 ')) : fit_platform = "SPT-H H170"
						elif any(s in sku_check for s in (' 68 00 01 80 00 ',' 02 D1 02 68 ')) : fit_platform = "SPT-H Z170"
						elif any(s in sku_check for s in (' 69 00 01 80 00 ',' 02 D1 02 69 ')) : fit_platform = "SPT-H H110"
						elif any(s in sku_check for s in (' 6A 00 01 80 00 ',' 02 D1 02 6A ')) : fit_platform = "SPT-H QM170"
						elif any(s in sku_check for s in (' 6B 00 01 80 00 ',' 02 D1 02 6B ')) : fit_platform = "SPT-H HM170"
						elif any(s in sku_check for s in (' 6C 00 01 80 00 ',' 02 D1 02 6C ')) : fit_platform = "SPT-H No Emulation"
						elif any(s in sku_check for s in (' 6D 00 01 80 00 ',' 02 D1 02 6D ')) : fit_platform = "SPT-H C236"
						elif any(s in sku_check for s in (' 6E 00 01 80 00 ',' 02 D1 02 6E ')) : fit_platform = "SPT-H CM236"
						elif any(s in sku_check for s in (' 6F 00 01 80 00 ',' 02 D1 02 6F ')) : fit_platform = "SPT-H C232"
						elif any(s in sku_check for s in (' 70 00 01 80 00 ',' 02 D1 02 70 ')) : fit_platform = "SPT-H QMS180"
						elif any(s in sku_check for s in (' 32 01 01 80 00 ',' 02 D1 02 32 ')) : fit_platform = "SPT-H QMU185"
						elif any(s in sku_check for s in (' 93 01 01 80 00 ',' 02 D1 02 93 ')) : fit_platform = "SPT-H QM175"
						elif any(s in sku_check for s in (' 94 01 01 80 00 ',' 02 D1 02 94 ')) : fit_platform = "SPT-H HM175"
						elif any(s in sku_check for s in (' 95 01 01 80 00 ',' 02 D1 02 95 ')) : fit_platform = "SPT-H CM238"
						elif any(s in sku_check for s in (' C8 00 02 80 00 ',' 04 11 06 C8 ')) : fit_platform = "PCH-C620 LBG 1G"
						elif any(s in sku_check for s in (' C9 00 02 80 00 ',' 04 11 06 C9 ')) : fit_platform = "PCH-C620 LBG 2"
						elif any(s in sku_check for s in (' CA 00 02 80 00 ',' 04 11 06 CA ')) : fit_platform = "PCH-C620 LBG 4"
						elif any(s in sku_check for s in (' CB 00 02 80 00 ',' 04 11 06 CB ')) : fit_platform = "PCH-C620 LBG No Emulation"
						elif any(s in sku_check for s in (' 31 01 03 80 00 ',' 02 D1 02 31 ')) : fit_platform = "KBP-H Z270"
						elif any(s in sku_check for s in (' 92 01 03 80 00 ',' 02 D1 02 92 ')) : fit_platform = "KBP-H X299"
						elif any(s in sku_check for s in (' 2D 01 03 80 00 ',' 02 D1 02 2D ')) : fit_platform = "KBP-H Q270"
						elif any(s in sku_check for s in (' 2E 01 03 80 00 ',' 02 D1 02 2E ')) : fit_platform = "KBP-H Q250"
						elif any(s in sku_check for s in (' 30 01 03 80 00 ',' 02 D1 02 30 ')) : fit_platform = "KBP-H H270"
						elif any(s in sku_check for s in (' 91 01 03 80 00 ',' 02 D1 02 91 ')) : fit_platform = "KBP-H C422"
						elif any(s in sku_check for s in (' 2F 01 03 80 00 ',' 02 D1 02 2F ')) : fit_platform = "KBP-H B250"
						elif any(s in sku_check for s in (' 2C 01 03 80 00 ',' 02 D1 02 2C ')) : fit_platform = "KBP-H No Emulation"
						elif any(s in sku_check for s in (' 01 00 00 80 00 ',' 02 B0 02 01 ',' 02 D0 02 01 ')) : fit_platform = "SPT-LP Premium U"
						elif any(s in sku_check for s in (' 02 00 00 80 00 ',' 02 B0 02 02 ',' 02 D0 02 02 ')) : fit_platform = "SPT-LP Premium Y"
						elif any(s in sku_check for s in (' 03 00 00 80 00 ',' 02 B0 02 03 ',' 02 D0 02 03 ')) : fit_platform = "PCH-LP No Emulation"
						elif any(s in sku_check for s in (' 04 00 00 80 00 ',' 02 B0 02 04 ',' 02 D0 02 04 ')) : fit_platform = "PCH-LP Base U KBL"
						elif any(s in sku_check for s in (' 05 00 00 80 00 ',' 02 B0 02 05 ',' 02 D0 02 05 ')) : fit_platform = "PCH-LP Premium U KBL"
						elif any(s in sku_check for s in (' 06 00 00 80 00 ',' 02 B0 02 06 ',' 02 D0 02 06 ')) : fit_platform = "PCH-LP Premium Y KBL"
						elif any(s in sku_check for s in (' 02 B0 02 00 ',' 02 D0 02 00 ')) : fit_platform = "SPT-LP Base U"
						elif me11_sku_ranges :
							(start_sku_match, end_sku_match) = me11_sku_ranges[-1] # Take last SKU range
							sku_check = krod_fit_sku(start_sku_match) # Store the new SKU check bytes
							me11_sku_ranges.pop(-1) # Remove last SKU range
							continue # Invoke while, check fit_platform in new sku_check
						else : break # Could not find FIT SKU at any KROD
				
				# 11.0 : Skylake , Sunrise Point
				if minor == 0 :
					
					# Ignore: 11.0.0.7101
					if hotfix == 0 and build == 7101 : upd_found = True
					
					platform = "SPT"
				
				# 11.5 : Kabylake , Sunrise Point
				elif minor == 5 :
					
					platform = "SPT/KBP"
				
				# 11.6 : Kabylake , Union Point
				elif minor == 6 :
					
					# Ignore: 11.6.0.7069
					if hotfix == 0 and build == 7069 : upd_found = True
					
					platform = "SPT/KBP"
				
				# 11.x : Unknown
				else :
					sku = col_red + "Error" + col_end + ", unknown ME 11.x Minor version!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)
				
				if '-LP' in fit_platform : pos_sku_fit = "LP"
				elif '-H' in fit_platform : pos_sku_fit = "H"
				
				if pos_sku_ker == "Unknown" : # SKU not retreived from Kernel Analysis
					if sku == "NaN" : # SKU not retreived from manual DB entry
						if pos_sku_fit == "NaN" : # SKU not retreived from FIT Platform SKU
							sku = col_red + "Error" + col_end + ", unknown ME %s.%s %s SKU!" % (major,minor,sku_init) + col_red + " *" + col_end
							err_rep += 1
							err_stor.append(sku)
						else :
							sku = sku_init + ' ' + pos_sku_fit # SKU retreived from FIT Platform SKU
					else :
						pass # SKU retreived from manual DB entry
				else :
					sku = sku_init + ' ' + pos_sku_ker # SKU retreived from Kernel Analysis
				
				# Adjust PCH Stepping if not from DB
				if sku_stp == 'NaN' :
					if minor == 0 and hotfix > 0 :
						if ' LP' in sku : sku_stp = 'C0'
						elif ' H' in sku : sku_stp = 'D0'
				
				# Store SKU and check Latest version for all 11.x
				if sku == "Consumer H" :
					if sku_stp == "NaN" : sku_db = "CON_H_XX"
					else : sku_db = "CON_H" + "_" + sku_stp
					db_maj,db_min,db_hot,db_bld = check_upd(('Latest_ME_11%s_CONH' % minor))
					if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
				elif sku == "Consumer LP" :
					if sku_stp == "NaN" : sku_db = "CON_LP_XX"
					else : sku_db = "CON_LP" + "_" + sku_stp
					db_maj,db_min,db_hot,db_bld = check_upd(('Latest_ME_11%s_CONLP' % minor))
					if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
				elif sku == "Corporate H" :
					if sku_stp == "NaN" : sku_db = "COR_H_XX"
					else : sku_db = "COR_H" + "_" + sku_stp
					db_maj,db_min,db_hot,db_bld = check_upd(('Latest_ME_11%s_CORH' % minor))
					if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
				elif sku == "Corporate LP" :
					if sku_stp == "NaN" : sku_db = "COR_LP_XX"
					else : sku_db = "COR_LP" + "_" + sku_stp
					db_maj,db_min,db_hot,db_bld = check_upd(('Latest_ME_11%s_CORLP' % minor))
					if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
				
				# Adjust PDM status manually from DB (PDM,NOPDM,UKPDM)
				# PDM is defined in FTPR>BUP module (Huffman, proprietary)
				# Cannot detect any patterns in BUP to separate PDM/NOPDM yet
				sku_db += '_%s' % sku_pdm
				if sku_pdm == 'PDM' : pdm_status = 'Yes'
				elif sku_pdm == 'NOPDM' : pdm_status = 'No'
				else : pdm_status = 'Unknown'
				
				if ('Error' in sku) or param.me11_ker_disp: me11_ker_anl = True
				
				# Kernel Analysis for all 11.x
				if me11_ker_anl :
						
					if pos_sku_ker == pos_sku_fit :
						if pos_sku_ker == "Unknown" :
							err_stor_ker.append(col_magenta + "\nWarning, the SKU cannot be determined by Kernel & FIT:" + col_end + "\n\n	" + col_red + "Avoid flash" + col_end)
						else :
							err_stor_ker.append(col_magenta + "\nBased on Kernel & FIT, the SKU could be:"  + col_end + "\n\n	%s %s" % (sku_init, pos_sku_ker))
						if db_sku_chk not in ["NaN",pos_sku_ker] :
							err_stor_ker.append(col_magenta + "\nWarning, Kernel & FIT (%s) & Database (%s) SKU mismatch!" % (pos_sku_ker, db_sku_chk) + col_end)
					elif pos_sku_ker == "Unknown" and pos_sku_fit != "Unknown" :
						err_stor_ker.append(col_magenta + "\nBased on FIT only, the SKU could be:"  + col_end + "\n\n	%s %s" % (sku_init, pos_sku_fit) + col_end)
						if db_sku_chk not in ["NaN",pos_sku_fit] :
							err_stor_ker.append(col_magenta + "\nWarning, FIT (%s) & Database (%s) SKU mismatch!" % (pos_sku_fit, db_sku_chk) + col_end)
					elif pos_sku_fit == "Unknown" and pos_sku_ker != "Unknown" :
						err_stor_ker.append(col_magenta + "\nBased on Kernel only, the SKU could be:"  + col_end + "\n\n	%s %s" % (sku_init, pos_sku_ker) + col_end)
						if db_sku_chk not in ["NaN",pos_sku_ker] :
							err_stor_ker.append(col_magenta + "\nWarning, Kernel (%s) & Database (%s) SKU mismatch!" % (pos_sku_ker, db_sku_chk) + col_end)
					elif pos_sku_ker != pos_sku_fit :
						err_stor_ker.append(col_magenta + "\nWarning, Kernel (%s) & FIT (%s) SKU mismatch:" % (pos_sku_ker,pos_sku_fit) + col_end + "\n\n	" + col_red + "Avoid flash" + col_end)
						if db_sku_chk not in ["NaN",pos_sku_ker,pos_sku_fit] :
							err_stor_ker.append(col_magenta + "\nWarning, Kernel (%s) & FIT (%s) & Database (%s) SKU mismatch!" % (pos_sku_ker, pos_sku_fit, db_sku_chk) + col_end)
							
					me11_ker_msg = True
					for i in range(len(err_stor_ker)) : err_stor.append(err_stor_ker[i]) # For -msg
				
				# Kernel Extraction for all 11.x
				if param.me11_ker_extr :
					ker_anl('extr')
					continue # Next input file
				
				# UEFIStrip Fix for all 11.x
				if param.extr_mea and sku != "Consumer H" and sku != "Consumer LP" and sku != "Corporate H" and sku != "Corporate LP" :
					if sku_init == "Consumer" : sku_db = "CON_X"
					elif sku_init == "Corporate" : sku_db = "COR_X"
			
			# Report unknown ME Major version (ME 1.x exits before this check)
			if major < 1 or major > 11 :
				unk_major = True
				sku = col_red + "Error" + col_end + ", unknown ME SKU due to unknown Major version!" + col_red + " *" + col_end
				err_rep += 1
				err_stor.append(sku)
		
		if variant == "TXE" : # Trusted Execution Engine (SEC)
		
			if sku_match is not None :
				sku_txe = reading[start_sku_match + 8:start_sku_match + 0x10]
				sku_txe = binascii.b2a_hex(sku_txe).decode('utf-8').upper() # Hex value with Little Endianess
			
			if major == 1 or major == 0 :
				if rsa_pkey == "C7E5538622F3A6EC90F5F7CCD76FA8F1" or rsa_pkey == "5FB2D04BC4D8B4E90AECB5C708458F95" :
					txe_sub = " M/D"
					txe_sub_db = "_MD"
				elif rsa_pkey == "FF9F0A456C6D120D1C021E4453E5F726" : # Unknown I/T Pre-Production RSA Public Key
					txe_sub = " I/T"
					txe_sub_db = "_IT"
				else :
					txe_sub = col_red + " UNK" + col_end
					txe_sub_db = "_UNK_RSAPK_" + rsa_pkey # Additionally prints the unknown RSA Public Key
					err_rep += 1
				
				if major == 0 : # Weird TXE 1.0/1.1 (3MB/1.375MB) Android-only testing firmware (Rom_8MB_Tablet_Android, Teclast X98 3G)
					# PSI fiwi version 06 for BYT board Android_BYT_B0_Engg_IFWI_00.14 (from flash batch script)
					if sku_txe == "675CFF0D06430000" : # xxxxxxxx06xxxxxx is ~3MB for TXE v0.x
						sku = "3MB" + txe_sub
						sku_db = "3MB" + txe_sub_db
					else :
						sku = col_red + "Error" + col_end + ", unknown TXE 0.x SKU!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(sku)
				
				if major == 1 :
					if minor == 0 :
						if sku_txe == "675CFF0D03430000" : # xxxxxxxx03xxxxxx is 1.25MB for TXE v1.0
							sku = "1.25MB" + txe_sub
							sku_db = "1.25MB" + txe_sub_db
							if txe_sub_db == "_MD" :
								db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_10_125MB_MD')
								if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
							elif txe_sub_db == "_IT" :
								db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_10_125MB_IT')
								if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
						elif sku_txe == "675CFF0D05430000" : # xxxxxxxx05xxxxxx is 3MB for TXE v1.0
							sku = "3MB" + txe_sub
							sku_db = "3MB" + txe_sub_db
							if txe_sub_db == "_MD" :
								db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_10_3MB_MD')
								if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
							elif txe_sub_db == "_IT" :
								db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_10_3MB_IT')
								if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
						else :
							sku = col_red + "Error" + col_end + ", unknown TXE 1.0 SKU!" + col_red + " *" + col_end
							err_rep += 1
							err_stor.append(sku)
					elif minor == 1 :
						if sku_txe == "675CFF0D03430000" : # xxxxxxxx03xxxxxx is 1.375MB for TXE v1.1 (same as 1.25MB TXE v1.0)
							sku = "1.375MB" + txe_sub
							sku_db = "1.375MB" + txe_sub_db
							if txe_sub_db == "_MD" :
								db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_11_1375MB_MD')
								if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
							elif txe_sub_db == "_IT" :
								db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_11_1375MB_IT')
								if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
						else :
							sku = col_red + "Error" + col_end + ", unknown TXE 1.1 SKU!" + col_red + " *" + col_end
							err_rep += 1
							err_stor.append(sku)
					elif minor == 2 :
						if sku_txe == "675CFF0D03430000" : # xxxxxxxx03xxxxxx is 1.375MB for TXE v1.2 (same as v1.0 1.25MB and v1.1 1.375MB)
							sku = "1.375MB" + txe_sub
							sku_db = "1.375MB" + txe_sub_db
							if txe_sub_db == "_MD" :
								db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_12_1375MB_MD')
								if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
							#elif txe_sub_db == "_IT" :
								#db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_12_1375MB_IT')
								#if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
						else :
							sku = col_red + "Error" + col_end + ", unknown TXE 1.2 SKU!" + col_red + " *" + col_end
							err_rep += 1
							err_stor.append(sku)
					else :
						sku = col_red + "Error" + col_end + ", unknown TXE 1.x Minor version!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(sku)
					
					platform = "BYT"
					
			if major == 2 :
				if rsa_pkey == "87FF93E922C97926248C139DC902292A" or rsa_pkey == "5FB2D04BC4D8B4E90AECB5C708458F95" :
					txe_sub = " BSW/CHT"
					txe_sub_db = "_BSW-CHT"
				else :
					txe_sub = col_red + " UNK" + col_end
					txe_sub_db = "_UNK_RSAPK_" + rsa_pkey # Additionally prints the unknown RSA Public Key
					err_rep += 1
				
				if minor == 0 :
					if sku_txe == "675CFF0D03430000" :
						if 'UNK' in txe_sub : sku = "1.375MB" + txe_sub
						else : sku = sku = "1.375MB" # No need for + txe_sub as long as there is only one platform
						if 'UNK' in txe_sub_db : sku_db = "1.375MB" + txe_sub_db
						else : sku_db = "1.375MB" # No need for + txe_sub_db as long as there is only one platform
						if txe_sub_db == "_BSW-CHT" :
							db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_20_1375MB')
							if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					else :
						sku = col_red + "Error" + col_end + ", unknown TXE 2.0 SKU!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(sku)
				elif minor == 1 :
					if sku_txe == "675CFF0D03430000" :
						if 'UNK' in txe_sub : sku = "1.375MB" + txe_sub
						else : sku = sku = "1.375MB" # No need for + txe_sub as long as there is only one platform
						if 'UNK' in txe_sub_db : sku_db = "1.375MB" + txe_sub_db
						else : sku_db = "1.375MB" # No need for + txe_sub_db as long as there is only one platform
						if txe_sub_db == "_BSW-CHT" :
							db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_21_1375MB')
							if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
					else :
						sku = col_red + "Error" + col_end + ", unknown TXE 2.1 SKU!" + col_red + " *" + col_end
						err_rep += 1
						err_stor.append(sku)
				else :
					sku = col_red + "Error" + col_end + ", unknown TXE 2.x Minor version!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)
				
				platform = "BSW/CHT"
				
			if major == 3 : # Not fully supported yet!
				
				apl_warn = True
				
				vcn = vcn_skl(start_man_match, variant) # Detect VCN
				
				uuid_found,sku_check,me11_sku_ranges = krod_anl() # Detect OEMID and FIT SKU
				
				# Cannot detect RGN/EXTR properly, $FPT missing
				fw_type = "Unknown"
				rgn_exist = False
				fd_lock_state = 0
				
				if minor == 0 :
					
					db_sku_chk,sku,sku_stp,sku_pdm = db_skl(variant) # Retreive SKU & Rev from DB
					
					if sku_stp == "NaN" :
						# Adjust SoC Stepping if not from DB
						if hotfix < 12 :
							if release == "Production" : sku_stp = 'B' # PRD
							else : sku_stp = 'A' # PRE, BYP
						else :
							sku_db = "X" # No/Single SKU for TXE 3.x, Rev only
					else :
						sku_db = sku_stp
					
					db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_30')
					if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
				
				else :
					sku = col_red + "Error" + col_end + ", unknown TXE 3.x Minor version!" + col_red + " *" + col_end
					err_rep += 1
					err_stor.append(sku)

				if param.me11_ker_extr :
					ker_start,ker_end,rel_db = ker_anl('anl') # Detect Kernel offsets
					ker_anl('extr') # Kernel Extraction
				
				platform = "Apollo Lake"
			
			if major > 3 :
				unk_major = True
				sku = col_red + "Error" + col_end + ", unknown TXE SKU due to unknown Major version" + col_red + " *" + col_end
				err_rep += 1
				err_stor.append(sku)

		if variant == "SPS" : # Server Platform Services
			
			if sku_match is not None :
				sku_sps = reading[start_sku_match + 8:start_sku_match + 0xC]
				sku_sps = binascii.b2a_hex(sku_sps).decode('utf-8').upper() # Hex value with Little Endianess
			
			opr2_pat = re.compile(br'\x4F\x50\x52\x32\xFF\xFF\xFF\xFF') # OPR2 detection for SPS2,3,4 (the 4xFF force FPT area only)
			opr2_match = opr2_pat.search(reading)
			
			cod2_pat = re.compile(br'\x43\x4F\x44\x32\xFF\xFF\xFF\xFF') # COD2 detection for SPS1 (the 4xFF force FPT area only)
			cod2_match = cod2_pat.search(reading)
			
			if not rgn_exist :
				# REC detection always first, FTPR Manifest
				if major == 1 :
					sps1_rec_pat = re.compile(br'\x45\x70\x73\x52\x65\x63\x6F\x76\x65\x72\x79') # EpsRecovery detection
					sps1_rec_match = sps1_rec_pat.search(reading)
					if sps1_rec_match is not None : fw_type = "Recovery"
					else : fw_type = "Operational"
				elif major < 4 :
					mme_pat = re.compile(br'\x24\x4D\x4D\x45') # $MME detection
					mme_match = mme_pat.findall(reading)
					if len(mme_match) == 1 : fw_type = "Recovery" # SPSRecovery , FTPR for SPS2,3 (only $MMEBUP section)
					elif len(mme_match) > 1 : fw_type = "Operational" # SPSOperational , OPR1/OPR2 for SPS2,3 or COD1/COD2 for SPS1 regions
				else :
					norgn_sps_match = (re.compile(br'\x24\x43\x50\x44........\x46\x54\x50\x52', re.DOTALL)).search(reading) # SPSRecovery, $CPD + [0x8] + FTPR
					if norgn_sps_match is not None : fw_type = "Recovery"
					else :
						norgn_sps_match = (re.compile(br'\x24\x43\x50\x44........\x4F\x50\x52\x00', re.DOTALL)).search(reading) # SPSOperational, $CPD + [0x8] + OPR.
						if norgn_sps_match is not None : fw_type = "Operational"
			else :
				if opr2_match is not None or cod2_match is not None :
					sub_sku = "1" # xx.xx.xxx.1
					opr_mode = "Dual OPR"
				else :
					sub_sku = "0" # xx.xx.xxx.0
					opr_mode = "Single OPR"
			
			if major == 1 :
				if sku_sps != "08000000" : # All SPS 1 firmware have the same SKU.
					sku = col_red + "Error" + col_end + ", unknown SPS 1 SKU!" + col_red + " *" + col_end
					err_sps_sku = "Yes"
					err_rep += 1
					err_stor.append(sku)
					
			if major == 2 :
				if sku_sps != "2FE40100" : # All SPS 2 & 3 firmware have the same SKU.
					sku = col_red + "Error" + col_end + ", unknown SPS 2 SKU!" + col_red + " *" + col_end
					err_sps_sku = "Yes"
					err_rep += 1
					err_stor.append(sku)
			
			if major == 3 :
				if sku_sps != "2FE40100" : # All SPS 2 & 3 firmware have the same SKU.
					sku = col_red + "Error" + col_end + ", unknown SPS 3 SKU!" + col_red + " *" + col_end
					err_sps_sku = "Yes"
					err_rep += 1
					err_stor.append(sku)
				
				if rgn_exist :
					nm_sien_match = (re.compile(br'\x4F\x75\x74\x6C\x65\x74\x20\x54\x65\x6D\x70')).search(reading) # "Outlet Temp" detection (NM only)
					if nm_sien_match is not None : sps_serv = "Node Manager" # NM
					else : sps_serv = "Silicon Enabling" # SiEn
				
			if major == 4 :
				# SKU is at Kernel
				if fw_type != "Operational" : vcn = vcn_skl(start_man_match, variant) # VCN only at FTPR (REC)
				
				if param.me11_ker_extr and fw_type not in ['Operational','Recovery'] :
					ker_start,ker_end = ker_anl('anl') # Detect Kernel offsets
					ker_anl('extr') # Kernel Extraction
			
			if major > 4 :
				unk_major = True
				sku = col_red + "Error" + col_end + ", unknown SPS SKU due to unknown Major version" + col_red + " *" + col_end
				err_rep += 1
				err_stor.append(sku)
		
		# Region detection (Stock or Extracted)
		if rgn_exist : # SPS 1-3 have their own Firmware Types
			if variant == "SPS" and major < 4 :
				fw_type = "Region" # SPS is built manually so EXTR
			elif variant == "ME" and (1 < major < 8) :
				# Check 1, FOVD section
				if (major > 2 and not fovd_clean("new")) or (major == 2 and not fovd_clean("old")) :
					fw_type = "Region, Extracted"
				else :
					# Check 2, EFFS/NVKR strings
					fitc_pat = re.compile(br'\x4B\x52\x4E\x44\x00') # KRND. detection = FITC image, 0x00 adds old ME RGN support
					fitc_match = fitc_pat.search(reading)
					if fitc_match is not None :
						if major == 4 : # ME4-Only Fix 3, KRND. not enough
							# noinspection PyUnboundLocalVariable
							if len(me4_type_fix1) > 5 or me4_type_fix2 is not None or me4_type_fix3 is not None : fw_type = "Region, Extracted"
							else : fw_type = "Region, Stock"
						else :
							fw_type = "Region, Extracted"
					else :
						if major == 2 : # ME2-Only Fix 1
							if me2_type_fix != me2_type_exp : fw_type = "Region, Extracted"
							else : fw_type = "Region, Stock"
						elif major == 3 : # ME3-Only Fix 1
							# noinspection PyUnboundLocalVariable
							if len(me3_type_fix1) > 2 or (0x10 * 'FF') not in me3_type_fix3 or (0x10 * 'FF') not in me3_type_fix2a\
							or (0x10 * 'FF') not in me3_type_fix2b : fw_type = "Region, Extracted"
							else : fw_type = "Region, Stock"
						elif major == 6 and sku == "Ignition" : # ME6 Ignition does not work with KRND
							ign_pat = (re.compile(br'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6D\x3C\x75\x6D')).findall(reading) # Clean $MINIFAD checksum
							if len(ign_pat) < 2 : fw_type = "Region, Extracted" # 2 before NFTP & IGRT
							else : fw_type = "Region, Stock"
						else :
							fw_type = "Region, Stock"
			elif (variant == "ME" and major >=8) or (variant == "TXE") or (variant == "SPS" and major > 3) :
				fitc_exist = reading[fpt_start + 0x28:fpt_start + 0x30]
				fitc_exist = binascii.b2a_hex(fitc_exist).decode('utf-8').upper() # Hex value with Little Endianess
				# Check 1, FITC Version
				if fitc_exist == "0000000000000000" or fitc_exist == "FFFFFFFFFFFFFFFF" : # 00/FF --> clean ME/TXE
					fw_type = "Region, Stock"
					# Check 2, FOVD section
					if not fovd_clean("new") : fw_type = "Region, Extracted"
				else :
					fitc_ver_found = True
					fw_type = "Region, Extracted" # Exact version of FITC used to create the image can be found
					fitc_major = int(binascii.b2a_hex( (reading[fpt_start + 0x28:fpt_start + 0x2A]) [::-1]), 16)
					fitc_minor = int(binascii.b2a_hex( (reading[fpt_start + 0x2A:fpt_start + 0x2C]) [::-1]), 16)
					fitc_hotfix = int(binascii.b2a_hex( (reading[fpt_start + 0x2C:fpt_start + 0x2E]) [::-1]), 16)
					fitc_build = int(binascii.b2a_hex( (reading[fpt_start + 0x2E:fpt_start + 0x30]) [::-1]), 16)
		
		# Partial Firmware Update Detection (WCOD, LOCL)
		locl_start = (re.compile(br'\x24\x43\x50\x44........\x4C\x4F\x43\x4C', re.DOTALL)).search(reading[:0x10])
		if (variant == "ME") and (major == 11) and (locl_start is not None) :
			if locl_start.start() == 0 : # Partial Update has "$CPD + [0x8] + LOCL" at first 0x10
				wcod_found = True
				fw_type = "Partial Update"
				sku = "Corporate"
				del err_stor[:]
				err_rep = 0
		elif (variant == "ME") and (major < 11) and (sku_match is None) : # Partial Updates do not have $SKU
			wcod_match = (re.compile(br'\x24\x4D\x4D\x45\x57\x43\x4F\x44')).search(reading) # $MMEWCOD detection (found at 5MB & Partial Update firmware)
			if wcod_match is not None :
				wcod_found = True
				fw_type = "Partial Update"
				sku = "5MB"
				del err_stor[:]
				err_rep = 0
		
		# ME Firmware non Partial Update without $SKU
		if sku_match is None and fw_type != "Partial Update" and not me_rec_ffs :
			if (variant == "ME" and 1 < major < 11) or (variant == "TXE" and major < 3) or (variant == "SPS" and major < 4) :
				sku_missing = True
				err_rep += 1
		
		# OEM FWUpdate UUID Detection, RGN & EXTR only
		if fw_type != "Update" and ((variant == "ME" and major < 11) or (variant == "TXE" and major < 3) or (variant == "SPS" and major < 4)) : # post-SKL have their own checks
			uuid_pat_1 = re.compile(br'\x6F\x6E\x65\x4C\x6F\x76\x00\x00') # Lenovo OEM UUID 1 (4C656E6F766F --> Lenovo)
			uuid_match_1 = uuid_pat_1.search(reading)
			uuid_pat_2 = re.compile(br'\x22\x36\x85\x68\xD3\xEE') # Dell OEM UUID
			uuid_match_2 = uuid_pat_2.search(reading)
			#uuid_pat_3 = re.compile(br'(\x06|x05)\x04\x00\x00\x00\x00\x00\x00') # Lenovo OEM UUID 2 --> Disabled due to false positives
			#uuid_match_3 = uuid_pat_3.search(reading)
			if uuid_match_1 is not None : uuid_found = "Lenovo"
			elif uuid_match_2 is not None : uuid_found = "Dell"
		
		# Check database for unknown firmware, all firmware filenames have this stucture: Major.Minor.Hotfix.Build_SKU_Release_Type.bin
		if release == "Production" : rel_db = "PRD"
		elif release == "Pre-Production" : rel_db = "PRE"
		elif release == "ROM-Bypass" : rel_db = "BYP"
		
		if variant == "SPS" and (fw_type == "Region" or fw_type == "Region, Stock" or fw_type == "Region, Extracted") : # SPS --> Region (EXTR at DB)
			fw_type = "Region"
			type_db = "EXTR"
		elif fw_type == "Region, Extracted" : type_db = "EXTR"
		elif fw_type == "Region, Stock" or fw_type == "Region" : type_db = "RGN"
		elif fw_type == "Update" : type_db = "UPD"
		elif fw_type == "Operational" : type_db = "OPR"
		elif fw_type == "Recovery" : type_db = "REC"
		elif fw_type == "Unknown" : type_db = "UNK"
		
		# Create firmware DB names
		if variant == "ME" or variant == "TXE" :
			name_db = "%s.%s.%s.%s_%s_%s_%s" % (major, minor, hotfix, build, sku_db, rel_db, type_db) # The re-created filename without extension
			name_db_rgn = "%s.%s.%s.%s_%s_%s_RGN_%s" % (major, minor, hotfix, build, sku_db, rel_db, rsa_hash) # The equivalent "clean" RGN filename
			name_db_extr = "%s.%s.%s.%s_%s_%s_EXTR_%s" % (major, minor, hotfix, build, sku_db, rel_db, rsa_hash) # The equivalent "dirty" EXTR filename
		elif variant == "SPS" :
			if sub_sku == "NaN" :
				name_db = "%s.%s.%s.%s_%s_%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), rel_db, type_db)
				name_db_rgn = "%s.%s.%s.%s_%s_RGN_%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), rel_db, rsa_hash) # The equivalent RGN filename
				name_db_extr = "%s.%s.%s.%s_%s_EXTR_%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), rel_db, rsa_hash) # The equivalent EXTR filename
				name_db_0_extr = "%s.%s.%s.%s.0_%s_EXTR_%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), rel_db, rsa_hash) # The equivalent EXTR 0 filename
				name_db_1_extr = "%s.%s.%s.%s.1_%s_EXTR_%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), rel_db, rsa_hash) # The equivalent EXTR 1 filename
			else :
				name_db = "%s.%s.%s.%s.%s_%s_%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), sub_sku, rel_db, type_db)
				name_db_rgn = "%s.%s.%s.%s.%s_%s_RGN_%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), sub_sku, rel_db, rsa_hash) # The equivalent RGN filename
				name_db_extr = "%s.%s.%s.%s.%s_%s_EXTR_%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), sub_sku, rel_db, rsa_hash) # The equivalent EXTR filename
		name_db_hash = name_db + '_' + rsa_hash
		
		if param.db_print_new :
			with open(mea_dir + "\\" + 'MEA_DB_NEW.txt', 'a') as db_file : db_file.write(name_db_hash + '\n')
			continue # Next input file
		
		# Search Engine database for firmware
		fw_db = db_open()
		if not wcod_found : # Must not be Partial Update
			if (((variant == "ME" or variant == "TXE") and sku_db != "NaN") or err_sps_sku == "") and rel_db != "NaN" and type_db != "NaN" : # Search database only if SKU, Release & Type are known
				for line in fw_db :
					if len(line) < 2 or line[:3] == "***" :
						continue # Skip empty lines or comments
					else : # Search the re-created file name without extension at the database
						if name_db_hash in line : fw_in_db_found = "Yes" # Known firmware, nothing new
						if type_db == "EXTR" and name_db_rgn in line :
							rgn_over_extr_found = True # Same firmware found at database but RGN instead of imported EXTR, so nothing new
							fw_in_db_found = "Yes"
						if type_db == "UPD" and ((variant == "ME" and (major > 7 or (major == 7 and release != "Production") or
							(major == 6 and sku == "Ignition"))) or variant == "TXE") : # Only for ME8 and up or ME7 non-PRD or ME6.0 IGN
							# noinspection PyUnboundLocalVariable
							if (name_db_rgn in line) or (name_db_extr in line) : rgn_over_extr_found = True # Same RGN/EXTR firmware found at database, UPD disregarded
						# noinspection PyUnboundLocalVariable
						if (type_db == "OPR" or type_db == "REC") and ((name_db_0_extr in line) or (name_db_1_extr in line)) : rgn_over_extr_found = True # Same EXTR found at DB, OPR/REC disregarded
				fw_db.close()
			# If SKU and/or Release and/or Type are NaN (unknown), the database will not be searched but rare firmware will be reported (Partial Update excluded)
		else :
			can_search_db = False # Do not search DB for Partial Update images
		
		# Check if firmware is updated, Production only
		if variant == "SPS" :
			if release == "Production" and err_rep == 0 and fw_type != "Operational" and fw_type != "Recovery" : # Does not display if there is any error or firmware is OPR/REC
				if upd_found :
					upd_rslt = "Latest:   " + col_red + "No" + col_end
				elif not upd_found :
					upd_rslt = "Latest:   " + col_green + "Yes" + col_end
		elif release == "Production" and err_rep == 0 and not wcod_found : # Does not display if there is any error or firmware is Partial Update
			if variant == "TXE" and major == 0 : pass # Exclude TXE v0.x
			else :
				if upd_found : upd_rslt = "Latest:   " + col_red + "No" + col_end
				elif not upd_found : upd_rslt = "Latest:   " + col_green + "Yes" + col_end
		
		# Extract Dell HDR RBU ImagME Regions
		if param.rbu_me_extr :
			rbume_pat = re.compile(b'\x49\x6D\x61\x67\x4D\x65')
			rbume_match = rbume_pat.search(reading)
			if rbume_match is not None :
				(start_rbume_match, end_rbume_match) = rbume_match.span()
				me_start = end_rbume_match + 0xA
				me_size = int.from_bytes(reading[end_rbume_match + 0x6:end_rbume_match + 0xA], 'little') - 0x14
				me_end = start_rbume_match + me_size
				me_data = reading[me_start:me_end]
				try :
					with open(mea_dir + "\\" + "rbu_temp.bin", 'w+b') as rbu_temp : rbu_temp.write(me_data)
					if os.path.isfile(mea_dir + "\\" + name_db + '.bin') : os.remove(mea_dir + "\\" + name_db + '.bin')
					os.rename(mea_dir + "\\" + 'rbu_temp.bin', mea_dir + "\\" + name_db + '.bin')
					print(col_yellow + "Extracted ImagME from %s to %s\n" % (hex(me_start), hex(me_end - 0x1)) + col_end)
				except :
					print(col_red + "Error, could not extract ImagME from %s to %s\n" % (hex(me_start), hex(me_end - 0x1)) + col_end)
					if os.path.isfile(mea_dir + "\\" + "rbu_temp.bin") : os.remove(mea_dir + "\\" + "rbu_temp.bin")
				continue # Next input file
		
		# Rename input file based on the DB structured name
		if param.give_db_name :
			file_name = file_in
			new_dir_name = os.path.join(os.path.dirname(file_in), name_db + '.bin')
			f.close()
			if not os.path.exists(new_dir_name) : os.rename(file_name, new_dir_name)
			continue # Next input file
		
		# UEFI Bios Updater Pre-Menu Integration (must be after processing but before message printing)
		if param.ubu_mea_pre :
			if can_search_db and not rgn_over_extr_found and fw_in_db_found == "No" :
				print(col_yellow + "Engine firmware not found at the database, run ME Analyzer for details!" + col_end)
			mea_exit(9)
		
		# UEFI Strip Integration (must be after Printed Messages)
		elif param.extr_mea :
			if fw_in_db_found == "No" and not rgn_over_extr_found and not wcod_found : 
				if variant == "SPS" :
					name_db = "%s_%s_%s_%s" % (fw_ver(), rel_db, type_db, rsa_hash)
				else :
					# noinspection PyUnboundLocalVariable
					if variant == 'ME' and major == 11 and (sku_db == 'CON_X' or sku_db == 'COR_X') and sku_stp == 'NaN' and sku_pdm == 'NaN' : sku_db += "_XX_UKPDM"
					name_db = "%s_%s_%s_%s_%s" % (fw_ver(), sku_db, rel_db, type_db, rsa_hash)
				
			if fuj_rgn_exist : name_db = "%s_UMEM" % name_db
			
			date_extr = ("%s-%s-%s" % (date[-2:], date[4:6], date[:4])) # format is dd-mm-yyyy
			
			if me_rec_ffs : print("%s %s_NaN_REC %s NaN %s" % (variant, fw_ver(), fw_ver(), date_extr))
			elif jhi_warn : print("%s %s_NaN_IPT %s NaN %s" % (variant, fw_ver(), fw_ver(), date_extr))
			else : print("%s %s %s %s %s" % (variant, name_db, fw_ver(), sku_db, date_extr))
			
			mea_exit(0)
		
		# Print MEA Messages
		elif variant == "SPS" and not param.print_msg :
			print("Firmware: Intel %s" % variant)
			if sub_sku != "NaN" : print("Version:  %s.%s.%s.%s.%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build), sub_sku)) # xx.xx.xx.xxx.y
			else : print("Version:  %s.%s.%s.%s" % ("{0:02d}".format(major), "{0:02d}".format(minor), "{0:02d}".format(hotfix), "{0:03d}".format(build))) # xx.xx.xx.xxx
			print("Release:  %s" % release)
			if sps_serv != "NaN" : print("Service:  %s" % sps_serv)
			print("Type:     %s" % fw_type)
			if opr_mode != "NaN" : print("Mode:     %s" % opr_mode)
			if err_sps_sku != "" : print("SKU:      %s" % sku) # only if SKU is not "standard"
			if major == 4 and vcn > 0 : print("VCN:      %s" % vcn) # Only for SPS4 (new format-based)
			print("Date:     %s" % date_print)
			if fitc_ver_found : print("FIT Ver:  %s.%s.%s.%s" % ("{0:02d}".format(fitc_major), "{0:02d}".format(fitc_minor), "{0:02d}".format(fitc_hotfix), "{0:03d}".format(fitc_build)))
			#if upd_rslt != "" : print(upd_rslt)
		elif not param.print_msg :
			print("Firmware: Intel %s" % variant)
			print("Version:  %s.%s.%s.%s" % (major, minor, hotfix, build))
			print("Release:  %s" % release)
			
			if not me_rec_ffs and not jhi_warn : # The following should not appear when ME-REC/IPT-DAL modules are loaded
				
				print("Type:     %s" % fw_type)

				if fd_lock_state == 2 : print("FD:       Unlocked")
				elif fd_lock_state == 1 : print("FD:       Locked")
				
				if (variant == "TXE" and major > 2 and 'Error' not in sku) or wcod_found : pass
				else : print("SKU:      %s" % sku)

				if (variant == "ME" and major >= 11) or (variant == "TXE" and major >= 3):
					if sku_stp != "NaN" : print("Rev:      %s" % sku_stp)
					elif wcod_found : pass
					else : print("Rev:      Unknown")
				
				if ((variant == "ME" and major >= 8) or variant == "TXE") and svn > 1 : print("SVN:      %s" % svn)

				if ((variant == "ME" and major >= 8) or variant == "TXE") and not wcod_found : print("VCN:      %s" % vcn)

				if variant == "ME" and major == 11 and wcod_found is False :
					# noinspection PyUnboundLocalVariable
					print("PDM:      %s" % pdm_status)

				if pvpc != "NaN" and wcod_found is False : print("PV:       %s" % pvpc)
				
				print("Date:     %s" % date_print)
				
				if ((variant == "ME" and major <= 10) or variant == "TXE") and fitc_ver_found:
					print("FITC Ver: %s.%s.%s.%s" % (fitc_major, fitc_minor, fitc_hotfix, fitc_build))
				elif variant == "ME" and major > 10 and fitc_ver_found:
					print("FIT Ver:  %s.%s.%s.%s" % (fitc_major, fitc_minor, fitc_hotfix, fitc_build))
				
				if fit_platform != "NaN" :
					if variant == "ME" and major == 11 : print("FIT SKU:  %s" % fit_platform)
				
				if platform != "NaN" : print("Platform: %s" % platform)
				
				if upd_rslt != "" : print(upd_rslt)
				
				# Display ME7 Blacklist
				if major == 7 :
					print("")
					if me7_blist_1_build != 0 :
						# noinspection PyUnboundLocalVariable
						print("Blist 1:  <= %s.%s.%s.%s" % (7, me7_blist_1_minor, me7_blist_1_hotfix, me7_blist_1_build))
					else :
						print("Blist 1:  Empty")
					if me7_blist_2_build != 0 :
						# noinspection PyUnboundLocalVariable
						print("Blist 2:  <= %s.%s.%s.%s" % (7, me7_blist_2_minor, me7_blist_2_hotfix, me7_blist_2_build))
					else :
						print("Blist 2:  Empty")
			elif me_rec_ffs :
				err_rep = 0
				print("Date:     %s" % date_print)
				print("GUID:     821D110C-D0A3-4CF7-AEF3-E28088491704")
			elif jhi_warn :
				err_rep = 0
				print("Date:     %s" % date_print)
				
		# General MEA Messages (must be Errors > Warnings > Notes)
		if unk_major :
			if not param.print_msg :
				print("")
				print(col_red + "Error, unknown Intel Engine Major version" + col_end)
				
			err_stor.append(col_red + "\nError, unknown Intel Engine Major version" + col_end)
		
		if not param.print_msg and me11_ker_msg and fw_type != "Partial Update" :
			for i in range(len(err_stor_ker)) : print(err_stor_ker[i])
		
		if rec_missing and fw_type != "Partial Update" :
			if not param.print_msg :
				print("")
				print(col_red + "Error, Recovery section missing, Manifest Header not found! *" + col_end)
			
			if (not err_stor) and (not warn_stor) and (not note_stor) :			
				err_stor.append(col_red + "Error, Recovery section missing, Manifest Header not found! *" + col_end)
			else :
				err_stor.append(col_red + "\nError, Recovery section missing, Manifest Header not found! *" + col_end)
		
		if sku_missing :
			if not param.print_msg :
				print("")
				print(col_red + "Error, SKU tag missing, incomplete Intel Engine firmware!" + col_end)
			
			if (not err_stor) and (not warn_stor) and (not note_stor) :			
				err_stor.append(col_red + "Error, SKU tag missing, incomplete Intel Engine firmware!" + col_end)
			else :
				err_stor.append(col_red + "\nError, SKU tag missing, incomplete Intel Engine firmware!" + col_end)

		if variant == "TXE" and ('UNK' in txe_sub) :
			if not param.print_msg :
				print("")
				print(col_red + "Error" + col_end + ", unknown TXE %s.x platform!" % major + col_red + " *" + col_end)
		
			err_stor.append(col_red + "Error" + col_end + ", unknown TXE %s.x platform!" % major + col_red + " *" + col_end)
		
		if apl_warn :
			
			if not param.print_msg :
				print("")
				print(col_red + "Error, Intel TXE 3 APL is not fully supported yet!" + col_end)
			
			if (not err_stor) and (not warn_stor) and (not note_stor) :			
				err_stor.append(col_red + "Error, Intel TXE 3 APL is not fully supported yet!" + col_end)
			else :
				err_stor.append(col_red + "\nError, Intel TXE 3 APL is not fully supported yet!" + col_end)
				
		if uf_error :
			
			if not param.print_msg :
				print("")
				print(col_red + "Error, UEFIFind Engine GUID detection failed!" + col_end)
			
			if (not err_stor) and (not warn_stor) and (not note_stor) :			
				err_stor.append(col_red + "Error, UEFIFind Engine GUID detection failed!" + col_end)
			else :
				err_stor.append(col_red + "\nError, UEFIFind Engine GUID detection failed!" + col_end)
		
		if err_rep > 0 :
			if not param.print_msg :
				print("")
				print(col_red + "* Please report this issue!" + col_end)
			
			err_stor.append(col_red + "\n* Please report this issue!" + col_end)

		if fpt_chk_fail :

			if not param.print_msg:
				print("")
				print(col_magenta + "Warning: Corrupted $FPT header, wrong checksum!" + col_end)

			if (not err_stor) and (not warn_stor) and (not note_stor):
				note_stor.append(col_magenta + "Warning: Corrupted $FPT header, wrong checksum!" + col_end)
			else:
				note_stor.append(col_magenta + "\nWarning: Corrupted $FPT header, wrong checksum!" + col_end)

		if fuj_rgn_exist :

			if not param.print_msg : 
				print("")
				print(col_magenta + "Warning: Fujitsu Intel Engine Firmware detected!" + col_end)
			
			if (not err_stor) and (not warn_stor) and (not note_stor) :
				note_stor.append(col_magenta + "Warning: Fujitsu Intel Engine Firmware detected!" + col_end)
			else :
				note_stor.append(col_magenta + "\nWarning: Fujitsu Intel Engine Firmware detected!" + col_end)
		
		if me_rec_ffs or jhi_warn :
			
			if not param.print_msg :
				print("")
				print(col_magenta + "Warning, this is NOT a flashable Intel Engine Firmware image!" + col_end)
			else : 
				del err_stor[:] # Empties all Errors from array that should not be shown at FFS/IPT-DAL modules
			
			if (not err_stor) and (not warn_stor) and (not note_stor) :
				warn_stor.append(col_magenta + "Warning, this is NOT a flashable Intel Engine Firmware image!" + col_end)
			else :
				warn_stor.append(col_magenta + "\nWarning, this is NOT a flashable Intel Engine Firmware image!" + col_end)
			
		if uuid_found != "" or uuid_found == "Unknown":
			
			if not param.print_msg : 
				print("")
				print(col_yellow + "Note: %s Firmware Update OEM ID detected!" % uuid_found + col_end)
			
			if (not err_stor) and (not warn_stor) and (not note_stor) :
				note_stor.append(col_yellow + "Note: %s Firmware Update OEM ID detected!" % uuid_found + col_end)
			else :
				note_stor.append(col_yellow + "\nNote: %s Firmware Update OEM ID detected!" % uuid_found + col_end)
				
		if multi_rgn :
			
			if not param.print_msg : 
				print("")
				print(col_yellow + "Note: Multiple (%d) Intel Engine Firmware detected in file!" % fpt_count + col_end)
			
			if (not err_stor) and (not warn_stor) and (not note_stor) :
				note_stor.append(col_yellow + "Note: Multiple (%d) Intel Engine Firmware detected in file!" % fpt_count + col_end)
			else :
				note_stor.append(col_yellow + "\nNote: Multiple (%d) Intel Engine Firmware detected in file!" % fpt_count + col_end)		
		
		if can_search_db and not rgn_over_extr_found and fw_in_db_found == "No" :
			
			if not param.print_msg :
				print("")
				print(col_yellow + "Note: This firmware was not found at the database, please report it!" + col_end)
			
			if (not err_stor) and (not warn_stor) and (not note_stor) :
				note_stor.append(col_yellow + "Note: This firmware was not found at the database, please report it!" + col_end)
			else :
				note_stor.append(col_yellow + "\nNote: This firmware was not found at the database, please report it!" + col_end)
		
		if found_guid != "" : gen_msg('uefifind_guid', found_guid)
		
		# Print Error/Warning/Note Messages
		if param.print_msg : msg_rep()
		
		if param.ubu_mea : print()
		
		if param.multi : multi_drop()
		
		f.close()
		
	if param.db_print_clean or param.help_scr : mea_exit(0) # Only once for -?,-pwdb
	
mea_exit(0)