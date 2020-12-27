import os
import sys
import time
import math

def isPE(fileStream):
	return fileStream[0:2] == b'MZ'

def crash(msg):
	print("   -> %s" % msg)
	exit(-1)

def findEntryPoint(fileStream):
	"""
	AddressOfEntryPoint: RVA of entry point (relative to imageBase)
	so we have to do ImageBase+AddressOfEntryPoint
	"""
	return int.from_bytes(fileStream[0xa8:0xab], "little") + int.from_bytes(fileStream[0xb4:0xb8], "little")

def findSectionHeader(fileStream, section):
	for offset in range(len(fileStream)):
		if(fileStream[offset:offset+5] == section):
			return offset
	return -1

def CalculateNewImageSize(fileStream, Valigned_addition_size):
	ImageSize = int.from_bytes(fileStream[0xD0:0xD4], "little")
	return ImageSize + Valigned_addition_size

def findSectionEntry(fileStream, section=b'.text'):
	"""
	section name - 8 bytes?
	section virtual size - 4 bytes
	Virtual address - 4 bytes
	Size of raw data - 4 bytes
	Raw data offset - 4 bytes
	"""
	for offset in range(len(fileStream)):
		if(fileStream[offset:offset+len(section)] == section):
			RawSize = int.from_bytes(fileStream[offset+8:offset+12], "little")
			RawOffset = int.from_bytes(fileStream[offset+20:offset+24], "little")

			return (RawSize, RawOffset)
	return ()

def FindNewSectionHeader(fileStream):
	sizeOfsection = 0x28
	numberOfSections = int.from_bytes(fileStream[0x86:0x88], "little")
	return 0x178+(numberOfSections*sizeOfsection)

def GetNewSectionVA(fileStream, LastSection):
	LastSectionVsize = int.from_bytes(fileStream[LastSection+0x8:LastSection+0xC], "little")
	LastSectionVA 	 = int.from_bytes(fileStream[LastSection+0xC:LastSection+0xF], "little")
	SectionAlignment = int.from_bytes(fileStream[0xB8:0xBC], "little")

	EndOfLastSection = LastSectionVsize + LastSectionVA
	AdjustedVA 		 = EndOfLastSection / SectionAlignment
	return 	math.ceil(AdjustedVA) * SectionAlignment 

def CalculateRawSize(fileStream, unaligned_size):
	FileAlignment	 = int.from_bytes(fileStream[0xBC:0xBF], "little") 

	ReAdjustedOffset = unaligned_size / FileAlignment
	return math.ceil(ReAdjustedOffset * FileAlignment)

def AppendBytes(filePath, size):
	file = open(filePath, "ab")
	pos = file.tell()
	file.write(bytes(size))
	file.close()
	return pos

def FindCodeCave(fileStream, size):
	(DataSize, DataOffset) = findSectionEntry(fileStream, b'.data')

	offset = 0
	zeroOffset = 0
	zeroCount = 0

	while offset < DataSize:
		zeroOffset = offset
		while(fileStream[DataOffset+zeroOffset] == 0):
			zeroCount += 1
			zeroOffset += 1
		if(zeroCount >= size):
			return DataOffset+offset
		else:
			zeroCount = 0
		offset += 1
	return -1

def AllocInitializedDataSpace(file, fileStream, data):
	SectionHeader          = findSectionHeader(fileStream, b'.data')
	DataVirtualaddress	   = int.from_bytes(fileStream[SectionHeader+0xC:SectionHeader+0xF], "little")
	DataRawSize   		   = int.from_bytes(fileStream[SectionHeader+0x10:SectionHeader+0x14],"little")
	ImageBase     		   = int.from_bytes(fileStream[0xb4:0xb8], "little")
	(DataSize, DataOffset) = findSectionEntry(fileStream, b'.data')

	DataAddress = FindCodeCave(fileStream, len(data))
	if(DataAddress != -1):
		file.seek(DataAddress,0)
		file.write(bytes(data, "ascii"))
		return ImageBase+(DataVirtualaddress+abs(DataAddress-DataOffset))
	else:
		crash("Could not allocate strings in executable.")
	return -1

def GetOffsetFromRVA(fileStream, RVA):
	offset = 0x178
	SizeOfHeader = 0x28

	LastSectionRaw = 0
	LastSectionRVA = 0

	ResultingOffset = 0

	while(fileStream[offset:offset+SizeOfHeader] != bytes(SizeOfHeader)):
		SectionRVA = int.from_bytes(fileStream[offset+0xC:offset+0x10],"little")
		SectionRaw = int.from_bytes(fileStream[offset+0x14:offset+0x18],"little")

		if(RVA < SectionRVA):
			ResultingOffset = LastSectionRaw+(RVA-LastSectionRVA)
			break

		LastSectionRaw = SectionRaw
		LastSectionRVA = SectionRVA
		offset += SizeOfHeader

	return ResultingOffset

def FindImportByName(fileStream, name):
	ImageBase = int.from_bytes(fileStream[0xb4:0xb8], "little")

	IT_RVA = int.from_bytes(fileStream[0x100:0x104], "little")
	IToffset = GetOffsetFromRVA(fileStream, IT_RVA)

	ImportedOffset = 0
	SizeOfImportDescriptor = 0x14 

	while fileStream[IToffset+ImportedOffset:IToffset+ImportedOffset+SizeOfImportDescriptor] != bytes(SizeOfImportDescriptor):
		IAT_RVA = int.from_bytes(fileStream[IToffset+ImportedOffset+0x10:IToffset+ImportedOffset+0x14], "little")#first imported dll IAT RVA
		IAToffset = GetOffsetFromRVA(fileStream, IAT_RVA)
		IATsize = int.from_bytes(fileStream[0x104:0x108],"little")

		HintsNameArrayRVA = int.from_bytes(fileStream[IAToffset:IAToffset+0x4], "little")
		HintsNameArrayOffset = GetOffsetFromRVA(fileStream, HintsNameArrayRVA)

		offset = 0
		cursor = HintsNameArrayOffset+0x2

		while fileStream[cursor:cursor+5] != bytes(5):
			currentName = ""
			while(fileStream[cursor] != 0x00):
				currentName += chr(fileStream[cursor])
				cursor += 1

			if(len(currentName) <= 3):
				offset = -1
				break

			while(fileStream[cursor] == 0x00):
				cursor += 1

			if(currentName == name):
				return ImageBase+IAT_RVA+(offset*4)

			offset += 1
		ImportedOffset += SizeOfImportDescriptor
	crash("Could not find imported function(case sensitive), check IAT")
	return -1

def AddSection(filePath, name, shellcode, RawSize):
	file                  = open(filePath, "r+b")
	fileStream            = file.read()

	SectionName           = name
	VirtualSectionSize    = RawSize 

	numberOfSections 	  = int.from_bytes(fileStream[0x86:0x88], "little")
	ImageSize 			  = int.from_bytes(fileStream[0xD0:0xD4], "little")
	ImageBase 			  = int.from_bytes(fileStream[0xB4:0xB8], "little")
	SectionAlignment 	  = int.from_bytes(fileStream[0xB8:0xBC], "little")
	FileAlignment 		  = int.from_bytes(fileStream[0xBC:0xBF], "little")
	Characteristics 	  = 0x60000020 #MEM_EXECUTE, MEM_READ, CNT_CODE, CNT_INIALIZED_DATA

	print("[!] Calculting aligned sizes")
	RawSectionSize 		  = CalculateRawSize(fileStream, RawSize)

	print("[!] Creating empty section")
	file.seek(0, 0)
	RawSectionPointer 	  = AppendBytes(filePath, len(shellcode))

	print("[!] Writing to section")
	file.seek(RawSectionPointer)
	file.write(shellcode)

	NewHeaderOffset       = FindNewSectionHeader(fileStream)

	LastHeaderOffset 	  = NewHeaderOffset - 0x28#sizeof section header
	RVirtualSectionAddress= GetNewSectionVA(fileStream, LastHeaderOffset)
	VirtualSectionSize    = RawSize

	print("[!] Found new header space, offset:",hex(NewHeaderOffset))
	try:
		SectionHeader = bytearray(bytes(SectionName, 'ascii'))
		SectionHeader += bytes(8-len(SectionName))
		SectionHeader += VirtualSectionSize.to_bytes(4,"little") 
		SectionHeader += RVirtualSectionAddress.to_bytes(4, "little")
		SectionHeader += RawSectionSize.to_bytes(4, "little")
		SectionHeader += RawSectionPointer.to_bytes(4, "little")
		SectionHeader += bytes(12)
		SectionHeader += Characteristics.to_bytes(4, "little")
	except:
		crash("Failed creating the custom section header")
	
	print("[!] Updating headers")
	file.seek(NewHeaderOffset)
	file.write(SectionHeader)

	print("[!] Updating sizes")

	file.seek(0x86,0)
	numberOfSections += 1
	file.write(numberOfSections.to_bytes(2, "little"))

	file.seek(0xD0,0)
	ImageSize 			= CalculateNewImageSize(fileStream, VirtualSectionSize)
	file.write(ImageSize.to_bytes(4, "little"))

	print("[!] Changing Entry Point")
	file.seek(0xA8,0)
	file.write(RVirtualSectionAddress.to_bytes(4, "little"))

	file.close()
	return RawSectionPointer

def ror(n,rotations,width):
    return (2**width-1)&(n>>rotations|n<<(width-rotations))

def Encrypt(bytes_array, *xor_keys):
	encrypted_buffer = list()
	index 		 	 = 0
	intByteArray 	 = bytearray()
	
	for byte in bytes_array:
		for key in xor_keys:
			byte  = ror(byte, 2, 8)
			byte ^= key
		sys.stdout.write("[!] Encrypting data %d%% \r" % (index/len(bytes_array)*100))
		sys.stdout.flush()
		encrypted_buffer.append(byte)
		index += 1
	sys.stdout.write("[!] Encrypting data %d%% \r" % (100))
	sys.stdout.flush()
	print()
	return encrypted_buffer

def PrintBytes(byteArray):
	for byte in byteArray:
		print(format(byte, 'x'), end='')

def main():
	try:
		path = sys.argv[1]
	except: 
		crash("No executable was given!\nUsage: ZEncryptor.exe <executable_path>")

	start = time.time()

	file = open(path, "r+b")
	fileStream = file.read()

	print("File: %s\nSize: %d Bytes" % (path, len(fileStream)))
	print("\nLogs:\n");

	if(not isPE(fileStream)): crash("This file is not a valid PE file")

	print("[!] Checking if file is already encrypted")

	if(len(findSectionEntry(fileStream, b'.zenc')) != 0): crash("File has already been encrypted with ZXcryptor")

	print("[!] Fetching PE Header infos")

	if(findEntryPoint(fileStream) == 0x0): crash("Could not find Entry point")

	print("[!] Searching necessary section infos")

	if(len(findSectionEntry(fileStream, b'.text')) == 0): crash("Could not find needed sections")

	(size, offset) = findSectionEntry(fileStream, b'.text')

	bytes_array = Encrypt(fileStream[offset:offset+size],0xF3, 0xFF, 0x43, 0xDE, 0x10, 0x80)

	print("[!] Applying encryption")

	if(not file.writable()): crash("File cannot be written to. Check if any app is currently using it.")

	file.seek(offset, 0)
	file.write(bytearray(bytes_array))
	file.seek(0)
	
	print("[!] File was succesfully encrypted")
	
	print("[!] Trying to add custom payload")

	print("[!] Allocating strings")
	string1 	= AllocInitializedDataSpace(file, fileStream, "ZXCRYPTED")
	string2 	= AllocInitializedDataSpace(file, fileStream, "This file has been encrypted with ZXcryptor.")

	print("[!] Allocated strings at offset: %s , %s" % (hex(string1), hex(string2)))

	file.seek(0)
	MsgBoxA 	= FindImportByName(fileStream, "MessageBoxA")
	ExitProcess = FindImportByName(fileStream, "ExitProcess")

	if(MsgBoxA == -1): crash("Cannot find necessary imports.")

	print("[!] Fetching necessary imports %s" % hex(MsgBoxA))

	print("[!] Shellcode: ")

	"""
	push 0 ;WindowHandle
	mov eax, string1
	push eax
	mov eax, string2
	push eax
	push 0 ;MB_OK
	call MessageBoxA
	push 0 ;exitCode
	call ExitProcess
	"""

	shellcode =  bytes([0x6a, 0x00, 0xB8])
	shellcode += string1.to_bytes(4, "little")
	shellcode += bytes([0x50, 0xB8])#push eax, mov eax, xxxx
	shellcode += string2.to_bytes(4,"little")
	shellcode += bytes([0x50, 0x6a, 0x00, 0xFF, 0x15])
	shellcode += MsgBoxA.to_bytes(4, "little")
	shellcode += bytes([0x6a, 0x00, 0xFF, 0x15])
	shellcode += ExitProcess.to_bytes(4, "little")
	PrintBytes(shellcode)
	print()

	print("[!] Adding crypted section")

	AddSection(path, ".zenc",shellcode, len(shellcode))

	FileBytes = fileStream

	file.close()

	end = time.time()
	total = (end-start) % 60

	print("[!] Successfully applied encryption on %s in %d seconds.\n" % (path, total))
	print("Updated size: %d Bytes" % len(FileBytes))
	
	os.system("pause")
	
if __name__ == "__main__":
    main()
