#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>
#include <shellapi.h>

int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	int argc;
	LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);

	if(argc < 3)
		return 0;

	wchar_t *stubExe = argv[1];
	wchar_t *resultFile = argv[2];
	bool is64 = false;

	HANDLE outFile = CreateFile(resultFile, GENERIC_WRITE, 0, 0, TRUNCATE_EXISTING, 0, 0);
	if(outFile == INVALID_HANDLE_VALUE)
		outFile = CreateFile(resultFile, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, 0, 0);

	HANDLE file = CreateFile(stubExe, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if(file == INVALID_HANDLE_VALUE)
		return 0;
	HANDLE map = CreateFileMapping(file, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
	uint8_t *data = reinterpret_cast<uint8_t *>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));

	IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(data);
	//TODO determine 64/32.
#ifdef _WIN64
	IMAGE_NT_HEADERS64 *ntHeader = reinterpret_cast<IMAGE_NT_HEADERS64 *>(data + dosHeader->e_lfanew);
	is64 = true;
#else
	IMAGE_NT_HEADERS32 *ntHeader = reinterpret_cast<IMAGE_NT_HEADERS32 *>(data + dosHeader->e_lfanew);
#endif
	IMAGE_SECTION_HEADER *sectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER *>(
		reinterpret_cast<uint8_t *>(&ntHeader->OptionalHeader) + ntHeader->FileHeader.SizeOfOptionalHeader);

	char buf[255];
	DWORD dwWritten;

	wsprintfA(buf, "#pragma once\n#include <cstdint>\nuint8_t stubData%s[] = {", (is64 ? "64" : "32"));
	WriteFile(outFile, buf, lstrlenA(buf), &dwWritten, 0);
	size_t codeBase;
	for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i ++)
	{
		if(sectionHeaders[i].Characteristics & IMAGE_SCN_CNT_CODE && sectionHeaders[i].SizeOfRawData > 0)
		{
			codeBase = sectionHeaders[i].VirtualAddress;
			buf[0] = 0;
			for(size_t j = 0; j < sectionHeaders[i].SizeOfRawData; j ++)
			{
				size_t k = j;
				for(; k < sectionHeaders[i].SizeOfRawData; k ++)
					if((data + sectionHeaders[i].VirtualAddress)[k] != 0)
						break;
				if(k == sectionHeaders[i].SizeOfRawData)
					break;
				char buf1[255];
				wsprintfA(buf1, "0x%02x,", (data + sectionHeaders[i].VirtualAddress)[j]);
				lstrcatA(buf, buf1);
				if((j + 1) % 10 == 0)
				{
					WriteFile(outFile, buf, lstrlenA(buf), &dwWritten, 0);
					buf[0] = 0;
				}
			}
			WriteFile(outFile, buf, lstrlenA(buf), &dwWritten, 0);
			lstrcpyA(buf, "};\n");
			WriteFile(outFile, buf, lstrlenA(buf), &dwWritten, 0);
		}
	}

	uint32_t exportEntry = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	IMAGE_EXPORT_DIRECTORY *directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(data + exportEntry);

	uint32_t *addressOfFunctions = reinterpret_cast<uint32_t *>(data + directory->AddressOfFunctions);
	uint32_t *addressOfNames = reinterpret_cast<uint32_t *>(data + directory->AddressOfNames);
	uint16_t *ordinals = reinterpret_cast<uint16_t *>(data + directory->AddressOfNameOrdinals);

	for(size_t i = 0; i < directory->NumberOfFunctions; i ++)
	{
		if(addressOfNames[i])
		{
			const char *name = reinterpret_cast<const char *>(data + addressOfNames[i]);
			uint16_t ordinal = ordinals[i];
			size_t address = addressOfFunctions[ordinal];

			char newName[255];
			lstrcpyA(newName, name);
			if(name[0] == '_')
			{
				lstrcpyA(newName, name + 1);
				strstr(newName, "@")[0] = 0;
			}
			wsprintfA(buf, "%s %sAddr%s = 0x%x;\n", (is64 ? "uint64_t" : "uint32_t"), newName, (is64 ? "64" : "32"), address - codeBase);
			WriteFile(outFile, buf, lstrlenA(buf), &dwWritten, 0);
		}
	}
	CloseHandle(outFile);
	UnmapViewOfFile(data);
	CloseHandle(map);
	CloseHandle(file);

	return 0;
}