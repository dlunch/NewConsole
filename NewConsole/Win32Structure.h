#include <cstdint>
//win32 structures

#ifndef _WINNT_
typedef union _LARGE_INTEGER
{
	struct
	{
		uint32_t LowPart;
		uint32_t HighPart;
	};
	struct
	{
		uint32_t LowPart;
		uint32_t HighPart;
	} u;
	uint64_t QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _LIST_ENTRY
{
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _NT_TIB
{
	struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
	void *StackBase;
	void *StackLimit;
	void *SubSystemTib;
#if defined(_MSC_EXTENSIONS)
	union
	{
		void *FiberData;
		uint32_t Version;
	};
#else
	void *FiberData;
#endif
	void *ArbitraryUserPointer;
	struct _NT_TIB *Self;
} NT_TIB;
typedef NT_TIB *PNT_TIB;

#pragma pack(push, 2)
typedef struct _IMAGE_DOS_HEADER
{      // DOS .EXE header
	uint16_t   e_magic;                     // Magic number
	uint16_t   e_cblp;                      // Bytes on last page of file
	uint16_t   e_cp;                        // Pages in file
	uint16_t   e_crlc;                      // Relocations
	uint16_t   e_cparhdr;                   // Size of header in paragraphs
	uint16_t   e_minalloc;                  // Minimum extra paragraphs needed
	uint16_t   e_maxalloc;                  // Maximum extra paragraphs needed
	uint16_t   e_ss;                        // Initial (relative) SS value
	uint16_t   e_sp;                        // Initial SP value
	uint16_t   e_csum;                      // Checksum
	uint16_t   e_ip;                        // Initial IP value
	uint16_t   e_cs;                        // Initial (relative) CS value
	uint16_t   e_lfarlc;                    // File address of relocation table
	uint16_t   e_ovno;                      // Overlay number
	uint16_t   e_res[4];                    // Reserved words
	uint16_t   e_oemid;                     // OEM identifier (for e_oeminfo)
	uint16_t   e_oeminfo;                   // OEM information; e_oemid specific
	uint16_t   e_res2[10];                  // Reserved words
	uint32_t   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
#pragma pack(pop)

typedef struct _IMAGE_FILE_HEADER
{
	uint16_t    Machine;
	uint16_t    NumberOfSections;
	uint32_t   TimeDateStamp;
	uint32_t   PointerToSymbolTable;
	uint32_t   NumberOfSymbols;
	uint16_t    SizeOfOptionalHeader;
	uint16_t    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20

#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved externel references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Agressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000  // System File.
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB             0x01c2  // ARM Thumb/Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_ARMNT             0x01c4  // ARM Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI Byte Code
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R little-endian
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY
{
	uint32_t   VirtualAddress;
	uint32_t   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

//
// Optional header format.
//

typedef struct _IMAGE_OPTIONAL_HEADER
{
	//
	// Standard fields.
	//

	uint16_t    Magic;
	uint8_t    MajorLinkerVersion;
	uint8_t    MinorLinkerVersion;
	uint32_t   SizeOfCode;
	uint32_t   SizeOfInitializedData;
	uint32_t   SizeOfUninitializedData;
	uint32_t   AddressOfEntryPoint;
	uint32_t   BaseOfCode;
	uint32_t   BaseOfData;

	//
	// NT additional fields.
	//

	uint32_t   ImageBase;
	uint32_t   SectionAlignment;
	uint32_t   FileAlignment;
	uint16_t    MajorOperatingSystemVersion;
	uint16_t    MinorOperatingSystemVersion;
	uint16_t    MajorImageVersion;
	uint16_t    MinorImageVersion;
	uint16_t    MajorSubsystemVersion;
	uint16_t    MinorSubsystemVersion;
	uint32_t   Win32VersionValue;
	uint32_t   SizeOfImage;
	uint32_t   SizeOfHeaders;
	uint32_t   CheckSum;
	uint16_t    Subsystem;
	uint16_t    DllCharacteristics;
	uint32_t   SizeOfStackReserve;
	uint32_t   SizeOfStackCommit;
	uint32_t   SizeOfHeapReserve;
	uint32_t   SizeOfHeapCommit;
	uint32_t   LoaderFlags;
	uint32_t   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;


typedef struct _IMAGE_OPTIONAL_HEADER64
{
	//
	// Standard fields.
	//

	uint16_t    Magic;
	uint8_t    MajorLinkerVersion;
	uint8_t    MinorLinkerVersion;
	uint32_t   SizeOfCode;
	uint32_t   SizeOfInitializedData;
	uint32_t   SizeOfUninitializedData;
	uint32_t   AddressOfEntryPoint;
	uint32_t   BaseOfCode;
	uint64_t   ImageBase;
	uint32_t       SectionAlignment;
	uint32_t       FileAlignment;
	uint16_t        MajorOperatingSystemVersion;
	uint16_t        MinorOperatingSystemVersion;
	uint16_t        MajorImageVersion;
	uint16_t        MinorImageVersion;
	uint16_t        MajorSubsystemVersion;
	uint16_t        MinorSubsystemVersion;
	uint32_t       Win32VersionValue;
	uint32_t       SizeOfImage;
	uint32_t       SizeOfHeaders;
	uint32_t       CheckSum;
	uint16_t        Subsystem;
	uint16_t        DllCharacteristics;
	uint64_t   SizeOfStackReserve;
	uint64_t   SizeOfStackCommit;
	uint64_t   SizeOfHeapReserve;
	uint64_t   SizeOfHeapCommit;
	uint32_t       LoaderFlags;
	uint32_t       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

typedef struct _IMAGE_NT_HEADERS64
{
	uint32_t Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS
{
	uint32_t Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;
#else
typedef IMAGE_NT_HEADERS32                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
#endif
// Subsystem Values

#define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10  //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
#define IMAGE_SUBSYSTEM_EFI_ROM              13
#define IMAGE_SUBSYSTEM_XBOX                 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

// DllCharacteristics Entries

//      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020  // Image can handle a high entropy 64-bit virtual address space.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040     // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080     // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT    0x0100     // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200     // Image understands isolation and doesn't want it
#define IMAGE_DLLCHARACTERISTICS_NO_SEH       0x0400     // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_BIND      0x0800     // Do not bind this image.
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000     // Image should execute in an AppContainer
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER   0x2000     // Driver uses WDM model
//                                            0x4000     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor


//
// Section header format.
//

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER
{
	uint8_t    Name[IMAGE_SIZEOF_SHORT_NAME];
	union
	{
		uint32_t   PhysicalAddress;
		uint32_t   VirtualSize;
	};
	uint32_t   VirtualAddress;
	uint32_t   SizeOfRawData;
	uint32_t   PointerToRawData;
	uint32_t   PointerToRelocations;
	uint32_t   PointerToLinenumbers;
	uint16_t    NumberOfRelocations;
	uint16_t    NumberOfLinenumbers;
	uint32_t   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

//
// Section characteristics.
//
//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  //
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  //
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  //
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  //
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  //
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  //
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  //
// Unused                                    0x00F00000
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.

//
// TLS Characteristic Flags
//
#define IMAGE_SCN_SCALE_INDEX                0x00000001  // Tls index is scaled

typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
	union
	{
		uint32_t   Characteristics;            // 0 for terminating null import descriptor
		uint32_t   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	};
	uint32_t   TimeDateStamp;                  // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	uint32_t   ForwarderChain;                 // -1 if no forwarders
	uint32_t   Name;
	uint32_t   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME
{
	uint16_t    Hint;
	char   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000


typedef struct _IMAGE_BASE_RELOCATION
{
	uint32_t   VirtualAddress;
	uint32_t   SizeOfBlock;
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION * PIMAGE_BASE_RELOCATION;

//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_5    5
#define IMAGE_REL_BASED_RESERVED              6
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_7    7
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_8    8
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_9    9
#define IMAGE_REL_BASED_DIR64                 10

//
// Platform-specific based relocation types.
//

#define IMAGE_REL_BASED_IA64_IMM64            9

#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_MIPS_JMPADDR16        9

#define IMAGE_REL_BASED_ARM_MOV32             5
#define IMAGE_REL_BASED_THUMB_MOV32           7


//
// Export Format
//

typedef struct _IMAGE_EXPORT_DIRECTORY
{
	uint32_t   Characteristics;
	uint32_t   TimeDateStamp;
	uint16_t    MajorVersion;
	uint16_t    MinorVersion;
	uint32_t   Name;
	uint32_t   Base;
	uint32_t   NumberOfFunctions;
	uint32_t   NumberOfNames;
	uint32_t   AddressOfFunctions;     // RVA from base of image
	uint32_t   AddressOfNames;         // RVA from base of image
	uint32_t   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
#endif

typedef struct _UNICODE_STRING
{
	uint16_t Length;
	uint16_t MaximumLength;
	wchar_t *Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _ANSI_STRING
{
	uint16_t Length;
	uint16_t MaximumLength;
	char *  Buffer;
} ANSI_STRING;
typedef ANSI_STRING *PANSI_STRING;
typedef const ANSI_STRING *PCANSI_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	uint32_t           Length;
	void *          RootDirectory;
	PUNICODE_STRING ObjectName;
	uint32_t           Attributes;
	void *           SecurityDescriptor;
	void *           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		uint32_t Status;
		void *    Pointer;
	};
	uint32_t *Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _LDR_MODULE
{

	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	void * BaseAddress;
	void * EntryPoint;
	uint32_t SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	uint32_t Flags;
	int16_t LoadCount;
	int16_t TlsIndex;
	LIST_ENTRY HashTableEntry;
	uint32_t TimeDateStamp;

} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{

	uint32_t Length;
	int8_t Initialized;
	void * SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;

} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{

	uint16_t Flags;
	uint16_t Length;
	uint32_t TimeStamp;
	UNICODE_STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{

	uint32_t MaximumLength;
	uint32_t Length;
	uint32_t Flags;
	uint32_t DebugFlags;
	void * ConsoleHandle;
	uint32_t ConsoleFlags;
	void * StdInputHandle;
	void * StdOutputHandle;
	void * StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	void * CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	void * Environment;
	uint32_t StartingPositionLeft;
	uint32_t StartingPositionTop;
	uint32_t Width;
	uint32_t Height;
	uint32_t CharWidth;
	uint32_t CharHeight;
	uint32_t ConsoleTextAttributes;
	uint32_t WindowFlags;
	uint32_t ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopName;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];


} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void(*PPEBLOCKROUTINE)(
	void * PebLock
	);

typedef struct _PEB32
{
	int8_t InheritedAddressSpace;
	int8_t ReadImageFileExecOptions;
	int8_t BeingDebugged;
	int8_t Spare;
	uint32_t Mutant;
	uint32_t ImageBaseAddress;
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	uint32_t SubSystemData;
	uint32_t ProcessHeap;
	uint32_t FastPebLock;
	PPEBLOCKROUTINE FastPebLockRoutine;
	PPEBLOCKROUTINE FastPebUnlockRoutine;
	uint32_t EnvironmentUpdateCount;
	uint32_t KernelCallbackTable;
	uint32_t EventLogSection;
	uint32_t EventLog;
	uint8_t *ApiSet;
	uint32_t TlsExpansionCounter;
	uint32_t TlsBitmap;
	uint32_t TlsBitmapBits[0x2];
	uint32_t ReadOnlySharedMemoryBase;
	uint32_t ReadOnlySharedMemoryHeap;
	uint32_t ReadOnlyStaticServerData;
	uint32_t AnsiCodePageData;
	uint32_t OemCodePageData;
	uint32_t UnicodeCaseTableData;
	uint32_t NumberOfProcessors;
	uint32_t NtGlobalFlag;
	uint8_t Spare2[0x4];
	LARGE_INTEGER CriticalSectionTimeout;
	uint32_t HeapSegmentReserve;
	uint32_t HeapSegmentCommit;
	uint32_t HeapDeCommitTotalFreeThreshold;
	uint32_t HeapDeCommitFreeBlockThreshold;
	uint32_t NumberOfHeaps;
	uint32_t MaximumNumberOfHeaps;
	uint32_t *ProcessHeaps;
	uint32_t GdiSharedHandleTable;
	uint32_t ProcessStarterHelper;
	uint32_t GdiDCAttributeList;
	uint32_t LoaderLock;
	uint32_t OSMajorVersion;
	uint32_t OSMinorVersion;
	uint32_t OSBuildNumber;
	uint32_t OSPlatformId;
	uint32_t ImageSubSystem;
	uint32_t ImageSubSystemMajorVersion;
	uint32_t ImageSubSystemMinorVersion;
	uint32_t GdiHandleBuffer[0x22];
	uint32_t PostProcessInitRoutine;
	uint32_t TlsExpansionBitmap;
	uint8_t TlsExpansionBitmapBits[0x80];
	uint32_t SessionId;

} PEB32, *PPEB32;

typedef struct _PEB64
{
	int8_t InheritedAddressSpace;
	int8_t ReadImageFileExecOptions;
	int8_t BeingDebugged;
	int8_t Spare;
	uint64_t Mutant;
	uint64_t ImageBaseAddress;
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	uint64_t SubSystemData;
	uint64_t ProcessHeap;
	uint64_t FastPebLock;
	PPEBLOCKROUTINE FastPebLockRoutine;
	PPEBLOCKROUTINE FastPebUnlockRoutine;
	uint32_t EnvironmentUpdateCount;
	uint64_t KernelCallbackTable;
	uint64_t EventLogSection;
	uint64_t EventLog;
	uint8_t *ApiSet;
	uint32_t TlsExpansionCounter;
	uint64_t TlsBitmap;
	uint32_t TlsBitmapBits[0x2];
	uint64_t ReadOnlySharedMemoryBase;
	uint64_t ReadOnlySharedMemoryHeap;
	uint64_t ReadOnlyStaticServerData;
	uint64_t AnsiCodePageData;
	uint64_t OemCodePageData;
	uint64_t UnicodeCaseTableData;
	uint32_t NumberOfProcessors;
	uint32_t NtGlobalFlag;
	uint8_t Spare2[0x4];
	LARGE_INTEGER CriticalSectionTimeout;
	uint32_t HeapSegmentReserve;
	uint32_t HeapSegmentCommit;
	uint32_t HeapDeCommitTotalFreeThreshold;
	uint32_t HeapDeCommitFreeBlockThreshold;
	uint32_t NumberOfHeaps;
	uint32_t MaximumNumberOfHeaps;
	uint64_t *ProcessHeaps;
	uint64_t GdiSharedHandleTable;
	uint64_t ProcessStarterHelper;
	uint64_t GdiDCAttributeList;
	uint64_t LoaderLock;
	uint32_t OSMajorVersion;
	uint32_t OSMinorVersion;
	uint32_t OSBuildNumber;
	uint32_t OSPlatformId;
	uint32_t ImageSubSystem;
	uint32_t ImageSubSystemMajorVersion;
	uint32_t ImageSubSystemMinorVersion;
	uint32_t GdiHandleBuffer[0x22];
	uint32_t PostProcessInitRoutine;
	uint32_t TlsExpansionBitmap;
	uint8_t TlsExpansionBitmapBits[0x80];
	uint32_t SessionId;

} PEB64, *PPEB64;

typedef struct _PROCESS_BASIC_INFORMATION 
{
    void *Reserved1;
    void *PebBaseAddress;
    void *Reserved2[2];
    unsigned long *UniqueProcessId;
    void *Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _CLIENT_ID
{
	void *UniqueProcess;
	void *UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _TEB
{
	NT_TIB Tib;
	void * EnvironmentPointer;
	CLIENT_ID 	ClientId;

	//omitted unused properties.
} TEB, *PTEB;

#define DELETE                           (0x00010000L)
#define READ_CONTROL                     (0x00020000L)
#define WRITE_DAC                        (0x00040000L)
#define WRITE_OWNER                      (0x00080000L)
#define SYNCHRONIZE                      (0x00100000L)

#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)

#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL)

#define STANDARD_RIGHTS_ALL              (0x001F0000L)

#define SPECIFIC_RIGHTS_ALL              (0x0000FFFFL)


#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe


#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ     |\
	FILE_READ_DATA           |\
	FILE_READ_ATTRIBUTES     |\
	FILE_READ_EA             |\
	SYNCHRONIZE)


#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE    |\
	FILE_WRITE_DATA          |\
	FILE_WRITE_ATTRIBUTES    |\
	FILE_WRITE_EA            |\
	FILE_APPEND_DATA         |\
	SYNCHRONIZE)


#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE  |\
	FILE_READ_ATTRIBUTES     |\
	FILE_EXECUTE             |\
	SYNCHRONIZE)

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

#define PAGE_NOACCESS          0x01     
#define PAGE_READONLY          0x02     
#define PAGE_READWRITE         0x04     
#define PAGE_WRITECOPY         0x08     
#define PAGE_EXECUTE           0x10     
#define PAGE_EXECUTE_READ      0x20     
#define PAGE_EXECUTE_READWRITE 0x40     
#define PAGE_EXECUTE_WRITECOPY 0x80   

#define MEM_COMMIT                  0x1000      
#define MEM_RESERVE                 0x2000      
#define MEM_DECOMMIT                0x4000      
#define MEM_RELEASE                 0x8000      

#ifdef _WIN64
#define NtCurrentProcess() reinterpret_cast<void *>(0xffffffffffffffffUL)
#define NtCurrentThread() reinterpret_cast<void *>(0xfffffffffffffffeUL)
#elif defined(_WIN32)
#define NtCurrentProcess() reinterpret_cast<void *>(0xffffffffL)
#define NtCurrentThread() reinterpret_cast<void *>(0xfffffffeL)
#endif

typedef struct _FILE_FS_DEVICE_INFORMATION {
  uint32_t DeviceType;
  uint32_t Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

#define 	DUPLICATE_CLOSE_SOURCE   0x00000001
#define 	DUPLICATE_SAME_ACCESS   0x00000002
#define 	DUPLICATE_SAME_ATTRIBUTES   0x00000004

#define FILE_SUPERSEDED                         0x00000000
#define FILE_OPENED                             0x00000001
#define FILE_CREATED                            0x00000002
#define FILE_OVERWRITTEN                        0x00000003
#define FILE_EXISTS                             0x00000004
#define FILE_DOES_NOT_EXIST                     0x00000005

typedef struct _LPC_MESSAGE {

	uint16_t DataLength; 
	uint16_t Length; 
	uint16_t MessageType; 
	uint16_t DataInfoOffset; 
	CLIENT_ID ClientId; 
	uint32_t MessageId; 
	size_t CallbackId;

} LPC_MESSAGE, *PLPC_MESSAGE;

typedef struct _LPC_SECTION_OWNER_MEMORY {

	uint32_t Length; 
	void *SectionHandle; 
	uint32_t OffsetInSection; 
	uint32_t ViewSize; 
	void *ViewBase; 
	void *OtherSideViewBase;

} LPC_SECTION_OWNER_MEMORY, *PLPC_SECTION_OWNER_MEMORY;

typedef struct _LPC_SECTION_MEMORY {

	uint32_t Length; 
	uint32_t ViewSize; 
	void *ViewBase;

} LPC_SECTION_MEMORY, *PLPC_SECTION_MEMORY;
