#include "config/config.hpp"
#include "logger/exception_handler.hpp"
#include "paths/paths.hpp"
#include "threads/thread_pool.hpp"
#include "threads/util.hpp"

#include <DbgHelp.h>
#include <PDB.h>
#include <PDB_DBIStream.h>
#include <PDB_ImageSectionStream.h>
#include <PDB_InfoStream.h>
#include <PDB_RawFile.h>
#include <PDB_TPIStream.h>
#include <regex>

namespace MemoryMappedFile
{
	struct Handle
	{
#ifdef _WIN32
		void *file;
		void *fileMapping;
#else
		int file;
#endif
		void *baseAddress;
		size_t len;
	};

	Handle Open(const char *path);
	void Close(Handle &handle);
} // namespace MemoryMappedFile

MemoryMappedFile::Handle MemoryMappedFile::Open(const char *path)
{
#ifdef _WIN32
	void *file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, nullptr);

	if (file == INVALID_HANDLE_VALUE)
	{
		return Handle{INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, nullptr, 0};
	}

	void *fileMapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);

	if (fileMapping == nullptr)
	{
		CloseHandle(file);

		return Handle{INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, nullptr, 0};
	}

	void *baseAddress = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);

	if (baseAddress == nullptr)
	{
		CloseHandle(fileMapping);
		CloseHandle(file);

		return Handle{INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, nullptr, 0};
	}

	BY_HANDLE_FILE_INFORMATION fileInformation;
	const bool getInformationResult = GetFileInformationByHandle(file, &fileInformation);
	if (!getInformationResult)
	{
		UnmapViewOfFile(baseAddress);
		CloseHandle(fileMapping);
		CloseHandle(file);

		return Handle{INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, nullptr, 0};
	}

	const size_t fileSizeHighBytes = static_cast<size_t>(fileInformation.nFileSizeHigh) << 32;
	const size_t fileSizeLowBytes  = fileInformation.nFileSizeLow;
	const size_t fileSize          = fileSizeHighBytes | fileSizeLowBytes;
	return Handle{file, fileMapping, baseAddress, fileSize};
#else
	struct stat fileSb;

	int file = open(path, O_RDONLY);

	if (file == INVALID_HANDLE_VALUE)
	{
		return Handle{INVALID_HANDLE_VALUE, nullptr, 0};
	}

	if (fstat(file, &fileSb) == -1)
	{
		close(file);

		return Handle{INVALID_HANDLE_VALUE, nullptr, 0};
	}

	void *baseAddress = mmap(nullptr, fileSb.st_size, PROT_READ, MAP_PRIVATE, file, 0);

	if (baseAddress == MAP_FAILED)
	{
		close(file);

		return Handle{INVALID_HANDLE_VALUE, nullptr, 0};
	}

	return Handle{file, baseAddress, static_cast<size_t>(fileSb.st_size)};
#endif
}

void MemoryMappedFile::Close(Handle &handle)
{
#ifdef _WIN32
	UnmapViewOfFile(handle.baseAddress);
	CloseHandle(handle.fileMapping);
	CloseHandle(handle.file);

	handle.file        = nullptr;
	handle.fileMapping = nullptr;
#else
	munmap(handle.baseAddress, handle.len);
	close(handle.file);

	handle.file = 0;
#endif

	handle.baseAddress = nullptr;
}

PDB_NO_DISCARD static bool IsError(PDB::ErrorCode errorCode)
{
	switch (errorCode)
	{
	case PDB::ErrorCode::Success: return false;

	case PDB::ErrorCode::InvalidSuperBlock: LOGF(ERROR, "Invalid Superblock"); return true;

	case PDB::ErrorCode::InvalidFreeBlockMap: LOGF(ERROR, "Invalid free block map"); return true;

	case PDB::ErrorCode::InvalidStream: LOGF(ERROR, "Invalid stream"); return true;

	case PDB::ErrorCode::InvalidSignature: LOGF(ERROR, "Invalid stream signature"); return true;

	case PDB::ErrorCode::InvalidStreamIndex: LOGF(ERROR, "Invalid stream index"); return true;

	case PDB::ErrorCode::UnknownVersion: LOGF(ERROR, "Unknown version"); return true;
	}

	// only ErrorCode::Success means there wasn't an error, so all other paths have to assume there was an error
	return true;
}

PDB_NO_DISCARD static bool HasValidDBIStreams(const PDB::RawFile &rawPdbFile, const PDB::DBIStream &dbiStream)
{
	// check whether the DBI stream offers all sub-streams we need
	if (IsError(dbiStream.HasValidSymbolRecordStream(rawPdbFile)))
	{
		return false;
	}

	if (IsError(dbiStream.HasValidPublicSymbolStream(rawPdbFile)))
	{
		return false;
	}

	if (IsError(dbiStream.HasValidGlobalSymbolStream(rawPdbFile)))
	{
		return false;
	}

	if (IsError(dbiStream.HasValidSectionContributionStream(rawPdbFile)))
	{
		return false;
	}

	if (IsError(dbiStream.HasValidImageSectionStream(rawPdbFile)))
	{
		return false;
	}

	return true;
}

struct symbol_entry_t
{
	std::string name;
	uint32_t rva;
};

std::vector<symbol_entry_t> g_symbols;

static void read_pdb(std::filesystem::path pdb_path)
{
	// try to open the PDB file and check whether all the data we need is available
	MemoryMappedFile::Handle pdbFile = MemoryMappedFile::Open((char *)pdb_path.u8string().c_str());
	if (!pdbFile.baseAddress)
	{
		LOGF(ERROR, "Cannot memory-map file {}", (char *)pdb_path.u8string().c_str());
	}

	if (IsError(PDB::ValidateFile(pdbFile.baseAddress, pdbFile.len)))
	{
		MemoryMappedFile::Close(pdbFile);
	}

	const PDB::RawFile rawPdbFile = PDB::CreateRawFile(pdbFile.baseAddress);
	if (IsError(PDB::HasValidDBIStream(rawPdbFile)))
	{
		MemoryMappedFile::Close(pdbFile);
	}

	const PDB::InfoStream infoStream(rawPdbFile);
	if (infoStream.UsesDebugFastLink())
	{
		LOGF(ERROR, "PDB was linked using unsupported option /DEBUG:FASTLINK");

		MemoryMappedFile::Close(pdbFile);
	}

	const auto h = infoStream.GetHeader();
	LOGF(INFO,
	     std::format("Version {}, signature {}, age {}, GUID "
	                 "{:08x}-{:04x}-{:04x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
	                 static_cast<uint32_t>(h->version),
	                 h->signature,
	                 h->age,
	                 h->guid.Data1,
	                 h->guid.Data2,
	                 h->guid.Data3,
	                 h->guid.Data4[0],
	                 h->guid.Data4[1],
	                 h->guid.Data4[2],
	                 h->guid.Data4[3],
	                 h->guid.Data4[4],
	                 h->guid.Data4[5],
	                 h->guid.Data4[6],
	                 h->guid.Data4[7]));


	const PDB::DBIStream dbiStream = PDB::CreateDBIStream(rawPdbFile);
	if (!HasValidDBIStreams(rawPdbFile, dbiStream))
	{
		MemoryMappedFile::Close(pdbFile);
	}

	const PDB::TPIStream tpiStream = PDB::CreateTPIStream(rawPdbFile);
	if (PDB::HasValidTPIStream(rawPdbFile) != PDB::ErrorCode::Success)
	{
		MemoryMappedFile::Close(pdbFile);
	}

	// in order to keep the example easy to understand, we load the PDB data serially.
	// note that this can be improved a lot by reading streams concurrently.

	// prepare the image section stream first. it is needed for converting section + offset into an RVA
	const PDB::ImageSectionStream imageSectionStream = dbiStream.CreateImageSectionStream(rawPdbFile);


	const PDB::ModuleInfoStream moduleInfoStream = dbiStream.CreateModuleInfoStream(rawPdbFile);


	const PDB::CoalescedMSFStream symbolRecordStream = dbiStream.CreateSymbolRecordStream(rawPdbFile);

	// read global symbols
	const PDB::GlobalSymbolStream globalSymbolStream = dbiStream.CreateGlobalSymbolStream(rawPdbFile);

	const PDB::ArrayView<PDB::HashRecord> hashRecords = globalSymbolStream.GetRecords();
	const size_t count                                = hashRecords.GetLength();

	for (const PDB::HashRecord &hashRecord : hashRecords)
	{
		const PDB::CodeView::DBI::Record *record = globalSymbolStream.GetRecord(symbolRecordStream, hashRecord);

		const char *name = nullptr;
		uint32_t rva     = 0u;
		if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GDATA32)
		{
			name = record->data.S_GDATA32.name;
			rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GDATA32.section, record->data.S_GDATA32.offset);
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GTHREAD32)
		{
			name = record->data.S_GTHREAD32.name;
			rva =
			    imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GTHREAD32.section, record->data.S_GTHREAD32.offset);
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32)
		{
			name = record->data.S_LDATA32.name;
			rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LDATA32.section, record->data.S_LDATA32.offset);
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LTHREAD32)
		{
			name = record->data.S_LTHREAD32.name;
			rva =
			    imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LTHREAD32.section, record->data.S_LTHREAD32.offset);
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_UDT)
		{
			name = record->data.S_UDT.name;
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_UDT_ST)
		{
			name = record->data.S_UDT_ST.name;
		}

		if (rva == 0u)
		{
			// certain symbols (e.g. control-flow guard symbols) don't have a valid RVA, ignore those
			continue;
		}

		g_symbols.push_back({name, rva});
	}

	// read module symbols
	{
		const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules = moduleInfoStream.GetModules();

		for (const PDB::ModuleInfoStream::Module &module : modules)
		{
			if (!module.HasSymbolStream())
			{
				continue;
			}

			const PDB::ModuleSymbolStream moduleSymbolStream = module.CreateSymbolStream(rawPdbFile);
			moduleSymbolStream.ForEachSymbol(
			    [&imageSectionStream](const PDB::CodeView::DBI::Record *record)
			    //[&symbols, &imageSectionStream](const PDB::CodeView::DBI::Record *record)
			    {
				    const char *name = nullptr;
				    uint32_t rva     = 0u;
				    if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_THUNK32)
				    {
					    if (record->data.S_THUNK32.thunk == PDB::CodeView::DBI::ThunkOrdinal::TrampolineIncremental)
					    {
						    // we have never seen incremental linking thunks stored inside a S_THUNK32 symbol, but better be safe than sorry
						    name = "ILT";
						    rva  = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_THUNK32.section,
                                                                               record->data.S_THUNK32.offset);
					    }
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_TRAMPOLINE)
				    {
					    // incremental linking thunks are stored in the linker module
					    name = "ILT";
					    rva  = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_TRAMPOLINE.thunkSection,
                                                                           record->data.S_TRAMPOLINE.thunkOffset);
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_BLOCK32)
				    {
					    // blocks never store a name and are only stored for indicating whether other symbols are children of this block
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LABEL32)
				    {
					    // labels don't have a name
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32)
				    {
					    name = record->data.S_LPROC32.name;
					    rva  = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LPROC32.section,
                                                                           record->data.S_LPROC32.offset);
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32)
				    {
					    name = record->data.S_GPROC32.name;
					    rva  = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GPROC32.section,
                                                                           record->data.S_GPROC32.offset);
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID)
				    {
					    name = record->data.S_LPROC32_ID.name;
					    rva  = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LPROC32_ID.section,
                                                                           record->data.S_LPROC32_ID.offset);
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID)
				    {
					    name = record->data.S_GPROC32_ID.name;
					    rva  = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GPROC32_ID.section,
                                                                           record->data.S_GPROC32_ID.offset);
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_REGREL32)
				    {
					    name = record->data.S_REGREL32.name;
					    // You can only get the address while running the program by checking the register value and adding the offset
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32)
				    {
					    name = record->data.S_LDATA32.name;
					    rva  = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LDATA32.section,
                                                                           record->data.S_LDATA32.offset);
				    }
				    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LTHREAD32)
				    {
					    name = record->data.S_LTHREAD32.name;
					    rva  = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LTHREAD32.section,
                                                                           record->data.S_LTHREAD32.offset);
				    }

				    if (rva == 0u)
				    {
					    // certain symbols (e.g. control-flow guard symbols) don't have a valid RVA, ignore those
					    return;
				    }

				    g_symbols.push_back({name, rva});
			    });
		}
	}

	MemoryMappedFile::Close(pdbFile);
}

int main(int argc, char *argv[])
{
	using namespace big;

	const auto exception_handling = new exception_handler(false, nullptr);

	if (argc == 1) // If no arguments are provided, display help text
	{
		std::cout << "Usage: " << argv[0] << " -pdb <pdb_path> -log <log_path> -dll <dll_name>\n\n";
		std::cout << "Description: This program reads a PDB file and a log file to match RVA offsets with symbols.\n\n";
		std::cout << "To get the matching PDB file:\n";
		std::cout << "1. Open the LogOutput.log file.\n";
		std::cout << "2. Retrieve the Git hash at the top of the log.\n";
		std::cout
		    << "3. Download the binary.zip from the corresponding GitHub Action output associated with the Git hash.\n";
		std::cout << "Example usage: " << argv[0] << " -pdb \"C:/Users/Quentin/Desktop/d3d12.pdb\" -log \"C:/Users/Quentin/Desktop/LogOutput.log\" -dll d3d12.dll\n";
		return 0;
	}

	//std::string pdb_path = "C:/Users/Quentin/Desktop/d3d12.pdb";
	std::string pdb_path;
	for (int i = 1; i < argc; ++i) // Start from 1 to skip program name
	{
		if (std::string(argv[i]) == "-pdb" && i + 1 < argc)
		{
			pdb_path = argv[i + 1];
			break;
		}
	}

	if (pdb_path.empty())
	{
		std::cerr << "pdb path not provided. Example: -pdb \"C:/Users/Quentin/Desktop/d3d12.pdb\"\n";

		return 1;
	}

	if (!std::filesystem::exists(pdb_path))
	{
		std::cerr << "PDB file does not exist: " << pdb_path << "\n";
		return 1;
	}

	//std::string log_path = "C:/Users/Quentin/Desktop/LogOutput.log";
	std::string log_path;
	for (int i = 1; i < argc; ++i) // Start from 1 to skip program name
	{
		if (std::string(argv[i]) == "-log" && i + 1 < argc)
		{
			log_path = argv[i + 1];
			break;
		}
	}

	if (log_path.empty())
	{
		std::cerr << "log path not provided. Example: -log \"C:/Users/Quentin/Desktop/LogOutput.log\"\n";

		return 1;
	}

	std::ifstream log_file(log_path);
	if (!log_file)
	{
		std::cerr << "Failed to open log file!\n";
		return 1;
	}

	//std::string dll_name = "d3d12.dll";
	std::string dll_name;
	for (int i = 1; i < argc; ++i) // Start from 1 to skip program name
	{
		if (std::string(argv[i]) == "-dll" && i + 1 < argc)
		{
			dll_name = argv[i + 1];
			break;
		}
	}

	if (dll_name.empty())
	{
		std::cerr << "dll name not provided. Example: -dll d3d12.dll\n";

		return 1;
	}

	read_pdb(pdb_path.c_str());

	// sort the symbols by rva
	std::sort(g_symbols.begin(),
	          g_symbols.end(),
	          [](const symbol_entry_t &a, const symbol_entry_t &b)
	          {
		          return a.rva < b.rva;
	          });

	std::regex dll_offset_regex(dll_name + R"(\+0x([0-9A-Fa-f]+))");
	std::string line;
	while (std::getline(log_file, line))
	{
		std::smatch match;
		if (std::regex_search(line, match, dll_offset_regex))
		{
			uint32_t offset = std::stoul(match[1].str(), nullptr, 16);

			// Find the nearest symbol
			auto it = std::upper_bound(g_symbols.begin(),
			                           g_symbols.end(),
			                           offset,
			                           [](uint32_t val, const symbol_entry_t &sym)
			                           {
				                           return val < sym.rva;
			                           });
			if (it != g_symbols.begin())
			{
				--it;
			}

			std::cout << "0x" << std::hex << offset << " -> " << it->name << " (RVA: 0x" << it->rva << ")\n";
		}
	}

	return 0;
}
