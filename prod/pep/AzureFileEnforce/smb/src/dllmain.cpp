// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include <boost/log/core.hpp>
#include <boost/log/attributes.hpp> 
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sinks/debug_output_backend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/console.hpp> // boost::log::add_console_log
#include <boost/log/utility/setup/file.hpp> // boost::log::add_file_log
#include <boost/filesystem.hpp>
#include <boost/log/sinks/async_frontend.hpp>
#include <boost/program_options.hpp>
#include <Shlobj.h>
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

HMODULE g_hThisModule;

namespace sources = boost::log::sources;
namespace sinks = boost::log::sinks;

#define LOG_CONF_NAME "log.conf"
#define LOG_CONF_LOG_SEVERITY "LogSeverity"
#define LOG_CONF_MAX_FILES "MaxFiles"
#define LOG_CONF_MIN_FREE_SPACE "MinFreeSpace"
#define LOG_CONF_ROTATION_SIZE "RotationSize"
#define LOG_CONF_OUTPUT_PATH "OutputPath"

// Declare attribute keywords
BOOST_LOG_ATTRIBUTE_KEYWORD(severity, "Severity", boost::log::trivial::severity_level)
BOOST_LOG_ATTRIBUTE_KEYWORD(timestamp, "TimeStamp", boost::posix_time::ptime)

/**
FOLDERID_ProgramData: %ALLUSERSPROFILE% (%ProgramData%, %SystemDrive%\ProgramData).
Here, %ProgramData%\NextLabs\EMSMB\SMBProxy\log
@see https://docs.microsoft.com/en-us/windows/desktop/shell/knownfolderid#FOLDERID_PROGRAMDATA
*/
std::wstring GetProgramDataFolder()
{
	wchar_t* pwszFolder = NULL;
	HRESULT hr = ::SHGetKnownFolderPath(FOLDERID_ProgramData, 0, NULL, &pwszFolder);
	if (SUCCEEDED(hr) && (NULL != pwszFolder))
	{
		std::wstring strFolder = pwszFolder;
		CoTaskMemFree(pwszFolder);


		//create sub folder
		strFolder += L"\\NextLabs\\EMSMB\\SMBProxy";

		int nRes = SHCreateDirectoryExW(NULL, strFolder.c_str(), NULL);
		if ((nRes != ERROR_SUCCESS) &&
			(nRes != ERROR_ALREADY_EXISTS) &&
			(nRes != ERROR_FILE_EXISTS))
		{
			strFolder = L"";
		}


		return strFolder;
	}
	return L"";
}

// Returns the expanded path of %ProgramData%\NextLabs\EMSMB\SMBProxy\log\ with a tailing backslash.
std::wstring GetLogPath()
{
	std::wstring strAppDataFolder = GetProgramDataFolder();

	::OutputDebugStringW(strAppDataFolder.c_str());
	if (!strAppDataFolder.empty())
	{
		//std::wstring strLogFile = strAppDataFolder + L"\\log";
		//CreateDirectoryW(strLogFile.c_str(), NULL);
		//strLogFile += L"\\";
		//return strLogFile;
		return strAppDataFolder + L"\\";
	}

	return L"";
}

/**
* Usage:
*	BOOST_LOG_TRIVIAL(trace) << "A trace severity message";
*	BOOST_LOG_TRIVIAL(debug) << "A debug severity message";
*	BOOST_LOG_TRIVIAL(info) << "An informational severity message";
*	BOOST_LOG_TRIVIAL(warning) << "A warning severity message";
*	BOOST_LOG_TRIVIAL(error) << "An error severity message";
*	BOOST_LOG_TRIVIAL(fatal) << "A fatal severity message";
* Note:
* # Configuring and building the library
* The library has a separately compiled part which should be built as described in the Getting Started guide.
* One thing should be noted, though. If your application consists of more than one module (e.g. an exe and
* one or several dll's) that use Boost.Log, the library must be built as a shared object. If you have a single
* executable or a single module that works with Boost.Log, you may build the library as a static library.
* @see https://www.boost.org/doc/libs/1_67_0/libs/log/doc/html/log/installation/config.html
* @see https://www.boost.org/doc/libs/1_67_0/libs/log/doc/html/log/tutorial.html#log.tutorial.trivial
*/
void init_logging()
{
	boost::shared_ptr< boost::log::core > core = boost::log::core::get();

	core->set_filter(boost::log::trivial::severity >= boost::log::trivial::trace);
	boost::log::add_common_attributes(); // Add TimeStamp, ThreadID so that we can use those attributes in Format.
										 // core->add_global_attribute("ThreadID", boost::log::attributes::current_thread_id());

										 /* log formatter: [TimeStamp] [ThreadId] [Severity Level] [Scope] Log message */
										 // #include <boost/log/support/date_time.hpp>
										 // https://www.boost.org/doc/libs/1_67_0/doc/html/date_time/date_time_io.html#date_time.format_flags
	auto fmtTimeStamp = boost::log::expressions::format_date_time(timestamp, "%Y-%m-%d %H:%M:%S.%f");
	auto fmtThreadId = boost::log::expressions::attr<boost::log::attributes::current_thread_id::value_type>("ThreadID");
	auto fmtSeverity = boost::log::expressions::attr<boost::log::trivial::severity_level>(severity.get_name());
	//auto fmtScope = boost::log::expressions::format_named_scope("Scope",
	//	boost::log::keywords::format = "%n(%f:%l)",
	//	boost::log::keywords::iteration = boost::log::expressions::reverse,
	//	boost::log::keywords::depth = 2);
	boost::log::formatter logFmt = boost::log::expressions::format("%1%|%2%|%3%|%4%")
		% fmtTimeStamp % fmtThreadId % fmtSeverity % boost::log::expressions::smessage;

	/* console sink #include <boost/log/utility/setup/console.hpp> */
	//auto consoleSink = boost::log::add_console_log(std::clog);
	//consoleSink->set_formatter(logFmt);
	//core->add_sink(consoleSink);

	/* fs sink #include <boost/log/utility/setup/file.hpp> */

	/*auto fsSink = IsDebuggerPresent() ? boost::log::add_file_log("smb_debug_%N.log") : boost::log::add_file_log(
	boost::log::keywords::file_name = "smb_%Y-%m-%d_%H-%M-%S.%N.log",
	boost::log::keywords::rotation_size = 10 * 1024 * 1024,
	boost::log::keywords::min_free_space = 30 * 1024 * 1024,
	boost::log::keywords::open_mode = std::ios_base::app);
	fsSink->set_formatter(logFmt);
	fsSink->locked_backend()->auto_flush(true);*/
	{
		typedef sinks::asynchronous_sink< sinks::text_file_backend > sink_t;

		//char szPath[MAX_PATH] = { 0 }, szExePath[MAX_PATH] = { 0 };
		////If this parameter is NULL, GetModuleFileName retrieves the path of the executable file (NOT dll) of the current process.
		//if (GetModuleFileNameA(NULL, szExePath, _countof(szExePath)))
		//{
		//	PathRemoveFileSpecA(szExePath);
		//}
		std::wstring wsLogDir = GetLogPath();
		typedef sinks::text_file_backend backend_t;
		boost::shared_ptr< sinks::text_file_backend > backend =
			boost::make_shared< sinks::text_file_backend >(
				boost::log::keywords::file_name = wsLogDir + L"smb_%Y-%m-%d_%H-%M-%S.%N.log",//PathCombineA(szPath, szExePath, "log\\smb_%Y-%m-%d_%H-%M-%S.%N.log"),
				boost::log::keywords::rotation_size = 1 * 1024 * 1024,
				boost::log::keywords::min_free_space = 30 * 1024 * 1024,
				boost::log::keywords::max_files = 10,
				boost::log::keywords::open_mode = std::ios_base::app);
		boost::shared_ptr< sink_t > fsSink(new sink_t(backend));
		fsSink->set_formatter(logFmt);

		auto fsBackend = fsSink->locked_backend();

		fsBackend->auto_flush(true);

		// Set header and footer writing functors #include <boost/lambda/lambda.hpp>
		//namespace bll = boost::lambda;
		//fsSink->locked_backend()->set_open_handler( bll::_1 << "<?xml version=\"1.0\"?>\n<log>\n" );
		//fsSink->locked_backend()->set_close_handler( bll::_1 << "</log>\n" );
		//auto openHandler = [](backend_t::stream_type &stream) {
		//	stream << "set_open_handler: GetCurrentThreadId=" << GetCurrentThreadId() << ", boost::this_thread::get_id()=0x" << boost::this_thread::get_id() << "\n";
		//};
		//fsBackend->set_open_handler(openHandler);

		core->add_sink(fsSink);


		int maxHistoryFiles = -1;
		UINT minFreeSpace, rotationSize = std::numeric_limits< uintmax_t >::max();
		std::string sLogDir;
		// logging settings https://www.boost.org/doc/libs/1_57_0/libs/log/doc/html/log/detailed/utilities.html#log.detailed.utilities.setup.settings_file
		// boost::log::sources::wseverity_logger<boost::log::trivial::severity_level> severityLogger;
		boost::log::trivial::severity_level logSeverity;
		boost::program_options::options_description loggingSettings("Logging settings");
		loggingSettings.add_options()(LOG_CONF_LOG_SEVERITY, boost::program_options::value<boost::log::trivial::severity_level>(
			&logSeverity)->default_value(boost::log::trivial::severity_level::warning), "log level to output")
			(LOG_CONF_MAX_FILES, boost::program_options::value<int>(&maxHistoryFiles),
				"The maximum number of history log files in the target directory, upon which the oldest file will be deleted.")
			(LOG_CONF_MIN_FREE_SPACE, boost::program_options::value<UINT>(&minFreeSpace)->default_value(static_cast< uintmax_t >(0)),
				"Minimum free space in the target directory, in bytes, upon which the oldest file will be deleted. If not specified, no space-based file cleanup will be performed.")
			(LOG_CONF_ROTATION_SIZE, boost::program_options::value<UINT>(&rotationSize),
				"The file size to rotate the file upon reaching (can be imprecise)")
			//(LOG_CONF_OUTPUT_PATH, boost::program_options::wvalue<std::wstring>(&wsLogDir), "Log output path");
			(LOG_CONF_OUTPUT_PATH, boost::program_options::value<std::string>(&sLogDir), "Log output path");

		WCHAR szDllPath[MAX_PATH] = { 0 };
		GetModuleFileNameW(g_hThisModule, szDllPath, MAX_PATH);
		boost::filesystem::path modulePath(szDllPath);
		// e.g. "D:\\Dev\\prod\\pep\\AzureFilePEP\\x64\\Debug\\modules\\smb\\log.conf"
		std::string strConfFilePath = (modulePath.parent_path() / LOG_CONF_NAME).string();

		std::ifstream confFile(strConfFilePath); // LogSeverity = info
		if (confFile)
		{
			boost::program_options::variables_map variables_map;
			try
			{
				auto parsed = boost::program_options::parse_config_file(confFile, loggingSettings);
				boost::program_options::store(parsed, variables_map);
				boost::program_options::notify(variables_map);
			}
			catch (const boost::program_options::error& e)
			{
				BOOST_LOG_TRIVIAL(error) << "Init|Couldn't parse the logging setting file properly:" << e.what();
			}
			if (variables_map.count(LOG_CONF_LOG_SEVERITY))
			{
				boost::log::core::get()->set_filter(boost::log::trivial::severity >= logSeverity);
			}
			if (variables_map.count(LOG_CONF_ROTATION_SIZE))
			{
				backend->set_rotation_size(rotationSize);
			}
			if (variables_map.count(LOG_CONF_OUTPUT_PATH))
			{
				//https://docs.microsoft.com/en-us/windows/desktop/api/processenv/nf-processenv-expandenvironmentstringsw
				//wchar_t szPath[MAX_PATH] = L"";
				//ExpandEnvironmentStringsW(wsLogDir.c_str(), szPath, _countof(szPath));
				char szPath[MAX_PATH] = "";
				ExpandEnvironmentStringsA(sLogDir.c_str(), szPath, _countof(szPath));
				backend->set_file_name_pattern(boost::filesystem::path(szPath) / L"smb_%Y-%m-%d_%H-%M-%S.%N.log");
			}
			BOOST_LOG_TRIVIAL(info) << "Init|Read logging settings " << strConfFilePath
				<< ": " << LOG_CONF_LOG_SEVERITY << "=" << logSeverity
				<< ", " << LOG_CONF_MAX_FILES << "=" << maxHistoryFiles
				<< ", " << LOG_CONF_MIN_FREE_SPACE << "=" << minFreeSpace
				<< ", " << LOG_CONF_ROTATION_SIZE << "=" << rotationSize
				<< ", " << LOG_CONF_OUTPUT_PATH << "=" << sLogDir;
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "Init|Failed to read logging settings " << strConfFilePath;
		}
		if (maxHistoryFiles >= 0)
		{
			//Set up where the rotated files will be stored
			//https://www.boost.org/doc/libs/1_69_0/libs/log/doc/html/log/detailed/sink_backends.html#log.detailed.sink_backends.text_file.managing_rotated_files
			fsBackend->set_file_collector(sinks::file::make_collector(
				boost::log::keywords::target = wsLogDir, // PathCombineA(szPath, szExePath, "log"), //\\history
				boost::log::keywords::min_free_space = minFreeSpace, //100 * 1024 * 1024
				//boost::log::keywords::max_size = 16 * 1024 * 1024,
				boost::log::keywords::max_files = maxHistoryFiles
			));
			// Upon restart, scan the directory for files matching the file_name pattern
			fsBackend->scan_for_files();
		}
	}

	// Add the sink to the core
	// boost::log::core::get()->add_sink(fsSink);

	/* Windows debugger output backend OutputDebugString */
	// Complete sink type
	typedef sinks::asynchronous_sink< sinks::debug_output_backend > debug_sink_t;
	// Create the sink. The backend requires synchronization in the frontend.
	boost::shared_ptr< debug_sink_t > dbgSink = boost::make_shared<debug_sink_t>();
	// Set the special filter to the frontend in order to skip the sink when no debugger is available
	dbgSink->set_filter(boost::log::expressions::is_debugger_present());
	dbgSink->set_formatter(logFmt);
	core->add_sink(dbgSink);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_hThisModule = hModule;
		OutputDebugStringW(L"\nCurrent path is ");
		OutputDebugStringW(boost::filesystem::current_path().c_str());
		OutputDebugStringW(L"\n");
		init_logging();
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}