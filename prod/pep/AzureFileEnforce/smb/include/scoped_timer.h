#pragma once

// https://stackoverflow.com/questions/15305310/predefined-macros-for-function-name-func
// https://msdn.microsoft.com/en-us/library/b0084kay.aspx
#ifndef __FUNCTION_NAME__
#ifdef WIN32   //WINDOWS
#define __FUNCTION_NAME__   __FUNCTION__  
#else          //*NIX
#define __FUNCTION_NAME__   __func__ 
#endif
#endif

#ifdef _DEBUG
// https://gcc.gnu.org/onlinedocs/cpp/Standard-Predefined-Macros.html
// https://msdn.microsoft.com/en-us/library/b0084kay.aspx
#define TIME_LOG_FILE_LINE  scoped_timer __scoped_timer(__FILE__, __LINE__)
#define TIME_LOG_FUNCTION  scoped_timer __scoped_timer(__FUNCTION_NAME__)
#else
#define TIME_LOG_FILE_LINE
#define TIME_LOG_FUNCTION 
#endif

class scoped_timer
{
public:
	typedef std::chrono::high_resolution_clock _clock;
	typedef _clock::time_point _clock_point;

	scoped_timer(const char *pszFunctionName);
	scoped_timer(const char *pszFileName, int nLineNumber);
	~scoped_timer();
private:
	_clock_point now();

	const char *pszFileName; // File Name or Function name
	int nLineNumber;
	// std::clock_t _init(std::clock());
	_clock_point _init;
};

