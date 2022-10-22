@echo off

:: Is batch file called from 32 or 64 cmd.exe? (https://groups.google.com/d/msg/alt.msdos.batch.nt/r5RxiY4qx3E/9v4QZfllCAAJ)
REM where MSVCP140D.dll

set SystemDir32=%windir%\System32
mkdir 32bit

reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && set OS=32BIT || set OS=64BIT

if %OS%==32BIT goto copy_32bit_dll
:: if %OS%==64BIT goto copy_64bit_32bit_dll

:copy_64bit_32bit_dll
IF EXIST "%windir%\Sysnative\cmd.exe" (
    @echo [^_^] I'm a 32-bit process on 64-bit windows
	set SystemDir64=%windir%\Sysnative
) ELSE (
	@echo [^_^] I'm a 64-bit process and host is 64-bit windows
    set SystemDir64=%windir%\System32
	set SystemDir32=%windir%\SysWOW64
)

:: https://github.com/Microsoft/cpprestsdk/issues/796
SET DLL_NAMES=MSVCP140D.dll VCRUNTIME140D.dll ucrtbased.dll concrt140d.dll

:copy_64bit_dll
echo copy_64bit_dll: SystemDir64 = %SystemDir64%
mkdir 64bit
for %%n in (%DLL_NAMES%) do copy /Y %SystemDir64%\%%n 64bit
:: $ file /cygdrive/d/Dev/32bit/concrt140d.dll /cygdrive/d/Dev/32bit/msvcp140d.dll /cygdrive/d/Dev/32bit/ucrtbased.dll /cygdrive/d/Dev/32bit/vcruntime140d.dll
:: /cygdrive/d/Dev/32bit/concrt140d.dll:    PE32 executable (DLL) (console) Intel 80386, for MS Windows
:: /cygdrive/d/Dev/32bit/msvcp140d.dll:     PE32 executable (DLL) (console) Intel 80386, for MS Windows
:: /cygdrive/d/Dev/32bit/ucrtbased.dll:     PE32 executable (DLL) (console) Intel 80386, for MS Windows
:: /cygdrive/d/Dev/32bit/vcruntime140d.dll: PE32 executable (DLL) (console) Intel 80386, for MS Windows


:copy_32bit_dll
echo copy_32bit_dll: SystemDir32 = %SystemDir32%
for %%n in (%DLL_NAMES%) do copy /Y %SystemDir32%\%%n 32bit
:: $ file /cygdrive/d/Dev/64bit/concrt140d.dll /cygdrive/d/Dev/64bit/msvcp140d.dll /cygdrive/d/Dev/64bit/ucrtbased.dll /cygdrive/d/Dev/64bit/vcruntime140d.dll
:: /cygdrive/d/Dev/64bit/concrt140d.dll:    PE32+ executable (DLL) (console) x86-64, for MS Windows
:: /cygdrive/d/Dev/64bit/msvcp140d.dll:     PE32+ executable (DLL) (console) x86-64, for MS Windows
:: /cygdrive/d/Dev/64bit/ucrtbased.dll:     PE32+ executable (DLL) (console) x86-64, for MS Windows
:: /cygdrive/d/Dev/64bit/vcruntime140d.dll: PE32+ executable (DLL) (console) x86-64, for MS Windows


:: $ file --version
:: file-5.11
:: magic file from /usr/share/misc/magic