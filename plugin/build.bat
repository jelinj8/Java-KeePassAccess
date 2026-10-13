@echo off
setlocal
rem Builds out\KeePassAccess.dll with the C# compiler of .NET Framework 4 (no SDK needed).
rem KEEPASS_DIR: KeePass 2.x installation, default "C:\Program Files\KeePass Password Safe 2".
rem Install: copy out\KeePassAccess.dll into %KEEPASS_DIR%\Plugins and restart KeePass.

if "%KEEPASS_DIR%"=="" set "KEEPASS_DIR=C:\Program Files\KeePass Password Safe 2"
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo csc.exe of .NET Framework 4 not found
  exit /b 2
)
if not exist "%KEEPASS_DIR%\KeePass.exe" (
  echo KeePass.exe not found in %KEEPASS_DIR%; set KEEPASS_DIR
  exit /b 2
)

cd /d "%~dp0"
if not exist out mkdir out
"%CSC%" /nologo /codepage:65001 /target:library /optimize+ /out:out\KeePassAccess.dll ^
  /reference:"%KEEPASS_DIR%\KeePass.exe" /reference:System.Core.dll /reference:System.Windows.Forms.dll ^
  KeePassAccess.cs Properties\AssemblyInfo.cs
exit /b %ERRORLEVEL%
