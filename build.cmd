@echo off
setlocal
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" (
    echo ERROR: csc.exe not found at %CSC%
    echo This build script needs in-box .NET Framework 4.x.
    exit /b 1
)
"%CSC%" /nologo /target:exe /out:KeyIdentifier.exe /optimize+ /platform:x64 KeyIdentifier.cs
if errorlevel 1 (
    echo BUILD FAILED.
    exit /b 1
)
echo Built KeyIdentifier.exe
