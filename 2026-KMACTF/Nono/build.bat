@echo off
setlocal enabledelayedexpansion
::
:: build.bat [release|debug] [managed|payload|all]
::
:: Requirements:
::   - VS x64 Native Tools Command Prompt for payload/all
::   - Python available as python
::

set CONFIG=Release
set TARGET=all

:parse_args
if "%1"=="" goto :args_done
if /i "%1"=="release" set CONFIG=Release
if /i "%1"=="debug" set CONFIG=Debug
if /i "%1"=="managed" set TARGET=managed
if /i "%1"=="payload" set TARGET=payload
if /i "%1"=="all" set TARGET=all
shift
goto :parse_args

:args_done

set ROOT=%~dp0
set OUT_DIR=%ROOT%Nono\bin\x64\%CONFIG%\net8.0
set PAYLOAD_SRC=%ROOT%Nono\payload\payload.c
set PAYLOAD_OBJ=%OUT_DIR%\payload.obj
set PAYLOAD_EXE=%OUT_DIR%\payload.exe
set PAYLOAD_BIN=%OUT_DIR%\payload.bin
set PAYLOAD_META=%OUT_DIR%\payload.json
set GAME_EXE=%OUT_DIR%\Nono.exe
set PATCHED_EXE=%OUT_DIR%\Nono.patched.exe
set CFLAGS=/c /GS- /O1 /Zl /nologo
set LDFLAGS=/NODEFAULTLIB /NOLOGO /ENTRY:ShellMain /SUBSYSTEM:WINDOWS /FIXED /DYNAMICBASE:NO

if /i "%CONFIG%"=="Debug" set CFLAGS=%CFLAGS% /DDEBUG

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo Configuration: %CONFIG%
echo Target: %TARGET%

call :cleanup_old_outputs

if /i "%TARGET%"=="managed" goto :build_managed
if /i "%TARGET%"=="payload" goto :build_payload_target
if /i "%TARGET%"=="all" goto :build_all

echo Unknown target: %TARGET%
exit /b 1

:build_all
call :build_managed
if errorlevel 1 exit /b 1
call :build_payload
if errorlevel 1 exit /b 1
call :convert_payload
if errorlevel 1 exit /b 1
call :patch_game
if errorlevel 1 exit /b 1
goto :done

:build_payload_target
call :build_payload
if errorlevel 1 exit /b 1
call :convert_payload
if errorlevel 1 exit /b 1
goto :done

:build_managed
echo.
echo -- Building managed game -----------------------------------------------
python "%ROOT%tools\inject_prompt_bait.py"
if errorlevel 1 exit /b 1
dotnet build "%ROOT%Nono\Nono.csproj" -c %CONFIG% -p:Platform=x64 -o "%OUT_DIR%"
exit /b %ERRORLEVEL%

:build_payload
echo.
echo -- Building native payload ---------------------------------------------
cl %CFLAGS% /Fo"%PAYLOAD_OBJ%" "%PAYLOAD_SRC%"
if errorlevel 1 exit /b 1
link %LDFLAGS% /OUT:"%PAYLOAD_EXE%" "%PAYLOAD_OBJ%"
if errorlevel 1 exit /b 1
exit /b 0

:convert_payload
echo.
echo -- Converting PE payload to raw payload blob ---------------------------
python "%ROOT%tools\extract_payload.py" "%PAYLOAD_EXE%" "%PAYLOAD_BIN%" --meta "%PAYLOAD_META%"
exit /b %ERRORLEVEL%

:patch_game
echo.
echo -- Patching game executable --------------------------------------------
if not exist "%GAME_EXE%" (
    echo Missing game executable: %GAME_EXE%
    exit /b 1
)
python "%ROOT%tools\patch_pe_payload.py" "%GAME_EXE%" "%PAYLOAD_BIN%" --meta "%PAYLOAD_META%" -o "%PATCHED_EXE%"
exit /b %ERRORLEVEL%

:done
echo.
echo Done.
echo Payload EXE: %PAYLOAD_EXE%
echo Payload blob: %PAYLOAD_BIN%
echo Payload meta: %PAYLOAD_META%
echo Patched game: %PATCHED_EXE%
exit /b 0

:cleanup_old_outputs
if exist "%ROOT%Nono\bin\Any CPU" rmdir /s /q "%ROOT%Nono\bin\Any CPU" 2>nul
if exist "%ROOT%artifacts\%CONFIG%" rmdir /s /q "%ROOT%artifacts\%CONFIG%" 2>nul
rmdir "%ROOT%artifacts" 2>nul
exit /b 0
