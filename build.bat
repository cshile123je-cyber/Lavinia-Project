@echo off
echo XWrapper build basliyor...

:: VS 2022 community path
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" 2>nul
)

if not exist build mkdir build
cd build

cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

cd ..

if exist build\Release\xwrapper.dll (
    copy build\Release\xwrapper.dll . >nul
    echo.
    echo [OK] xwrapper.dll hazir
    echo.
    echo Kullanim:
    echo   1. xwrapper.dll ve xhanger_yazilim__lavinia_project_.dll ayni klasore koy
    echo   2. extreme injector ile xwrapper.dll inject et - LoadLibrary yeterli
    echo   3. 2.5 saniye bekle, hile yuklenir
) else (
    echo [HATA] build basarisiz
)

pause
