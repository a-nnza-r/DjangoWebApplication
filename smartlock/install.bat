
@REM Install standalone python3
curl -L -O "https://github.com/conda-forge/miniforge/releases/download/25.1.1-0/Miniforge3-Windows-x86_64.exe"
start /wait "" Miniforge3-Windows-x86_64.exe /InstallationType=JustMe /RegisterPython=0 /S /D=%cd%\venv
del Miniforge3-Windows-x86_64.exe

@REM Install python packages
.\venv\python -m pip install -r requirements.txt
echo Done, now run ".\run.bat --gui"