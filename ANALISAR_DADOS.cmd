@echo off
setlocal
pushd "%~dp0" || exit /b 1
if not exist "run_demo.py" goto not_extracted
if not exist "quantumtrace\__init__.py" goto not_extracted

rem Descobre instalacoes habituais do Wireshark sem alterar o PATH do sistema.
where tshark >nul 2>&1
if errorlevel 1 (
    if exist "%ProgramFiles%\Wireshark\tshark.exe" set "PATH=%ProgramFiles%\Wireshark;%PATH%"
    if exist "%ProgramFiles(x86)%\Wireshark\tshark.exe" set "PATH=%ProgramFiles(x86)%\Wireshark;%PATH%"
)

rem Usa apenas um interpretador Python que cumpra a versao minima do projeto.
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 goto python_launcher
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 goto python_command
echo Instala Python 3.10 ou mais recente e volta a executar este ficheiro.
echo Durante a instalacao, ativa o Python Launcher ou Add python.exe to PATH.
goto failed

:python_launcher
py -3 -m quantumtrace doctor
py -3 run_demo.py
if errorlevel 1 goto failed
goto completed

:python_command
python -m quantumtrace doctor
python run_demo.py
if errorlevel 1 goto failed

:completed
echo.
echo Analise concluida. Consulta a cobertura e os avisos no relatorio.
start "" "%~dp0reports\report.html"
popd
pause
exit /b 0

:failed
echo.
echo Nao foi possivel concluir a analise. Consulta a mensagem acima.
popd
pause
exit /b 1

:not_extracted
echo Extrai o ZIP completo: botao direito no ZIP, Extrair Tudo.
echo Depois abre a pasta extraida quantumtrace e executa novamente.
goto failed
