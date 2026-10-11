@echo off
setlocal
pushd "%~dp0" || exit /b 1
if not exist "quantumtrace\app.py" goto not_extracted
if not exist "data\README.md" goto not_extracted

py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 goto python_launcher
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 goto python_command
echo Instala Python 3.10 ou mais recente e volta a executar este ficheiro.
echo Ativa o Python Launcher ou Add python.exe to PATH na instalacao.
goto failed

:python_launcher
py -3 -m quantumtrace serve
if errorlevel 1 goto failed
goto completed

:python_command
python -m quantumtrace serve
if errorlevel 1 goto failed
goto completed

:not_extracted
echo Extrai o ZIP completo antes de abrir a app.
echo No Explorador: botao direito no ZIP, Extrair Tudo.
echo Abre a pasta extraida quantumtrace e executa INICIAR_APP.cmd.
goto failed

:failed
echo.
echo Nao foi possivel iniciar a app. Consulta a mensagem acima.
popd
pause
exit /b 1

:completed
popd
pause
exit /b 0
