@echo off
setlocal
pushd "%~dp0" || exit /b 1
if not exist "..\quantumtrace\__init__.py" goto wrong_folder
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 goto python_launcher
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 goto python_command
echo Instala Python 3.10 ou mais recente e volta a tentar.
goto failed
:python_launcher
py -3 validar_exemplos.py --project ".."
if errorlevel 1 goto failed
goto completed
:python_command
python validar_exemplos.py --project ".."
if errorlevel 1 goto failed
:completed
echo.
echo Validacao concluida. O relatorio abre a seguir.
start "" "%~dp0resultados\report.html"
popd
pause
exit /b 0
:wrong_folder
echo Copia a pasta Preparacao para a pasta que contem INICIAR_APP.cmd.
echo Depois abre novamente VALIDAR_EXEMPLOS.cmd.
goto failed
:failed
echo.
echo Consulta a mensagem acima e resultados\validacao.json, se existir.
popd
pause
exit /b 1
