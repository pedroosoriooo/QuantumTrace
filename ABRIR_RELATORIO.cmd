@echo off
setlocal
if not exist "%~dp0quantumtrace\__init__.py" (
    echo Extrai o ZIP completo: botao direito no ZIP, Extrair Tudo.
    echo Depois abre a pasta extraida quantumtrace e executa novamente.
    pause
    exit /b 1
)
if not exist "%~dp0reports\report.html" (
    echo O relatorio nao foi encontrado. Executa ANALISAR_DADOS.cmd primeiro.
    pause
    exit /b 1
)
start "" "%~dp0reports\report.html"
endlocal
