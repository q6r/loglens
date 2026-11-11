@echo off
rem Windows launcher: loglens.cmd report access.log   (needs lua.exe on PATH)
lua "%~dp0loglens" %*
exit /b %ERRORLEVEL%
