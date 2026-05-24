@echo off
setlocal

cd /d D:\Development\Self_LLM_SOC

set "PRODUCT_CONTAINER=self-llm-soc-product-api"
set "DEMO_CONTAINER=self-llm-soc-demo-gui"

docker ps --format "{{.Names}}" | findstr /x "%PRODUCT_CONTAINER% %DEMO_CONTAINER%" >nul
if %ERRORLEVEL%==0 goto stop_servers

if "%GEMINI_API_KEY%"=="" (
  echo GEMINI_API_KEY is not set in this cmd session.
  set /p "GEMINI_API_KEY=Enter Gemini API key: "
)

docker rm -f "%DEMO_CONTAINER%" >nul 2>nul
docker rm -f "%PRODUCT_CONTAINER%" >nul 2>nul

echo Starting Product API on http://127.0.0.1:8080 ...
docker compose run -d --rm --name "%PRODUCT_CONTAINER%" -p 8080:8080 app python scripts/product_api.py --host 0.0.0.0 --port 8080
if errorlevel 1 goto start_failed

echo Starting Demo GUI on http://127.0.0.1:8081 ...
docker compose run -d --rm --name "%DEMO_CONTAINER%" -p 8081:8081 app python scripts/demo_gui_server.py --host 0.0.0.0 --port 8081 --product-url http://host.docker.internal:8080
if errorlevel 1 goto start_failed

echo.
echo Started:
echo   Product API: http://127.0.0.1:8080
echo   Demo GUI:    http://127.0.0.1:8081
echo.
echo Press any key here to stop both servers.
pause >nul
goto stop_servers

:stop_servers
echo Stopping demo servers ...
docker stop "%DEMO_CONTAINER%" >nul 2>nul
docker stop "%PRODUCT_CONTAINER%" >nul 2>nul
docker rm -f "%DEMO_CONTAINER%" >nul 2>nul
docker rm -f "%PRODUCT_CONTAINER%" >nul 2>nul
echo Stopped Product API and Demo GUI.
exit /b 0

:start_failed
echo.
echo Failed to start one of the servers. Cleaning up any started container ...
docker stop "%DEMO_CONTAINER%" >nul 2>nul
docker stop "%PRODUCT_CONTAINER%" >nul 2>nul
pause
exit /b 1
