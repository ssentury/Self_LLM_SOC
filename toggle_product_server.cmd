@echo off
setlocal

set "PRODUCT_CONTAINER=self-llm-soc-product-api"

docker ps --format "{{.Names}}" | findstr /x "%PRODUCT_CONTAINER%" >nul
if %ERRORLEVEL%==0 goto stop_server

docker rm -f "%PRODUCT_CONTAINER%" >nul 2>nul

echo Starting Product API and GUI on http://127.0.0.1:8080 ...
docker compose run -d --rm --name "%PRODUCT_CONTAINER%" -p 8080:8080 app python scripts/product_api.py --config config/settings.example.yaml --host 0.0.0.0 --port 8080
if errorlevel 1 goto start_failed

echo.
echo Started:
echo   Product GUI/API: http://127.0.0.1:8080
echo   LLM setup is handled in the browser on first open.
echo.
echo Press any key here to stop the product server.
pause >nul
goto stop_server

:stop_server
echo Stopping product server ...
docker stop "%PRODUCT_CONTAINER%" >nul 2>nul
docker rm -f "%PRODUCT_CONTAINER%" >nul 2>nul
echo Stopped Product API and GUI.
exit /b 0

:start_failed
echo.
echo Failed to start the product server. Cleaning up any started container ...
docker stop "%PRODUCT_CONTAINER%" >nul 2>nul
pause
exit /b 1
