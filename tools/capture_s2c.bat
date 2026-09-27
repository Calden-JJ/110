@echo off
setlocal
title DFO s2c capture

net session >nul 2>&1
if errorlevel 1 (
  echo.
  echo   [X] This script must run as Administrator.
  echo       Right-click it -^> "Run as administrator"
  echo.
  pause
  exit /b 1
)

cd /d "%~dp0"

echo.
echo   === DFO s2c capture ===
echo.
echo   Cleaning old filters...
pktmon filter remove >nul 2>&1

echo   Adding filter: TCP to/from 192.168.1.6
pktmon filter add DFO -i 192.168.1.6 -t TCP >nul 2>&1
if errorlevel 1 (
  echo   [i] Filter not supported, capturing everything instead.
  pktmon filter remove >nul 2>&1
)

echo   Starting capture...
pktmon start --capture --pkt-size 0 --file-name dfo_capture.etl --file-size 512 >nul
if errorlevel 1 (
  echo   [X] pktmon failed to start.
  pause
  exit /b 1
)

echo.
echo   ############################################################
echo   #                                                          #
echo   #   CAPTURING.  Now start the game and do exactly this:     #
echo   #                                                          #
echo   #     1. log in                                            #
echo   #     2. pick the server  (Cain)                           #
echo   #     3. pick a channel   (any)                            #
echo   #     4. enter town and stand still about 10 seconds        #
echo   #     5. walk a few steps and stop                          #
echo   #                                                          #
echo   #   Then come back here and press any key.                  #
echo   #                                                          #
echo   ############################################################
echo.
pause >nul

echo   Stopping capture...
pktmon stop >nul
pktmon filter remove >nul 2>&1

echo   Converting to pcapng...
pktmon etl2pcap dfo_capture.etl -o dfo_capture.pcapng

if exist dfo_capture.pcapng (
  for %%A in (dfo_capture.pcapng) do echo   [OK] %%~fA  (%%~zA bytes)
) else (
  echo   [X] No pcapng produced. Check dfo_capture.etl manually.
)

echo.
pause
