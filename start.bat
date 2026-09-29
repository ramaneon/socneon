@echo off
echo.
echo  SOCNeon — Full Stack Startup
echo  =============================
echo  Backend:  http://localhost:8000
echo  Frontend: http://localhost:5173
echo.
start "SOCNeon Backend" cmd /k "cd /d backend && python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
timeout /t 2 /nobreak >nul
start "SOCNeon Frontend" cmd /k "cd /d frontend && npm run dev"
echo.
echo  Both servers starting...
echo  Open http://localhost:5173 in your browser.
echo.
