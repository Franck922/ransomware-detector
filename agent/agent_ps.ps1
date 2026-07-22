# ==============================================================================
# RANSOMWARE DETECTOR - AGENT POWERSHELL (RESPONSE ENGINE V2.1)
# ==============================================================================
# Ce script tourne en boucle sur la machine virtuelle Windows protegee.
# Il interroge l'API centrale (FastAPI) toutes les 2 secondes.
# Dans cette V2.1, il execute une frappe chirurgicale (PID) et affiche des
# preuves contextuelles.
# ==============================================================================

$API_URL = "http://192.168.10.2:8000"

Write-Host "==============================================" -ForegroundColor DarkCyan
Write-Host "  AGENT EDR - DETECTION & REPONSE ACTIVE" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor DarkCyan
Write-Host "[*] Demarrage du daemon en arriere-plan..." -ForegroundColor Gray
Write-Host "[*] Connexion a l'API centrale : $API_URL" -ForegroundColor Gray
Write-Host "[+] Pret et en attente d'ordres." -ForegroundColor Green
Write-Host ""

while ($true) {
    try {
        $response = Invoke-RestMethod -Uri "$API_URL/agent/commands" -Method GET -TimeoutSec 2

        if ($response.action -ne "NONE") {

            if ($response.action -eq "KILL") {
                Write-Host ""
                Write-Host "==============================" -ForegroundColor Red
                Write-Host "        EDR RESPONSE" -ForegroundColor Red
                Write-Host "==============================" -ForegroundColor Red

                Write-Host ""
                Write-Host "Threat Level : " -ForegroundColor Yellow -NoNewline
                Write-Host "CRITICAL" -ForegroundColor Red

                Write-Host ""
                Write-Host "Process :" -ForegroundColor Yellow
                Write-Host "  $($response.process)" -ForegroundColor White

                Write-Host ""
                Write-Host "PID :" -ForegroundColor Yellow
                Write-Host "  $($response.pid)" -ForegroundColor White

                if ($response.parent) {
                    Write-Host ""
                    Write-Host "Parent :" -ForegroundColor Yellow
                    Write-Host "  $($response.parent) ($($response.parent_pid))" -ForegroundColor Gray
                }

                Write-Host ""
                Write-Host "Evidence" -ForegroundColor Yellow
                Write-Host "---------" -ForegroundColor Yellow
                foreach ($reason in $response.reasons) {
                    Write-Host "  [x] $reason" -ForegroundColor DarkRed
                }

                Write-Host ""
                Write-Host "Decision" -ForegroundColor Yellow
                Write-Host "--------" -ForegroundColor Yellow
                Write-Host "  Score      : $($response.score)" -ForegroundColor Red
                Write-Host "  Confidence : $($response.confidence)" -ForegroundColor Red

                Write-Host ""
                Write-Host "Action" -ForegroundColor Yellow
                Write-Host "------" -ForegroundColor Yellow
                Write-Host "  Terminate PID $($response.pid)" -ForegroundColor Magenta

                Write-Host ""
                Write-Host "Result" -ForegroundColor Yellow
                Write-Host "------" -ForegroundColor Yellow

                if ($response.pid) {
                    try {
                        Stop-Process -Id $response.pid -Force -ErrorAction Stop
                        Write-Host "  SUCCESS : Process (PID: $($response.pid)) terminated." -ForegroundColor Green
                    }
                    catch {
                        Write-Host "  FALLBACK : PID not found. Trying by name..." -ForegroundColor DarkYellow
                        if ($response.process) {
                            $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($response.process)
                            Stop-Process -Name $nameWithoutExt -Force -ErrorAction SilentlyContinue
                            Write-Host "  SUCCESS : Process '$nameWithoutExt' terminated by name." -ForegroundColor Green
                        }
                    }
                }
                Write-Host ""
                Write-Host "==============================" -ForegroundColor Red
                Write-Host ""
            }
            elseif ($response.action -eq "ISOLATE") {
                Write-Host "[!] Execution de l'isolation reseau (Pare-feu)..." -ForegroundColor Magenta
                netsh advfirewall set allprofiles state on | Out-Null
                netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
                netsh advfirewall firewall add rule name="Allow Ransomware API" dir=out action=allow protocol=TCP remoteport=8000 | Out-Null
                Write-Host "[+] Machine isolee du reseau. Seule la communication avec l'API est maintenue." -ForegroundColor Green
            }
        }
    }
    catch {
        # API injoignable, on ignore silencieusement
    }

    Start-Sleep -Seconds 2
}
