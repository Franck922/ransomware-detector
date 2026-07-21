# ==============================================================================
# RANSOMWARE DETECTOR - AGENT POWERSHELL (RESPONSE ENGINE V2.1)
# ==============================================================================
# Ce script tourne en boucle sur la machine virtuelle Windows protégée.
# Il interroge l'API centrale (FastAPI) toutes les 2 secondes.
# Dans cette V2.1, il exécute une frappe chirurgicale (PID) et affiche des
# preuves contextuelles.
# ==============================================================================

# L'adresse IP de la machine hôte où tourne Uvicorn (adaptée au réseau VMnet1 de ce lab)
$API_URL = "http://192.168.10.2:8000"

Write-Host "==============================================" -ForegroundColor DarkCyan
Write-Host "🛡️ AGENT EDR - DÉTECTION & RÉPONSE ACTIVE 🛡️" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor DarkCyan
Write-Host "[*] Démarrage du daemon en arrière-plan..." -ForegroundColor Gray
Write-Host "📡 Connexion à l'API centrale : $API_URL" -ForegroundColor Gray
Write-Host "✔️ Prêt et en attente d'ordres.`n" -ForegroundColor Green

while ($true) {
    try {
        # Interrogation de la "boîte aux lettres" des commandes de l'API
        $response = Invoke-RestMethod -Uri "$API_URL/agent/commands" -Method GET -TimeoutSec 2
        
        if ($response.action -ne "NONE") {
            # --- ACTION 1 : TUER UN PROCESSUS ---
            if ($response.action -eq "KILL") {
                Write-Host "`n==============================" -ForegroundColor Red
                Write-Host "        EDR RESPONSE" -ForegroundColor Red
                Write-Host "==============================" -ForegroundColor Red
                
                Write-Host "`nThreat Level : " -ForegroundColor Yellow -NoNewline
                Write-Host "CRITICAL" -ForegroundColor Red
                
                Write-Host "`nProcess :" -ForegroundColor Yellow
                Write-Host "$($response.process)" -ForegroundColor White
                
                Write-Host "`nPID :" -ForegroundColor Yellow
                Write-Host "$($response.pid)" -ForegroundColor White
                
                if ($response.parent) {
                    Write-Host "`nParent :" -ForegroundColor Yellow
                    Write-Host "$($response.parent) ($($response.parent_pid))" -ForegroundColor Gray
                }
                
                Write-Host "`nEvidence" -ForegroundColor Yellow
                Write-Host "---------" -ForegroundColor Yellow
                foreach ($reason in $response.reasons) {
                    Write-Host "✓ $reason" -ForegroundColor DarkRed
                }
                
                Write-Host "`nDecision" -ForegroundColor Yellow
                Write-Host "--------" -ForegroundColor Yellow
                Write-Host "Score : $($response.score)" -ForegroundColor Red
                Write-Host "Confidence : $($response.confidence)" -ForegroundColor Red
                
                Write-Host "`nAction" -ForegroundColor Yellow
                Write-Host "------" -ForegroundColor Yellow
                Write-Host "Terminate PID $($response.pid)" -ForegroundColor Magenta
                
                Write-Host "`nResult" -ForegroundColor Yellow
                Write-Host "------" -ForegroundColor Yellow
                
                # Exécution de l'ordre par PID
                if ($response.pid) {
                    try {
                        Stop-Process -Id $response.pid -Force -ErrorAction Stop
                        Write-Host "✅ Succès : Le processus (PID: $($response.pid)) a été exterminé." -ForegroundColor Green
                    } catch {
                        Write-Host "⚠️ Échec PID : Le processus est introuvable ou déjà mort. Fallback sur le nom..." -ForegroundColor DarkYellow
                        # Fallback sur le nom
                        if ($response.process) {
                            $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($response.process)
                            Stop-Process -Name $nameWithoutExt -Force -ErrorAction SilentlyContinue
                            Write-Host "✅ Succès Fallback : Nom de processus '$nameWithoutExt' éliminé." -ForegroundColor Green
                        }
                    }
                }
                Write-Host "=================================================`n" -ForegroundColor Red
            }
            
            # --- ACTION 2 : ISOLATION ---
            elseif ($response.action -eq "ISOLATE") {
                Write-Host "🧱 Exécution de l'isolation réseau (Pare-feu)..." -ForegroundColor Magenta
                # Active le pare-feu sur tous les profils (au cas où il était désactivé)
                netsh advfirewall set allprofiles state on | Out-Null
                
                # Bloque le trafic sortant par défaut
                netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
                
                # Optionnel: Autoriser le port 8000 pour continuer à communiquer avec l'API
                netsh advfirewall firewall add rule name="Allow Ransomware API" dir=out action=allow protocol=TCP remoteport=8000 | Out-Null
                
                Write-Host "✅ Machine isolée du réseau. Seule la communication avec l'API est maintenue." -ForegroundColor Green
            }
        }
    }
    catch {
        # Si l'API est injoignable, on ignore l'erreur pour ne pas spammer la console
    }
    
    # Polling toutes les 2 secondes
    Start-Sleep -Seconds 2
}
