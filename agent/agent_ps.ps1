# ==============================================================================
# RANSOMWARE DETECTOR - AGENT POWERSHELL (RESPONSE ENGINE)
# ==============================================================================
# Ce script tourne en boucle sur la machine virtuelle Windows protégée.
# Il interroge l'API centrale (FastAPI) toutes les 2 secondes pour savoir
# s'il doit prendre des mesures d'urgence (Tuer un processus, isoler le réseau).
# ==============================================================================

# L'adresse IP de la machine hôte où tourne Uvicorn (adaptée au réseau VMnet1 de ce lab)
$API_URL = "http://192.168.10.2:8000"

Write-Host "🛡️ Démarrage de l'Agent de Réponse Active..." -ForegroundColor Cyan
Write-Host "📡 Connexion à l'API centrale : $API_URL" -ForegroundColor Gray

while ($true) {
    try {
        # Interrogation de la "boîte aux lettres" des commandes de l'API
        $response = Invoke-RestMethod -Uri "$API_URL/agent/commands" -Method GET -TimeoutSec 2
        
        if ($response.action -ne "NONE") {
            Write-Host "[!] ORDRE REÇU DE L'API :" -ForegroundColor Yellow -NoNewline
            Write-Host " Action=$($response.action) Target=$($response.target)" -ForegroundColor Red
            
            # --- ACTION 1 : TUER UN PROCESSUS ---
            if ($response.action -eq "KILL") {
                Write-Host "🔪 Exécution de Stop-Process..." -ForegroundColor Magenta
                if ($response.target -eq "ALL_SUSPICIOUS") {
                    # Dans le cadre de ce laboratoire, on tue le script de simulation
                    # En production, on tuerait les processus enfants non-standards identifiés
                    Stop-Process -Name "powershell" -Force -ErrorAction SilentlyContinue
                    Write-Host "✅ Processus suspects éliminés." -ForegroundColor Green
                }
                else {
                    # Si un PID spécifique a été fourni manuellement depuis un dashboard
                    Stop-Process -Id $response.target -Force -ErrorAction SilentlyContinue
                    Write-Host "✅ PID $($response.target) éliminé." -ForegroundColor Green
                }
            }
            
            # --- ACTION 2 : ISOLATION RÉSEAU ---
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
