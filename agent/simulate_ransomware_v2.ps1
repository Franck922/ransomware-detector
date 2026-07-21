<#
.SYNOPSIS
Simule le comportement d'un ransomware complet (Chiffrement + Réseau + Processus enfants).
Ce script est conçu de manière sécurisée (aucun vrai fichier n'est chiffré, aucune commande destructrice n'est exécutée).
#>

Write-Host "==============================================" -ForegroundColor Red
Write-Host "   SIMULATION RANSOMWARE V2 (COMPLEXE)" -ForegroundColor Red
Write-Host "==============================================" -ForegroundColor Red

# 1. SIMULATION DE CONNEXION C2 (Command & Control)
Write-Host "[*] Étape 1 : Connexion au serveur de clés (Simulation C2)..." -ForegroundColor Yellow
try {
    # On fait un ping vers un serveur public aléatoire pour déclencher l'Event 3 Sysmon
    Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing -TimeoutSec 2 | Out-Null
    Write-Host "[+] Connexion réseau établie." -ForegroundColor Green
} catch {
    Write-Host "[-] Échec connexion réseau (Normal si VM isolée)." -ForegroundColor Gray
}

# 2. SIMULATION DE SUPPRESSION DES SAUVEGARDES (Shadow Copies)
Write-Host "[*] Étape 2 : Lancement d'un processus suspect (vssadmin.exe)..." -ForegroundColor Yellow
# On lance la commande système pour déclencher l'Event 1 Sysmon.
# ATTENTION: Pour que la démo soit sans danger, on affiche juste l'aide de vssadmin, on ne supprime rien !
Start-Process -FilePath "vssadmin.exe" -ArgumentList "list shadows" -WindowStyle Hidden
Write-Host "[+] Processus enfant lancé." -ForegroundColor Green


# 3. SIMULATION DU CHIFFREMENT MASSIF
$TargetDir = "$env:TEMP\Simulation_Ransomware"
if (-Not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir | Out-Null
}

$NumberOfFiles = 500
Write-Host "[*] Étape 3 : Création massive de faux fichiers chiffrés ($NumberOfFiles fichiers)..." -ForegroundColor Yellow

for ($i = 1; $i -le $NumberOfFiles; $i++) {
    # Nom de fichier à forte entropie (aléatoire)
    $RandomString = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
    
    # On utilise .exe car on a vu que Sysmon le surveillait parfaitement
    $FilePath = Join-Path -Path $TargetDir -ChildPath "$RandomString.exe"
    
    # Création du fichier
    Set-Content -Path $FilePath -Value "RANSOMWARE_ENCRYPTED_DATA_SIMULATION_$i"
}

Write-Host "[+] $NumberOfFiles fichiers créés." -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Red
Write-Host "   SIMULATION TERMINÉE" -ForegroundColor Red
Write-Host "==============================================" -ForegroundColor Red
