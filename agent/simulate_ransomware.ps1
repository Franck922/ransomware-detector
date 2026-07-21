<#
.SYNOPSIS
Simulateur de comportement de Ransomware pour générer des logs Sysmon (EventID 11 et 23).
Ne contient AUCUN code malveillant. Agit uniquement sur un dossier temporaire dédié.
#>

$SimulationDir = "$env:USERPROFILE\Desktop\Ransomware_Simulation"

Write-Host "[*] Préparation de l'environnement de simulation..." -ForegroundColor Cyan
if (Test-Path $SimulationDir) {
    Remove-Item -Path $SimulationDir -Recurse -Force
}
New-Item -ItemType Directory -Path $SimulationDir | Out-Null

# 1. Génération de faux fichiers de victimes (Comportement normal)
# On passe à 500 fichiers pour laisser le temps au système de réagir
Write-Host "[*] Génération de 500 faux documents (Activité normale)..." -ForegroundColor Green
for ($i = 1; $i -le 500; $i++) {
    $content = "Ceci est un document important de l'entreprise - Fichier $i"
    Set-Content -Path "$SimulationDir\document_financier_$i.docx" -Value $content
}

Write-Host "[*] Fichiers générés. L'attaque va commencer dans 3 secondes..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# 2. Lancement de la simulation (Comportement Ransomware)
Write-Host "[!] DÉMARRAGE DE LA SIMULATION RANSOMWARE !" -ForegroundColor Red
Write-Host "[!] Sysmon va enregistrer une vague massive d'Event 11 et 23." -ForegroundColor Red

$files = Get-ChildItem -Path $SimulationDir -Filter "*.docx"

$count = 0
foreach ($file in $files) {
    $count++
    
    # Génération d'un nom de fichier avec une haute entropie (chaîne aléatoire)
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $randomName = -join (1..12 | ForEach-Object { $chars.ToCharArray() | Get-Random })
    $encryptedName = "$randomName.encrypted"
    $encryptedPath = "$SimulationDir\$encryptedName"

    # Simulation du chiffrement
    $content = Get-Content $file.FullName
    $fakeEncryptedContent = "ENCRYPTED_DATA_" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($content))
    
    # EVENT 11 : File Create (Fichier chiffré créé)
    Set-Content -Path $encryptedPath -Value $fakeEncryptedContent
    
    # EVENT 23 : File Delete (Fichier original supprimé)
    Remove-Item -Path $file.FullName -Force

    if ($count % 10 -eq 0) {
        Write-Host " -> $count fichiers chiffrés..." -ForegroundColor DarkYellow
    }

    # Pause de 50ms (l'attaque totale durera environ 25 secondes)
    # C'est parfait pour laisser le temps à l'API de détecter (10s) et à l'Agent de réagir (2s)
    Start-Sleep -Milliseconds 50
}

Write-Host "[*] Simulation terminée ! S'il s'affiche, c'est que l'EDR a échoué à vous protéger." -ForegroundColor Red
