<#
.SYNOPSIS
Simulateur de comportement de Ransomware pour générer des logs Sysmon (EventID 11 et 23).
Ne contient AUCUN code malveillant. Agit uniquement sur un dossier temporaire dédié.

.DESCRIPTION
Ce script crée des fichiers textes normaux, puis simule un chiffrement :
1. Il crée une copie du fichier avec un nom à haute entropie et l'extension .encrypted
2. Il supprime le fichier original
Cela déclenchera les règles de détection de notre EDR (Création massive, Suppression massive, Haute Entropie).
#>

$SimulationDir = "$env:USERPROFILE\Desktop\Ransomware_Simulation"

Write-Host "[*] Préparation de l'environnement de simulation..." -ForegroundColor Cyan
if (Test-Path $SimulationDir) {
    Remove-Item -Path $SimulationDir -Recurse -Force
}
New-Item -ItemType Directory -Path $SimulationDir | Out-Null

# 1. Génération de faux fichiers de victimes (Comportement normal)
Write-Host "[*] Génération de 100 faux documents (Activité normale)..." -ForegroundColor Green
for ($i = 1; $i -le 100; $i++) {
    $content = "Ceci est un document important de l'entreprise - Fichier $i"
    Set-Content -Path "$SimulationDir\document_financier_$i.docx" -Value $content
}

Start-Sleep -Seconds 3

# 2. Lancement de la simulation (Comportement Ransomware)
Write-Host "[!] DÉMARRAGE DE LA SIMULATION RANSOMWARE (Attaque rapide) !" -ForegroundColor Red
Write-Host "[!] Sysmon va enregistrer une vague massive d'Event 11 et 23." -ForegroundColor Yellow

$files = Get-ChildItem -Path $SimulationDir -Filter "*.docx"

foreach ($file in $files) {
    # Génération d'un nom de fichier avec une haute entropie (chaîne aléatoire)
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $randomName = -join (1..12 | ForEach-Object { $chars.ToCharArray() | Get-Random })
    $encryptedName = "$randomName.encrypted"
    $encryptedPath = "$SimulationDir\$encryptedName"

    # Simulation du chiffrement : On lit l'original, on l'écrit dans le nouveau fichier
    $content = Get-Content $file.FullName
    $fakeEncryptedContent = "ENCRYPTED_DATA_" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($content))
    
    # EVENT 11 : File Create (Fichier chiffré créé)
    Set-Content -Path $encryptedPath -Value $fakeEncryptedContent
    
    # EVENT 23 : File Delete (Fichier original supprimé)
    Remove-Item -Path $file.FullName -Force

    # Petite pause pour ne pas surcharger le processeur de la VM, mais assez rapide (10ms)
    Start-Sleep -Milliseconds 10
}

Write-Host "[*] Simulation terminée ! 100 fichiers ont été 'chiffrés' et supprimés." -ForegroundColor Cyan
Write-Host "[*] Vérifiez le dashboard ou les logs de votre API pour voir si l'alerte a été déclenchée." -ForegroundColor Green
