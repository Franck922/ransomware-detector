<#
.SYNOPSIS
Agent Forwarder. Lit les logs JSON générés par Winlogbeat et les envoie
à l'API FastAPI au format requis (machine_id + batch).

.DESCRIPTION
À exécuter sur la VM Windows en tâche de fond.
#>

$ApiUrl = "http://192.168.10.2:8000/ingest"
$MachineId = $env:COMPUTERNAME
$LogDir = "C:\ProgramData\winlogbeat\logs"

Write-Host "[*] Démarrage de l'Agent Forwarder vers $ApiUrl..." -ForegroundColor Cyan

# Trouver dynamiquement le dernier fichier créé par Winlogbeat
$LogFile = (Get-ChildItem -Path $LogDir -Filter "winlogbeat-output*.ndjson" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

if (-not $LogFile -or -not (Test-Path $LogFile)) {
    Write-Host "[!] Aucun fichier winlogbeat-output*.ndjson trouvé dans $LogDir." -ForegroundColor Red
    Write-Host "[!] Veuillez démarrer le service avec : Start-Service winlogbeat" -ForegroundColor Yellow
    Exit
}

Write-Host "[*] Fichier surveillé : $LogFile" -ForegroundColor Green

# Fonction pour lire les X dernières lignes du fichier
function Get-NewLogs {
    param([int]$LastSize)
    $CurrentSize = (Get-Item $LogFile).Length
    
    if ($CurrentSize -eq $LastSize) { return @(), $LastSize }
    if ($CurrentSize -lt $LastSize) { $LastSize = 0 } # Fichier tournant (rotation)

    # Lire seulement la nouvelle partie du fichier
    $stream = [System.IO.File]::Open($LogFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $stream.Seek($LastSize, [System.IO.SeekOrigin]::Begin) | Out-Null
    $reader = New-Object System.IO.StreamReader($stream)
    $content = $reader.ReadToEnd()
    $reader.Close()
    $stream.Close()

    $lines = $content -split "`r`n" | Where-Object { $_ -ne "" }
    return $lines, $CurrentSize
}

$LastFileSize = (Get-Item $LogFile).Length

while ($true) {
    Start-Sleep -Seconds 2 # Vérifie toutes les 2 secondes

    $newLogs, $LastFileSize = Get-NewLogs -LastSize $LastFileSize

    if ($newLogs.Count -gt 0) {
        $batch = @()
        foreach ($line in $newLogs) {
            try {
                $jsonObj = $line | ConvertFrom-Json
                $batch += $jsonObj
            } catch {
                # Ignorer les lignes corrompues
            }
        }

        if ($batch.Count -gt 0) {
            $Payload = @{
                machine_id = $MachineId
                batch = $batch
            } | ConvertTo-Json -Depth 10

            try {
                $response = Invoke-RestMethod -Uri $ApiUrl -Method Post -Body $Payload -ContentType "application/json"
                Write-Host "[+] Batch de $($batch.Count) événements envoyé avec succès." -ForegroundColor Green
            } catch {
                Write-Host "[-] Erreur d'envoi à l'API : $_" -ForegroundColor Red
            }
        }
    }
}
