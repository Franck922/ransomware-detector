<#
.SYNOPSIS
Relais de secours : lit le fichier NDJSON produit par Winlogbeat et le pousse
sur POST /ingest.

.DESCRIPTION
À n'utiliser que si la sortie Elasticsearch de Winlogbeat ne peut pas atteindre
l'API directement (proxy d'entreprise, version de Winlogbeat trop ancienne).
La configuration recommandée reste winlogbeat.yml en sortie directe : elle évite
ce processus intermédiaire et la latence du fichier tampon.

.EXAMPLE
$env:EDR_AGENT_TOKEN = '<token>'
.\forwarder.ps1 -ApiUrl http://192.168.10.1:8000
#>

param(
    [string]$ApiUrl      = $env:EDR_API_URL,
    [string]$AgentToken  = $env:EDR_AGENT_TOKEN,
    [string]$LogDir      = "C:\ProgramData\winlogbeat\logs",
    [int]   $PollSeconds = 2,
    [int]   $BatchMax    = 500
)

if (-not $ApiUrl) { $ApiUrl = "http://192.168.10.1:8000" }
if (-not $AgentToken) {
    Write-Host "[!] Token d'agent absent : definissez `$env:EDR_AGENT_TOKEN." -ForegroundColor Red
    exit 1
}

$ApiUrl    = $ApiUrl.TrimEnd('/')
$MachineId = $env:COMPUTERNAME
$Headers   = @{ "X-Agent-Token" = $AgentToken }

Write-Host "[*] Relais Winlogbeat -> $ApiUrl/ingest" -ForegroundColor Cyan
Write-Host "[*] Terminal : $MachineId" -ForegroundColor Gray

function Get-LatestLogFile {
    (Get-ChildItem -Path $LogDir -Filter "winlogbeat-output*.ndjson" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

$LogFile = Get-LatestLogFile
if (-not $LogFile) {
    Write-Host "[!] Aucun winlogbeat-output*.ndjson dans $LogDir." -ForegroundColor Red
    Write-Host "[!] Demarrez le service : Start-Service winlogbeat" -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Fichier surveille : $LogFile" -ForegroundColor Green

function Get-NewLines {
    param([string]$Path, [long]$Offset)

    $size = (Get-Item $Path).Length
    if ($size -eq $Offset) { return @(), $Offset }
    if ($size -lt $Offset) { $Offset = 0 }  # rotation du fichier

    # ReadWrite en partage : Winlogbeat garde le fichier ouvert en écriture.
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $stream.Seek($Offset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        $reader.Close()
    }
    finally {
        $stream.Dispose()
    }

    $lines = $content -split "`r?`n" | Where-Object { $_.Trim() -ne "" }
    return $lines, $size
}

function Send-Batch {
    param([array]$Events)

    $payload = @{ machine_id = $MachineId; batch = $Events } | ConvertTo-Json -Depth 12
    try {
        Invoke-RestMethod -Uri "$ApiUrl/ingest" -Method Post -Headers $Headers `
            -Body $payload -ContentType "application/json" -TimeoutSec 20 | Out-Null
        Write-Host "[+] $($Events.Count) evenements transmis." -ForegroundColor Green
        return $true
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -eq 401) {
            Write-Host "[!] Token d'agent refuse (401) : verifiez AGENT_TOKEN." -ForegroundColor Red
        }
        else {
            Write-Host "[-] Envoi impossible : $($_.Exception.Message)" -ForegroundColor Red
        }
        return $false
    }
}

$Offset = (Get-Item $LogFile).Length

while ($true) {
    Start-Sleep -Seconds $PollSeconds

    # Winlogbeat crée un nouveau fichier lors d'une rotation : on suit le plus récent.
    $current = Get-LatestLogFile
    if ($current -and $current -ne $LogFile) {
        Write-Host "[*] Rotation detectee, bascule sur $current" -ForegroundColor DarkCyan
        $LogFile = $current
        $Offset = 0
    }

    $lines, $Offset = Get-NewLines -Path $LogFile -Offset $Offset
    if ($lines.Count -eq 0) { continue }

    $batch = @()
    foreach ($line in $lines) {
        try { $batch += ($line | ConvertFrom-Json) } catch { }

        # Un pic d'activité (typiquement un chiffrement de masse) peut produire
        # des milliers de lignes : on découpe pour ne pas dépasser la limite de
        # taille de requête de l'API.
        if ($batch.Count -ge $BatchMax) {
            Send-Batch -Events $batch | Out-Null
            $batch = @()
        }
    }

    if ($batch.Count -gt 0) { Send-Batch -Events $batch | Out-Null }
}
