# ==============================================================================
# AGENT DE RÉPONSE EDR
# ==============================================================================
# Tourne en continu sur chaque poste surveillé et exécute les ordres déposés par
# le serveur : arrêt de processus, isolation réseau, levée d'isolation.
#
# Différences avec la version précédente :
#   - authentification par token : la file de commandes n'est plus lisible par
#     n'importe qui sur le réseau (auparavant, un poste compromis pouvait
#     dépiler l'ordre KILL qui le visait pour ne jamais l'exécuter) ;
#   - filtrage par machine : on ne récupère que les ordres destinés à ce poste ;
#   - acquittement : le serveur sait si l'action a réussi, et l'analyste le voit
#     dans le journal des réponses. Sans cela, une commande partie dans le vide
#     restait indistinguable d'une commande exécutée ;
#   - action UNISOLATE, pour rendre un poste au réseau après investigation.
# ==============================================================================

param(
    [string]$ApiUrl    = $env:EDR_API_URL,
    [string]$AgentToken = $env:EDR_AGENT_TOKEN,
    [int]   $PollSeconds = 2
)

if (-not $ApiUrl)     { $ApiUrl = "http://192.168.10.1:8000" }
if (-not $AgentToken) {
    Write-Host "[!] Token d'agent absent." -ForegroundColor Red
    Write-Host "    Definissez `$env:EDR_AGENT_TOKEN avec la valeur d'AGENT_TOKEN du serveur," -ForegroundColor Yellow
    Write-Host "    ou lancez : .\agent_ps.ps1 -AgentToken '<token>'" -ForegroundColor Yellow
    exit 1
}

$ApiUrl   = $ApiUrl.TrimEnd('/')
$MachineId = $env:COMPUTERNAME
$Headers  = @{ "X-Agent-Token" = $AgentToken }

# Port de l'API, réautorisé dans le pare-feu pendant l'isolation : sans cette
# exception, le poste isolé ne pourrait plus recevoir l'ordre de désisolation.
$ApiPort = ([System.Uri]$ApiUrl).Port
$IsolationRuleName = "EDR - Canal de controle"

function Write-Section {
    param([string]$Title, [string]$Color = "Red")
    Write-Host ""
    Write-Host ("=" * 46) -ForegroundColor $Color
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Host ("=" * 46) -ForegroundColor $Color
}

function Send-Ack {
    param([int]$CommandId, [bool]$Success, [string]$Message)
    try {
        $body = @{
            command_id = $CommandId
            success    = $Success
            message    = $Message
        } | ConvertTo-Json
        Invoke-RestMethod -Uri "$ApiUrl/agent/commands/ack" -Method Post `
            -Headers $Headers -Body $body -ContentType "application/json" -TimeoutSec 5 | Out-Null
    }
    catch {
        Write-Host "  [!] Acquittement impossible : $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

function Invoke-Kill {
    param($Command)

    $payload = $Command.payload
    $pidTarget = $Command.pid

    Write-Section "REPONSE EDR - ARRET DE PROCESSUS"
    Write-Host ""
    Write-Host "Processus : " -ForegroundColor Yellow -NoNewline
    Write-Host "$($payload.process) (PID $pidTarget)" -ForegroundColor White

    if ($payload.parent) {
        Write-Host "Parent    : " -ForegroundColor Yellow -NoNewline
        Write-Host "$($payload.parent) ($($payload.parent_pid))" -ForegroundColor Gray
    }

    if ($payload.score) {
        Write-Host "Score     : " -ForegroundColor Yellow -NoNewline
        Write-Host "$($payload.score) / 100  ($($payload.confidence))" -ForegroundColor Red
    }

    if ($payload.reasons) {
        Write-Host ""
        Write-Host "Indices retenus :" -ForegroundColor Yellow
        foreach ($reason in $payload.reasons) {
            Write-Host "  - $reason" -ForegroundColor DarkRed
        }
    }

    Write-Host ""

    if (-not $pidTarget) {
        Write-Host "  ECHEC : aucun PID cible dans l'ordre recu." -ForegroundColor Red
        Send-Ack -CommandId $Command.command_id -Success $false -Message "Ordre sans PID cible"
        return
    }

    # Frappe par PID en priorité : arrêter par nom tuerait aussi les instances
    # légitimes du même binaire (svchost.exe, powershell.exe...).
    try {
        Stop-Process -Id $pidTarget -Force -ErrorAction Stop
        Write-Host "  SUCCES : PID $pidTarget arrete." -ForegroundColor Green
        Send-Ack -CommandId $Command.command_id -Success $true -Message "PID $pidTarget arrete"
        return
    }
    catch {
        Write-Host "  PID introuvable (processus deja termine ?)." -ForegroundColor DarkYellow
    }

    if ($payload.process) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($payload.process)
        $running = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($running) {
            Stop-Process -Name $name -Force -ErrorAction SilentlyContinue
            Write-Host "  SUCCES : processus '$name' arrete par nom." -ForegroundColor Green
            Send-Ack -CommandId $Command.command_id -Success $true -Message "Arrete par nom : $name"
            return
        }
    }

    # Le processus n'existe plus : la menace n'est plus active, l'ordre est
    # considéré comme satisfait plutôt qu'en échec.
    Write-Host "  Processus deja absent : rien a arreter." -ForegroundColor Gray
    Send-Ack -CommandId $Command.command_id -Success $true -Message "Processus deja termine"
}

function Invoke-Isolate {
    param($Command)

    Write-Section "REPONSE EDR - ISOLATION RESEAU" "Magenta"
    try {
        netsh advfirewall set allprofiles state on | Out-Null
        netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
        netsh advfirewall firewall delete rule name="$IsolationRuleName" | Out-Null
        netsh advfirewall firewall add rule name="$IsolationRuleName" dir=out action=allow `
            protocol=TCP remoteport=$ApiPort | Out-Null

        Write-Host "  SUCCES : poste isole, seul le canal EDR (port $ApiPort) reste ouvert." -ForegroundColor Green
        Send-Ack -CommandId $Command.command_id -Success $true -Message "Isolation appliquee"
    }
    catch {
        Write-Host "  ECHEC : $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  (l'agent doit tourner en administrateur)" -ForegroundColor DarkYellow
        Send-Ack -CommandId $Command.command_id -Success $false -Message $_.Exception.Message
    }
}

function Invoke-Unisolate {
    param($Command)

    Write-Section "REPONSE EDR - LEVEE D'ISOLATION" "Cyan"
    try {
        netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
        netsh advfirewall firewall delete rule name="$IsolationRuleName" | Out-Null

        Write-Host "  SUCCES : connectivite reseau restauree." -ForegroundColor Green
        Send-Ack -CommandId $Command.command_id -Success $true -Message "Isolation levee"
    }
    catch {
        Write-Host "  ECHEC : $($_.Exception.Message)" -ForegroundColor Red
        Send-Ack -CommandId $Command.command_id -Success $false -Message $_.Exception.Message
    }
}

Write-Host ("=" * 46) -ForegroundColor DarkCyan
Write-Host "  AGENT EDR - DETECTION ET REPONSE" -ForegroundColor Cyan
Write-Host ("=" * 46) -ForegroundColor DarkCyan
Write-Host "[*] Serveur   : $ApiUrl" -ForegroundColor Gray
Write-Host "[*] Terminal  : $MachineId" -ForegroundColor Gray
Write-Host "[*] Intervalle: $PollSeconds s" -ForegroundColor Gray
Write-Host "[+] En attente d'ordres." -ForegroundColor Green

$authWarned = $false
$downWarned = $false

while ($true) {
    try {
        $command = Invoke-RestMethod -Method GET -TimeoutSec 5 -Headers $Headers `
            -Uri "$ApiUrl/agent/commands?machine_id=$([uri]::EscapeDataString($MachineId))"

        if ($downWarned) {
            Write-Host "[+] Liaison avec le serveur EDR retablie." -ForegroundColor Green
            $downWarned = $false
        }
        $authWarned = $false

        switch ($command.action) {
            "KILL"      { Invoke-Kill      -Command $command }
            "ISOLATE"   { Invoke-Isolate   -Command $command }
            "UNISOLATE" { Invoke-Unisolate -Command $command }
            "NONE"      { }
            default     {
                if ($command.command_id) {
                    Write-Host "[?] Action inconnue : $($command.action)" -ForegroundColor DarkYellow
                    Send-Ack -CommandId $command.command_id -Success $false `
                        -Message "Action non prise en charge par cet agent"
                }
            }
        }
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__

        # Un token invalide est une erreur de configuration : la signaler une
        # fois est utile, la répéter toutes les 2 secondes noierait la console.
        if ($status -eq 401 -and -not $authWarned) {
            Write-Host "[!] Token d'agent refuse par le serveur (401)." -ForegroundColor Red
            $authWarned = $true
        }
        elseif (-not $status -and -not $downWarned) {
            Write-Host "[!] Serveur EDR injoignable, nouvelle tentative en continu..." -ForegroundColor DarkYellow
            $downWarned = $true
        }
    }

    Start-Sleep -Seconds $PollSeconds
}
