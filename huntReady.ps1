# ============================================================
#  huntReady-compagnon
#  Verificateur de telemetrie de detection Windows
#  Famille « Outils Compagnon »
# ============================================================

# --- Auto-elevation administrateur ---
$courant = [Security.Principal.WindowsIdentity]::GetCurrent()
$role    = [Security.Principal.WindowsPrincipal]::new($courant)
if (-not $role.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Relance avec les droits administrateur..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" `
                  -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
                  -Verb RunAs
    exit
}
Write-Host "[OK] Droits administrateur confirmes." -ForegroundColor Green

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# --- Bandeau d'accueil ---
Write-Host ""
Write-Host "===== huntReady-compagnon =====" -ForegroundColor DarkMagenta
Write-Host "Verificateur de telemetrie de detection" -ForegroundColor Gray
Write-Host ""

# ===== LES CONTROLES =====
# (les fonctions Test-* viendront ici)
function Test-PolitiqueAudit {

    # Sous-categories cles pour la chasse, identifiees par GUID (insensible a la langue Windows)
    $cibles = @(
        @{ Nom = "Creation de processus";           Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"; Niveau = "Success" },
        @{ Nom = "Ouverture de session";            Guid = "{0CCE9215-69AE-11D9-BED3-505054503030}"; Niveau = "Both"    },
        @{ Nom = "Fermeture de session";            Guid = "{0CCE9216-69AE-11D9-BED3-505054503030}"; Niveau = "Success" },
        @{ Nom = "Gestion des comptes utilisateur"; Guid = "{0CCE9235-69AE-11D9-BED3-505054503030}"; Niveau = "Both"    },
        @{ Nom = "Changement de strategie d'audit"; Guid = "{0CCE922F-69AE-11D9-BED3-505054503030}"; Niveau = "Both"    },
        @{ Nom = "Validation des credentials";      Guid = "{0CCE923F-69AE-11D9-BED3-505054503030}"; Niveau = "Both"    }
    )

    $sortie = auditpol /get /category:* /r 2>$null
    if (-not $sortie -or $sortie.Count -lt 2) {
        return @{
            Nom = "Politique d'audit"; Categorie = "Politique d'audit"
            Etat = "Critique"; Poids = 3
            Valeur = "Impossible de lire la politique d'audit (auditpol n'a rien renvoye)."
            Risque = "Sans politique d'audit, Wazuh ne recoit aucun evenement de securite."
            Action = "Verifier les droits administrateur."
        }
    }

    # On force nos propres en-tetes (l'en-tete d'auditpol peut etre traduit selon la langue)
    $table = $sortie | Select-Object -Skip 1 |
             ConvertFrom-Csv -Header "MachineName","Policy","Subcategory","Guid","Inclusion","Exclusion"

    # Regex tolerantes FR/EN sur les valeurs ("Success" / "Réussite", "Failure" / "Échec")
    $regSuccess = 'success|succ.s|r.ussite'
    $regFailure = 'failure|.chec'

    $insuffisants = @()
    $details      = @()

    foreach ($c in $cibles) {
        $ligne = $table | Where-Object { $_.Guid -eq $c.Guid } | Select-Object -First 1
        if (-not $ligne) {
            $insuffisants += $c.Nom
            $details      += "  - {0} : sous-categorie introuvable (GUID a verifier)" -f $c.Nom
            continue
        }
        $regle     = $ligne.Inclusion.Trim()
        $okSuccess = $regle -match $regSuccess
        $okFailure = $regle -match $regFailure
        $ok        = if ($c.Niveau -eq "Both") { $okSuccess -and $okFailure } else { $okSuccess }

        $details += "  - {0} : {1}" -f $c.Nom, $regle
        if (-not $ok) { $insuffisants += $c.Nom }
    }

    if ($insuffisants.Count -eq 0) {
        $etat   = "Conforme"
        $valeur = "Toutes les sous-categories cles sont auditees correctement :`n" + ($details -join "`n")
        $risque = ""
        $action = ""
    }
    else {
        $etat   = if ($insuffisants.Count -ge 3) { "Critique" } else { "Attention" }
        $valeur = "Etat des sous-categories cles :`n" + ($details -join "`n") +
                  "`n  -> A renforcer : " + ($insuffisants -join ", ")
        $risque = "Les techniques MITRE qui s'expriment via ces sous-categories ne genereront pas d'evenements - Wazuh sera aveugle dessus."
        $action = "Activer via GPO (Configuration ordinateur > Strategies > Parametres Windows > Parametres de securite > Configuration avancee de la strategie d'audit), ou en local : auditpol /set /subcategory:'<nom>' /success:enable /failure:enable"
    }

    return @{
        Nom       = "Politique d'audit (sous-categories cles)"
        Categorie = "Politique d'audit"
        Etat      = $etat
        Poids     = 3
        Valeur    = $valeur
        Risque    = $risque
        Action    = $action
    }
}

function Test-CreationProcessusCmdLine {

    $cle    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $nom    = "ProcessCreationIncludeCmdLine_Enabled"
    $valeur = $null
    try {
        $valeur = (Get-ItemProperty -Path $cle -Name $nom -ErrorAction Stop).$nom
    } catch {
        $valeur = $null
    }

    if ($valeur -eq 1) {
        return @{
            Nom       = "Capture de la ligne de commande dans 4688"
            Categorie = "Création de processus"
            Etat      = "Conforme"
            Poids     = 3
            Valeur    = "ProcessCreationIncludeCmdLine_Enabled = 1 : les evenements 4688 contiennent la ligne de commande complete."
            Risque    = ""
            Action    = ""
        }
    } else {
        $val = if ($null -eq $valeur) { "non defini (par defaut : 0)" } else { "$valeur" }
        return @{
            Nom       = "Capture de la ligne de commande dans 4688"
            Categorie = "Création de processus"
            Etat      = "Critique"
            Poids     = 3
            Valeur    = "ProcessCreationIncludeCmdLine_Enabled = $val : la ligne de commande n'est PAS capturee."
            Risque    = "Wazuh voit qu'un processus s'est cree, mais pas avec quels arguments - impossible de detecter '-EncodedCommand', 'cmd /c whoami', les LOLBins parametres, l'execution de scripts a distance."
            Action    = "Activer en local : reg add `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f. Ou via GPO : Configuration ordinateur > Modeles d'administration > Systeme > Audit de creation de processus > Inclure la ligne de commande dans les evenements de creation de processus."
        }
    }
}

function Test-JournalisationPowerShell {

    # Les trois reglages PowerShell utiles a la chasse
    $reglages = @(
        @{ Nom = "ScriptBlock Logging (evenements 4104)";
           Chemin = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
           Valeur = "EnableScriptBlockLogging";
           Critique = $true },
        @{ Nom = "Module Logging";
           Chemin = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging";
           Valeur = "EnableModuleLogging";
           Critique = $false },
        @{ Nom = "Transcription";
           Chemin = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription";
           Valeur = "EnableTranscripting";
           Critique = $false }
    )

    $details          = @()
    $scriptBlockActif = $false
    $tousActifs       = $true

    foreach ($r in $reglages) {
        $v = $null
        try {
            $v = (Get-ItemProperty -Path $r.Chemin -Name $r.Valeur -ErrorAction Stop).$($r.Valeur)
        } catch {
            $v = $null
        }
        $actif = ($v -eq 1)
        if (-not $actif) { $tousActifs = $false }
        if ($r.Critique -and $actif) { $scriptBlockActif = $true }

        $etiquette = if ($actif) { "actif" } else { "inactif" }
        $details += "  - {0} : {1}" -f $r.Nom, $etiquette
    }

    if (-not $scriptBlockActif) {
        $etat   = "Critique"
        $valeur = "Etat des reglages PowerShell :`n" + ($details -join "`n")
        $risque = "Sans ScriptBlock Logging, Wazuh ne voit pas le code PowerShell execute - aucune detection sur le 'fileless' (T1059.001), Empire, PowerSploit, Cobalt Strike, scripts encodes."
        $action = "Activer via GPO (Modeles d'administration > Composants Windows > Windows PowerShell > Activer la journalisation des blocs de scripts). Ou en local : New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force ; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force"
    }
    elseif (-not $tousActifs) {
        $etat   = "Attention"
        $valeur = "Etat des reglages PowerShell :`n" + ($details -join "`n")
        $risque = "ScriptBlock Logging est actif (l'essentiel), mais Module Logging et/ou Transcription completent utilement la visibilite."
        $action = "Activer egalement Module Logging et Transcription via les memes cles registre (EnableModuleLogging et EnableTranscripting a 1)."
    }
    else {
        $etat   = "Conforme"
        $valeur = "Telemetrie PowerShell complete :`n" + ($details -join "`n")
        $risque = ""
        $action = ""
    }

    return @{
        Nom       = "Journalisation PowerShell"
        Categorie = "Journalisation PowerShell"
        Etat      = $etat
        Poids     = 3
        Valeur    = $valeur
        Risque    = $risque
        Action    = $action
    }
}

function Test-Sysmon {

    # Sysmon peut s'installer sous differents noms : Sysmon64, Sysmon, ou nom personnalise
    $service = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $service) {
        return @{
            Nom       = "Sysmon"
            Categorie = "Sysmon"
            Etat      = "Critique"
            Poids     = 2
            Valeur    = "Sysmon n'est pas installe sur ce poste."
            Risque    = "Sans Sysmon, la telemetrie de chasse reste tres pauvre. Sysmon enrichit massivement les evenements : creations de processus avec hash et parent, connexions reseau (event 3), chargements de DLL (event 7), threads distants (event 8 - injection classique), acces LSASS (event 10), creations de fichiers (event 11)."
            Action    = "Telecharger Sysmon depuis Microsoft Sysinternals (https://learn.microsoft.com/sysinternals/downloads/sysmon) et l'installer avec une configuration eprouvee (SwiftOnSecurity ou Olaf Hartong recommandes) : Sysmon64.exe -accepteula -i <config.xml>"
        }
    }

    $nomService = $service.Name
    $statut     = $service.Status

    # Tentative de recuperer la version du binaire
    $version = $null
    try {
        $cheminExe = (Get-CimInstance Win32_Service -Filter "Name='$nomService'").PathName
        if ($cheminExe) {
            $cheminExe = $cheminExe -replace '^"', '' -replace '".*$', ''
            if (Test-Path $cheminExe) {
                $version = (Get-Item $cheminExe).VersionInfo.FileVersion
            }
        }
    } catch { $version = $null }

    $versionTxt = if ($version) { "version $version" } else { "version inconnue" }

    if ($statut -ne "Running") {
        return @{
            Nom       = "Sysmon"
            Categorie = "Sysmon"
            Etat      = "Critique"
            Poids     = 2
            Valeur    = "Sysmon installe ($nomService, $versionTxt) mais service a l'arret (statut : $statut)."
            Risque    = "Sysmon arrete ne genere aucun evenement. Le SOC ne recoit rien de Sysmon."
            Action    = "Demarrer le service : Start-Service $nomService ; Set-Service $nomService -StartupType Automatic"
        }
    }

    return @{
        Nom       = "Sysmon"
        Categorie = "Sysmon"
        Etat      = "Conforme"
        Poids     = 2
        Valeur    = "Sysmon installe et actif ($nomService, $versionTxt)."
        Risque    = ""
        Action    = "Verifier periodiquement que la configuration appliquee est a jour : '$nomService.exe -c' affiche la configuration en vigueur."
    }
}

function Test-CentralisationLogs {

    # Cherche un agent Wazuh (nom de service variable selon les versions)
    $service = Get-Service -Name "*Wazuh*","*Ossec*" -ErrorAction SilentlyContinue |
               Where-Object { $_ } | Select-Object -First 1

    if (-not $service) {
        return @{
            Nom       = "Centralisation des logs (Wazuh)"
            Categorie = "Centralisation"
            Etat      = "Critique"
            Poids     = 3
            Valeur    = "Aucun agent Wazuh detecte sur ce poste."
            Risque    = "Sans agent de centralisation, les evenements de securite restent confines sur la machine. Aucune chasse de menaces ni correlation possible depuis le SOC, peu importe ce que captent les autres reglages."
            Action    = "Installer l'agent Wazuh (https://documentation.wazuh.com/current/installation-guide/wazuh-agent/). Alternative : configurer Windows Event Forwarding (WEF) vers un collecteur central."
        }
    }

    $statut = $service.Status
    $nom    = $service.Name

    # Tentative de recuperer la version (cles registre selon installation)
    $version = $null
    foreach ($cle in @(
        "HKLM:\SOFTWARE\Wazuh Inc.\Wazuh Agent",
        "HKLM:\SOFTWARE\WOW6432Node\Wazuh Inc.\Wazuh Agent",
        "HKLM:\SOFTWARE\ossec"
    )) {
        if (Test-Path $cle) {
            try {
                $props = Get-ItemProperty -Path $cle -ErrorAction Stop
                if ($props.Version) { $version = $props.Version; break }
            } catch {}
        }
    }
    $versionTxt = if ($version) { "version $version" } else { "version inconnue" }

    if ($statut -eq "Running") {
        return @{
            Nom       = "Centralisation des logs (Wazuh)"
            Categorie = "Centralisation"
            Etat      = "Conforme"
            Poids     = 3
            Valeur    = "Agent Wazuh installe et actif ($nom, $versionTxt)."
            Risque    = ""
            Action    = "Verifier periodiquement dans la console Wazuh que ce poste apparait comme 'active' et envoie des evenements regulierement."
        }
    }

    return @{
        Nom       = "Centralisation des logs (Wazuh)"
        Categorie = "Centralisation"
        Etat      = "Critique"
        Poids     = 3
        Valeur    = "Agent Wazuh installe ($nom, $versionTxt) mais service a l'arret (statut : $statut)."
        Risque    = "Agent present mais arrete : aucun evenement ne remonte au SOC. Wazuh est aveugle sur ce poste."
        Action    = "Demarrer le service : Start-Service $nom ; Set-Service $nom -StartupType Automatic. En cas d'erreur, consulter ossec.log dans le dossier d'installation Wazuh."
    }
}

function Test-CapaciteJournaux {
    # Categorie : Capacite des journaux
    # Verifie que les Event Logs critiques pour la chasse SOC ont une taille
    # suffisante pour conserver l'historique. Par defaut Security = 20 Mo,
    # ce qui represente quelques heures de retention sur un poste actif.

    $seuilCritique  = 50
    $seuilAttention = 100

    $logsACibler = @(
        @{ Nom = "Security";                                 Court = "Security"   },
        @{ Nom = "Microsoft-Windows-PowerShell/Operational"; Court = "PowerShell" },
        @{ Nom = "Microsoft-Windows-Sysmon/Operational";     Court = "Sysmon"     }
    )

    $details   = @()
    $piresEtat = "Conforme"

    foreach ($l in $logsACibler) {
        try {
            $log = Get-WinEvent -ListLog $l.Nom -ErrorAction Stop
            $tailleMo = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
            $details += "- $($l.Court) : $tailleMo Mo (mode $($log.LogMode))"

            if ($tailleMo -lt $seuilCritique) {
                $piresEtat = "Critique"
            } elseif ($tailleMo -lt $seuilAttention -and $piresEtat -eq "Conforme") {
                $piresEtat = "Attention"
            }
        }
        catch {
            if ($l.Court -eq "Sysmon") {
                $details += "- Sysmon : journal absent (Sysmon non installé - voir contrôle dédié)"
            } else {
                $details += "- $($l.Court) : journal introuvable"
                $piresEtat = "Critique"
            }
        }
    }

    $valeur = "Tailles maximales des journaux d'événements critiques pour la chasse SOC :`n" + ($details -join "`n") + "`n`nSeuils huntReady : Conforme ≥ 100 Mo, Attention 50-99 Mo, Critique < 50 Mo."

    switch ($piresEtat) {
        "Critique" {
            $risque = "Avec ces tailles, les journaux sont écrasés en quelques heures sur un poste actif. La chasse rétroactive du SOC perd son historique avant même que les règles aient eu le temps de corréler les événements. Les attaques 'low and slow' (mouvement latéral lent, brute force discret, persistance différée) passent sous les radars."
            $action = "Sur poste dans un domaine : via GPO (Computer Configuration > Policies > Windows Settings > Security Settings > Event Log > Maximum log size).`n`nSur poste hors domaine ou pour un correctif immédiat : ouvrir PowerShell en admin et exécuter :`n  wevtutil sl Security /ms:268435456`n  wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:104857600`n  wevtutil sl 'Microsoft-Windows-Sysmon/Operational' /ms:104857600`n`nAlternative graphique hors domaine : gpedit.msc > Configuration ordinateur > Modèles d'administration > Composants Windows > Service Journal des événements. Recommandation : 256 Mo pour Security, 100 Mo pour les autres. Le mode Circular (par défaut) doit être conservé pour éviter la saturation disque."
        }
        "Attention" {
            $risque = "Certains journaux ont une taille un peu juste. Sur les postes les plus actifs, la chasse rétroactive peut perdre quelques jours d'historique après un pic d'activité (compromission en cours, effacement de logs par un attaquant)."
            $action = "Porter la taille minimale à 100 Mo pour tous les journaux cibles, idéalement 256 Mo pour la Security log."
        }
        default {
            $risque = ""
            $action = "Vérifier périodiquement que les GPO de taille de log restent appliquées après une mise à jour majeure de Windows."
        }
    }

    return @{
        Nom       = "Capacité des journaux"
        Categorie = "Capacité des journaux"
        Poids     = 2
        Etat      = $piresEtat
        Valeur    = $valeur
        Risque    = $risque
        Action    = $action
    }
}

# ===== AFFICHAGE D'UN RESULTAT =====
function Show-Resultat($r) {
    switch ($r.Etat) {
        "Conforme"    { $couleur = "Green" }
        "Attention"   { $couleur = "DarkYellow" }
        "Critique"    { $couleur = "Red" }
        "Information" { $couleur = "Cyan" }
        default       { $couleur = "Gray" }
    }
    Write-Host ("[{0}] {1}" -f $r.Etat, $r.Nom) -ForegroundColor $couleur
    Write-Host ("    {0}" -f $r.Valeur) -ForegroundColor Gray
}

# ===== CALCUL ET AFFICHAGE DU SCORE =====
function Get-Score($resultats) {
    $totalMax    = 0
    $totalObtenu = 0
    foreach ($r in $resultats) {
        if ($r.Poids -lt 1) { continue }   # les controles purement informatifs sont exclus
        $totalMax += $r.Poids
        switch ($r.Etat) {
            "Conforme"  { $totalObtenu += $r.Poids }
            "Attention" { $totalObtenu += ($r.Poids / 2) }
            "Critique"  { $totalObtenu += 0 }
        }
    }
    if ($totalMax -eq 0) { return 0 }
    return [math]::Round(($totalObtenu / $totalMax) * 100)
}

function Show-Score($score) {
    if     ($score -ge 80) { $couleur = "Green";      $verdict = "Bonne posture de chasse" }
    elseif ($score -ge 50) { $couleur = "DarkYellow"; $verdict = "Posture moyenne - a renforcer" }
    else                   { $couleur = "Red";        $verdict = "Posture faible - urgences a corriger" }

    Write-Host ""
    Write-Host "===== SCORE GLOBAL =====" -ForegroundColor DarkMagenta
    Write-Host ("Score : {0} %  -  {1}" -f $score, $verdict) -ForegroundColor $couleur
    Write-Host ""
}

# ===== GENERATION DU RAPPORT HTML =====

# ===== GENERATION DU RAPPORT HTML =====

function ConvertTo-HtmlSafe($texte) {
    if ($null -eq $texte) { return "" }
    return ([string]$texte) -replace '&','&amp;' `
                            -replace '<','&lt;' `
                            -replace '>','&gt;' `
                            -replace '"','&quot;' `
                            -replace "`n",'<br>'
}

function Repair-AccentsAuditpol($texte) {
    if ($null -eq $texte) { return "" }
    # auditpol ecrit en codepage OEM : on repare les accents les plus frequents.
    # Les '.' regex couvrent les variantes (caractere correct ou remplacement).
    $t = [string]$texte
    $t = $t -replace 'Succ.s',      'Succès'
    $t = $t -replace 'succ.s',      'succès'
    $t = $t -replace 'R.ussite',    'Réussite'
    $t = $t -replace 'r.ussite',    'réussite'
    $t = $t -replace 'Échec',       'Échec'
    $t = $t -replace '.chec',       'échec'
    $t = $t -replace 'Pas daudit',  "Pas d'audit"
    $t = $t -replace "Pas d.audit", "Pas d'audit"
    $t = $t -replace 'Cr.ation',    'Création'
    $t = $t -replace 'cr.ation',    'création'
    $t = $t -replace 'Strat.gie',   'Stratégie'
    $t = $t -replace 'strat.gie',   'stratégie'
    return $t
}

function Get-TechniquesMITRE($categorie) {
    switch ($categorie) {
        "Politique d'audit" {
            return @(
                @{ Id = "T1078";     Nom = "Valid Accounts" },
                @{ Id = "T1110";     Nom = "Brute Force" },
                @{ Id = "T1136";     Nom = "Create Account" },
                @{ Id = "T1098";     Nom = "Account Manipulation" },
                @{ Id = "T1562.002"; Nom = "Disable Windows Event Logging" }
            )
        }
        "Création de processus" {
            return @(
                @{ Id = "T1059";     Nom = "Command and Scripting Interpreter" },
                @{ Id = "T1218";     Nom = "Signed Binary Proxy Execution (LOLBins)" },
                @{ Id = "T1027";     Nom = "Obfuscated Files / EncodedCommand" },
                @{ Id = "T1105";     Nom = "Ingress Tool Transfer" }
            )
        }
        "Journalisation PowerShell" {
            return @(
                @{ Id = "T1059.001"; Nom = "PowerShell" },
                @{ Id = "T1027.010"; Nom = "Command Obfuscation" },
                @{ Id = "T1140";     Nom = "Deobfuscate/Decode Files" },
                @{ Id = "T1620";     Nom = "Reflective Code Loading" }
            )
        }
        "Sysmon" {
            return @(
                @{ Id = "T1055";     Nom = "Process Injection" },
                @{ Id = "T1003.001"; Nom = "LSASS Memory Dumping" },
                @{ Id = "T1071";     Nom = "C2 sur protocoles applicatifs" },
                @{ Id = "T1574.001"; Nom = "DLL Search Order Hijacking" }
            )
        }

        "Capacité des journaux" {
            return @(
                @{ Id = "T1070.001"; Nom = "Clear Windows Event Logs" },
                @{ Id = "T1078";     Nom = "Valid Accounts (logons lents et discrets)" },
                @{ Id = "T1110";     Nom = "Brute Force (attaques lentes)" },
                @{ Id = "T1098";     Nom = "Account Manipulation (changements différés)" }
            )
        }

        "Centralisation" {
            return @(
                @{ Id = "*"; Nom = "Toutes les techniques détectées localement — sans remontée au SIEM, aucune corrélation possible" }
            )
        }
        default { return @() }
    }
}

function Get-ScoreParCategorie($resultats) {
    $sc = [ordered]@{}
    $categories = $resultats | ForEach-Object { $_.Categorie } | Select-Object -Unique
    foreach ($cat in $categories) {
        $ctrl = $resultats | Where-Object { $_.Categorie -eq $cat -and $_.Poids -gt 0 }
        if ($ctrl.Count -eq 0) { $sc[$cat] = $null; continue }
        $max = 0; $obtenu = 0
        foreach ($r in $ctrl) {
            $max += $r.Poids
            switch ($r.Etat) {
                "Conforme"  { $obtenu += $r.Poids }
                "Attention" { $obtenu += ($r.Poids / 2) }
                "Critique"  { $obtenu += 0 }
            }
        }
        $sc[$cat] = if ($max -eq 0) { $null } else { [math]::Round(($obtenu / $max) * 100) }
    }
    return $sc
}

function New-RapportHtml($resultats, $score) {
    $dateGen  = (Get-Date).ToString("dd/MM/yyyy 'à' HH:mm")
    $nomPoste = $env:COMPUTERNAME

    if     ($score -ge 80) { $niveau = "bon";    $verdictTitre = "$nomPoste parle correctement au SOC." }
    elseif ($score -ge 50) { $niveau = "moyen";  $verdictTitre = "$nomPoste n'est qu'à moitié audible." }
    else                   { $niveau = "faible"; $verdictTitre = "$nomPoste est silencieux : aucun SIEM ne peut le voir." }

    $nbConforme  = @($resultats | Where-Object { $_.Etat -eq "Conforme"  }).Count
    $nbAttention = @($resultats | Where-Object { $_.Etat -eq "Attention" }).Count
    $nbCritique  = @($resultats | Where-Object { $_.Etat -eq "Critique"  }).Count

    if ($nbCritique -gt 0) {
        $verdictProse = "<strong>$nbCritique capteur(s) sont en état critique.</strong> Les techniques MITRE qui s'expriment via ces canaux pourraient s'exécuter sans laisser de trace exploitable côté SOC."
    } elseif ($nbAttention -gt 0) {
        $verdictProse = "<strong>$nbConforme capteur(s) sur $($resultats.Count) sont conformes.</strong> Il reste $nbAttention point(s) à renforcer pour une couverture complète."
    } else {
        $verdictProse = "<strong>Tous les capteurs sont en place.</strong> La télémétrie de chasse est complète sur ce poste."
    }

    $maillons = @(
        @{ Nom = "Génération";     Sub = "Politique d'audit";       Cat = "Politique d'audit"        },
        @{ Nom = "Capture";        Sub = "Ligne de commande 4688";  Cat = "Création de processus"    },
        @{ Nom = "Journalisation"; Sub = "PowerShell";              Cat = "Journalisation PowerShell"},
        @{ Nom = "Enrichissement"; Sub = "Sysmon";                  Cat = "Sysmon"                   },
        @{ Nom = "Centralisation"; Sub = "Agent vers le SOC";       Cat = "Centralisation"           }
    )

    $maillonsHtml    = ""
    $premierCritique = -1
    for ($i = 0; $i -lt $maillons.Count; $i++) {
        $m    = $maillons[$i]
        $ctrl = $resultats | Where-Object { $_.Categorie -eq $m.Cat } | Select-Object -First 1
        if (-not $ctrl) {
            $etat = "vide"; $icone = "−"
        } else {
            switch ($ctrl.Etat) {
                "Conforme"  { $etat = "conforme";  $icone = "✓" }
                "Attention" { $etat = "attention"; $icone = "!" }
                "Critique"  { $etat = "critique";  $icone = "✗"
                              if ($premierCritique -lt 0) { $premierCritique = $i + 1 } }
                default     { $etat = "vide";      $icone = "−" }
            }
        }
        $numero = $i + 1
        $maillonsHtml += "<div class='maillon maillon-$etat'><div class='maillon-icone'>$icone</div><div class='maillon-num'>$numero. $($m.Nom)</div><div class='maillon-sub'>$($m.Sub)</div></div>"
    }

    if ($premierCritique -gt 0) {
        $texteConclusion  = "<strong>La chaîne se brise au maillon $premierCritique.</strong> Les maillons en aval ne peuvent rien enrichir si la donnée n'est pas générée en amont."
        $classeConclusion = ""
    } else {
        $texteConclusion  = "<strong>Chaîne complète.</strong> Tes capteurs alimentent le SOC de bout en bout."
        $classeConclusion = "ok"
    }

    $fichesHtml = ""
    $index = 1
    foreach ($r in $resultats) {
        $valeurPropre = Repair-AccentsAuditpol $r.Valeur
        $risquePropre = Repair-AccentsAuditpol $r.Risque
        $actionPropre = Repair-AccentsAuditpol $r.Action

        $badgeClasse = switch ($r.Etat) {
            "Conforme"    { "badge-conforme" }
            "Attention"   { "badge-attention" }
            "Critique"    { "badge-critique" }
            "Information" { "badge-information" }
            default       { "badge-information" }
        }
        $etatUpper      = $r.Etat.ToUpper()
        $numStr         = "{0:D2}" -f $index
        $openAttr       = if ($r.Etat -eq "Critique") { " open" } else { "" }
        $classeCritique = if ($r.Etat -eq "Critique") { " fiche-critique" } else { "" }

        $fichesHtml += "    <details class='fiche$classeCritique'$openAttr>`n"
        $fichesHtml += "      <summary class='fiche-entete'>`n"
        $fichesHtml += "        <div class='fiche-numero'><div class='fiche-numero-label'>Fiche</div><div class='fiche-numero-val'>$numStr</div></div>`n"
        $fichesHtml += "        <div class='fiche-titre-bloc'><h3 class='fiche-titre'>$(ConvertTo-HtmlSafe $r.Nom)</h3></div>`n"
        $fichesHtml += "        <div class='fiche-statut'><span class='badge $badgeClasse'>$etatUpper</span></div>`n"
        $fichesHtml += "        <div class='fiche-chevron' aria-hidden='true'></div>`n"
        $fichesHtml += "      </summary>`n"
        $fichesHtml += "      <div class='fiche-corps'>`n"
        $fichesHtml += "        <div class='fiche-valeur'>$(ConvertTo-HtmlSafe $valeurPropre)</div>`n"
        if ($risquePropre) {
            $fichesHtml += "        <div class='fiche-risque'><strong>Risque :</strong> $(ConvertTo-HtmlSafe $risquePropre)</div>`n"
        }

        # Section MITRE : seulement pour les controles non conformes
        if ($r.Etat -eq "Critique" -or $r.Etat -eq "Attention") {
            $techniques = Get-TechniquesMITRE $r.Categorie
            if ($techniques.Count -gt 0) {
                $mitreLabel = if ($r.Etat -eq "Critique") {
                    "Techniques MITRE ATT&amp;CK qui passeront inaperçues sans ce capteur"
                } else {
                    "Techniques MITRE ATT&amp;CK partiellement masquées sans renforcement"
                }
                $fichesHtml += "        <div class='fiche-mitre'>`n"
                $fichesHtml += "          <div class='fiche-mitre-label'>$mitreLabel</div>`n"
                $fichesHtml += "          <ul class='fiche-mitre-liste'>`n"
                foreach ($tech in $techniques) {
                    $fichesHtml += "            <li><span class='mitre-id'>$($tech.Id)</span><span class='mitre-nom'>$(ConvertTo-HtmlSafe $tech.Nom)</span></li>`n"
                }
                $fichesHtml += "          </ul>`n"
                $fichesHtml += "        </div>`n"
            }
        }

        if ($actionPropre) {
            $fichesHtml += "        <div class='fiche-action'><strong>Action :</strong> $(ConvertTo-HtmlSafe $actionPropre)</div>`n"
        }
        $fichesHtml += "      </div>`n"
        $fichesHtml += "    </details>`n"
        $index++
    }

    if ($premierCritique -gt 0) {
        $texteNote = "Commence par les capteurs en amont. Sans télémétrie générée à la source, les capteurs en aval n'ont rien à enrichir."
    } elseif ($nbAttention -gt 0) {
        $texteNote = "La majorité des capteurs sont en place. Les points en attention concernent surtout la complétude — à traiter dans un second temps."
    } else {
        $texteNote = "Tous les capteurs sont conformes. Penser à vérifier régulièrement que les GPO restent appliquées, surtout après les mises à jour majeures."
    }

    $catCapacite = $resultats | Where-Object { $_.Categorie -eq "Capacité des journaux" } | Select-Object -First 1
    $pipelineNote = if ($catCapacite) {
        "      <div class='pipeline-note'>À noter : la <strong>capacité des journaux</strong> n'apparaît pas dans la chaîne ci-dessus car ce n'est pas un maillon séquentiel, mais une <strong>dimension transversale</strong>. Elle conditionne la rétention historique de tous les événements générés par les capteurs de la chaîne — sans rétention suffisante, même les capteurs actifs perdent leur valeur passé quelques heures.</div>"
    } else { "" }

    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>huntReady - $nomPoste</title>
<link rel="stylesheet" href="rapport.css">
</head>
<body>
  <div class="conteneur">

    <header class="couverture">
      <div class="couverture-marque">
        <div class="mascotte"></div>
        <div class="couverture-textes">
          <div class="couverture-meta">Carnet de visibilité &middot; Famille Outils Compagnon</div>
          <h1 class="couverture-titre">huntReady-compagnon</h1>
          <div class="couverture-soustitre">&laquo; Le poste peut-il être vu par mon SOC ? &raquo;</div>
        </div>
      </div>
      <div class="couverture-droite">
        <div class="couverture-poste">Poste $nomPoste</div>
        <div>Inspection du $dateGen</div>
      </div>
    </header>

    <div class="intro-bandeau">
      <div class="intro-titre">Pourquoi ces capteurs sont essentiels</div>
      <div class="intro-texte">
        Toute détection moderne &mdash; <strong>Wazuh, Splunk, Sentinel, ELK, QRadar</strong> &mdash; repose sur la télémétrie générée par Windows lui-même. Si l'événement n'est pas enregistré à la source, aucun SIEM ne peut le détecter, peu importe la qualité des règles. <strong>Ces capteurs sont le pré-requis indispensable d'un SOC efficace</strong> : sans eux, ton SIEM est aveugle sur les techniques modernes (PowerShell offensif, LOLBins, mouvement latéral, injection LSASS&hellip;).
      </div>
    </div>

    <section class="verdict">
      <div class="sceau sceau-$niveau">
        <div class="sceau-score">$score</div>
        <div class="sceau-label">sur 100</div>
      </div>
      <div class="verdict-texte">
        <div class="verdict-meta">Verdict du chasseur</div>
        <h2 class="verdict-titre">$verdictTitre</h2>
        <p class="verdict-prose">$verdictProse</p>
      </div>
    </section>

    <section class="pipeline-bloc">
      <div class="section-titre">La chaîne de visibilité</div>
      <div class="pipeline">$maillonsHtml</div>
      <div class="pipeline-conclusion $classeConclusion">$texteConclusion</div>
    </section>

    <div class="section-separateur">
      <span class="section-separateur-label">Inventaire des capteurs</span>
      <div class="section-separateur-ligne"></div>
      <span class="section-separateur-count">$($resultats.Count) fiches</span>
    </div>

$fichesHtml
    <aside class="note-chasseur">
      <div class="note-icone">&#9998;</div>
      <div class="note-texte"><em class="note-prefix">Note du chasseur &mdash; </em>$texteNote</div>
    </aside>

    <footer class="pied">
      huntReady-compagnon &mdash; Famille &laquo; Outils Compagnon &raquo;<br>
      DOUKAKAS Yeni
    </footer>

  </div>
</body>
</html>
"@

    $chemin = Join-Path $PSScriptRoot "rapport.html"
    $html | Set-Content -Path $chemin -Encoding UTF8
    return $chemin
}

# ===== PROGRAMME PRINCIPAL =====
$controles = @(
    'Test-PolitiqueAudit',
    'Test-CreationProcessusCmdLine'
    'Test-JournalisationPowerShell'
    'Test-Sysmon'
    'Test-CentralisationLogs'
    'Test-CapaciteJournaux'
)

$resultats = @()
for ($i = 0; $i -lt $controles.Count; $i++) {
    $pct = [math]::Round((($i + 1) / $controles.Count) * 100)
    Write-Progress -Activity "Analyse de la telemetrie de detection" -Status "$pct %" -PercentComplete $pct
    $resultats += & $controles[$i]
}
Write-Progress -Activity "Analyse de la telemetrie de detection" -Completed

if ($resultats.Count -eq 0) {
    Write-Host "Aucun controle pour l'instant - squelette en place." -ForegroundColor Yellow
} else {
    foreach ($r in $resultats) { Show-Resultat $r }

    $score = Get-Score $resultats
    Show-Score $score

    $cheminRapport = New-RapportHtml $resultats $score
    Write-Host "[OK] Rapport genere : $cheminRapport" -ForegroundColor Green
    Invoke-Item $cheminRapport
}

Write-Host ""
$null = Read-Host "Appuyez sur Entree pour fermer cette fenetre"