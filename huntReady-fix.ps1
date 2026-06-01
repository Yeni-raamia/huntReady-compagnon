# ============================================================
#  huntReady-fix · Correcteur de télémétrie SOC
#  Famille Outils Compagnon — DOUKAKAS Yeni
#  Compagnon de huntReady-compagnon (v1.1)
#
#  Cet outil MODIFIE la configuration du poste pour le rendre
#  audible par le SOC. Il est volontairement séparé de
#  huntReady.ps1, qui reste strictement non destructif.
#  Rien n'est appliqué sans confirmation explicite, et l'état
#  d'origine est sauvegardé avant chaque modification.
# ============================================================

# ----- Auto-élévation administrateur -----
$identite  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identite)
$estAdmin  = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $estAdmin) {
    Write-Host "Cet outil a besoin des droits administrateur. Élévation en cours..." -ForegroundColor Yellow
    $hote = (Get-Process -Id $PID).Path
    Start-Process -FilePath $hote -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# ----- Encodage console en UTF-8 (accents et cadres corrects) -----
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ----- Bandeau d'accueil -----
$largeur = 54
$ligne   = "═" * $largeur
$titre   = "   huntReady-fix · Correcteur de télémétrie SOC"

Write-Host ""
Write-Host "  ╔$ligne╗" -ForegroundColor Magenta
Write-Host ("  ║" + $titre.PadRight($largeur) + "║") -ForegroundColor Magenta
Write-Host "  ╚$ligne╝" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Cet outil va proposer de corriger la configuration de" -ForegroundColor Gray
Write-Host "  télémétrie de ce poste afin de le rendre visible par le SOC." -ForegroundColor Gray
Write-Host ""
Write-Host "  Contrat de confiance :" -ForegroundColor White
Write-Host "   • Rien n'est appliqué sans ta confirmation explicite." -ForegroundColor Gray
Write-Host "   • L'état d'origine est sauvegardé avant chaque changement." -ForegroundColor Gray
Write-Host "   • Tu peux refuser n'importe quelle étape sans rien casser." -ForegroundColor Gray
Write-Host ""
Write-Host "  Poste : $env:COMPUTERNAME" -ForegroundColor Magenta
Write-Host ""

# ===== LES CORRECTIONS (ajoutées à l'étape suivante) =====
# ===== OUTILS PARTAGÉS =====

# Pose une question Oui/Non et renvoie $true ou $false.
function Confirm-Action {
    param([string]$Question)
    while ($true) {
        $reponse = (Read-Host "$Question (O/N)").Trim().ToUpper()
        if ($reponse -in 'O','OUI') { return $true }
        if ($reponse -in 'N','NON') { return $false }
        Write-Host "   Reponds par O (oui) ou N (non)." -ForegroundColor Yellow
    }
}

# Dossier de sauvegarde horodaté (créé seulement au premier usage)
$script:dossierSauvegarde = Join-Path $PSScriptRoot ("sauvegardes\sauvegarde-" + (Get-Date -Format "yyyyMMdd-HHmmss"))

# Enregistre l'état d'origine avant toute modification.
function Save-EtatOrigine {
    param([string]$NomFichier, [string]$Contenu)
    if (-not (Test-Path $script:dossierSauvegarde)) {
        New-Item -ItemType Directory -Path $script:dossierSauvegarde -Force | Out-Null
    }
    $chemin = Join-Path $script:dossierSauvegarde $NomFichier
    $Contenu | Out-File -FilePath $chemin -Encoding UTF8
    Write-Host "   Sauvegarde : $chemin" -ForegroundColor DarkGray
}


# ===== CORRECTION 1 : CAPACITÉ DU JOURNAL SECURITY =====
function Repair-CapaciteJournaux {
    $cible = 268435456

    Write-Host ""
    Write-Host "  --- Capacité du journal Security ---" -ForegroundColor Magenta

    $actuel   = (Get-WinEvent -ListLog "Security").MaximumSizeInBytes
    $actuelMo = [math]::Round($actuel / 1MB, 0)
    $cibleMo  = [math]::Round($cible  / 1MB, 0)
    $just     = "Conserve l'historique d'événements avant écrasement automatique."

    Write-Host "   Taille maximale actuelle : $actuelMo Mo" -ForegroundColor Gray

    if ($actuel -ge $cible) {
        Write-Host "   Déjà conforme (>= $cibleMo Mo). Rien à faire." -ForegroundColor Green
        return @{ Nom="Capacité du journal Security"; Maillon="Transversal"; Etat="DéjàConforme"; Avant="$actuelMo Mo"; Apres="$actuelMo Mo"; Justification=$just; Sauvegarde=""; Restauration="" }
    }

    Write-Host "   Recommandé : $cibleMo Mo (pour conserver plus d'historique)." -ForegroundColor Gray
    Write-Host ""

    if (-not (Confirm-Action "   Porter le journal Security à $cibleMo Mo ?")) {
        Write-Host "   Ignoré. Aucun changement." -ForegroundColor Yellow
        return @{ Nom="Capacité du journal Security"; Maillon="Transversal"; Etat="Ignorée"; Avant="$actuelMo Mo"; Apres="$actuelMo Mo"; Justification=$just; Sauvegarde=""; Restauration="" }
    }

    $cheminSauvegarde = Join-Path $script:dossierSauvegarde "journal-security-taille.txt"
    Save-EtatOrigine -NomFichier "journal-security-taille.txt" -Contenu @"
Journal      : Security
Taille avant : $actuel octets ($actuelMo Mo)
Pour revenir en arriere : wevtutil sl Security /ms:$actuel
"@

    wevtutil sl Security /ms:$cible | Out-Null

    $apres   = (Get-WinEvent -ListLog "Security").MaximumSizeInBytes
    $apresMo = [math]::Round($apres / 1MB, 0)
    if ($apres -ge $cible) {
        Write-Host "   ✓ Fait. Nouvelle taille maximale : $apresMo Mo" -ForegroundColor Green
    } else {
        Write-Host "   ✗ La taille n'a pas changé comme prévu ($apresMo Mo)." -ForegroundColor Red
    }

    return @{ Nom="Capacité du journal Security"; Maillon="Transversal"; Etat="Appliquée"; Avant="$actuelMo Mo"; Apres="$apresMo Mo"; Justification=$just; Sauvegarde=$cheminSauvegarde; Restauration="wevtutil sl Security /ms:$actuel" }
}


# ===== CORRECTION 2 : LIGNE DE COMMANDE DANS L'ÉVÉNEMENT 4688 =====
function Repair-CreationProcessusCmdLine {
    $cle = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $nom = "ProcessCreationIncludeCmdLine_Enabled"
    $just = "Le 4688 inclut la commande exécutée, pas seulement le nom du processus."

    Write-Host ""
    Write-Host "  --- Ligne de commande dans l'événement 4688 ---" -ForegroundColor Magenta

    $valeurActuelle = $null
    if (Test-Path $cle) {
        $prop = Get-ItemProperty -Path $cle -Name $nom -ErrorAction SilentlyContinue
        if ($prop) { $valeurActuelle = $prop.$nom }
    }

    if ($valeurActuelle -eq 1) {
        Write-Host "   Déjà conforme (activé). Rien à faire." -ForegroundColor Green
        return @{ Nom="Ligne de commande dans l'événement 4688"; Maillon="Capture"; Etat="DéjàConforme"; Avant="activé"; Apres="activé"; Justification=$just; Sauvegarde=""; Restauration="" }
    }

    $etatLisible = if ($null -eq $valeurActuelle) { "absent" } else { "désactivé" }
    Write-Host "   État actuel : $etatLisible" -ForegroundColor Gray
    Write-Host "   Sans ce réglage, l'event 4688 dit qu'un processus a démarré," -ForegroundColor Gray
    Write-Host "   mais pas AVEC QUELLE commande — le SOC est aveugle au contenu." -ForegroundColor Gray
    Write-Host ""

    if (-not (Confirm-Action "   Activer l'enregistrement de la ligne de commande ?")) {
        Write-Host "   Ignoré. Aucun changement." -ForegroundColor Yellow
        return @{ Nom="Ligne de commande dans l'événement 4688"; Maillon="Capture"; Etat="Ignorée"; Avant=$etatLisible; Apres=$etatLisible; Justification=$just; Sauvegarde=""; Restauration="" }
    }

    if ($null -eq $valeurActuelle) {
        $revert = "Remove-ItemProperty -Path '$cle' -Name '$nom'"
    } else {
        $revert = "New-ItemProperty -Path '$cle' -Name '$nom' -Value $valeurActuelle -PropertyType DWord -Force"
    }
    $cheminSauvegarde = Join-Path $script:dossierSauvegarde "process-cmdline.txt"
    Save-EtatOrigine -NomFichier "process-cmdline.txt" -Contenu @"
Cle   : $cle
Nom   : $nom
Avant : $etatLisible
Pour revenir en arriere : $revert
"@

    if (-not (Test-Path $cle)) { New-Item -Path $cle -Force | Out-Null }
    New-ItemProperty -Path $cle -Name $nom -Value 1 -PropertyType DWord -Force | Out-Null

    $apres = (Get-ItemProperty -Path $cle -Name $nom -ErrorAction SilentlyContinue).$nom
    if ($apres -eq 1) {
        Write-Host "   ✓ Fait. La ligne de commande sera incluse dans l'event 4688." -ForegroundColor Green
    } else {
        Write-Host "   ✗ Le réglage n'a pas pris (valeur : $apres)." -ForegroundColor Red
    }

    return @{ Nom="Ligne de commande dans l'événement 4688"; Maillon="Capture"; Etat="Appliquée"; Avant=$etatLisible; Apres="activé"; Justification=$just; Sauvegarde=$cheminSauvegarde; Restauration=$revert }
}


# ===== CORRECTION 3 : POLITIQUE D'AUDIT AVANCÉE =====
function Repair-PolitiqueAudit {
    Write-Host ""
    Write-Host "  --- Politique d'audit avancée ---" -ForegroundColor Magenta

    $cibles = @(
        @{ Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"; Nom = "Création de processus";                       Niveau = "Success" }
        @{ Guid = "{0CCE9215-69AE-11D9-BED3-505054503030}"; Nom = "Ouverture de session";                         Niveau = "Both"    }
        @{ Guid = "{0CCE9216-69AE-11D9-BED3-505054503030}"; Nom = "Fermeture de session";                         Niveau = "Success" }
        @{ Guid = "{0CCE9235-69AE-11D9-BED3-505054503030}"; Nom = "Gestion des comptes utilisateur";              Niveau = "Both"    }
        @{ Guid = "{0CCE922F-69AE-11D9-BED3-505054503030}"; Nom = "Changement de stratégie d'audit";              Niveau = "Both"    }
        @{ Guid = "{0CCE923F-69AE-11D9-BED3-505054503030}"; Nom = "Validation des informations d'identification"; Niveau = "Both"    }
    )
    $total = $cibles.Count
    $just  = "Décide quels événements Windows sont générés (sessions, comptes, processus)."

    $brut   = auditpol /get /category:* /r 2>$null
    $lignes = $brut | Where-Object { $_ -match '\S' } | Select-Object -Skip 1 |
              ConvertFrom-Csv -Header "Machine","Policy","Subcat","Guid","Inclusion","Exclusion"

    $aCorriger = @()
    $nbConforme = 0
    foreach ($c in $cibles) {
        $ligne = $lignes | Where-Object { $_.Guid -eq $c.Guid } | Select-Object -First 1
        $inclusion = if ($ligne) { $ligne.Inclusion } else { "" }
        $hasSuccess = $inclusion -match 'success|succ.s|r.ussite'
        $hasFailure = $inclusion -match 'failure|.chec'
        $besoinFailure = ($c.Niveau -eq "Both")
        if ($hasSuccess -and ((-not $besoinFailure) -or $hasFailure)) {
            $nbConforme++
            Write-Host ("   ✓ {0} : conforme" -f $c.Nom) -ForegroundColor Green
        } else {
            $attendu = if ($besoinFailure) { "Succès + Échec" } else { "Succès" }
            Write-Host ("   → {0} : à activer ({1})" -f $c.Nom, $attendu) -ForegroundColor Yellow
            $aCorriger += $c
        }
    }

    if ($aCorriger.Count -eq 0) {
        Write-Host "   Déjà conforme. Rien à faire." -ForegroundColor Green
        return @{ Nom="Politique d'audit avancée"; Maillon="Génération"; Etat="DéjàConforme"; Avant="$nbConforme / $total"; Apres="$nbConforme / $total"; Justification=$just; Sauvegarde=""; Restauration="" }
    }

    $avantTxt = "$nbConforme / $total"
    Write-Host ""
    if (-not (Confirm-Action ("   Activer les {0} sous-catégorie(s) manquante(s) ?" -f $aCorriger.Count))) {
        Write-Host "   Ignoré. Aucun changement." -ForegroundColor Yellow
        return @{ Nom="Politique d'audit avancée"; Maillon="Génération"; Etat="Ignorée"; Avant=$avantTxt; Apres=$avantTxt; Justification=$just; Sauvegarde=""; Restauration="" }
    }

    if (-not (Test-Path $script:dossierSauvegarde)) { New-Item -ItemType Directory -Path $script:dossierSauvegarde -Force | Out-Null }
    $cheminBackup = Join-Path $script:dossierSauvegarde "politique-audit-avant.csv"
    auditpol /backup /file:"$cheminBackup" | Out-Null
    Write-Host "   Sauvegarde : $cheminBackup" -ForegroundColor DarkGray

    foreach ($c in $aCorriger) {
        if ($c.Niveau -eq "Both") {
            auditpol /set /subcategory:"$($c.Guid)" /success:enable /failure:enable | Out-Null
        } else {
            auditpol /set /subcategory:"$($c.Guid)" /success:enable | Out-Null
        }
    }

    $brut2   = auditpol /get /category:* /r 2>$null
    $lignes2 = $brut2 | Where-Object { $_ -match '\S' } | Select-Object -Skip 1 |
               ConvertFrom-Csv -Header "Machine","Policy","Subcat","Guid","Inclusion","Exclusion"
    $nbApres = 0
    foreach ($c in $cibles) {
        $ligne = $lignes2 | Where-Object { $_.Guid -eq $c.Guid } | Select-Object -First 1
        $inclusion = if ($ligne) { $ligne.Inclusion } else { "" }
        $hasSuccess = $inclusion -match 'success|succ.s|r.ussite'
        $hasFailure = $inclusion -match 'failure|.chec'
        $besoinFailure = ($c.Niveau -eq "Both")
        if ($hasSuccess -and ((-not $besoinFailure) -or $hasFailure)) { $nbApres++ }
    }

    if ($nbApres -eq $total) {
        Write-Host "   ✓ Fait. Toutes les sous-catégories ciblées sont actives." -ForegroundColor Green
    } else {
        Write-Host "   ✗ Certaines sous-catégories ne se sont pas activées comme prévu." -ForegroundColor Red
    }

    return @{ Nom="Politique d'audit avancée"; Maillon="Génération"; Etat="Appliquée"; Avant=$avantTxt; Apres="$nbApres / $total"; Justification=$just; Sauvegarde=$cheminBackup; Restauration="auditpol /restore /file:`"$cheminBackup`"" }
}


# ===== CORRECTION 4 : JOURNALISATION POWERSHELL =====

function Get-ValeurRegistre {
    param([string]$Cle, [string]$Nom)
    if (Test-Path $Cle) {
        $p = Get-ItemProperty -Path $Cle -Name $Nom -ErrorAction SilentlyContinue
        if ($p) { return $p.$Nom }
    }
    return $null
}

function Repair-JournalisationPowerShell {
    Write-Host ""
    Write-Host "  --- Journalisation PowerShell ---" -ForegroundColor Magenta

    $racine = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    $cleSB  = "$racine\ScriptBlockLogging"
    $cleMod = "$racine\ModuleLogging"
    $cleTr  = "$racine\Transcription"
    $dossierTranscripts = "$env:ProgramData\PSTranscripts"
    $just   = "Enregistre le code PowerShell réellement exécuté, même désobfusqué (4104)."

    $sbOk  = (Get-ValeurRegistre $cleSB  "EnableScriptBlockLogging") -eq 1
    $modOk = (Get-ValeurRegistre $cleMod "EnableModuleLogging")      -eq 1
    $trOk  = (Get-ValeurRegistre $cleTr  "EnableTranscripting")      -eq 1

    if ($sbOk)  { Write-Host "   ✓ Blocs de script (4104) : conforme" -ForegroundColor Green }
    else        { Write-Host "   → Blocs de script (4104) : à activer" -ForegroundColor Yellow }
    if ($modOk) { Write-Host "   ✓ Journalisation des modules (4103) : conforme" -ForegroundColor Green }
    else        { Write-Host "   → Journalisation des modules (4103) : à activer" -ForegroundColor Yellow }
    if ($trOk)  { Write-Host "   ✓ Transcription : conforme" -ForegroundColor Green }
    else        { Write-Host "   → Transcription : à activer" -ForegroundColor Yellow }

    $nbAvant = @($sbOk, $modOk, $trOk | Where-Object { $_ }).Count

    if ($sbOk -and $modOk -and $trOk) {
        Write-Host "   Déjà conforme. Rien à faire." -ForegroundColor Green
        return @{ Nom="Journalisation PowerShell"; Maillon="Journalisation"; Etat="DéjàConforme"; Avant="3 / 3 couches"; Apres="3 / 3 couches"; Justification=$just; Sauvegarde=""; Restauration="" }
    }

    Write-Host ""
    Write-Host "   Les blocs de script (4104) enregistrent le code réellement exécuté," -ForegroundColor Gray
    Write-Host "   même désobfusqué — c'est la couche la plus utile au SOC." -ForegroundColor Gray
    if (-not $trOk) { Write-Host "   La transcription écrira dans : $dossierTranscripts" -ForegroundColor Gray }
    Write-Host ""

    if (-not (Confirm-Action "   Activer la journalisation PowerShell manquante ?")) {
        Write-Host "   Ignoré. Aucun changement." -ForegroundColor Yellow
        return @{ Nom="Journalisation PowerShell"; Maillon="Journalisation"; Etat="Ignorée"; Avant="$nbAvant / 3 couches"; Apres="$nbAvant / 3 couches"; Justification=$just; Sauvegarde=""; Restauration="" }
    }

    if (-not (Test-Path $script:dossierSauvegarde)) { New-Item -ItemType Directory -Path $script:dossierSauvegarde -Force | Out-Null }
    if (Test-Path $racine) {
        $cheminSauvegarde = Join-Path $script:dossierSauvegarde "powershell-logging-avant.reg"
        reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "$cheminSauvegarde" /y | Out-Null
        $restauration = "reg import `"$cheminSauvegarde`""
        Write-Host "   Sauvegarde : $cheminSauvegarde" -ForegroundColor DarkGray
    } else {
        $cheminSauvegarde = Join-Path $script:dossierSauvegarde "powershell-logging-avant.txt"
        Save-EtatOrigine -NomFichier "powershell-logging-avant.txt" -Contenu @"
Les cles de journalisation PowerShell etaient absentes avant cette execution.
Pour tout annuler : Remove-Item -Path '$racine' -Recurse -Force
"@
        $restauration = "Remove-Item -Path '$racine' -Recurse -Force"
    }

    if (-not $sbOk) {
        if (-not (Test-Path $cleSB)) { New-Item -Path $cleSB -Force | Out-Null }
        New-ItemProperty -Path $cleSB -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null
    }
    if (-not $modOk) {
        if (-not (Test-Path $cleMod)) { New-Item -Path $cleMod -Force | Out-Null }
        New-ItemProperty -Path $cleMod -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force | Out-Null
        $cleModNames = "$cleMod\ModuleNames"
        if (-not (Test-Path $cleModNames)) { New-Item -Path $cleModNames -Force | Out-Null }
        New-ItemProperty -Path $cleModNames -Name "*" -Value "*" -PropertyType String -Force | Out-Null
    }
    if (-not $trOk) {
        if (-not (Test-Path $cleTr)) { New-Item -Path $cleTr -Force | Out-Null }
        New-ItemProperty -Path $cleTr -Name "EnableTranscripting"    -Value 1 -PropertyType DWord  -Force | Out-Null
        New-ItemProperty -Path $cleTr -Name "EnableInvocationHeader" -Value 1 -PropertyType DWord  -Force | Out-Null
        New-ItemProperty -Path $cleTr -Name "OutputDirectory" -Value $dossierTranscripts -PropertyType String -Force | Out-Null
        if (-not (Test-Path $dossierTranscripts)) { New-Item -ItemType Directory -Path $dossierTranscripts -Force | Out-Null }
    }

    $nbApres = @(((Get-ValeurRegistre $cleSB "EnableScriptBlockLogging") -eq 1), ((Get-ValeurRegistre $cleMod "EnableModuleLogging") -eq 1), ((Get-ValeurRegistre $cleTr "EnableTranscripting") -eq 1) | Where-Object { $_ }).Count

    if ($nbApres -eq 3) {
        Write-Host "   ✓ Fait. Journalisation PowerShell complète activée." -ForegroundColor Green
    } else {
        Write-Host "   ✗ Une partie ne s'est pas activée comme prévu." -ForegroundColor Red
    }

    return @{ Nom="Journalisation PowerShell"; Maillon="Journalisation"; Etat="Appliquée"; Avant="$nbAvant / 3 couches"; Apres="$nbApres / 3 couches"; Justification=$just; Sauvegarde=$cheminSauvegarde; Restauration=$restauration }
}


# ===== ÉVALUATION DE LA VISIBILITÉ (lecture seule) =====
function Get-EtatVisibilite {
    $cibles = @(
        @{ Guid="{0CCE922B-69AE-11D9-BED3-505054503030}"; Niveau="Success" }
        @{ Guid="{0CCE9215-69AE-11D9-BED3-505054503030}"; Niveau="Both"    }
        @{ Guid="{0CCE9216-69AE-11D9-BED3-505054503030}"; Niveau="Success" }
        @{ Guid="{0CCE9235-69AE-11D9-BED3-505054503030}"; Niveau="Both"    }
        @{ Guid="{0CCE922F-69AE-11D9-BED3-505054503030}"; Niveau="Both"    }
        @{ Guid="{0CCE923F-69AE-11D9-BED3-505054503030}"; Niveau="Both"    }
    )
    $brut   = auditpol /get /category:* /r 2>$null
    $lignes = $brut | Where-Object { $_ -match '\S' } | Select-Object -Skip 1 |
              ConvertFrom-Csv -Header "Machine","Policy","Subcat","Guid","Inclusion","Exclusion"
    $nbAudit = 0
    foreach ($c in $cibles) {
        $ligne = $lignes | Where-Object { $_.Guid -eq $c.Guid } | Select-Object -First 1
        $inc = if ($ligne) { $ligne.Inclusion } else { "" }
        $s = $inc -match 'success|succ.s|r.ussite'
        $f = $inc -match 'failure|.chec'
        $bf = ($c.Niveau -eq "Both")
        if ($s -and ((-not $bf) -or $f)) { $nbAudit++ }
    }
    $cGeneration = $nbAudit / 6

    $cleAudit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $cCapture = if ((Get-ValeurRegistre $cleAudit "ProcessCreationIncludeCmdLine_Enabled") -eq 1) { 1 } else { 0 }

    $racine = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    $nbPS = 0
    if ((Get-ValeurRegistre "$racine\ScriptBlockLogging" "EnableScriptBlockLogging") -eq 1) { $nbPS++ }
    if ((Get-ValeurRegistre "$racine\ModuleLogging" "EnableModuleLogging") -eq 1)           { $nbPS++ }
    if ((Get-ValeurRegistre "$racine\Transcription" "EnableTranscripting") -eq 1)           { $nbPS++ }
    $cJournalisation = $nbPS / 3

    $sysmon = @(Get-Service -Name "Sysmon","Sysmon64" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
    $cEnrichissement = if ($sysmon.Count -gt 0) { 1 } else { 0 }

    $agents = "WazuhSvc","Wazuh","OssecSvc","SplunkForwarder","winlogbeat","elastic-agent","nxlog"
    $siem = @(Get-Service -Name $agents -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
    $cCentralisation = if ($siem.Count -gt 0) { 1 } else { 0 }

    $taille = (Get-WinEvent -ListLog "Security").MaximumSizeInBytes
    $cTransversal = if ($taille -ge 268435456) { 1 } else { 0 }

    $somme = ($cGeneration*3) + ($cCapture*3) + ($cJournalisation*3) + ($cEnrichissement*2) + ($cCentralisation*3) + ($cTransversal*2)
    $score = [math]::Round(100 * $somme / 16, 0)

    return @{
        Score          = $score
        Generation     = ($cGeneration -ge 1)
        Capture        = ($cCapture -ge 1)
        Journalisation = ($cJournalisation -ge 1)
        Enrichissement = ($cEnrichissement -ge 1)
        Centralisation = ($cCentralisation -ge 1)
        Transversal    = ($cTransversal -ge 1)
    }
}


# ===== GÉNÉRATION DU RAPPORT HTML =====

function ConvertTo-HtmlSafe {
    param([string]$Texte)
    if ([string]::IsNullOrEmpty($Texte)) { return "" }
    return ($Texte -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;')
}

function New-RapportInterventionHtml {
    param($Resultats, $EtatAvant, $EtatApres, [string]$Chemin)

    $poste     = $env:COMPUTERNAME
    $operateur = $env:USERNAME
    $dateTxt   = Get-Date -Format "dd/MM/yyyy HH:mm"
    $scoreApres = $EtatApres.Score

    $classeSceau = if ($scoreApres -ge 80) { "sceau-bon" } elseif ($scoreApres -ge 50) { "sceau-moyen" } else { "sceau-faible" }

    # --- Pipeline ---
    $maillonsDef = @(
        @{ Num="1"; Nom="Génération";     Ok=$EtatApres.Generation }
        @{ Num="2"; Nom="Capture";        Ok=$EtatApres.Capture }
        @{ Num="3"; Nom="Journalisation"; Ok=$EtatApres.Journalisation }
        @{ Num="4"; Nom="Enrichissement"; Ok=$EtatApres.Enrichissement }
        @{ Num="5"; Nom="Centralisation"; Ok=$EtatApres.Centralisation }
    )
    $pipelineHtml = ""
    foreach ($m in $maillonsDef) {
        if ($m.Ok) { $cls = "maillon-conforme"; $ic = "&#10003;" }
        else       { $cls = "maillon-attention"; $ic = "!" }
        $pipelineHtml += "<div class='maillon $cls'><div class='maillon-icone'>$ic</div><div class='maillon-num'>$($m.Num)</div><div class='maillon-sub'>$($m.Nom)</div></div>"
    }

    $nbOk = @($maillonsDef | Where-Object { $_.Ok }).Count
    if ($nbOk -eq 5) {
        $concCls = "ok"; $concTxt = "Les cinq maillons sont en place : le poste est pleinement visible par le SOC."
    } elseif ($EtatApres.Generation -and $EtatApres.Capture -and $EtatApres.Journalisation) {
        $concCls = "attention"; $concTxt = "La génération, la capture et la journalisation sont en place. Il reste l'enrichissement (Sysmon) et la centralisation (SIEM) pour une visibilité complète."
    } else {
        $concCls = ""; $concTxt = "Plusieurs maillons restent à rétablir avant que le SOC puisse exploiter ce poste."
    }

    # --- Ce que le SOC voit / aveugle ---
    $voit = @()
    $aveugle = @()
    if ($EtatApres.Generation)     { $voit += "Génération des événements de sécurité" }
    if ($EtatApres.Capture)        { $voit += "Les commandes exécutées (4688 + ligne de commande)" }
    if ($EtatApres.Journalisation) { $voit += "Le code PowerShell réel, même désobfusqué (4104)" }
    if ($EtatApres.Transversal)    { $voit += "Un historique d'événements conservé" }
    if ($EtatApres.Enrichissement) { $voit += "Les comportements fins via Sysmon" } else { $aveugle += "Injection de processus, accès LSASS (nécessite Sysmon)" }
    if ($EtatApres.Centralisation) { $voit += "La corrélation centralisée au SIEM" } else { $aveugle += "La corrélation au niveau du SIEM (centralisation des logs)" }
    if ($aveugle.Count -eq 0) { $aveugle += "Aucun angle mort détecté." }

    $voitHtml    = ($voit    | ForEach-Object { "<li>$(ConvertTo-HtmlSafe $_)</li>" }) -join ""
    $aveugleHtml = ($aveugle | ForEach-Object { "<li>$(ConvertTo-HtmlSafe $_)</li>" }) -join ""

    # --- Prose du verdict ---
    $prose = "La visibilité du poste est passée de <strong>$($EtatAvant.Score)&nbsp;%</strong> à <strong class='ok'>$scoreApres&nbsp;%</strong>. "
    if ($scoreApres -lt 100) {
        $manques = @()
        if (-not $EtatApres.Enrichissement) { $manques += "l'enrichissement (Sysmon)" }
        if (-not $EtatApres.Centralisation) { $manques += "la centralisation des logs (SIEM)" }
        if ($manques.Count -gt 0) { $prose += "Pour aller plus loin, il reste à mettre en place " + ($manques -join " et ") + "." }
    }

    # --- Fiches (corrections appliquées / ignorées) ---
    $aDetailler = @($Resultats | Where-Object { $_.Etat -eq 'Appliquée' -or $_.Etat -eq 'Ignorée' })
    $dejaConf   = @($Resultats | Where-Object { $_.Etat -eq 'DéjàConforme' })

    $fichesHtml = ""
    $num = 0
    foreach ($r in $aDetailler) {
        $num++
        $numTxt = "{0:00}" -f $num
        if ($r.Etat -eq 'Appliquée') { $bCls = "badge-conforme"; $bTxt = "appliquée" }
        else                         { $bCls = "badge-attention"; $bTxt = "ignorée" }
        $action = ""
        if ($r.Sauvegarde) {
            $action = "<div class='fiche-action'><strong>Sauvegarde&nbsp;:</strong> $(ConvertTo-HtmlSafe $r.Sauvegarde)<div class='cmd'>$(ConvertTo-HtmlSafe $r.Restauration)</div></div>"
        }
        $fichesHtml += "<div class='fiche'><div class='fiche-entete'>"
        $fichesHtml += "<div class='fiche-numero'><div class='fiche-numero-label'>fiche</div><div class='fiche-numero-val'>$numTxt</div></div>"
        $fichesHtml += "<h3 class='fiche-titre'>$(ConvertTo-HtmlSafe $r.Nom)</h3><span class='badge $bCls'>$bTxt</span></div>"
        $fichesHtml += "<div class='fiche-corps'><div class='transf'><span class='transf-avant'>$(ConvertTo-HtmlSafe $r.Avant)</span><span class='transf-fleche'>&#8594;</span><span class='transf-apres'>$(ConvertTo-HtmlSafe $r.Apres)</span></div>"
        $fichesHtml += "<div class='fiche-valeur'>$(ConvertTo-HtmlSafe $r.Justification)</div>$action</div></div>"
    }
    if ($aDetailler.Count -eq 0) {
        $fichesHtml = "<div class='note-chasseur'><div class='note-icone'>&#10003;</div><div class='note-texte'>Aucune correction n'a été nécessaire : tous les réglages à la portée du correcteur étaient déjà conformes.</div></div>"
    }

    # --- Déjà conformes ---
    $dejaSection = ""
    if ($dejaConf.Count -gt 0) {
        $dejaLignes = ""
        foreach ($r in $dejaConf) {
            $dejaLignes += "<div class='deja-ligne'><span class='deja-puce'></span><span class='deja-nom'>$(ConvertTo-HtmlSafe $r.Nom)</span><span>$(ConvertTo-HtmlSafe $r.Apres)</span></div>"
        }
        $dejaSection = "<div class='section-separateur'><span class='section-separateur-label'>Déjà conformes</span><span class='section-separateur-ligne'></span><span class='section-separateur-count'>$($dejaConf.Count)</span></div><div class='deja-bloc'>$dejaLignes</div>"
    }

    $styleSupp = @"
.transf { display:flex; align-items:center; gap:16px; background:var(--creme); border-radius:10px; padding:10px 16px; margin-bottom:14px; }
.transf-avant { color:var(--gris-clair); text-decoration:line-through; }
.transf-fleche { color:var(--aubergine); font-weight:700; font-size:18px; }
.transf-apres { color:var(--vert); font-weight:700; font-family:'Baloo 2','Segoe UI',sans-serif; }
.cmd { font-family:'Consolas','Courier New',monospace; background:#F0EBF1; border:1px solid var(--bordure); border-radius:6px; padding:7px 10px; margin-top:8px; font-size:12.5px; color:var(--aubergine); word-break:break-all; }
.soc-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:22px; }
.soc-col { background:var(--blanc); border:1px solid var(--bordure); border-radius:14px; padding:18px 22px; }
.soc-col h4 { font-family:'Baloo 2','Segoe UI',sans-serif; font-size:14px; margin-bottom:10px; }
.soc-voit h4 { color:var(--vert); } .soc-aveugle h4 { color:var(--ambre); }
.soc-col ul { list-style:none; } .soc-col li { font-size:13px; line-height:1.7; padding-left:18px; position:relative; }
.soc-col li::before { content:'\2022'; position:absolute; left:0; }
.soc-voit li::before { color:var(--vert); } .soc-aveugle li::before { color:var(--ambre); }
.deja-bloc { background:#F7F4EE; border:1px solid var(--bordure); border-radius:14px; padding:4px 22px; margin-bottom:22px; }
.deja-ligne { display:flex; align-items:center; gap:12px; font-size:13px; color:var(--gris); padding:8px 0; }
.deja-ligne + .deja-ligne { border-top:1px solid var(--bordure-douce); }
.deja-puce { width:7px; height:7px; border-radius:50%; background:var(--gris-clair); flex-shrink:0; }
.deja-nom { flex:1; }
"@

    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Journal d'intervention - $poste</title>
<link rel="stylesheet" href="rapport.css">
<style>
$styleSupp
</style>
</head>
<body>
<div class="conteneur">
  <div class="couverture">
    <div class="couverture-marque">
      <div class="mascotte"></div>
      <div class="couverture-textes">
        <div class="couverture-meta">Journal d'intervention</div>
        <h1 class="couverture-titre">huntReady-fix</h1>
        <div class="couverture-soustitre">Corrections de télémétrie appliquées au poste</div>
      </div>
    </div>
    <div class="couverture-droite">
      <div class="couverture-poste">$poste</div>
      <div>$dateTxt</div>
      <div>Opérateur : $operateur</div>
    </div>
  </div>

  <div class="verdict">
    <div class="sceau $classeSceau">
      <div class="sceau-score">$($scoreApres)%</div>
      <div class="sceau-label">Visibilité SOC</div>
    </div>
    <div class="verdict-texte">
      <div class="verdict-meta">Bilan d'intervention</div>
      <h2 class="verdict-titre">Visibilité du poste : $($EtatAvant.Score)&nbsp;% &#8594; $($scoreApres)&nbsp;%</h2>
      <div class="verdict-prose">$prose</div>
    </div>
  </div>

  <div class="pipeline-bloc">
    <div class="section-titre">Chaîne de détection</div>
    <div class="pipeline">$pipelineHtml</div>
    <div class="pipeline-conclusion $concCls">$concTxt</div>
  </div>

  <div class="soc-grid">
    <div class="soc-col soc-voit"><h4>Ce que le SOC voit désormais</h4><ul>$voitHtml</ul></div>
    <div class="soc-col soc-aveugle"><h4>Encore aveugle</h4><ul>$aveugleHtml</ul></div>
  </div>

  <div class="section-separateur">
    <span class="section-separateur-label">Détail des corrections</span>
    <span class="section-separateur-ligne"></span>
    <span class="section-separateur-count">$($aDetailler.Count) fiche(s)</span>
  </div>
  $fichesHtml

  $dejaSection

  <div class="note-chasseur">
    <div class="note-icone">&#8635;</div>
    <div class="note-texte"><span class="note-prefix">Prochaine étape —</span> relancez <strong>huntReady.ps1</strong> pour réévaluer le score de visibilité du poste.</div>
  </div>

  <div class="pied">huntReady-fix &middot; Famille Outils Compagnon &middot; DOUKAKAS Yeni</div>
</div>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($Chemin, $html, (New-Object System.Text.UTF8Encoding($false)))
}


# ===== ÉVALUATION ET CORRECTIONS =====
Write-Host ""
Write-Host "  Évaluation de la visibilité avant correction..." -ForegroundColor DarkGray
$etatAvant = Get-EtatVisibilite

$resultats = @()
$resultats += Repair-PolitiqueAudit
$resultats += Repair-CreationProcessusCmdLine
$resultats += Repair-JournalisationPowerShell
$resultats += Repair-CapaciteJournaux

Write-Host ""
Write-Host "  Évaluation de la visibilité après correction..." -ForegroundColor DarkGray
$etatApres = Get-EtatVisibilite

$cheminRapport = Join-Path $PSScriptRoot "rapport-intervention.html"
New-RapportInterventionHtml -Resultats $resultats -EtatAvant $etatAvant -EtatApres $etatApres -Chemin $cheminRapport

Write-Host ""
Write-Host "  Score de visibilité SOC : $($etatAvant.Score)% -> $($etatApres.Score)%" -ForegroundColor Magenta
Write-Host "  Rapport généré : $cheminRapport" -ForegroundColor Green
Invoke-Item $cheminRapport

Write-Host ""
Read-Host "  Appuie sur Entrée pour fermer"