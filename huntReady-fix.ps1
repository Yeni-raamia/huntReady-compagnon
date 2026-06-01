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
    $cible = 268435456   # 256 Mo, exprimé en octets

    Write-Host ""
    Write-Host "  --- Capacité du journal Security ---" -ForegroundColor Magenta

    $actuel   = (Get-WinEvent -ListLog "Security").MaximumSizeInBytes
    $actuelMo = [math]::Round($actuel / 1MB, 0)
    $cibleMo  = [math]::Round($cible  / 1MB, 0)

    Write-Host "   Taille maximale actuelle : $actuelMo Mo" -ForegroundColor Gray

    if ($actuel -ge $cible) {
        Write-Host "   Déjà conforme (>= $cibleMo Mo). Rien à faire." -ForegroundColor Green
        return
    }

    Write-Host "   Recommandé : $cibleMo Mo (pour conserver plus d'historique)." -ForegroundColor Gray
    Write-Host ""

    if (-not (Confirm-Action "   Porter le journal Security à $cibleMo Mo ?")) {
        Write-Host "   Ignoré. Aucun changement." -ForegroundColor Yellow
        return
    }

    Save-EtatOrigine -NomFichier "journal-security-taille.txt" -Contenu @"
Journal      : Security
Taille avant : $actuel octets ($actuelMo Mo)
Pour revenir en arriere : wevtutil sl Security /ms:$actuel
"@

    wevtutil sl Security /ms:$cible

    $apres   = (Get-WinEvent -ListLog "Security").MaximumSizeInBytes
    $apresMo = [math]::Round($apres / 1MB, 0)
    if ($apres -ge $cible) {
        Write-Host "   ✓ Fait. Nouvelle taille maximale : $apresMo Mo" -ForegroundColor Green
    } else {
        Write-Host "   ✗ La taille n'a pas changé comme prévu ($apresMo Mo)." -ForegroundColor Red
    }
}


# ===== APPEL DES CORRECTIONS =====
Repair-CapaciteJournaux

# ===== CORRECTION 2 : LIGNE DE COMMANDE DANS L'ÉVÉNEMENT 4688 =====
function Repair-CreationProcessusCmdLine {
    $cle = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $nom = "ProcessCreationIncludeCmdLine_Enabled"

    Write-Host ""
    Write-Host "  --- Ligne de commande dans l'événement 4688 ---" -ForegroundColor Magenta

    $valeurActuelle = $null
    if (Test-Path $cle) {
        $prop = Get-ItemProperty -Path $cle -Name $nom -ErrorAction SilentlyContinue
        if ($prop) { $valeurActuelle = $prop.$nom }
    }

    if ($valeurActuelle -eq 1) {
        Write-Host "   Déjà conforme (activé). Rien à faire." -ForegroundColor Green
        return
    }

    $etatLisible = if ($null -eq $valeurActuelle) { "absent (non configuré)" } else { "désactivé ($valeurActuelle)" }
    Write-Host "   État actuel : $etatLisible" -ForegroundColor Gray
    Write-Host "   Sans ce réglage, l'event 4688 dit qu'un processus a démarré," -ForegroundColor Gray
    Write-Host "   mais pas AVEC QUELLE commande — le SOC est aveugle au contenu." -ForegroundColor Gray
    Write-Host ""

    if (-not (Confirm-Action "   Activer l'enregistrement de la ligne de commande ?")) {
        Write-Host "   Ignoré. Aucun changement." -ForegroundColor Yellow
        return
    }

    if ($null -eq $valeurActuelle) {
        $revert = "Remove-ItemProperty -Path '$cle' -Name '$nom'"
    } else {
        $revert = "New-ItemProperty -Path '$cle' -Name '$nom' -Value $valeurActuelle -PropertyType DWord -Force"
    }
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
}
Repair-CreationProcessusCmdLine

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

    # Lecture de l'état courant (matché par GUID, insensible à la langue)
    $brut   = auditpol /get /category:* /r 2>$null
    $lignes = $brut | Where-Object { $_ -match '\S' } | Select-Object -Skip 1 |
              ConvertFrom-Csv -Header "Machine","Policy","Subcat","Guid","Inclusion","Exclusion"

    $aCorriger = @()
    foreach ($c in $cibles) {
        $ligne     = $lignes | Where-Object { $_.Guid -eq $c.Guid } | Select-Object -First 1
        $inclusion = if ($ligne) { $ligne.Inclusion } else { "" }
        $hasSuccess = $inclusion -match 'success|succ.s|r.ussite'
        $hasFailure = $inclusion -match 'failure|.chec'
        $besoinFailure = ($c.Niveau -eq "Both")
        $conforme = $hasSuccess -and ((-not $besoinFailure) -or $hasFailure)

        if ($conforme) {
            Write-Host ("   ✓ {0} : conforme" -f $c.Nom) -ForegroundColor Green
        } else {
            $attendu = if ($besoinFailure) { "Succès + Échec" } else { "Succès" }
            Write-Host ("   → {0} : à activer ({1})" -f $c.Nom, $attendu) -ForegroundColor Yellow
            $aCorriger += $c
        }
    }

    if ($aCorriger.Count -eq 0) {
        Write-Host "   Déjà conforme. Rien à faire." -ForegroundColor Green
        return
    }

    Write-Host ""
    if (-not (Confirm-Action ("   Activer les {0} sous-catégorie(s) manquante(s) ?" -f $aCorriger.Count))) {
        Write-Host "   Ignoré. Aucun changement." -ForegroundColor Yellow
        return
    }

    # Sauvegarde complète et restaurable de la politique d'audit
    if (-not (Test-Path $script:dossierSauvegarde)) {
        New-Item -ItemType Directory -Path $script:dossierSauvegarde -Force | Out-Null
    }
    $cheminBackup = Join-Path $script:dossierSauvegarde "politique-audit-avant.csv"
    auditpol /backup /file:"$cheminBackup" | Out-Null
    Write-Host "   Sauvegarde : $cheminBackup" -ForegroundColor DarkGray
    Write-Host "   (restauration : auditpol /restore /file:`"$cheminBackup`")" -ForegroundColor DarkGray

    # Application
    foreach ($c in $aCorriger) {
        if ($c.Niveau -eq "Both") {
            auditpol /set /subcategory:"$($c.Guid)" /success:enable /failure:enable | Out-Null
        } else {
            auditpol /set /subcategory:"$($c.Guid)" /success:enable | Out-Null
        }
    }

    # Vérification
    $brut2   = auditpol /get /category:* /r 2>$null
    $lignes2 = $brut2 | Where-Object { $_ -match '\S' } | Select-Object -Skip 1 |
               ConvertFrom-Csv -Header "Machine","Policy","Subcat","Guid","Inclusion","Exclusion"

    $ok = $true
    foreach ($c in $aCorriger) {
        $ligne     = $lignes2 | Where-Object { $_.Guid -eq $c.Guid } | Select-Object -First 1
        $inclusion = if ($ligne) { $ligne.Inclusion } else { "" }
        $hasSuccess = $inclusion -match 'success|succ.s|r.ussite'
        $hasFailure = $inclusion -match 'failure|.chec'
        $besoinFailure = ($c.Niveau -eq "Both")
        if (-not ($hasSuccess -and ((-not $besoinFailure) -or $hasFailure))) { $ok = $false }
    }

    if ($ok) {
        Write-Host "   ✓ Fait. Toutes les sous-catégories ciblées sont actives." -ForegroundColor Green
    } else {
        Write-Host "   ✗ Certaines sous-catégories ne se sont pas activées comme prévu." -ForegroundColor Red
    }
}
Repair-PolitiqueAudit

# ===== CORRECTION 4 : JOURNALISATION POWERSHELL =====

# (utilitaire) lit une valeur de registre, renvoie $null si absente
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

    $sbOk  = (Get-ValeurRegistre $cleSB  "EnableScriptBlockLogging") -eq 1
    $modOk = (Get-ValeurRegistre $cleMod "EnableModuleLogging")      -eq 1
    $trOk  = (Get-ValeurRegistre $cleTr  "EnableTranscripting")      -eq 1

    if ($sbOk)  { Write-Host "   ✓ Blocs de script (4104) : conforme" -ForegroundColor Green }
    else        { Write-Host "   → Blocs de script (4104) : à activer" -ForegroundColor Yellow }
    if ($modOk) { Write-Host "   ✓ Journalisation des modules (4103) : conforme" -ForegroundColor Green }
    else        { Write-Host "   → Journalisation des modules (4103) : à activer" -ForegroundColor Yellow }
    if ($trOk)  { Write-Host "   ✓ Transcription : conforme" -ForegroundColor Green }
    else        { Write-Host "   → Transcription : à activer" -ForegroundColor Yellow }

    if ($sbOk -and $modOk -and $trOk) {
        Write-Host "   Déjà conforme. Rien à faire." -ForegroundColor Green
        return
    }

    Write-Host ""
    Write-Host "   Les blocs de script (4104) enregistrent le code réellement exécuté," -ForegroundColor Gray
    Write-Host "   même désobfusqué — c'est la couche la plus utile au SOC." -ForegroundColor Gray
    if (-not $trOk) {
        Write-Host "   La transcription écrira dans : $dossierTranscripts" -ForegroundColor Gray
    }
    Write-Host ""

    if (-not (Confirm-Action "   Activer la journalisation PowerShell manquante ?")) {
        Write-Host "   Ignoré. Aucun changement." -ForegroundColor Yellow
        return
    }

    # Sauvegarde : export .reg si la branche existe, sinon note d'annulation
    if (-not (Test-Path $script:dossierSauvegarde)) {
        New-Item -ItemType Directory -Path $script:dossierSauvegarde -Force | Out-Null
    }
    if (Test-Path $racine) {
        $cheminReg = Join-Path $script:dossierSauvegarde "powershell-logging-avant.reg"
        reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "$cheminReg" /y | Out-Null
        Write-Host "   Sauvegarde : $cheminReg" -ForegroundColor DarkGray
    } else {
        Save-EtatOrigine -NomFichier "powershell-logging-avant.txt" -Contenu @"
Les cles de journalisation PowerShell etaient absentes avant cette execution.
Pour tout annuler : Remove-Item -Path '$racine' -Recurse -Force
"@
    }

    # Application
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

    # Vérification
    $sbOk2  = (Get-ValeurRegistre $cleSB  "EnableScriptBlockLogging") -eq 1
    $modOk2 = (Get-ValeurRegistre $cleMod "EnableModuleLogging")      -eq 1
    $trOk2  = (Get-ValeurRegistre $cleTr  "EnableTranscripting")      -eq 1

    if ($sbOk2 -and $modOk2 -and $trOk2) {
        Write-Host "   ✓ Fait. Journalisation PowerShell complète activée." -ForegroundColor Green
    } else {
        Write-Host "   ✗ Une partie ne s'est pas activée comme prévu." -ForegroundColor Red
    }
}
Repair-JournalisationPowerShell


Write-Host ""
Read-Host "  Appuie sur Entrée pour fermer"