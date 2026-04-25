#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Assigns Microsoft Graph API permissions (app roles) to a Managed Identity.

.DESCRIPTION
    Connects to Microsoft Graph and grants one or more Graph API application
    permissions to a User-Assigned or System-Assigned Managed Identity.
    Provide either -DisplayName or -ObjectId, but not both.

.PARAMETER DisplayName
    The display name of the Managed Identity service principal.
    Mutually exclusive with -ObjectId.

.PARAMETER ObjectId
    The Object (principal) ID of the Managed Identity service principal.
    Mutually exclusive with -DisplayName.

.PARAMETER TenantId
    The Azure AD tenant ID to connect to.
    If omitted, the current user's default tenant is used.

.NOTES
    The following Graph API application permissions are assigned by this script:
      - DeviceManagementManagedDevices.Read.All
      - DeviceManagementConfiguration.ReadWrite.All
      - Mail.Send
      - Device.Read.All

.EXAMPLE
    .\Assign-GraphApiPermissions.ps1 `
        -DisplayName "my-managed-identity" `
        -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    .\Assign-GraphApiPermissions.ps1 `
        -ObjectId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory, ParameterSetName = 'ByDisplayName')]
    [ValidateNotNullOrEmpty()]
    [string] $DisplayName,

    [Parameter(Mandatory, ParameterSetName = 'ByObjectId')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string] $ObjectId,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string] $TenantId
)

# Permissions granted by this script — edit here to add or remove roles
$RequiredPermissions = @(
    'DeviceManagementManagedDevices.Read.All'
    'DeviceManagementConfiguration.ReadWrite.All'
    'Mail.Send'
    'Device.Read.All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

────────────────────────────────── Helper functions ──────────────────────────────────

function Connect-ToGraph {
    param([string] $TenantId)

    $connectParams = @{
        Scopes = @(
            'Application.Read.All',
            'AppRoleAssignment.ReadWrite.All'
        )
    }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }

    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph @connectParams -NoWelcome
    Write-Host "Connected." -ForegroundColor Green
}

function Get-ManagedIdentityPrincipal {
    param(
        [string] $DisplayName,
        [string] $ObjectId
    )

    if ($ObjectId) {
        Write-Host "Looking up Managed Identity by Object ID: $ObjectId" -ForegroundColor Cyan
        $sp = Get-MgServicePrincipal -ServicePrincipalId $ObjectId -ErrorAction SilentlyContinue
        if (-not $sp) {
            throw "No service principal found with Object ID '$ObjectId'."
        }
    }
    else {
        Write-Host "Looking up Managed Identity by Display Name: $DisplayName" -ForegroundColor Cyan
        $results = Get-MgServicePrincipal -Filter "displayName eq '$DisplayName'" -All
        if (-not $results) {
            throw "No service principal found with display name '$DisplayName'."
        }
        if ($results.Count -gt 1) {
            $ids = ($results | Select-Object -ExpandProperty Id) -join ', '
            throw "Multiple service principals match display name '$DisplayName'. " +
                  "Use -ObjectId to target one specifically. Found IDs: $ids"
        }
        $sp = $results[0]
    }

    if ($sp.ServicePrincipalType -notin @('ManagedIdentity')) {
        Write-Warning ("Service principal '$($sp.DisplayName)' (ID: $($sp.Id)) has type " +
                       "'$($sp.ServicePrincipalType)'. Expected 'ManagedIdentity'. Proceeding anyway.")
    }

    Write-Host "Found: $($sp.DisplayName) (ID: $($sp.Id))" -ForegroundColor Green
    return $sp
}

function Get-GraphServicePrincipal {
    Write-Host "Retrieving Microsoft Graph service principal..." -ForegroundColor Cyan
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -All
    if (-not $graphSp) {
        throw "Could not find the Microsoft Graph service principal in this tenant."
    }
    return $graphSp
}

function Resolve-AppRoles {
    param(
        [Microsoft.Graph.PowerShell.Models.IMicrosoftGraphServicePrincipal] $GraphSp,
        [string[]] $PermissionNames
    )

    $resolved = [System.Collections.Generic.List[object]]::new()
    $missing   = [System.Collections.Generic.List[string]]::new()

    foreach ($name in $PermissionNames) {
        $role = $GraphSp.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains 'Application' }
        if ($role) {
            $resolved.Add($role)
        }
        else {
            $missing.Add($name)
        }
    }

    if ($missing.Count -gt 0) {
        throw "The following permissions were not found as Graph application roles: $($missing -join ', '). " +
              "Check spelling and ensure they are valid app-role permission names."
    }

    return $resolved
}

function Grant-AppRoleToManagedIdentity {
    param(
        [string] $PrincipalId,
        [string] $GraphSpId,
        [System.Collections.Generic.List[object]] $AppRoles,
        [switch] $WhatIf
    )

    # Retrieve existing assignments once to avoid duplicates
    $existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -All

    foreach ($role in $AppRoles) {
        $alreadyAssigned = $existingAssignments | Where-Object {
            $_.AppRoleId -eq $role.Id -and $_.ResourceId -eq $GraphSpId
        }

        if ($alreadyAssigned) {
            Write-Host "  [SKIP] '$($role.Value)' is already assigned." -ForegroundColor Yellow
            continue
        }

        $body = @{
            PrincipalId = $PrincipalId
            ResourceId  = $GraphSpId
            AppRoleId   = $role.Id
        }

        if ($WhatIf) {
            Write-Host "  [WHATIF] Would assign '$($role.Value)' (ID: $($role.Id))." -ForegroundColor DarkCyan
        }
        else {
            Write-Host "  [ASSIGN] Granting '$($role.Value)'..." -ForegroundColor Cyan
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $PrincipalId `
                -BodyParameter $body | Out-Null
            Write-Host "  [OK] '$($role.Value)' granted." -ForegroundColor Green
        }
    }
}

# End of helper functions

──────────────────────────────────Main──────────────────────────────────

try {
    Connect-ToGraph -TenantId $TenantId

    # Resolve the managed identity
    $miPrincipal = Get-ManagedIdentityPrincipal -DisplayName $DisplayName -ObjectId $ObjectId

    # Resolve Graph SP and the requested roles
    $graphSp   = Get-GraphServicePrincipal
    $appRoles  = Resolve-AppRoles -GraphSp $graphSp -PermissionNames $RequiredPermissions

    Write-Host "`nAssigning $($appRoles.Count) permission(s) to '$($miPrincipal.DisplayName)':" -ForegroundColor Cyan
    $appRoles | ForEach-Object { Write-Host "  - $($_.Value)" }
    Write-Host ""

    Grant-AppRoleToManagedIdentity `
        -PrincipalId $miPrincipal.Id `
        -GraphSpId   $graphSp.Id `
        -AppRoles    $appRoles `
        -WhatIf:($WhatIfPreference.IsPresent)

    Write-Host "`nDone." -ForegroundColor Green
}
catch {
    Write-Error "Script failed: $_"
    exit 1
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
