---
applyTo: "**/*.ps1,**/*.psm1,**/*.psd1"
---

# AutomatedLab Project-Specific PowerShell Best Practices

This document defines AutomatedLab-specific PowerShell patterns and practices observed in the codebase. These patterns supplement the general PowerShell best practices defined in `powershell.instructions.md` and `powershell-advanced.instructions.md`.

## Table of Contents

- [Logging and User Feedback Patterns](#logging-and-user-feedback-patterns)
- [Function Structure Standards](#function-structure-standards)
- [Progress Indication Patterns](#progress-indication-patterns)
- [Parameter Validation Patterns](#parameter-validation-patterns)
- [Error Handling Patterns](#error-handling-patterns)
- [Task Execution Patterns](#task-execution-patterns)
- [Module Organization](#module-organization)

---

## Logging and User Feedback Patterns

### Standard Logging Functions

AutomatedLab uses a consistent set of logging functions from the PSLog module:

#### Write-LogFunctionEntry

**Purpose**: Log function entry with parameter values for debugging and telemetry.

**Usage Pattern**:
```powershell
function Install-Lab {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LabName,
        
        [switch]$CreateCheckPoints
    )
    
    Write-LogFunctionEntry  # ALWAYS first executable line
    
    # Function implementation
    
    Write-LogFunctionExit   # ALWAYS before return
}
```

**Automatic Capabilities**:
- Captures all bound parameters and their values
- Sends telemetry if enabled
- Logs to PSFramework for structured logging
- Truncates long string values automatically
- Handles credentials securely (logs username, masks password)

#### Write-LogFunctionExit

**Purpose**: Log function exit and measure execution time.

**Usage Pattern**:
```powershell
function Get-LabData {
    [CmdletBinding()]
    param()
    
    Write-LogFunctionEntry
    
    try {
        # Function logic
        $data = Get-Data
        
        Write-LogFunctionExit  # Before successful return
        return $data
    }
    catch {
        Write-LogFunctionExitWithError -ErrorRecord $_
        throw
    }
}
```

#### Write-LogFunctionExitWithError

**Purpose**: Log function exit with error details.

**Usage Pattern**:
```powershell
function Install-Component {
    [CmdletBinding()]
    param()
    
    Write-LogFunctionEntry
    
    try {
        # Installation logic
    }
    catch {
        Write-LogFunctionExitWithError -ErrorRecord $_
        throw  # Re-throw to propagate error
    }
    finally {
        # Cleanup
    }
    
    Write-LogFunctionExit
}
```

### Write-ScreenInfo - User-Facing Output

**Purpose**: Provide consistent, timestamped, hierarchical user feedback.

**Key Features**:
- Automatic timestamp tracking (absolute and relative)
- Hierarchical task indentation with `-TaskStart` and `-TaskEnd`
- Color-coded message types
- Respects `-NoDisplay` parameter from caller
- Integrates with PSFramework logging

**Usage Patterns**:

#### Basic Messages
```powershell
# Informational message
Write-ScreenInfo -Message 'Starting deployment process'

# Warning
Write-ScreenInfo -Message 'Resource not found, using default' -Type Warning

# Error
Write-ScreenInfo -Message 'Failed to connect to server' -Type Error

# Verbose (only shown if -Verbose)
Write-ScreenInfo -Message 'Processing item 5 of 100' -Type Verbose

# Debug (only shown if -Debug)
Write-ScreenInfo -Message 'Variable state: $x = 42' -Type Debug
```

#### Task Hierarchies
```powershell
Write-ScreenInfo -Message 'Installing SQL Servers' -TaskStart
# Indentation level increases

Write-ScreenInfo -Message 'Waiting for machines to start up' -NoNewline
Start-LabVM -RoleName SQLServer -Wait -ProgressIndicator 15

Write-ScreenInfo -Message 'Installing SQL Server 2019'
# Nested task messages are automatically indented

Write-ScreenInfo -Message 'Done' -TaskEnd
# Indentation level decreases
```

#### Progress Indicators
```powershell
# Show progress without newline
Write-ScreenInfo -Message 'Waiting for installation' -NoNewline

# Later, complete the line
Write-ScreenInfo -Message 'Done'

# Common pattern with dots
Write-ScreenInfo -Message 'Processing files' -NoNewline
foreach ($file in $files) {
    Write-ScreenInfo -Message '.' -NoNewline
    Process-File $file
}
Write-ScreenInfo -Message ' Complete'
```

#### Standard Task Pattern
```powershell
function Install-LabComponent {
    [CmdletBinding()]
    param()
    
    Write-LogFunctionEntry
    
    # Check prerequisites
    if (-not (Test-Prerequisite)) {
        Write-ScreenInfo -Message 'Prerequisites not met' -Type Warning
        Write-LogFunctionExit
        return
    }
    
    # Main task
    Write-ScreenInfo -Message 'Installing Component' -TaskStart
    
    try {
        Write-ScreenInfo -Message 'Downloading files' -NoNewline
        Get-ComponentFiles
        Write-ScreenInfo -Message 'Done'
        
        Write-ScreenInfo -Message 'Installing binaries'
        Install-Binaries
        
        Write-ScreenInfo -Message 'Configuring service'
        Set-Configuration
        
        Write-ScreenInfo -Message 'Done' -TaskEnd
    }
    catch {
        Write-ScreenInfo -Message "Installation failed: $_" -Type Error -TaskEnd
        Write-LogFunctionExitWithError -ErrorRecord $_
        throw
    }
    
    Write-LogFunctionExit
}
```

### Message Type Guidelines

**Use `Info` (default) when**:
- Announcing major task start/completion
- Reporting successful operations
- General progress updates

**Use `Warning` when**:
- Non-critical issues occur but operation continues
- Using defaults due to missing configuration
- Resource not found but alternative used
- Deprecation notices

**Use `Error` when**:
- Operation failed and cannot continue
- Critical validation failures
- Unrecoverable errors (before throwing)

**Use `Verbose` when**:
- Detailed progress information
- Internal state for debugging
- Step-by-step operation details
- Only relevant when troubleshooting

**Use `Debug` when**:
- Variable dumps
- Execution path tracing
- Low-level diagnostic information
- Developer-focused details

---

## Progress Indication Patterns

### Write-ProgressIndicator (Lightweight)

**Purpose**: Provide visual feedback in tight loops without Write-Progress overhead.

**Pattern**:
```powershell
# Global counter managed automatically
$script:ProgressIndicatorCount = 0

function Write-ProgressIndicator {
    $script:ProgressIndicatorCount++
    
    switch ($script:ProgressIndicatorCount % 4) {
        0 { Write-Host '|' -NoNewline }
        1 { Write-Host '/' -NoNewline }
        2 { Write-Host '-' -NoNewline }
        3 { Write-Host '\' -NoNewline }
    }
}

function Write-ProgressIndicatorEnd {
    Write-Host ' Done' -ForegroundColor Green
    $script:ProgressIndicatorCount = 0
}
```

**Usage**:
```powershell
Write-ScreenInfo -Message 'Processing large dataset' -NoNewline
foreach ($item in $largeCollection) {
    Write-ProgressIndicator
    Process-Item $item
}
Write-ProgressIndicatorEnd
```

**When to Use**:
- Processing 100s or 1000s of items quickly
- Operations where Write-Progress would be too slow
- Console-only scenarios (not scripts)

**When NOT to Use**:
- Long-running operations (use `Write-Progress`)
- GUI applications
- Automation scripts (no console output)

### Standard Progress Pattern

```powershell
function Process-LabMachines {
    [CmdletBinding()]
    param(
        [string[]]$ComputerName
    )
    
    Write-LogFunctionEntry
    
    $totalMachines = $ComputerName.Count
    
    for ($i = 0; $i -lt $totalMachines; $i++) {
        $percentComplete = [Math]::Round(($i / $totalMachines) * 100, 2)
        
        Write-Progress -Activity 'Processing Machines' `
                       -Status "Processing $($ComputerName[$i]) ($($i + 1) of $totalMachines)" `
                       -PercentComplete $percentComplete `
                       -CurrentOperation $ComputerName[$i]
        
        Process-Machine -Name $ComputerName[$i]
    }
    
    Write-Progress -Activity 'Processing Machines' -Completed
    
    Write-LogFunctionExit
}
```

---

## Function Structure Standards

### Standard Function Template

```powershell
function Verb-LabNoun {
    <#
    .SYNOPSIS
        Brief description.
    
    .DESCRIPTION
        Detailed description of what the function does.
    
    .PARAMETER ParameterName
        Description of parameter.
    
    .EXAMPLE
        Verb-LabNoun -ParameterName Value
        
        Description of what example does.
    
    .NOTES
        Additional notes, author, version, etc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ParameterName,
        
        [switch]$CreateCheckPoints
    )
    
    Write-LogFunctionEntry
    
    # Validation
    if (-not (Test-Prerequisite)) {
        Write-ScreenInfo -Message 'Prerequisites not met' -Type Warning
        Write-LogFunctionExit
        return
    }
    
    # Main logic with proper error handling
    try {
        Write-ScreenInfo -Message 'Starting operation' -TaskStart
        
        # Implementation
        
        Write-ScreenInfo -Message 'Done' -TaskEnd
    }
    catch {
        Write-ScreenInfo -Message "Operation failed: $_" -Type Error
        Write-LogFunctionExitWithError -ErrorRecord $_
        throw
    }
    finally {
        # Cleanup
    }
    
    Write-LogFunctionExit
}
```

### Early Return Pattern

```powershell
function Install-LabRole {
    [CmdletBinding()]
    param(
        [string]$RoleName
    )
    
    Write-LogFunctionEntry
    
    # Early validation with immediate return
    if (-not (Get-LabVM -Role $RoleName)) {
        Write-ScreenInfo -Message "There is no machine with the role '$RoleName'" -Type Warning
        Write-LogFunctionExit
        return  # Exit early, log before return
    }
    
    if (Test-RoleInstalled -Role $RoleName) {
        Write-ScreenInfo -Message "Role '$RoleName' is already installed" -Type Warning
        Write-LogFunctionExit
        return
    }
    
    # Main logic only executes if validations pass
    Write-ScreenInfo -Message "Installing role '$RoleName'" -TaskStart
    # ...
    Write-ScreenInfo -Message 'Done' -TaskEnd
    
    Write-LogFunctionExit
}
```

---

## Parameter Validation Patterns

### Role-Based Parameter Pattern

```powershell
function Install-Lab {
    [CmdletBinding()]
    param(
        [switch]$NetworkSwitches,
        [switch]$BaseImages,
        [switch]$VMs,
        [switch]$Domains,
        [switch]$CA,
        [switch]$SQLServers,
        [switch]$WebServers,
        # ... more role switches
        
        [switch]$PostInstallations,
        [switch]$NoValidation,
        [int]$DelayBetweenComputers
    )
    
    Write-LogFunctionEntry
    
    # Detect if performing full install (no specific roles selected)
    $performAll = -not ($PSBoundParameters.Keys | Where-Object {
        $_ -notin ('NoValidation', 'DelayBetweenComputers' + 
                   [System.Management.Automation.Internal.CommonParameters].GetProperties().Name)
    }).Count
    
    # Execute based on switches or performAll
    if ($NetworkSwitches -or $performAll) {
        Write-ScreenInfo -Message 'Creating virtual networks' -TaskStart
        New-LabNetworkSwitches
        Write-ScreenInfo -Message 'Done' -TaskEnd
    }
    
    # ... more conditional installations
    
    Write-LogFunctionExit
}
```

### Machine Filtering Pattern

```powershell
# Filter machines by role and skip deployment flag
$machines = Get-LabVM -Role WebServer | Where-Object { -not $_.SkipDeployment }

if (-not $machines) {
    Write-ScreenInfo -Message "There is no machine with role 'WebServer' to install" -Type Warning
    Write-LogFunctionExit
    return
}

Write-ScreenInfo -Message "Machines with WebServer role to be installed: '$($machines.Name -join ', ')'"
```

---

## Error Handling Patterns

### Standard Try-Catch-Finally Pattern

```powershell
function Install-LabComponent {
    [CmdletBinding()]
    param()
    
    Write-LogFunctionEntry
    
    $labDiskDeploymentInProgressPath = Get-LabConfigurationItem -Name DiskDeploymentInProgressPath
    
    try {
        # Check for concurrent operations
        if (Test-Path -Path $labDiskDeploymentInProgressPath) {
            Write-ScreenInfo -Message "Another deployment is in progress" -Type Warning
            Write-ScreenInfo -Message 'Waiting for other deployment to finish' -NoNewline
            
            do {
                Write-ScreenInfo -Message '.' -NoNewline
                Start-Sleep -Seconds 15
            } while (Test-Path -Path $labDiskDeploymentInProgressPath)
            
            Write-ScreenInfo -Message 'done'
        }
        
        # Create lock file
        Write-ScreenInfo -Message 'Starting deployment' -TaskStart
        New-Item -Path $labDiskDeploymentInProgressPath -ItemType File -Value ($Script:data).Name | Out-Null
        
        # Main deployment logic
        Install-Component
        
        Write-ScreenInfo -Message 'Done' -TaskEnd
    }
    catch {
        Write-ScreenInfo -Message "Deployment failed: $_" -Type Error -TaskEnd
        Write-LogFunctionExitWithError -ErrorRecord $_
        throw
    }
    finally {
        # Always clean up lock file
        Remove-Item -Path $labDiskDeploymentInProgressPath -Force -ErrorAction SilentlyContinue
    }
    
    Write-LogFunctionExit
}
```

### Job Error Handling Pattern

```powershell
# Start jobs
$jobs = Invoke-LabCommand -ComputerName $machines -ScriptBlock { Install-Software } -PassThru -NoDisplay

# Wait and check results
$jobs | Where-Object { $_ -is [System.Management.Automation.Job] } | Wait-Job | Out-Null

# Handle failures
$failedJobs = $jobs | Where-Object { $_.State -eq 'Failed' }
if ($failedJobs) {
    Write-ScreenInfo -Type Error -Message "The following machines failed: $($failedJobs.Location -join ', ')"
    return
}
```

---

## Task Execution Patterns

### Sequential Role Installation Pattern

```powershell
function Install-Lab {
    [CmdletBinding()]
    param()
    
    Write-LogFunctionEntry
    $global:PSLog_Indent = 0  # Reset indentation
    
    # Install in dependency order
    
    # 1. Root DCs first (foundation)
    if (Get-LabVM -Role RootDC | Where-Object { -not $_.SkipDeployment }) {
        Write-ScreenInfo -Message 'Installing Root Domain Controllers' -TaskStart
        
        $jobs = Invoke-LabCommand -PreInstallationActivity -ComputerName $(Get-LabVM -Role RootDC) -PassThru -NoDisplay
        $jobs | Where-Object { $_ -is [System.Management.Automation.Job] } | Wait-Job | Out-Null
        
        Install-LabRootDcs -CreateCheckPoints:$CreateCheckPoints
        
        Write-ScreenInfo -Message 'Done' -TaskEnd
    }
    
    # 2. Child DCs (depend on Root DCs)
    if (Get-LabVM -Role FirstChildDC | Where-Object { -not $_.SkipDeployment }) {
        Write-ScreenInfo -Message 'Installing Child Domain Controllers' -TaskStart
        Install-LabFirstChildDcs -CreateCheckPoints:$CreateCheckPoints
        Write-ScreenInfo -Message 'Done' -TaskEnd
    }
    
    # 3. Member servers and other roles
    # ...
    
    Write-LogFunctionExit
}
```

### Pre-Installation Activity Pattern

```powershell
# Execute pre-installation activities before main installation
$jobs = Invoke-LabCommand -PreInstallationActivity `
                          -ActivityName 'Pre-installation' `
                          -ComputerName $(Get-LabVM -Role WebServer | Where-Object { -not $_.SkipDeployment }) `
                          -PassThru `
                          -NoDisplay

# Wait for pre-installation to complete
$jobs | Where-Object { $_ -is [System.Management.Automation.Job] } | Wait-Job | Out-Null

# Proceed with main installation
Write-ScreenInfo -Message 'Installing Web Servers' -TaskStart
Install-LabWebServers -CreateCheckPoints:$CreateCheckPoints
Write-ScreenInfo -Message 'Done' -TaskEnd
```

### Machine Startup Pattern

```powershell
# Standard pattern for starting machines and waiting
Write-ScreenInfo -Message 'Waiting for machines to start up' -NoNewline
Start-LabVM -RoleName WebServer -Wait -ProgressIndicator 30

# Alternative with specific computers
Write-ScreenInfo -Message 'Starting SQL Servers' -NoNewline
$sqlMachines = Get-LabVM -Role SQLServer | Where-Object { -not $_.SkipDeployment }
Start-LabVM -ComputerName $sqlMachines -Wait -ProgressIndicator 15 -PostDelaySeconds 5
```

---

## Module Organization

### Internal vs Public Functions

**Public Functions** (`source/Public/` or module root):
- Exported in module manifest
- Full comment-based help required
- Include Write-LogFunctionEntry/Exit
- Include Write-ScreenInfo for user feedback

**Internal/Private Functions** (`source/Private/` or `internal/functions/`):
- Not exported
- Helper functions
- May skip extensive help
- May skip user feedback (but keep logging)

### Script Variables

```powershell
# Module-level state
$script:ModuleConfiguration = @{
    Version = '1.0.0'
    Initialized = $false
}

# Global state for user sessions (careful with these)
$global:PSLog_Indent = 0
$global:AL_DeploymentStart = Get-Date
```

### Configuration Item Pattern

```powershell
# Get configuration values
$timeout = Get-LabConfigurationItem -Name 'Timeout.Installation'
$skipHostFile = Get-LabConfigurationItem -Name 'SkipHostFileModification'

# With defaults
$doNotWaitForLinux = Get-LabConfigurationItem -Name 'DoNotWaitForLinux' -Default $false
```

---

## Best Practices Summary

### Logging
- ✅ ALWAYS use `Write-LogFunctionEntry` as first line in public functions
- ✅ ALWAYS use `Write-LogFunctionExit` before every return
- ✅ Use `Write-LogFunctionExitWithError` in catch blocks
- ✅ Use `Write-ScreenInfo` for user-facing messages
- ✅ Use `-TaskStart` and `-TaskEnd` for hierarchical progress
- ✅ Respect `-NoDisplay` parameter in called functions

### Progress Indication
- ✅ Use `Write-ScreenInfo -NoNewline` for operations with unknown duration
- ✅ Use `Write-Progress` for long operations with progress tracking
- ✅ Use `Write-ProgressIndicator` for tight loops (100s+ iterations)
- ✅ Always complete progress indicators (call `Write-ProgressIndicatorEnd` or `Write-Progress -Completed`)

### Error Handling
- ✅ Use try-catch-finally for resource cleanup
- ✅ Always log errors before throwing
- ✅ Use `-ErrorAction Stop` for critical operations in try blocks
- ✅ Clean up resources in finally blocks
- ✅ Check job states after Wait-Job

### Function Structure
- ✅ Validate early, return early
- ✅ Log before every return statement
- ✅ Use consistent indentation with TaskStart/TaskEnd
- ✅ Include machines list in installation messages
- ✅ Filter by `SkipDeployment` property

### Parameters
- ✅ Use `-CreateCheckPoints` switch consistently
- ✅ Filter machines: `Get-LabVM -Role X | Where-Object { -not $_.SkipDeployment }`
- ✅ Use role-based switches for Install-Lab pattern
- ✅ Detect "perform all" vs specific role installation

---

## Common Anti-Patterns to Avoid

### ❌ Missing Function Entry/Exit Logging
```powershell
# BAD
function Install-Component {
    [CmdletBinding()]
    param()
    
    # Missing Write-LogFunctionEntry
    Install-Software
    # Missing Write-LogFunctionExit
}

# GOOD
function Install-Component {
    [CmdletBinding()]
    param()
    
    Write-LogFunctionEntry
    Install-Software
    Write-LogFunctionExit
}
```

### ❌ Unclosed Task Hierarchies
```powershell
# BAD - TaskEnd missing
Write-ScreenInfo -Message 'Installing component' -TaskStart
Install-Component
# Missing TaskEnd - indentation stays wrong for rest of output

# GOOD
Write-ScreenInfo -Message 'Installing component' -TaskStart
try {
    Install-Component
    Write-ScreenInfo -Message 'Done' -TaskEnd
}
catch {
    Write-ScreenInfo -Message "Failed: $_" -Type Error -TaskEnd
    throw
}
```

### ❌ Missing SkipDeployment Filter
```powershell
# BAD - processes machines marked for skip
$machines = Get-LabVM -Role WebServer
Install-Role -ComputerName $machines

# GOOD - respects SkipDeployment flag
$machines = Get-LabVM -Role WebServer | Where-Object { -not $_.SkipDeployment }
if ($machines) {
    Install-Role -ComputerName $machines
}
```

### ❌ Inconsistent Progress Completion
```powershell
# BAD - progress indicator never completed
Write-ScreenInfo -Message 'Processing' -NoNewline
foreach ($item in $items) {
    Process-Item $item
}
# User sees: "Processing" with no completion

# GOOD - always complete
Write-ScreenInfo -Message 'Processing' -NoNewline
foreach ($item in $items) {
    Process-Item $item
}
Write-ScreenInfo -Message ' Complete'
```

---

**Document Version:** 1.0.0  
**Last Updated:** 2025-12-10  
**Project:** AutomatedLab  
**Supplements:** `powershell.instructions.md`, `powershell-advanced.instructions.md`
