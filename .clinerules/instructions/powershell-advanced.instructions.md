---
applyTo: "**/*.ps1,**/*.psm1,**/*.psd1"
---

# PowerShell Advanced Best Practices and Patterns

This document supplements `powershell.instructions.md` with advanced patterns, modern techniques, and professional-grade practices observed in enterprise PowerShell projects and community best practices.

## Table of Contents

- [Type System Best Practices](#type-system-best-practices)
- [String Quotation Standards](#string-quotation-standards)
- [Advanced Parameter Patterns](#advanced-parameter-patterns)
- [Cross-Platform PowerShell](#cross-platform-powershell)
- [Logging and Debugging](#logging-and-debugging)
- [Resource Management](#resource-management)
- [Variable Scope Management](#variable-scope-management)
- [User Experience Patterns](#user-experience-patterns)
- [C# Integration](#c-integration)
- [Advanced Error Handling](#advanced-error-handling)

---

## Type System Best Practices

### Explicit Type Declaration

Always specify variable types explicitly for clarity, performance, and to prevent type coercion issues.

```powershell
# Good - Explicit full type names
[System.String]$userName = 'JohnDoe'
[System.Int32]$count = 42
[System.Boolean]$isEnabled = $true
[System.Collections.Generic.List[string]]$items = @()

# Acceptable but less explicit
[string]$userName = 'JohnDoe'
[int]$count = 42
[bool]$isEnabled = $true

# Avoid - No type specification (implicit typing)
$userName = 'JohnDoe'  # Type is inferred
$count = 42            # Could be [int] or [long]
```

### Full Type Names vs Type Accelerators

**Recommendation:** Use full .NET type names in production code for maximum clarity and consistency.

```powershell
# Preferred - Full type names
[System.String]$text
[System.Int32]$number
[System.Collections.Hashtable]$table
[System.Management.Automation.PSCredential]$credential

# Acceptable for interactive/prototyping
[string]$text
[int]$number
[hashtable]$table
[pscredential]$credential
```

### Common Type Accelerators Reference

| Type Accelerator | Full Type Name |
|------------------|----------------|
| `[string]` | `[System.String]` |
| `[int]` | `[System.Int32]` |
| `[long]` | `[System.Int64]` |
| `[bool]` | `[System.Boolean]` |
| `[datetime]` | `[System.DateTime]` |
| `[array]` | `[System.Array]` |
| `[hashtable]` | `[System.Collections.Hashtable]` |
| `[pscredential]` | `[System.Management.Automation.PSCredential]` |
| `[pscustomobject]` | `[System.Management.Automation.PSCustomObject]` |

### When to Use Each

**Full Type Names:**
- Production scripts and modules
- Educational/documentation code
- When type clarity is critical
- Shared/team codebases

**Type Accelerators:**
- Interactive PowerShell sessions
- Quick prototyping
- Personal scripts
- When brevity aids readability

### Generic Types

```powershell
# Generic collections with full types
[System.Collections.Generic.List[System.String]]$names = @()
[System.Collections.Generic.Dictionary[System.String, System.Int32]]$scores = @{}

# With type accelerators (acceptable)
[System.Collections.Generic.List[string]]$names = @()
[System.Collections.Generic.Dictionary[string, int]]$scores = @{}
```

---

## String Quotation Standards

### Single vs Double Quotes

**Default Rule: Use single quotes unless you need interpolation or escape sequences.**

```powershell
# Good - Single quotes for static strings
$message = 'Hello, World'
$path = 'C:\Temp\file.txt'
$literal = 'Use single quotes by default'

# Good - Double quotes for variable interpolation
$name = 'Alice'
$greeting = "Hello, $name"
$message = "Processing file: $($file.FullName)"

# Good - Double quotes for escape sequences
$multiLine = "Line 1`nLine 2`nLine 3"
$tab = "Column1`tColumn2"
$quote = "He said `"Hello`""

# Avoid - Unnecessary double quotes
$message = "Hello, World"     # No interpolation needed - use single quotes
$path = "C:\Temp\file.txt"    # No interpolation needed - use single quotes
```

### Why Single Quotes Are Preferred

1. **Performance**: Slightly faster (no variable expansion processing)
2. **Security**: Prevents unintended variable expansion
3. **Clarity**: Reader knows immediately there's no interpolation
4. **Safety**: Reduces injection risks

```powershell
# Security concern with double quotes
$userInput = Get-UserInput
$query = "SELECT * FROM Users WHERE Name = '$userInput'"  # SQL injection risk!

# Better with parameterized queries, but single quotes show intent
$staticQuery = 'SELECT * FROM Users WHERE UserID = @UserID'
```

### Here-Strings

```powershell
# Single-quoted here-string (literal)
$literal = @'
This is a literal string.
Variables like $PSVersionTable are not expanded.
Use for: SQL, JSON, config templates
'@

# Double-quoted here-string (interpolated)
$interpolated = @"
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Path: $PWD
"@
```

### Best Practices Summary

- ✅ Default to single quotes (`'text'`)
- ✅ Use double quotes only when needed (`"$variable"`)
- ✅ Use here-strings for multi-line content
- ✅ Escape special characters in double-quoted strings (`"Line 1`nLine 2"`)
- ❌ Don't use double quotes unnecessarily

---

## Advanced Parameter Patterns

### Dynamic ValidateSet with IValidateSetValuesGenerator

PowerShell 6+ supports dynamic validation using classes.

```powershell
# Define a class that generates valid values dynamically
class ValidEnvironments : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        # Return dynamic list of valid values
        return @('Development', 'Test', 'Staging', 'Production')
    }
}

# Use in parameter validation
function Deploy-Application {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet([ValidEnvironments])]
        [System.String]$Environment,
        
        [Parameter(Mandatory)]
        [System.String]$ApplicationName
    )
    
    Write-Host "Deploying $ApplicationName to $Environment"
}
```

### Advanced Example: File-Based Dynamic Validation

```powershell
class ValidConfigFiles : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        $configPath = Join-Path $PSScriptRoot 'configs'
        if (Test-Path $configPath) {
            return (Get-ChildItem -Path $configPath -Filter '*.json').BaseName
        }
        return @()
    }
}

function Import-Configuration {
    [CmdletBinding()]
    param(
        [ValidateSet([ValidConfigFiles])]
        [System.String]$ConfigName
    )
    
    $configFile = Join-Path $PSScriptRoot "configs\$ConfigName.json"
    Get-Content $configFile | ConvertFrom-Json
}
```

### Argument Transformation Attributes

Transform parameter input automatically before processing.

```powershell
# Custom transformation attribute
class ToLowerTransformAttribute : System.Management.Automation.ArgumentTransformationAttribute {
    [System.Object] Transform(
        [System.Management.Automation.EngineIntrinsics]$engineIntrinsics,
        [System.Object]$inputData
    ) {
        return $inputData.ToString().ToLower()
    }
}

# Usage
function Get-User {
    [CmdletBinding()]
    param(
        [ToLowerTransform()]
        [System.String]$UserName
    )
    
    # $UserName is automatically lowercased
    Write-Host "Looking up user: $UserName"
}

# Call with any case
Get-User -UserName 'ALICE'  # Automatically becomes 'alice'
```

### Path Normalization Transform

```powershell
class NormalizePathAttribute : System.Management.Automation.ArgumentTransformationAttribute {
    [System.Object] Transform(
        [System.Management.Automation.EngineIntrinsics]$engineIntrinsics,
        [System.Object]$inputData
    ) {
        $path = $inputData.ToString()
        
        # Resolve relative paths to absolute
        if (-not [System.IO.Path]::IsPathRooted($path)) {
            $path = Join-Path $PWD $path
        }
        
        # Normalize separators for current platform
        return [System.IO.Path]::GetFullPath($path)
    }
}

function Process-File {
    [CmdletBinding()]
    param(
        [NormalizePath()]
        [ValidateScript({ Test-Path $_ })]
        [System.String]$FilePath
    )
    
    Write-Host "Processing: $FilePath"
}
```

### Complex Validation with ValidateScript

```powershell
function New-DatabaseConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -notmatch '^\w+$') {
                throw "Database name must contain only alphanumeric characters and underscores"
            }
            if ($_.Length -gt 64) {
                throw "Database name cannot exceed 64 characters"
            }
            return $true
        })]
        [System.String]$DatabaseName,
        
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -lt 1 -or $_ -gt 65535) {
                throw "Port must be between 1 and 65535"
            }
            # Additional check: common database ports
            if ($_ -notin @(1433, 3306, 5432, 27017)) {
                Write-Warning "Using non-standard database port: $_"
            }
            return $true
        })]
        [System.Int32]$Port
    )
}
```

---

## Cross-Platform PowerShell

### Platform Detection

PowerShell Core provides automatic variables for platform detection.

```powershell
# Available automatic variables
# $IsWindows - True on Windows (PowerShell Core 6+)
# $IsLinux - True on Linux
# $IsMacOS - True on macOS
# $PSVersionTable.Platform - Platform name

# Platform-specific configuration
if ($IsLinux -or $IsMacOS) {
    $configPath = Join-Path $HOME '.config/myapp'
    $separator = ':'
    $tempPath = '/tmp'
} else {
    # Windows
    $configPath = Join-Path $env:APPDATA 'MyApp'
    $separator = ';'
    $tempPath = $env:TEMP
}
```

### Conditional Cmdlet Usage

```powershell
# Windows-specific cmdlets
if ($IsWindows) {
    $computerInfo = Get-ComputerInfo
    $services = Get-Service
} else {
    # Alternative approach for Linux/macOS
    $computerInfo = @{
        OSName = (uname -s)
        OSVersion = (uname -r)
    }
}
```

### Path Handling Best Practices

```powershell
# WRONG - Hardcoded separators don't work cross-platform
$path = "$baseDir\subfolder\file.txt"  # Fails on Linux/macOS

# CORRECT - Use Join-Path
$path = Join-Path -Path $baseDir -ChildPath 'subfolder'
$path = Join-Path -Path $path -ChildPath 'file.txt'

# BETTER - Chain Join-Path calls
$path = Join-Path -Path $baseDir -ChildPath 'subfolder' |
    Join-Path -ChildPath 'file.txt'

# BEST - Use [System.IO.Path] for multiple segments
$path = [System.IO.Path]::Combine($baseDir, 'subfolder', 'file.txt')
```

### Environment Variables

```powershell
# Cross-platform home directory
if ($IsWindows) {
    $homeDir = $env:USERPROFILE
} else {
    $homeDir = $env:HOME
}

# Better - Use PowerShell automatic variable
$homeDir = $HOME  # Works on all platforms
```

### Line Endings

```powershell
# Platform-appropriate line endings
$newLine = if ($IsWindows) { "`r`n" } else { "`n" }

# Or use [Environment]::NewLine
$newLine = [System.Environment]::NewLine

# When reading files
$content = Get-Content -Path $file -Raw
$lines = $content -split '\r?\n'  # Handles both Windows and Unix line endings
```

### Executable Extensions

```powershell
# Finding executables cross-platform
function Find-Executable {
    param([System.String]$Name)
    
    if ($IsWindows) {
        $extensions = @('.exe', '.cmd', '.bat')
        foreach ($ext in $extensions) {
            $path = Get-Command "$Name$ext" -ErrorAction SilentlyContinue
            if ($path) { return $path }
        }
    } else {
        return Get-Command $Name -ErrorAction SilentlyContinue
    }
}
```

---

## Logging and Debugging

### Structured Logging with PSFramework

PSFramework provides enterprise-grade logging capabilities.

```powershell
# Install PSFramework
# Install-Module PSFramework

function Get-UserData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.String]$UserId
    )
    
    # Different log levels
    Write-PSFMessage -Level Verbose -Message "Retrieving data for user: $UserId"
    Write-PSFMessage -Level Debug -Message "Connecting to database" -Target $UserId
    
    try {
        # Simulate data retrieval
        $userData = Get-DatabaseUser -Id $UserId
        
        Write-PSFMessage -Level Significant -Message "Successfully retrieved user data" -Target $UserId
        return $userData
    }
    catch {
        Write-PSFMessage -Level Error -Message "Failed to retrieve user data" -ErrorRecord $_ -Target $UserId
        throw
    }
}
```

### Function Entry/Exit Pattern

Standard pattern for tracking function execution flow.

```powershell
# Helper functions (typically in module)
function Write-LogFunctionEntry {
    [CmdletBinding()]
    param()
    
    $caller = (Get-PSCallStack)[1]
    Write-PSFMessage -Level Debug -Message "Entering function: $($caller.Command)"
}

function Write-LogFunctionExit {
    [CmdletBinding()]
    param()
    
    $caller = (Get-PSCallStack)[1]
    Write-PSFMessage -Level Debug -Message "Exiting function: $($caller.Command)"
}

# Usage in functions
function Get-ComplexData {
    [CmdletBinding()]
    param(
        [System.String]$Filter
    )
    
    Write-LogFunctionEntry
    
    try {
        # Function logic
        $data = Get-Data -Filter $Filter
        return $data
    }
    catch {
        Write-PSFMessage -Level Error -Message "Error in Get-ComplexData" -ErrorRecord $_
        throw
    }
    finally {
        Write-LogFunctionExit
    }
}
```

### Diagnostic Logging

```powershell
function Invoke-Operation {
    [CmdletBinding()]
    param()
    
    # Log diagnostic information
    Write-PSFMessage -Level Debug -Message "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-PSFMessage -Level Debug -Message "Operating System: $($PSVersionTable.OS)"
    Write-PSFMessage -Level Debug -Message "Execution Policy: $(Get-ExecutionPolicy)"
    
    # Log performance metrics
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        # Perform operation
        $result = Invoke-ExpensiveOperation
        
        $stopwatch.Stop()
        Write-PSFMessage -Level Verbose -Message "Operation completed in $($stopwatch.ElapsedMilliseconds)ms"
        
        return $result
    }
    catch {
        $stopwatch.Stop()
        Write-PSFMessage -Level Error -Message "Operation failed after $($stopwatch.ElapsedMilliseconds)ms" -ErrorRecord $_
        throw
    }
}
```

### Debug Tracing

```powershell
function Trace-Execution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.String]$Message,
        
        [System.Collections.Hashtable]$Data
    )
    
    if ($DebugPreference -ne 'SilentlyContinue') {
        $caller = (Get-PSCallStack)[1]
        $location = "$($caller.ScriptName):$($caller.ScriptLineNumber)"
        
        Write-Debug "[$location] $Message"
        
        if ($Data) {
            foreach ($key in $Data.Keys) {
                Write-Debug "  $key = $($Data[$key])"
            }
        }
    }
}

# Usage
function Process-Item {
    param($Item)
    
    Trace-Execution -Message "Processing item" -Data @{
        ItemName = $Item.Name
        ItemSize = $Item.Length
        ItemType = $Item.GetType().Name
    }
}
```

---

## Resource Management

### IDisposable Pattern

Always properly dispose of objects that implement `IDisposable`.

```powershell
# Traditional try-finally
try {
    $stream = [System.IO.File]::OpenRead($filePath)
    $reader = [System.IO.StreamReader]::new($stream)
    $content = $reader.ReadToEnd()
}
finally {
    if ($reader) { $reader.Dispose() }
    if ($stream) { $stream.Dispose() }
}

# PowerShell 7+ using statement (preferred)
using ($stream = [System.IO.File]::OpenRead($filePath)) {
    using ($reader = [System.IO.StreamReader]::new($stream)) {
        $content = $reader.ReadToEnd()
    }
}

# Alternative: Use built-in cmdlets when available
$content = Get-Content -Path $filePath -Raw  # Handles disposal automatically
```

### Database Connection Cleanup

```powershell
function Invoke-DatabaseQuery {
    [CmdletBinding()]
    param(
        [System.String]$ConnectionString,
        [System.String]$Query
    )
    
    $connection = $null
    $command = $null
    $reader = $null
    
    try {
        $connection = [System.Data.SqlClient.SqlConnection]::new($ConnectionString)
        $connection.Open()
        
        $command = [System.Data.SqlClient.SqlCommand]::new($Query, $connection)
        $reader = $command.ExecuteReader()
        
        $results = @()
        while ($reader.Read()) {
            $results += $reader.GetValue(0)
        }
        
        return $results
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($command) { $command.Dispose() }
        if ($connection) { 
            if ($connection.State -eq 'Open') {
                $connection.Close()
            }
            $connection.Dispose()
        }
    }
}
```

### PowerShell Drive Cleanup

```powershell
function Mount-TemporaryDrive {
    [CmdletBinding()]
    param(
        [System.String]$Name,
        [System.String]$Root
    )
    
    $drive = $null
    
    try {
        $drive = New-PSDrive -Name $Name -PSProvider FileSystem -Root $Root -ErrorAction Stop
        
        # Perform operations with drive
        Get-ChildItem -Path "${Name}:\"
        
        return $drive
    }
    catch {
        Write-Error "Failed to create temporary drive: $_"
        throw
    }
    finally {
        if ($drive) {
            Remove-PSDrive -Name $Name -ErrorAction SilentlyContinue
        }
    }
}
```

### COM Object Cleanup

```powershell
function Use-ExcelApplication {
    [CmdletBinding()]
    param()
    
    $excel = $null
    $workbook = $null
    
    try {
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        
        $workbook = $excel.Workbooks.Add()
        
        # Work with Excel
        $worksheet = $workbook.Worksheets.Item(1)
        $worksheet.Cells.Item(1, 1) = "Hello"
        
        $workbook.SaveAs("C:\Temp\output.xlsx")
    }
    finally {
        # Clean up in reverse order of creation
        if ($workbook) {
            $workbook.Close($false)
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbook) | Out-Null
        }
        
        if ($excel) {
            $excel.Quit()
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null
        }
        
        # Force garbage collection for COM objects
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}
```

---

## Variable Scope Management

### Scope Prefixes

Explicitly qualify variable scope for clarity.

```powershell
# Module-level state (script scope)
$script:ModuleConfiguration = @{
    Version = '1.0.0'
    Initialized = $false
}

# Private to current scope
$private:tempValue = 'internal use only'

# Global scope (avoid when possible)
$global:SharedData = @{}

# Local scope (default, rarely needs explicit declaration)
$local:counter = 0
```

### Module State Management

```powershell
# In .psm1 file

# Initialize module state
$script:ModuleState = [PSCustomObject]@{
    Initialized = $false
    Version = '1.0.0'
    ConnectionPool = @{}
    Cache = @{}
}

# Accessor functions instead of direct global access
function Get-ModuleState {
    [CmdletBinding()]
    param()
    
    return $script:ModuleState
}

function Set-ModuleInitialized {
    [CmdletBinding()]
    param([System.Boolean]$Value)
    
    $script:ModuleState.Initialized = $Value
}

# Exported function using module state
function Get-CachedData {
    [CmdletBinding()]
    param([System.String]$Key)
    
    if ($script:ModuleState.Cache.ContainsKey($Key)) {
        return $script:ModuleState.Cache[$Key]
    }
    
    return $null
}
```

### Avoiding Global Variables

```powershell
# ❌ BAD - Mutable global variable
$global:Configuration = @{}

function Set-Config {
    param($Key, $Value)
    $global:Configuration[$Key] = $Value
}

# ✅ GOOD - Module scope with accessor functions
$script:Configuration = @{}

function Get-Configuration {
    [CmdletBinding()]
    param()
    return $script:Configuration.Clone()  # Return copy
}

function Set-Configuration {
    [CmdletBinding()]
    param(
        [System.String]$Key,
        [System.Object]$Value
    )
    $script:Configuration[$Key] = $Value
}

# ✅ BEST - Read-only if global scope is truly needed
New-Variable -Name 'MODULE_VERSION' -Value '1.0.0' -Option ReadOnly -Scope Global -Force
New-Variable -Name 'MODULE_CONFIG_PATH' -Value 'C:\Config' -Option Constant -Scope Global -Force
```

### Closures and Scope

```powershell
# Create a closure that captures variables
function New-Counter {
    [CmdletBinding()]
    param([System.Int32]$InitialValue = 0)
    
    $count = $InitialValue
    
    # Return script block with access to $count
    return {
        param([System.String]$Action)
        
        switch ($Action) {
            'Increment' { $script:count++ }
            'Decrement' { $script:count-- }
            'Get' { return $script:count }
            'Reset' { $script:count = $InitialValue }
        }
    }.GetNewClosure()  # Create closure
}

# Usage
$counter = New-Counter -InitialValue 10
& $counter 'Increment'
& $counter 'Increment'
$value = & $counter 'Get'  # Returns 12
```

---

## User Experience Patterns

### Progress Reporting

```powershell
# Standard Write-Progress for long operations
function Process-LargeDataset {
    [CmdletBinding()]
    param(
        [System.Array]$Items
    )
    
    $totalItems = $Items.Count
    
    for ($i = 0; $i -lt $totalItems; $i++) {
        $percentComplete = [System.Math]::Round(($i / $totalItems) * 100, 2)
        
        Write-Progress -Activity "Processing Dataset" `
                       -Status "Processing item $($i + 1) of $totalItems" `
                       -PercentComplete $percentComplete `
                       -CurrentOperation $Items[$i].Name
        
        # Process item
        Start-Sleep -Milliseconds 100
    }
    
    # Clear progress bar
    Write-Progress -Activity "Processing Dataset" -Completed
}
```

### Nested Progress Indicators

```powershell
function Process-NestedOperation {
    [CmdletBinding()]
    param()
    
    $outerItems = 1..5
    $innerItems = 1..10
    
    foreach ($outer in $outerItems) {
        Write-Progress -Id 0 -Activity "Outer Loop" `
                       -Status "Processing outer item $outer of $($outerItems.Count)" `
                       -PercentComplete (($outer / $outerItems.Count) * 100)
        
        foreach ($inner in $innerItems) {
            Write-Progress -Id 1 -ParentId 0 -Activity "Inner Loop" `
                           -Status "Processing inner item $inner of $($innerItems.Count)" `
                           -PercentComplete (($inner / $innerItems.Count) * 100)
            
            Start-Sleep -Milliseconds 50
        }
        
        Write-Progress -Id 1 -Activity "Inner Loop" -Completed
    }
    
    Write-Progress -Id 0 -Activity "Outer Loop" -Completed
}
```

### Lightweight Progress Indicator Pattern

```powershell
# Pattern from AutomatedLab - for tight loops
$script:ProgressIndicatorCount = 0

function Write-ProgressIndicator {
    [CmdletBinding()]
    param()
    
    $script:ProgressIndicatorCount++
    
    switch ($script:ProgressIndicatorCount % 4) {
        0 { Write-Host '|' -NoNewline }
        1 { Write-Host '/' -NoNewline }
        2 { Write-Host '-' -NoNewline }
        3 { Write-Host '\' -NoNewline }
    }
}

function Write-ProgressIndicatorEnd {
    [CmdletBinding()]
    param()
    
    Write-Host ' Done' -ForegroundColor Green
    $script:ProgressIndicatorCount = 0
}

# Usage
Write-Host "Processing files: " -NoNewline
foreach ($file in $files) {
    Write-ProgressIndicator
    # Process file
}
Write-ProgressIndicatorEnd
```

### User-Friendly Output

```powershell
function Write-ColoredStatus {
    [CmdletBinding()]
    param(
        [System.String]$Message,
        
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [System.String]$Type = 'Info'
    )
    
    $color = switch ($Type) {
        'Info' { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
    }
    
    $prefix = switch ($Type) {
        'Info' { '[i]' }
        'Success' { '[✓]' }
        'Warning' { '[!]' }
        'Error' { '[✗]' }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

# Usage
Write-ColoredStatus "Starting operation..." -Type Info
Write-ColoredStatus "Operation completed successfully" -Type Success
Write-ColoredStatus "Resource usage is high" -Type Warning
Write-ColoredStatus "Operation failed" -Type Error
```

---

## C# Integration

### Inline C# for Performance

Use C# for performance-critical operations or complex algorithms.

```powershell
# Add C# class to PowerShell session
Add-Type -TypeDefinition @"
    using System;
    using System.Collections.Generic;
    using System.Linq;
    
    namespace MyModule {
        public class FastProcessor {
            public static List<string> FilterItems(string[] items, string pattern) {
                return items
                    .Where(x => x.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    .OrderBy(x => x)
                    .ToList();
            }
            
            public static int CalculateHash(string input) {
                unchecked {
                    int hash = 17;
                    foreach (char c in input) {
                        hash = hash * 31 + c;
                    }
                    return hash;
                }
            }
        }
    }
"@

# Use from PowerShell
$items = @('Apple', 'Banana', 'Cherry', 'Apricot')
$filtered = [MyModule.FastProcessor]::FilterItems($items, 'ap')
# Result: @('Apple', 'Apricot')
```

### C# for Complex Data Structures

```powershell
Add-Type -TypeDefinition @"
    using System;
    using System.Collections.Generic;
    
    namespace MyModule {
        public class TreeNode<T> {
            public T Value { get; set; }
            public List<TreeNode<T>> Children { get; set; }
            
            public TreeNode(T value) {
                Value = value;
                Children = new List<TreeNode<T>>();
            }
            
            public void AddChild(TreeNode<T> child) {
                Children.Add(child);
            }
            
            public int CountNodes() {
                int count = 1;
                foreach (var child in Children) {
                    count += child.CountNodes();
                }
                return count;
            }
        }
    }
"@

# Create and use tree structure
$root = [MyModule.TreeNode[string]]::new("Root")
$child1 = [MyModule.TreeNode[string]]::new("Child 1")
$child2 = [MyModule.TreeNode[string]]::new("Child 2")

$root.AddChild($child1)
$root.AddChild($child2)

$totalNodes = $root.CountNodes()  # Returns 3
```

### Custom Type Accelerators

```powershell
# Register custom type accelerators for frequently used types
$TypeAcceleratorsClass = [psobject].Assembly.GetType(
    'System.Management.Automation.TypeAccelerators'
)

# Add custom accelerator
$TypeAcceleratorsClass::Add('MyType', [MyNamespace.MyClass])

# Now use short name instead of full type
[MyType]$instance = [MyType]::new()

# Remove when no longer needed
$TypeAcceleratorsClass::Remove('MyType')
```

### P/Invoke for Win32 APIs

```powershell
# Call native Windows APIs
Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    
    namespace Win32 {
        public class API {
            [DllImport("user32.dll")]
            public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
            
            [DllImport("kernel32.dll")]
            public static extern IntPtr GetConsoleWindow();
        }
    }
"@

# Hide PowerShell console window
function Hide-ConsoleWindow {
    $consolePtr = [Win32.API]::GetConsoleWindow()
    $null = [Win32.API]::ShowWindow($consolePtr, 0)  # 0 = SW_HIDE
}
```

---

## Advanced Error Handling

### Detailed Error Record Construction

```powershell
function New-CustomError {
    [CmdletBinding()]
    param(
        [System.String]$Message,
        [System.String]$ErrorId,
        [System.Management.Automation.ErrorCategory]$Category,
        [System.Object]$TargetObject
    )
    
    # Create exception with detailed message
    $exception = [System.InvalidOperationException]::new($Message)
    
    # Create error record
    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
        $exception,
        $ErrorId,
        $Category,
        $TargetObject
    )
    
    # Add additional context
    $errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
        "For more information, see: https://docs.example.com/errors/$ErrorId"
    )
    
    return $errorRecord
}

# Usage
function Invoke-Operation {
    param($ResourceName)
    
    if (-not (Test-ResourceExists $ResourceName)) {
        $error = New-CustomError `
            -Message "Resource '$ResourceName' does not exist" `
            -ErrorId 'ResourceNotFound' `
            -Category ([System.Management.Automation.ErrorCategory]::ObjectNotFound) `
            -TargetObject $ResourceName
        
        $PSCmdlet.ThrowTerminatingError($error)
    }
}
```

### Error Categorization

Use appropriate error categories for different failure types.

```powershell
function Invoke-DatabaseOperation {
    [CmdletBinding()]
    param(
        [System.String]$DatabaseName,
        [System.String]$Query
    )
    
    # Validate input
    if ([string]::IsNullOrWhiteSpace($DatabaseName)) {
        $exception = [System.ArgumentException]::new('DatabaseName cannot be empty')
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'InvalidDatabaseName',
            [System.Management.Automation.ErrorCategory]::InvalidArgument,
            $DatabaseName
        )
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }
    
    # Check resource availability
    if (-not (Test-DatabaseExists $DatabaseName)) {
        $exception = [System.InvalidOperationException]::new("Database '$DatabaseName' not found")
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'DatabaseNotFound',
            [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
            $DatabaseName
        )
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }
    
    # Check permissions
    if (-not (Test-DatabasePermission $DatabaseName)) {
        $exception = [System.UnauthorizedAccessException]::new("Access denied to database '$DatabaseName'")
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'DatabaseAccessDenied',
            [System.Management.Automation.ErrorCategory]::PermissionDenied,
            $DatabaseName
        )
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }
}
```

### Common Error Categories

| Category | Use Case | Example |
|----------|----------|---------|
| `InvalidArgument` | Parameter validation failure | Invalid parameter value |
| `InvalidOperation` | Operation not valid in current state | Cannot delete while locked |
| `ResourceExists` | Resource already exists | File already exists |
| `ResourceUnavailable` | Required resource not available | Service not running |
| `ResourceBusy` | Resource is locked/in use | File is open by another process |
| `PermissionDenied` | Insufficient permissions | Access denied |
| `ObjectNotFound` | Object doesn't exist | File not found |
| `ConnectionError` | Network/connection failure | Cannot connect to server |
| `AuthenticationError` | Authentication failed | Invalid credentials |
| `SecurityError` | Security violation | Certificate validation failed |

### Error Context and Stack Traces

```powershell
function Invoke-ComplexOperation {
    [CmdletBinding()]
    param()
    
    try {
        # Multi-layered operation
        $data = Get-DataFromDatabase
        $processed = Process-Data $data
        $result = Save-ProcessedData $processed
        return $result
    }
    catch {
        # Capture full context
        $errorInfo = @{
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().FullName
            ScriptStackTrace = $_.ScriptStackTrace
            InvocationInfo = $_.InvocationInfo
            TargetObject = $_.TargetObject
            CategoryInfo = $_.CategoryInfo
        }
        
        # Log detailed error information
        Write-PSFMessage -Level Error -Message "Operation failed" -ErrorRecord $_ -Data $errorInfo
        
        # Re-throw with context
        throw
    }
}
```

---

## Summary and Quick Reference

### Type System
- ✅ Use explicit types: `[System.String]$var`
- ✅ Prefer full type names in production code
- ✅ Use type accelerators for interactive sessions

### Strings
- ✅ Default to single quotes: `'text'`
- ✅ Double quotes only for interpolation: `"Hello $name"`
- ✅ Here-strings for multi-line content

### Cross-Platform
- ✅ Use `$IsWindows`, `$IsLinux`, `$IsMacOS`
- ✅ Use `Join-Path` or `[System.IO.Path]::Combine()`
- ✅ Test platform-specific cmdlets with conditionals

### Resource Management
- ✅ Always dispose of `IDisposable` objects
- ✅ Use `using` statement in PowerShell 7+
- ✅ Clean up PSDrives, COM objects, database connections

### Scope
- ✅ Use `$script:` for module-level state
- ✅ Avoid `$global:` variables
- ✅ Use accessor functions for module state

### User Experience
- ✅ Use `Write-Progress` for long operations
- ✅ Provide colored, clear status messages
- ✅ Include progress indicators for user feedback

### Performance
- ✅ Use C# for performance-critical code
- ✅ Use .NET methods when faster than cmdlets
- ✅ Profile and benchmark critical paths

### Error Handling
- ✅ Use appropriate error categories
- ✅ Provide detailed error messages
- ✅ Include context and remediation info

---

## Additional Resources

- [PoshCode PowerShell Practice and Style Guide](https://github.com/PoshCode/PowerShellPracticeAndStyle)
- [Microsoft PowerShell Best Practices](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-development-guidelines)
- [PSFramework Documentation](https://psframework.org/)
- [PowerShell Gallery](https://www.powershellgallery.com/)

---

**Document Version:** 1.0.0  
**Last Updated:** 2025-12-10  
**Supplements:** `powershell.instructions.md`
