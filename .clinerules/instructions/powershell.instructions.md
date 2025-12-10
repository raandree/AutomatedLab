---
applyTo: "**/*.ps1,**/*.psm1,**/*.psd1"
---

# PowerShell Best Practices and Standards

When working with PowerShell code, adhere to the following comprehensive guidelines derived from PSScriptAnalyzer rules, DSC Community standards, and PowerShell community best practices.

## Approved Verbs

PowerShell uses a standardized Verb-Noun naming convention for cmdlets and functions.

### Use Only Approved Verbs
- **ALWAYS** use approved PowerShell verbs from `Get-Verb`
- Common verbs: `Get`, `Set`, `New`, `Remove`, `Add`, `Clear`, `Copy`, `Find`, `Format`, `Join`, `Move`, `Rename`, `Reset`, `Search`, `Select`, `Show`, `Split`, `Test`, `Invoke`, `Start`, `Stop`, `Enable`, `Disable`
- **NEVER** use synonyms: Use `Remove` not `Delete`, `Get` not `Retrieve`, `Set` not `Change`

### Verb Usage Examples
```powershell
# Correct
function Get-UserProfile { }
function Set-Configuration { }
function New-TemporaryFile { }
function Test-Connection { }

# Incorrect
function Retrieve-UserProfile { }  # Use Get-
function Change-Configuration { }   # Use Set-
function Create-TemporaryFile { }   # Use New-
function Check-Connection { }       # Use Test-
```

## Function Structure

### CmdletBinding Attribute
- **ALWAYS** use `[CmdletBinding()]` for advanced functions
- Provides access to common parameters (`-Verbose`, `-Debug`, `-ErrorAction`, etc.)
- Enables advanced parameter validation

```powershell
function Get-Example {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )
    
    Write-Verbose "Processing $Name"
}
```

### Output Type Declaration
- Declare output types using `[OutputType()]` attribute
- Helps with pipeline operations and IntelliSense

```powershell
function Get-Example {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    [PSCustomObject]@{
        Name = 'Value'
    }
}
```

### Parameter Best Practices

#### Mandatory Parameters
```powershell
[Parameter(Mandatory)]
[string]$RequiredParameter

# With custom error message (PowerShell 6+)
[Parameter(Mandatory, HelpMessage = 'Please provide the server name')]
[string]$ServerName
```

#### Parameter Validation
```powershell
# ValidateNotNullOrEmpty
[Parameter()]
[ValidateNotNullOrEmpty()]
[string]$Path

# ValidateSet for allowed values
[Parameter()]
[ValidateSet('Development', 'Test', 'Production')]
[string]$Environment

# ValidatePattern for regex validation
[Parameter()]
[ValidatePattern('^[A-Z]{3}-\d{4}$')]
[string]$Code

# ValidateScript for custom validation
[Parameter()]
[ValidateScript({ Test-Path $_ })]
[string]$FilePath

# ValidateRange for numeric ranges
[Parameter()]
[ValidateRange(1, 100)]
[int]$Percentage
```

#### Parameter Sets
```powershell
function Get-Data {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(ParameterSetName = 'ByName', Mandatory)]
        [string]$Name,
        
        [Parameter(ParameterSetName = 'ById', Mandatory)]
        [int]$Id
    )
}
```

#### Pipeline Input
```powershell
[Parameter(ValueFromPipeline)]
[string]$InputObject

[Parameter(ValueFromPipelineByPropertyName)]
[string]$ComputerName
```

## Naming Conventions

### Functions and Cmdlets
- Use PascalCase for function names: `Get-UserInformation`
- Use approved Verb-Noun format
- Nouns should be singular (use `Get-User` not `Get-Users`)

### Variables
- Use camelCase for local variables: `$userName`, `$connectionString`
- Use PascalCase for script/module scope variables: `$script:Configuration`
- Use descriptive names, avoid abbreviations unless well-known

```powershell
# Good
$userName = 'JohnDoe'
$connectionString = 'Server=localhost'
$maxRetryCount = 3

# Avoid
$un = 'JohnDoe'  # Too abbreviated
$cs = 'Server=localhost'  # Unclear
$x = 3  # Non-descriptive
```

### Constants and Enumerations
```powershell
# Constants (Read-Only variables)
New-Variable -Name 'MAX_RETRY_COUNT' -Value 3 -Option ReadOnly

# Enumerations
enum LogLevel {
    Debug
    Information
    Warning
    Error
    Critical
}
```

## Error Handling

### Use Try-Catch-Finally
```powershell
try {
    $content = Get-Content -Path $filePath -ErrorAction Stop
    Process-Content -Content $content
}
catch [System.IO.FileNotFoundException] {
    Write-Error "File not found: $filePath"
}
catch {
    Write-Error "An unexpected error occurred: $_"
    Write-Debug $_.ScriptStackTrace
}
finally {
    # Cleanup code
    if ($resource) {
        $resource.Dispose()
    }
}
```

### Error Action Preference
```powershell
# For specific commands
Get-Item -Path $path -ErrorAction SilentlyContinue

# For script scope
$ErrorActionPreference = 'Stop'  # Treat all errors as terminating
```

### Throwing Errors
```powershell
# Throw with message
throw "Configuration file not found at: $configPath"

# Throw with error record
$errorRecord = [System.Management.Automation.ErrorRecord]::new(
    [System.Exception]::new('Custom error'),
    'CustomErrorId',
    [System.Management.Automation.ErrorCategory]::InvalidOperation,
    $targetObject
)
throw $errorRecord

# Write-Error for non-terminating errors
Write-Error -Message "Failed to process item" -ErrorId "ProcessingError" -Category InvalidOperation
```

## Comment-Based Help

### Complete Help Template
```powershell
function Get-Example {
    <#
    .SYNOPSIS
        Brief description of the function (one line).
    
    .DESCRIPTION
        Detailed description of what the function does.
        Can span multiple lines.
    
    .PARAMETER Name
        Description of the Name parameter.
    
    .PARAMETER Path
        Description of the Path parameter.
    
    .EXAMPLE
        Get-Example -Name 'Test'
        
        Description of what this example does.
    
    .EXAMPLE
        'Item1', 'Item2' | Get-Example -Path C:\Temp
        
        Description of pipeline example.
    
    .INPUTS
        System.String
        
        Objects that can be piped to the function.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
        
        Objects that the function outputs.
    
    .NOTES
        Author: Your Name
        Date: 2025-11-03
        Version: 1.0.0
        
        Additional notes about the function.
    
    .LINK
        https://docs.example.com/Get-Example
    
    .LINK
        Get-RelatedCommand
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter()]
        [string]$Path
    )
    
    process {
        # Function implementation
    }
}
```

## Code Style and Formatting

### Indentation and Braces
- Use 4 spaces for indentation (NOT tabs)
- Opening brace on same line as statement (One True Brace Style)
- Closing brace on its own line, aligned with statement

```powershell
# Correct
if ($condition) {
    Write-Output "True"
} else {
    Write-Output "False"
}

# Incorrect - K&R style not preferred
if ($condition)
{
    Write-Output "True"
}
```

### Line Length
- Keep lines under 115 characters when possible
- Break long lines at logical points
- Use backtick (`) for line continuation sparingly, prefer splatting

```powershell
# Long parameter list - use splatting
$splat = @{
    ComputerName = $server
    Credential = $cred
    ErrorAction = 'Stop'
    Verbose = $true
}
Get-WmiObject @splat

# Long pipeline - break after pipe
$result = Get-Process |
    Where-Object { $_.CPU -gt 100 } |
    Select-Object Name, CPU, Id |
    Sort-Object CPU -Descending
```

### Whitespace
```powershell
# Spaces after commas
$array = @(1, 2, 3, 4)

# Spaces around operators
$result = $value1 + $value2
$condition = ($x -eq 5) -and ($y -gt 10)

# No spaces inside parentheses
if ($condition) { }  # Correct
if ( $condition ) { }  # Incorrect

# Space after opening brace and before closing brace
@{ Name = 'Value' }  # Correct
@{Name='Value'}  # Incorrect
```

## Output and Formatting

### Return Objects, Not Formatted Output
```powershell
# Good - Returns objects
function Get-UserInfo {
    [PSCustomObject]@{
        Name = $user.Name
        Email = $user.Email
        Department = $user.Department
    }
}

# Bad - Returns formatted string
function Get-UserInfo {
    "$($user.Name) - $($user.Email)"
}
```

### Use Write-Output (Implicitly)
```powershell
# These are equivalent and correct
function Get-Value {
    "Value"  # Implicit Write-Output
}

function Get-Value {
    Write-Output "Value"  # Explicit
}

# DON'T use Write-Host for output (use for information display only)
```

### Use Appropriate Write Streams
```powershell
Write-Verbose "Detailed processing information"  # -Verbose flag
Write-Debug "Debug information"  # -Debug flag
Write-Warning "Warning message"  # Always shown
Write-Error "Error message"  # Always shown
Write-Information "Informational message"  # PowerShell 5+
```

## PSScriptAnalyzer Rules

### Critical Rules
- **PSAvoidUsingCmdletAliases**: Never use aliases in scripts (use `Get-ChildItem`, not `gci` or `dir`)
- **PSAvoidUsingWriteHost**: Avoid `Write-Host` except for interactive scripts
- **PSUseDeclaredVarsMoreThanAssignments**: Remove unused variables
- **PSAvoidUsingPositionalParameters**: Always use parameter names
- **PSUseApprovedVerbs**: Only use approved PowerShell verbs

```powershell
# Bad
gci $path | % { Write-Host $_.Name }

# Good
Get-ChildItem -Path $path | ForEach-Object { Write-Output $_.Name }
```

### Important Rules
- **PSUseShouldProcessForStateChangingFunctions**: Implement `-WhatIf` and `-Confirm` for state-changing functions
- **PSAvoidUsingPlainTextForPassword**: Use `[SecureString]` for passwords
- **PSAvoidUsingInvokeExpression**: Never use `Invoke-Expression` with user input
- **PSAvoidGlobalVars**: Minimize global variable usage
- **PSUseSingularNouns**: Function nouns should be singular

### ShouldProcess Pattern
```powershell
function Remove-Example {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    if ($PSCmdlet.ShouldProcess($Path, 'Remove item')) {
        Remove-Item -Path $Path
    }
}
```

## Module Development with Sampler

### Module Structure
When using Sampler for module scaffolding:

```
ModuleName/
├── source/
│   ├── Classes/           # PowerShell classes
│   ├── Private/          # Private functions (not exported)
│   ├── Public/           # Public functions (exported)
│   ├── en-US/           # Help files
│   ├── ModuleName.psd1  # Module manifest
│   └── ModuleName.psm1  # Root module
├── tests/
│   └── Unit/            # Pester tests
├── build.ps1            # Build script
├── build.yaml           # Sampler build configuration
└── RequiredModules.psd1 # Module dependencies
```

### Public vs Private Functions
- **Public**: Functions in `Public/` folder are exported and available to users
- **Private**: Functions in `Private/` folder are internal helpers

```powershell
# Public function (source/Public/Get-Example.ps1)
function Get-Example {
    [CmdletBinding()]
    param()
    
    # Can call private functions
    $internal = Get-InternalData
    Process-Data -Data $internal
}

# Private function (source/Private/Get-InternalData.ps1)
function Get-InternalData {
    [CmdletBinding()]
    param()
    
    # Internal implementation
}
```

### Module Manifest Best Practices
```powershell
# ModuleName.psd1
@{
    RootModule = 'ModuleName.psm1'
    ModuleVersion = '1.0.0'
    GUID = '<generate-new-guid>'
    Author = 'Your Name'
    CompanyName = 'Company'
    Copyright = '(c) 2025. All rights reserved.'
    Description = 'Module description'
    PowerShellVersion = '5.1'
    
    # Functions to export (managed by Sampler)
    FunctionsToExport = @('Get-Example', 'Set-Example')
    
    # Private data
    PrivateData = @{
        PSData = @{
            Tags = @('Tag1', 'Tag2')
            LicenseUri = 'https://github.com/user/repo/blob/main/LICENSE'
            ProjectUri = 'https://github.com/user/repo'
            ReleaseNotes = 'See CHANGELOG.md'
        }
    }
}
```

## Performance Best Practices

### Use .NET Methods When Appropriate
```powershell
# Faster
[System.IO.File]::ReadAllText($path)

# Slower
Get-Content -Path $path -Raw
```

### Avoid Pipeline for Large Collections
```powershell
# Slow for large collections
$results = 1..10000 | Where-Object { $_ % 2 -eq 0 }

# Faster
$results = foreach ($num in 1..10000) {
    if ($num % 2 -eq 0) {
        $num
    }
}

# Or use .Where() method (PowerShell 4+)
$results = (1..10000).Where({ $_ % 2 -eq 0 })
```

### StringBuilder for String Concatenation
```powershell
# Slow
$result = ""
foreach ($item in $largeCollection) {
    $result += "$item`n"
}

# Fast
$sb = [System.Text.StringBuilder]::new()
foreach ($item in $largeCollection) {
    [void]$sb.AppendLine($item)
}
$result = $sb.ToString()
```

## Security Best Practices

### Credentials
```powershell
# Use SecureString for passwords
[Parameter()]
[SecureString]$Password

# Use PSCredential
[Parameter()]
[PSCredential]$Credential

# Creating credentials securely
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$credential = [PSCredential]::new($username, $securePassword)
```

### Avoid Injection
```powershell
# NEVER use Invoke-Expression with user input
# Bad
Invoke-Expression $userInput

# Use parameter binding instead
& $command -Parameter $userInput

# For SQL queries, use parameterized queries
$query = "SELECT * FROM Users WHERE UserID = @UserID"
$params = @{ UserID = $userId }
Invoke-SqlCmd -Query $query -Parameters $params
```

### Execution Policy
```powershell
# Check execution policy
Get-ExecutionPolicy

# Set for current user (doesn't require admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Testing with Pester

### Test Structure
```powershell
# ModuleName.Tests.ps1
BeforeAll {
    $modulePath = "$PSScriptRoot\..\output\ModuleName"
    Import-Module $modulePath -Force
}

Describe 'Get-Example' {
    Context 'When called with valid parameters' {
        It 'Should return expected object' {
            $result = Get-Example -Name 'Test'
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be 'Test'
        }
    }
    
    Context 'When called with invalid parameters' {
        It 'Should throw an error' {
            { Get-Example -Name $null } | Should -Throw
        }
    }
}
```

## Additional Best Practices

### Use Strict Mode
```powershell
# At top of script
Set-StrictMode -Version Latest
```

### Explicit Type Casting
```powershell
# Good
[int]$number = '42'
[datetime]$date = '2025-11-03'

# More reliable than implicit conversion
```

### Region Markers for Organization
```powershell
#region Initialization
$config = Get-Configuration
#endregion

#region Functions
function Get-Data { }
#endregion

#region Main Script
Main-Function
#endregion
```

### Version Compatibility
- Target PowerShell 5.1 for Windows compatibility
- Use `#Requires -Version 5.1` at top of script
- Test on both Windows PowerShell and PowerShell 7+
- Avoid platform-specific features unless necessary

## PowerShell Format Files (ps1xml)

### Overview
PowerShell format files (`.ps1xml`) define how objects are displayed in the console. They control the default formatting for `Format-Table`, `Format-List`, and `Format-Wide` outputs.

### Creating Format Definition Files

#### Basic Structure
```xml
<?xml version="1.0" encoding="utf-8"?>
<Configuration>
    <ViewDefinitions>
        <View>
            <Name>MyCustomView</Name>
            <ViewSelectedBy>
                <TypeName>MyModule.MyClass</TypeName>
            </ViewSelectedBy>
            <TableControl>
                <TableHeaders>
                    <TableColumnHeader>
                        <Label>Property Name</Label>
                        <Width>20</Width>
                        <Alignment>Left</Alignment>
                    </TableColumnHeader>
                </TableHeaders>
                <TableRowEntries>
                    <TableRowEntry>
                        <TableColumnItems>
                            <TableColumnItem>
                                <PropertyName>PropertyName</PropertyName>
                            </TableColumnItem>
                        </TableColumnItems>
                    </TableRowEntry>
                </TableRowEntries>
            </TableControl>
        </View>
    </ViewDefinitions>
</Configuration>
```

### Table Format Example
```xml
<View>
    <Name>ProcessTableView</Name>
    <ViewSelectedBy>
        <TypeName>System.Diagnostics.Process</TypeName>
    </ViewSelectedBy>
    <TableControl>
        <TableHeaders>
            <TableColumnHeader>
                <Label>Name</Label>
                <Width>25</Width>
            </TableColumnHeader>
            <TableColumnHeader>
                <Label>ID</Label>
                <Width>8</Width>
                <Alignment>Right</Alignment>
            </TableColumnHeader>
            <TableColumnHeader>
                <Label>CPU(s)</Label>
                <Width>10</Width>
                <Alignment>Right</Alignment>
            </TableColumnHeader>
        </TableHeaders>
        <TableRowEntries>
            <TableRowEntry>
                <TableColumnItems>
                    <TableColumnItem>
                        <PropertyName>ProcessName</PropertyName>
                    </TableColumnItem>
                    <TableColumnItem>
                        <PropertyName>Id</PropertyName>
                    </TableColumnItem>
                    <TableColumnItem>
                        <ScriptBlock>
                            [math]::Round($_.TotalProcessorTime.TotalSeconds, 2)
                        </ScriptBlock>
                    </TableColumnItem>
                </TableColumnItems>
            </TableRowEntry>
        </TableRowEntries>
    </TableControl>
</View>
```

### List Format Example
```xml
<View>
    <Name>ProcessListView</Name>
    <ViewSelectedBy>
        <TypeName>System.Diagnostics.Process</TypeName>
    </ViewSelectedBy>
    <ListControl>
        <ListEntries>
            <ListEntry>
                <ListItems>
                    <ListItem>
                        <PropertyName>ProcessName</PropertyName>
                        <Label>Process Name</Label>
                    </ListItem>
                    <ListItem>
                        <PropertyName>Id</PropertyName>
                        <Label>Process ID</Label>
                    </ListItem>
                    <ListItem>
                        <ScriptBlock>
                            "{0:N2} MB" -f ($_.WorkingSet64 / 1MB)
                        </ScriptBlock>
                        <Label>Memory Usage</Label>
                    </ListItem>
                </ListItems>
            </ListEntry>
        </ListEntries>
    </ListControl>
</View>
```

### Loading Format Files
```powershell
# Load format file for current session
Update-FormatData -PrependPath "C:\Path\To\MyFormat.ps1xml"

# Load in module manifest (.psd1)
@{
    FormatsToProcess = @('MyModule.Format.ps1xml')
}

# Load in module (.psm1)
$formatFile = Join-Path $PSScriptRoot 'MyModule.Format.ps1xml'
if (Test-Path $formatFile) {
    Update-FormatData -PrependPath $formatFile
}
```

### Best Practices for Format Files

#### File Organization
- Name format files with `.Format.ps1xml` suffix (e.g., `MyModule.Format.ps1xml`)
- Place in module root or `Formats/` subdirectory
- One format file per module or logical grouping

#### Performance Considerations
- Use `PropertyName` instead of `ScriptBlock` when possible
- Limit complex calculations in ScriptBlocks
- Consider caching expensive operations

#### Responsive Design
```xml
<!-- Responsive table that adapts to console width -->
<TableControl>
    <AutoSize/>
    <TableHeaders>
        <TableColumnHeader>
            <Label>Name</Label>
        </TableColumnHeader>
        <TableColumnHeader>
            <Label>Status</Label>
            <Width>10</Width>
        </TableColumnHeader>
        <TableColumnHeader>
            <Label>Details</Label>
        </TableColumnHeader>
    </TableHeaders>
    <!-- ... -->
</TableControl>
```

#### Conditional Formatting
```xml
<TableRowEntry>
    <EntrySelectedBy>
        <SelectionCondition>
            <SelectionSetName>ProcessWithHighCPU</SelectionSetName>
        </SelectionCondition>
    </EntrySelectedBy>
    <TableColumnItems>
        <TableColumnItem>
            <PropertyName>ProcessName</PropertyName>
        </TableColumnItem>
        <TableColumnItem>
            <ScriptBlock>
                if ($_.CPU -gt 50) { 
                    [ConsoleColor]::Red 
                } else { 
                    [ConsoleColor]::Green 
                }
            </ScriptBlock>
        </TableColumnItem>
    </TableColumnItems>
</TableRowEntry>
```

### Custom Object Formatting

#### PSCustomObject with TypeName
```powershell
function New-FormattedObject {
    param($Name, $Value)
    
    $obj = [PSCustomObject]@{
        Name = $Name
        Value = $Value
        Timestamp = Get-Date
    }
    
    # Add custom type name for formatting
    $obj.PSObject.TypeNames.Insert(0, 'MyModule.FormattedObject')
    return $obj
}
```

#### ETS (Extended Type System) Properties
```xml
<Types>
    <Type>
        <Name>MyModule.MyClass</Name>
        <Members>
            <ScriptProperty>
                <Name>DisplayName</Name>
                <GetScriptBlock>
                    "{0} ({1})" -f $this.Name, $this.Type
                </GetScriptBlock>
            </ScriptProperty>
            <AliasProperty>
                <Name>FullName</Name>
                <ReferencedMemberName>CompletePathName</ReferencedMemberName>
            </AliasProperty>
        </Members>
    </Type>
</Types>
```

### Testing Format Files
```powershell
# Test format file before deployment
try {
    Update-FormatData -PrependPath $formatFilePath -ErrorAction Stop
    Write-Host "Format file loaded successfully" -ForegroundColor Green
    
    # Test with sample object
    $testObject = [PSCustomObject]@{
        PSTypeName = 'MyModule.MyClass'
        Name = 'Test'
        Value = 42
    }
    
    $testObject | Format-Table
    $testObject | Format-List
} catch {
    Write-Error "Format file validation failed: $_"
}
```

### Common Format Elements Reference

#### Table Elements
- `<TableControl>` - Defines table format
- `<AutoSize/>` - Auto-size columns to content
- `<HideTableHeaders/>` - Hide column headers
- `<TableHeaders>` - Column header definitions
- `<TableRowEntries>` - Row data definitions

#### List Elements
- `<ListControl>` - Defines list format
- `<ListEntries>` - List entry definitions
- `<ListItems>` - Individual list items

#### Wide Elements
- `<WideControl>` - Defines wide format (like `Format-Wide`)
- `<WideEntries>` - Wide entry definitions
- `<WideItem>` - Individual wide items

#### Selection Elements
- `<ViewSelectedBy>` - Determines when view applies
- `<TypeName>` - Apply to specific type
- `<SelectionSetName>` - Apply to selection set
- `<SelectionCondition>` - Conditional application

## Summary Checklist

- ✅ Use approved verbs
- ✅ Include `[CmdletBinding()]`
- ✅ Add complete comment-based help
- ✅ Use proper parameter validation
- ✅ Implement error handling
- ✅ Follow naming conventions
- ✅ Return objects, not formatted text
- ✅ Use PSScriptAnalyzer and fix all warnings
- ✅ Write Pester tests for all public functions
- ✅ Use 4-space indentation
- ✅ Avoid aliases in scripts
- ✅ Implement `-WhatIf` and `-Confirm` for state changes
- ✅ Use secure credentials
- ✅ Document with examples
