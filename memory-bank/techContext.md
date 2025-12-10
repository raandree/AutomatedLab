# Technical Context: AutomatedLab

## Technology Stack

### Core Technologies

**PowerShell**
- **Primary Language**: PowerShell 5.1+ (Windows PowerShell)
- **Cross-Platform**: PowerShell 7+ (PowerShell Core)
- **Editions**: Compatible with both Desktop and Core editions
- **Version Requirements**: Minimum PowerShell 5.1

**C# / .NET**
- **LabXml Library**: C# class library for domain model
- **Framework**: .NET Framework 4.7.1+ (Windows)
- **Core**: .NET Core 2.x+ (Cross-platform)
- **CLR Version**: 4.0

### Virtualization Platforms

**Hyper-V**
- Primary on-premises virtualization engine
- Requires Windows Server 2012 R2+ or Windows 8.1+
- Hyper-V PowerShell module dependency
- Administrator privileges required
- Features: Generation 1 & 2 VMs, differencing disks, virtual switches

**Microsoft Azure**
- Cloud-based lab deployment
- Az PowerShell modules required (Az.Compute, Az.Network, Az.Storage, Az.Resources)
- Subscription and authentication required
- Supports: VMs, VNets, Storage Accounts, Resource Groups
- Linux and Windows VMs

**VMWare** (Limited Support)
- VMWare ESXi/vSphere support
- VMWare PowerCLI required
- Less mature than Hyper-V/Azure providers

**Future: Linux/KVM**
- Planned via libvirt
- Not yet implemented

## Development Environment

### Project Structure

```
AutomatedLab/
├── .vscode/                      # VS Code configuration
│   ├── settings.json            # Editor settings & formatting rules
│   └── analyzersettings.psd1    # (Not found, likely meant scriptanalyzer/)
├── scriptanalyzer/              # PSScriptAnalyzer configuration
│   ├── AutomatedLabRules.psd1   # Analysis rules & exclusions
│   └── ALCustomRules.psm1       # Custom analyzer rules
├── .clinerules/                 # Cline AI coding instructions
│   └── instructions/            # Language-specific best practices
├── AutomatedLab/                # Main wrapper module
├── AutomatedLabCore/            # Core orchestration module
├── AutomatedLabDefinition/      # Lab definition module
├── AutomatedLabWorker/          # Worker/execution module
├── AutomatedLabUnattended/      # Unattended install module
├── AutomatedLabNotifications/   # Notification module
├── AutomatedLabTest/            # Testing module
├── AutomatedLab.Recipe/         # Template/recipe module
├── AutomatedLab.Ships/          # Unknown purpose module
├── PSFileTransfer/              # File transfer utility module
├── PSLog/                       # Logging utility module
├── LabXml/                      # C# domain model library
├── LabSources/                  # Sample scripts & resources
├── Help/                        # Documentation (MkDocs)
├── Tests/                       # Integration tests
├── Installer/                   # WiX installer project
└── Assets/                      # Images, icons, resources
```

### Build System

**AppVeyor CI/CD**
- Continuous integration via AppVeyor
- Build configuration: `appveyor.yml`
- Automated builds on commits
- PowerShell Gallery publishing

**Build Scripts**
- `./.build/01-prerequisites.ps1` - Install build dependencies
- `./.build/02-build.ps1` - Build all modules and installer
- `./.build/03-validate.ps1` - Validate built modules
- Output: `./publish/` directory

**MSI Installer**
- WiX Toolset 3.x
- Project: `Installer/Installer.wixproj`
- Product definition: `Installer/Product.wxs`
- Bundles all PowerShell modules

**Module Build**
- Uses ModuleBuilder or similar
- Combines function files into .psm1
- Generates module manifests (.psd1)
- Creates help files

### Documentation System

**MkDocs**
- Static site generator for documentation
- Configuration: `mkdocs.yml`
- Source: `Help/` directory
- Output: https://automatedlab.org
- ReadTheDocs integration (`.readthedocs.yaml`)

**Comment-Based Help**
- PowerShell native help format
- Located in function files
- Compiled to external MAML help files
- `Help/` subdirectories per module

### Version Control

**Git**
- Repository: https://github.com/AutomatedLab/AutomatedLab
- Branching: master (stable), develop (integration)
- Submodules: `.gitmodules` present
- Attributes: `.gitattributes` for line endings

## Code Quality Tools

### PSScriptAnalyzer

**Configuration**: `scriptanalyzer/AutomatedLabRules.psd1`

**Enabled Rules**:
- `PSUseCompatibleCommands` - Check cmdlet compatibility
- `PSUseCompatibleCmdlets` - Ensure cmdlets work on target versions
- `PSUseCompatibleSyntax` - Syntax compatibility (PS 5.1 & 6.0+)

**Target Compatibility**:
- PowerShell 5.1 (Windows)
- PowerShell 6.0+ (Cross-platform)
- Desktop edition (Windows Server 2016+)
- Core edition (Ubuntu, Linux)

**Excluded Rules** (13 rules):
```powershell
'PSUseDeclaredVarsMoreThanAssignments'  # Variables may be used in different scopes
'PSAvoidGlobalVars'                     # Module uses script-scoped state
'PSAvoidUsingUsernameAndPasswordParams' # Lab credentials are intentional
'PSAvoidUsingWMICmdlet'                 # Legacy compatibility
'PSAvoidUsingPlainTextForPassword'      # Lab scenarios require this
'PSAvoidUsingEmptyCatchBlock'           # Some intentional error suppression
'PSUseShouldProcessForStateChangingFunctions'  # Not implemented everywhere
'PSAvoidUsingInvokeExpression'          # Some dynamic scenarios require it
'PSAvoidUsingConvertToSecureStringWithPlainText'  # Lab setup scenarios
'PSAvoidUsingComputerNameHardcoded'     # Lab definitions use hardcoded names
'PSPossibleIncorrectComparisonWithNull' # Custom rule handles this
```

**Custom Rules**: `scriptanalyzer/ALCustomRules.psm1`
- `Test-SimpleNullComparsion` - Suggests simpler null checks
  - `$null -eq $var` → `-not $var`
  - `$null -ne $var` → `$var`

### VS Code Settings

**PowerShell Formatting**: `.vscode/settings.json`

**Code Formatting Rules**:
```json
{
  "powershell.codeFormatting.autoCorrectAliases": false,
  "powershell.codeFormatting.useConstantStrings": false,
  "powershell.codeFormatting.useCorrectCasing": false,
  "powershell.codeFormatting.trimWhitespaceAroundPipe": false,
  "powershell.codeFormatting.ignoreOneLineBlock": true,
  "powershell.codeFormatting.pipelineIndentationStyle": "NoIndentation",
  "powershell.codeFormatting.preset": "Custom",
  "powershell.codeFormatting.openBraceOnSameLine": true,      // One True Brace
  "powershell.codeFormatting.newLineAfterOpenBrace": true,
  "powershell.codeFormatting.newLineAfterCloseBrace": true,
  "powershell.codeFormatting.whitespaceBeforeOpenBrace": true,
  "powershell.codeFormatting.whitespaceBeforeOpenParen": true,
  "powershell.codeFormatting.whitespaceAroundOperator": true,
  "powershell.codeFormatting.whitespaceAfterSeparator": true,
  "powershell.codeFormatting.whitespaceBetweenParameters": false,
  "powershell.codeFormatting.whitespaceInsideBrace": true,
  "powershell.codeFormatting.addWhitespaceAroundPipe": false
}
```

**File Handling for PowerShell**:
```json
{
  "files.trimTrailingWhitespace": false,  // Don't trim in PS files
  "files.trimFinalNewlines": false,       // Keep final newlines as-is
  "files.insertFinalNewline": false       // Don't force final newline
}
```

**Script Analyzer Path**:
```json
{
  "powershell.scriptAnalysis.settingsPath": "scriptanalyzer\\AutomatedLabRules.psd1"
}
```

### Cline Coding Instructions

**Location**: `.clinerules/instructions/`

**PowerShell Best Practices** (`powershell.instructions.md`):
- Approved verbs (Get-, Set-, New-, Remove-, etc.)
- CmdletBinding usage
- Parameter validation patterns
- Comment-based help templates
- Error handling standards
- Naming conventions
- Module structure patterns
- PSScriptAnalyzer compliance

**Markdown Standards** (`markdown.instructions.md`):
- Document organization and README requirements
- Changelog management (Keep a Changelog format)
- Version synchronization requirements
- Heading hierarchy
- Code block formatting

**YAML Standards** (`yaml.instructions.md`):
- Indentation rules (2 spaces)
- Key-value formatting
- Build configuration patterns

**Versioning Standards** (`versioning.instructions.md`):
- Semantic versioning (SemVer)
- GitVersion configuration
- Commit message conventions
- Changelog updates

## Testing Framework

### Pester

**Version**: Pester 5.0+ required for post-deployment tests

**Test Organization**:
```
AutomatedLabTest/tests/
├── 00General.tests.ps1      # PSScriptAnalyzer, module loading
├── ADFS.tests.ps1           # ADFS role tests
├── ADFSProxy.tests.ps1      # ADFS Proxy tests
├── ADFSWAP.tests.ps1        # ADFS WAP tests
└── [Other role tests]
```

**Test Execution**:
- `Invoke-LabPester` - Run tests against deployed lab
- `Test-LabDeployment` - Validate lab deployment
- `Install-Lab -PostDeploymentTests` - Automated validation

**Test Types**:
1. **General Tests**: Module structure, PSScriptAnalyzer compliance
2. **Role Tests**: Validate specific role installations
3. **Integration Tests**: Full lab deployment scenarios in `LabSources/SampleScripts/`

## Dependencies

### PowerShell Modules

**Required for Hyper-V**:
- `Hyper-V` - Built-in Windows module
- Admin privileges

**Required for Azure**:
- `Az.Accounts`
- `Az.Compute`
- `Az.Network`
- `Az.Storage`
- `Az.Resources`
- Additional Az modules as needed

**Required for VMWare**:
- `VMware.PowerCLI`

**Optional**:
- `Pester` 5.0+ - For testing
- Various role-specific modules loaded on-demand

### External Tools

**SysInternals Suite**:
- Auto-downloaded to LabSources
- Used for various utilities (PsExec, etc.)

**WiX Toolset**:
- Required for building MSI installer
- Version 3.x

**.NET SDKs**:
- .NET SDK 4.6.2 (Windows builds)
- .NET SDK 6.0 (Cross-platform builds)

## File Formats

### PowerShell Files

**Module Manifest (.psd1)**:
- Module metadata
- Version information
- Exported functions
- Dependencies
- Example: `AutomatedLabCore/AutomatedLabCore.psd1`

**Module Script (.psm1)**:
- Module initialization
- Dot-sourcing function files
- Module-scoped variables
- Example: `AutomatedLabCore/AutomatedLabCore.psm1`

**Function Files (.ps1)**:
- One function per file
- Comment-based help
- Located in `functions/` subdirectories

**Format Files (.format.ps1xml)**:
- Custom object formatting
- Example: `AutomatedLabCore/AutomatedLabCore.format.ps1xml`

### Data Files

**Lab Definition (Lab.xml)**:
- Serialized `[AutomatedLab.Lab]` object
- Stored in `$env:ProgramData\AutomatedLab\Labs\<LabName>\`
- XML format

**Configuration (Various .psd1)**:
- PowerShell data files
- Hashtable format
- Used for configuration storage

### Build Files

**AppVeyor (appveyor.yml)**:
- CI/CD configuration
- YAML format

**MkDocs (mkdocs.yml)**:
- Documentation build configuration
- YAML format

**WiX (.wxs, .wxi)**:
- Installer definitions
- XML format

## Platform-Specific Considerations

### Windows (Hyper-V)

**Requirements**:
- Windows Server 2012 R2+ or Windows 8.1+
- Hyper-V role enabled
- PowerShell 5.1+
- Administrator privileges
- Intel VT-x or AMD-V capable CPU

**Features Used**:
- Hyper-V PowerShell module
- Virtual switches (internal, external, private)
- Differencing disks
- Generation 1 & 2 VMs
- Integration Services

### Azure

**Requirements**:
- Azure subscription
- Az PowerShell modules
- Authentication (interactive or service principal)
- Sufficient quota for resources

**Resources Created**:
- Resource Groups
- Virtual Networks
- Storage Accounts (for LabSources)
- Virtual Machines
- Network Interfaces
- Public IPs (optional)
- Network Security Groups

### Linux (Cross-Platform PowerShell)

**Supported Distros**:
- Ubuntu (tested)
- Fedora (tested)
- Ubuntu WSL
- Azure Cloud Shell

**Requirements**:
- PowerShell Core 6+
- SSH or gss-ntlmssp for remoting
- Azure subscription (no local Hyper-V alternative yet)
- IP and route commands

**Limitations**:
- Azure-only deployment (no local hypervisor)
- KVM support planned but not implemented
- Less testing than Windows platform

## Security Considerations

### Credentials

**Lab Credentials**:
- Plain text allowed (lab environment assumption)
- Default installation credential configurable
- Domain administrator accounts created
- SQL SA passwords in configuration

**PSScriptAnalyzer Exclusions**:
- `PSAvoidUsingPlainTextForPassword`
- `PSAvoidUsingConvertToSecureStringWithPlainText`
- `PSAvoidUsingUsernameAndPasswordParams`

**Justification**: Lab environments are temporary, isolated, and for testing/training purposes only

### Network Isolation

- Internal virtual switches by default
- External connectivity optional
- Routing role for internet access
- Firewalls configurable per-VM

### Telemetry

**AutomatedLab Telemetry**:
- Opt-in telemetry system
- `Enable-LabTelemetry` / `Disable-LabTelemetry`
- Sends anonymous usage data
- Helps developers understand usage patterns

## Performance Characteristics

### Disk I/O

**Critical Factor**: Disk speed significantly impacts deployment time

**Optimization**:
- Automatic disk speed measurement
- Fastest disk selected for base images
- Differencing disks reduce I/O
- Recommendation: SSD storage

### Memory

**Dynamic Memory**:
- Hyper-V dynamic memory supported
- Automatic memory adjustment based on host
- `Update-LabMemorySettings` optimizes allocation

**Recommended**:
- Minimum 8GB host RAM for simple labs
- 16GB+ for complex multi-VM labs
- 32GB+ for enterprise scenario labs

### CPU

**Virtualization**:
- VT-x/AMD-V required
- Multiple vCPUs supported per VM
- Parallel VM creation for faster deployment

### Network

**Bandwidth**:
- Hyper-V: Local switch speeds (10Gbps+)
- Azure: Varies by VM SKU and region
- Affects file transfer and role installation speed

## Known Limitations

### Technical Constraints

1. **Hyper-V**: Windows host required (no macOS/Linux Hyper-V)
2. **Nested Virtualization**: Limited support, performance impact
3. **Large Labs**: Memory/disk constraints on single host
4. **Azure Costs**: Can accumulate quickly for large labs
5. **Linux Support**: Azure-only, no local Linux hypervisor yet

### Code Quality

1. **Legacy Code**: Some patterns from PowerShell 2.0/3.0 era
2. **Inconsistent Formatting**: 660+ files with varying styles
3. **Missing Comment Help**: Not all functions have complete help
4. **ShouldProcess**: Not implemented on all state-changing functions
5. **Error Handling**: Some empty catch blocks, inconsistent patterns

### Platform Support

1. **macOS**: Best-effort support, Azure-only
2. **Linux**: Fragmented distro support
3. **VMWare**: Less mature than Hyper-V/Azure
4. **KVM**: Planned but not implemented

## Development Tools

### Recommended Setup

**IDE**: Visual Studio Code
- PowerShell extension
- EditorConfig extension
- GitLens extension

**PowerShell**:
- Windows PowerShell 5.1
- PowerShell 7+ (for cross-platform development)

**Version Control**:
- Git command-line or Git GUI tools

**Testing**:
- Pester 5.0+
- PSScriptAnalyzer

**Build Tools** (Windows):
- Visual Studio Build Tools or full Visual Studio
- .NET SDK 4.6.2 and 6.0
- WiX Toolset 3.x

## Deployment Artifacts

### PowerShell Gallery

**Published Modules**:
- AutomatedLab (wrapper)
- AutomatedLabCore
- AutomatedLabDefinition
- AutomatedLabWorker
- AutomatedLabUnattended
- AutomatedLabNotifications
- AutomatedLabTest
- AutomatedLab.Recipe
- AutomatedLab.Ships
- PSFileTransfer
- PSLog

**Installation**:
```powershell
Install-Module -Name AutomatedLab -Scope CurrentUser
```

### MSI Installer

**Location**: GitHub Releases
**Contents**: All PowerShell modules, sample scripts, help files
**Installation Path**: Configurable during install

### GitHub Releases

**Assets**:
- MSI installer
- Release notes
- Source code archives

## Configuration Management

### Lab Configuration

**LabAppDataRoot**: Default `$env:ProgramData\AutomatedLab`
- Labs stored in `Labs\<LabName>\`
- Caches in `Cache\`
- Configuration in `Configuration\`

**LabSourcesLocation**: Default `C:\LabSources` (customizable)
- ISOs in `ISOs\`
- Software packages in `SoftwarePackages\`
- Custom roles in `CustomRoles\`
- Post-installation activities in `PostInstallationActivities\`
- Sample scripts in `SampleScripts\`
- Tools in `Tools\`

### Module Configuration

**PSFramework** (if used):
- Configuration items via `Get-LabConfigurationItem`
- Settings like disk deployment paths, notifications, etc.

## Future Technical Direction

### Planned Enhancements

1. **KVM/libvirt Support**: Linux local hypervisor
2. **Improved Cross-Platform**: Better macOS/Linux support
3. **Code Modernization**: Align with current PowerShell best practices
4. **Enhanced Testing**: More comprehensive Pester coverage
5. **Performance**: Further optimization of deployment speed

### Technical Debt to Address

1. **Code Quality Alignment**: Current initiative
2. **PSScriptAnalyzer Compliance**: Enable more rules
3. **ShouldProcess Implementation**: Add to state-changing functions
4. **Error Handling**: Standardize across all modules
5. **Documentation**: Complete comment-based help everywhere
