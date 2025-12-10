---
applyTo: "**/GitVersion.yml,**/*.psd1,**/CHANGELOG.md"
---

# Versioning Best Practices and Standards

This document covers versioning strategies, semantic versioning, GitVersion automation, and version synchronization across project artifacts.

## Semantic Versioning

### Overview

Follow [Semantic Versioning 2.0.0](https://semver.org/) for all module and project versioning.

**Version Format**: `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`

**Version Components:**
- **MAJOR**: Incompatible API changes (breaking changes)
- **MINOR**: Backwards-compatible new functionality
- **PATCH**: Backwards-compatible bug fixes
- **PRERELEASE**: Optional pre-release identifier (alpha, beta, rc)
- **BUILD**: Optional build metadata

### Version Increment Rules

**Increment MAJOR version when:**
- ✅ Making incompatible API changes
- ✅ Removing features or functionality
- ✅ Changing behavior that breaks existing implementations
- ✅ Renaming or removing parameters
- ✅ Changing default values that affect behavior
- ✅ Requiring higher minimum PowerShell version
- ✅ Breaking changes in data structures or schemas

**Increment MINOR version when:**
- ✅ Adding new features in a backwards-compatible manner
- ✅ Adding new functions, cmdlets, or resources
- ✅ Adding new parameters with default values
- ✅ Deprecating features (but not removing them yet)
- ✅ Substantial internal improvements that add value

**Increment PATCH version when:**
- ✅ Making backwards-compatible bug fixes
- ✅ Fixing issues that don't change functionality
- ✅ Correcting typos in error messages
- ✅ Performance improvements without API changes
- ✅ Updating dependencies to patch versions

**Do NOT increment version for:**
- ❌ Documentation-only changes
- ❌ Comment updates
- ❌ Code formatting/style changes
- ❌ Test-only changes (unless fixing test bugs)
- ❌ CI/CD pipeline changes

### Pre-release Versions

Use pre-release identifiers for versions not yet ready for production:

```plaintext
1.0.0-alpha.1    # Early testing, unstable
1.0.0-beta.1     # Feature complete, testing
1.0.0-rc.1       # Release candidate, final testing
1.0.0            # Stable release
```

**Pre-release Guidelines:**
- Alpha: Early development, expect breaking changes
- Beta: Feature complete, stabilizing
- RC (Release Candidate): Final testing, no new features
- Use numeric suffixes for iterations: `alpha.1`, `alpha.2`, etc.

## GitVersion

### What is GitVersion?

GitVersion is an automated versioning tool that:
- Calculates semantic versions based on Git history
- Uses branch names and commit messages to determine version increments
- Integrates with CI/CD pipelines
- Ensures consistent versioning across artifacts
- Eliminates manual version management

### Basic GitVersion Configuration

Create `GitVersion.yml` in repository root:

```yaml
mode: Mainline
branches:
  main:
    tag: ''
  develop:
    tag: 'preview'
ignore:
  sha: []
```

**Key Settings:**
- `mode: Mainline` - Continuous delivery from main branch
- `branches` - Per-branch versioning strategies
- `tag` - Pre-release tag for versions
- `ignore` - Commits to exclude from versioning

### Advanced GitVersion Configuration (DSC Community Standard)

For PowerShell modules following DSC Community patterns:

```yaml
mode: Mainline
assembly-versioning-scheme: MajorMinorPatch
assembly-file-versioning-scheme: MajorMinorPatch
next-version: 1.0.0
major-version-bump-message: '\+semver:\s?(breaking|major)'
minor-version-bump-message: '\+semver:\s?(feature|minor)'
patch-version-bump-message: '\+semver:\s?(fix|patch)'
no-bump-message: '\+semver:\s?none'
legacy-semver-padding: 4
build-metadata-padding: 4
commits-since-version-source-padding: 4

branches:
  main:
    tag: ''
    regex: ^master$|^main$
    source-branches: ['develop', 'release']
    is-release-branch: true
    
  develop:
    tag: 'preview'
    regex: ^dev(elop)?(ment)?$
    source-branches: []
    is-release-branch: false
    
  feature:
    tag: 'preview'
    regex: ^features?[/-]
    source-branches: ['develop']
    increment: Minor
    
  pull-request:
    tag: 'PR'
    regex: ^(pull|pull\-requests|pr)[/-]
    source-branches: ['develop', 'main', 'release', 'feature', 'hotfix']
    tag-number-pattern: '[/-](?<number>\d+)'
    
  hotfix:
    tag: 'fix'
    regex: ^hotfix(es)?[/-]
    source-branches: ['main']
    
  release:
    tag: ''
    regex: ^releases?[/-]
    source-branches: ['develop']
    is-release-branch: true

ignore:
  sha: []
```

**Configuration Explained:**
- **assembly-versioning-scheme**: How assembly versions are calculated
- **next-version**: Starting version for new repositories
- **bump-message patterns**: Regex to detect version increment from commits
- **padding**: Zero-padding for version components
- **Branch strategies**: Different versioning per branch type

## Commit Message Conventions

### Conventional Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```plaintext
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Common Types:**
- `feat`: New feature (increments MINOR)
- `fix`: Bug fix (increments PATCH)
- `docs`: Documentation only
- `style`: Code style/formatting
- `refactor`: Code restructuring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes
- `build`: Build system changes

**Breaking Changes:**
Add `BREAKING CHANGE:` in footer or `!` after type:

```plaintext
feat!: remove legacy API endpoint

BREAKING CHANGE: The /api/v1/legacy endpoint has been removed.
Use /api/v2/resource instead.
```

### SemVer Hints in Commit Messages

Override GitVersion's default behavior with `+semver:` hints:

```plaintext
feat: add new caching layer +semver: minor
fix: correct parameter validation +semver: patch
refactor: restructure authentication +semver: major
docs: update README +semver: none
```

**SemVer Hint Options:**
- `+semver: major` or `+semver: breaking` - Force major increment
- `+semver: minor` or `+semver: feature` - Force minor increment
- `+semver: patch` or `+semver: fix` - Force patch increment
- `+semver: none` - Skip version increment

### Commit Message Examples

**Feature Addition:**
```plaintext
feat(user-management): add password reset functionality

Implements password reset via email verification.
Includes new Send-PasswordResetEmail function.

Closes #123
```

**Bug Fix:**
```plaintext
fix(validation): correct email regex pattern

The previous regex allowed invalid email formats.
Updated to RFC 5322 compliant pattern.

Fixes #456
```

**Breaking Change:**
```plaintext
feat(api)!: change authentication to OAuth 2.0

BREAKING CHANGE: Basic authentication is no longer supported.
All clients must migrate to OAuth 2.0.

Migration guide: docs/oauth-migration.md
```

**Documentation Update:**
```plaintext
docs: update installation instructions +semver: none

Added troubleshooting section for common installation issues.
```

## Branch-Based Versioning Strategies

### Main/Master Branch

**Purpose**: Production-ready code
**Versioning**: Stable releases without pre-release tags
**Example**: `1.2.3`

**Workflow:**
1. All merges to main create release versions
2. Tagged automatically in CI/CD
3. Published to PowerShell Gallery
4. Changelog updated with release date

### Develop Branch

**Purpose**: Integration branch for features
**Versioning**: Preview versions with `-preview` tag
**Example**: `1.3.0-preview.4`

**Workflow:**
1. Feature branches merge here
2. CI/CD builds preview versions
3. Can be published to PSGallery as prerelease
4. Merged to main when stable

### Feature Branches

**Purpose**: New feature development
**Versioning**: Preview versions with branch name
**Example**: `1.3.0-feature-caching.12`

**Workflow:**
1. Branch from develop: `feature/caching`
2. Commits increment preview counter
3. Merge to develop when complete
4. Branch deleted after merge

### Pull Request Branches

**Purpose**: Code review and validation
**Versioning**: PR-specific preview versions
**Example**: `1.2.1-PR123.5`

**Workflow:**
1. Created from feature or develop
2. Version includes PR number
3. CI/CD validates all checks
4. Merged after approval

### Hotfix Branches

**Purpose**: Critical production fixes
**Versioning**: Patch increment with `-fix` tag
**Example**: `1.2.4-fix.1`

**Workflow:**
1. Branch from main: `hotfix/critical-bug`
2. Immediate patch version increment
3. Merged to both main and develop
4. Tagged and released quickly

### Release Branches

**Purpose**: Release preparation and stabilization
**Versioning**: Release candidate versions
**Example**: `2.0.0-rc.1`

**Workflow:**
1. Branch from develop: `release/2.0.0`
2. Only bug fixes and documentation
3. No new features
4. Merged to main when stable
5. Tagged with final version

## Version Synchronization

### Critical Requirement

**All version numbers MUST be synchronized across:**
1. Module manifest (`.psd1`) - `ModuleVersion` property
2. Changelog (`CHANGELOG.md`) - Latest `[Unreleased]` or version header
3. Git tags - Annotated tag matching release version
4. PowerShell Gallery metadata - Published version

### Module Manifest (.psd1)

**Update ModuleVersion:**

```powershell
@{
    ModuleVersion = '1.2.3'
    # For prerelease versions, use Prerelease property (PSGallery SemVer 2.0)
    Prerelease = 'preview'  # Results in 1.2.3-preview
}
```

**Automated Update in CI/CD:**

```powershell
# PowerShell script to update manifest
$manifestPath = './MyModule/MyModule.psd1'
$version = $env:GitVersion_SemVer

Update-ModuleManifest -Path $manifestPath -ModuleVersion $version
```

### Changelog (CHANGELOG.md)

**Version Header Format:**

```markdown
## [Unreleased]

### Added
- New feature descriptions

## [1.2.3] - 2024-01-15

### Fixed
- Bug fix descriptions
```

**Automated Update:**

```powershell
# Update changelog with version and date
$changelog = Get-Content -Path './CHANGELOG.md' -Raw
$version = $env:GitVersion_SemVer
$date = Get-Date -Format 'yyyy-MM-dd'

$updated = $changelog -replace '\[Unreleased\]', "[$version] - $date`n`n## [Unreleased]"
Set-Content -Path './CHANGELOG.md' -Value $updated
```

### Git Tags

**Tagging Strategy:**

```bash
# Annotated tag with message
git tag -a v1.2.3 -m "Release version 1.2.3"

# Push tag to remote
git push origin v1.2.3
```

**Automated Tagging in CI/CD:**

```yaml
# Azure Pipelines
- task: Bash@3
  inputs:
    targetType: 'inline'
    script: |
      git tag -a "v$(GitVersion.SemVer)" -m "Release $(GitVersion.SemVer)"
      git push origin "v$(GitVersion.SemVer)"
```

### Validation Requirements

**Pre-release Checklist:**
- [ ] Module manifest version matches GitVersion calculation
- [ ] CHANGELOG.md has entry for new version with date
- [ ] Git tag exists for version
- [ ] All tests pass with new version
- [ ] Documentation references correct version
- [ ] Breaking changes documented if MAJOR increment

**Automated Validation Script:**

```powershell
# Validate version synchronization
$manifestVersion = (Import-PowerShellDataFile './MyModule/MyModule.psd1').ModuleVersion
$changelogVersion = (Select-String -Path './CHANGELOG.md' -Pattern '## \[(\d+\.\d+\.\d+)\]').Matches[0].Groups[1].Value
$gitTag = git describe --tags --abbrev=0

if ($manifestVersion -ne $changelogVersion -or "v$manifestVersion" -ne $gitTag) {
    Write-Error "Version mismatch detected!"
    Write-Host "Manifest: $manifestVersion"
    Write-Host "Changelog: $changelogVersion"
    Write-Host "Git Tag: $gitTag"
    exit 1
}
```

## Automated Versioning Workflow

### Azure Pipelines Integration

**Install and Run GitVersion:**

```yaml
trigger:
  branches:
    include:
      - main
      - develop
      - feature/*
      - hotfix/*

pool:
  vmImage: 'windows-latest'

steps:
- task: gitversion/setup@0
  displayName: 'Install GitVersion'
  inputs:
    versionSpec: '5.x'

- task: gitversion/execute@0
  displayName: 'Calculate Version'
  inputs:
    useConfigFile: true
    configFilePath: 'GitVersion.yml'

- task: PowerShell@2
  displayName: 'Update Module Manifest'
  inputs:
    targetType: 'inline'
    script: |
      $version = "$(GitVersion.SemVer)"
      Update-ModuleManifest -Path './MyModule/MyModule.psd1' -ModuleVersion $version
      Write-Host "Updated manifest to version: $version"

- task: PowerShell@2
  displayName: 'Display Version Info'
  inputs:
    targetType: 'inline'
    script: |
      Write-Host "SemVer: $(GitVersion.SemVer)"
      Write-Host "Major: $(GitVersion.Major)"
      Write-Host "Minor: $(GitVersion.Minor)"
      Write-Host "Patch: $(GitVersion.Patch)"
      Write-Host "PreReleaseTag: $(GitVersion.PreReleaseTag)"
```

### GitHub Actions Integration

**GitVersion Workflow:**

```yaml
name: Version and Build

on:
  push:
    branches:
      - main
      - develop
  pull_request:

jobs:
  version:
    runs-on: windows-latest
    
    steps:
    - name: Checkout
      uses: actions/checkout@v3
      with:
        fetch-depth: 0  # Required for GitVersion
    
    - name: Install GitVersion
      uses: gittools/actions/gitversion/setup@v0
      with:
        versionSpec: '5.x'
    
    - name: Determine Version
      id: gitversion
      uses: gittools/actions/gitversion/execute@v0
      with:
        useConfigFile: true
        configFilePath: GitVersion.yml
    
    - name: Display Version
      run: |
        echo "SemVer: ${{ steps.gitversion.outputs.semVer }}"
        echo "Major: ${{ steps.gitversion.outputs.major }}"
        echo "Minor: ${{ steps.gitversion.outputs.minor }}"
        echo "Patch: ${{ steps.gitversion.outputs.patch }}"
    
    - name: Update Module Manifest
      shell: pwsh
      run: |
        $version = "${{ steps.gitversion.outputs.semVer }}"
        Update-ModuleManifest -Path './MyModule/MyModule.psd1' -ModuleVersion $version
        Write-Host "Updated to version: $version"
```

### CI/CD Version Variables

**Available GitVersion Variables:**

| Variable | Description | Example |
|----------|-------------|---------|
| `GitVersion.SemVer` | Full semantic version | `1.2.3-preview.4` |
| `GitVersion.Major` | Major version number | `1` |
| `GitVersion.Minor` | Minor version number | `2` |
| `GitVersion.Patch` | Patch version number | `3` |
| `GitVersion.PreReleaseTag` | Pre-release identifier | `preview.4` |
| `GitVersion.BuildMetaData` | Build metadata | `5.Branch.develop` |
| `GitVersion.FullSemVer` | Complete version string | `1.2.3-preview.4+5` |
| `GitVersion.InformationalVersion` | Informational version | `1.2.3-preview.4+5.Branch.develop.Sha.abc123` |

## Function-Level Versioning

### Internal Version Tracking

Track version metadata within functions for debugging and compatibility:

```powershell
function Get-UserData {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$UserId
    )
    
    # Function metadata
    $functionVersion = '1.2.0'
    $moduleVersion = $MyInvocation.MyCommand.Module.Version
    
    Write-Verbose "Function Version: $functionVersion"
    Write-Verbose "Module Version: $moduleVersion"
    
    # Function implementation
    # ...
}
```

### Version Attributes

Use PowerShell custom attributes for version documentation:

```powershell
class VersionAttribute : System.Attribute {
    [string]$Version
    [string]$Since
    [string]$Deprecated
    
    VersionAttribute([string]$version) {
        $this.Version = $version
    }
}

[Version("1.2.0")]
function Get-UserData {
    # Implementation
}
```

## Version Validation and Testing

### Pre-commit Validation

**Git Hook for Version Checks:**

```powershell
# .git/hooks/pre-commit
#!/usr/bin/env pwsh

$manifest = Import-PowerShellDataFile './MyModule/MyModule.psd1'
$changelog = Get-Content './CHANGELOG.md' -Raw

if ($changelog -notmatch "\[Unreleased\]") {
    Write-Error "CHANGELOG.md must have [Unreleased] section"
    exit 1
}

Write-Host "✓ Version validation passed"
exit 0
```

### CI/CD Validation

**Automated Version Validation:**

```yaml
- task: PowerShell@2
  displayName: 'Validate Versioning'
  inputs:
    targetType: 'inline'
    script: |
      # Validate manifest exists
      $manifestPath = './MyModule/MyModule.psd1'
      if (-not (Test-Path $manifestPath)) {
          Write-Error "Module manifest not found"
          exit 1
      }
      
      # Validate changelog format
      $changelog = Get-Content './CHANGELOG.md' -Raw
      if ($changelog -notmatch '## \[\d+\.\d+\.\d+\]') {
          Write-Error "CHANGELOG.md missing version entries"
          exit 1
      }
      
      # Validate SemVer format
      $version = (Import-PowerShellDataFile $manifestPath).ModuleVersion
      if ($version -notmatch '^\d+\.\d+\.\d+$') {
          Write-Error "Invalid semantic version: $version"
          exit 1
      }
      
      Write-Host "✓ All version validations passed"
```

## Best Practices Summary

### Version Management

**DO:**
- ✅ Use GitVersion for automated version calculation
- ✅ Follow semantic versioning strictly
- ✅ Synchronize versions across manifest, changelog, and tags
- ✅ Use conventional commit messages
- ✅ Validate versions in CI/CD pipelines
- ✅ Tag releases with annotated Git tags
- ✅ Document breaking changes clearly
- ✅ Use pre-release versions for non-production releases

**DON'T:**
- ❌ Manually edit version numbers without updating all artifacts
- ❌ Skip version increments for significant changes
- ❌ Use inconsistent versioning across branches
- ❌ Forget to update CHANGELOG.md with version details
- ❌ Tag commits without proper validation
- ❌ Release breaking changes as MINOR or PATCH versions
- ❌ Use generic commit messages that skip version metadata

### Commit Message Best Practices

**DO:**
- ✅ Write clear, descriptive commit messages
- ✅ Use conventional commit format
- ✅ Include `+semver:` hints when needed
- ✅ Reference issue numbers
- ✅ Explain the "why" in commit body
- ✅ Mark breaking changes explicitly

**DON'T:**
- ❌ Write vague messages like "fix stuff" or "update"
- ❌ Commit without considering version impact
- ❌ Mix multiple unrelated changes in one commit
- ❌ Forget to add `+semver: none` for docs-only changes

### Release Process

**Preparation:**
1. Ensure all tests pass
2. Update CHANGELOG.md with release notes
3. Validate version synchronization
4. Review breaking changes documentation
5. Test in pre-release environment

**Execution:**
1. GitVersion calculates version from Git history
2. CI/CD updates module manifest automatically
3. Automated tests run with new version
4. Git tag created for release
5. Publish to PowerShell Gallery
6. Update CHANGELOG.md with release date

**Post-release:**
1. Verify published version on PSGallery
2. Update documentation links
3. Create GitHub release with notes
4. Announce release in appropriate channels

### Changelog Integration

Versioning and changelog management are tightly coupled:

- **Version increments** must have corresponding CHANGELOG.md entries
- **Breaking changes** in commits must appear in CHANGELOG.md
- **Release dates** in CHANGELOG.md must match Git tag dates
- **Version headers** in CHANGELOG.md must match module manifest versions

See `markdown.instructions.md` for detailed changelog management practices.

## Common Versioning Scenarios

### Scenario 1: Adding a New Feature

**Situation:** Adding a new `Export-Report` function to the module.

**Steps:**
1. Create feature branch: `git checkout -b feature/export-report`
2. Implement function with tests
3. Commit with conventional message:
   ```
   feat(reports): add Export-Report function
   
   Implements PDF and Excel export capabilities for reports.
   Includes comprehensive parameter validation and error handling.
   
   Closes #234
   ```
4. GitVersion calculates: `1.3.0-feature-export-report.1`
5. Merge to develop: Version becomes `1.3.0-preview.X`
6. Update CHANGELOG.md:
   ```markdown
   ## [Unreleased]
   
   ### Added
   - New `Export-Report` function for PDF and Excel export (#234)
   ```
7. Merge to main: Version becomes `1.3.0`
8. Tag release: `git tag -a v1.3.0 -m "Release 1.3.0"`

**Result:** MINOR version increment (new functionality, backwards-compatible)

### Scenario 2: Fixing a Bug

**Situation:** Fixing null reference error in `Get-UserData`.

**Steps:**
1. Create hotfix branch from main: `git checkout -b hotfix/null-reference`
2. Fix bug and add regression test
3. Commit with message:
   ```
   fix(users): handle null values in Get-UserData
   
   Previously threw NullReferenceException when user had no email.
   Now returns empty string with proper warning.
   
   Fixes #456
   ```
4. GitVersion calculates: `1.2.1-fix.1`
5. Merge to main: Version becomes `1.2.1`
6. Tag and release immediately
7. Merge back to develop to keep branches in sync

**Result:** PATCH version increment (bug fix, backwards-compatible)

### Scenario 3: Breaking Change

**Situation:** Renaming parameter from `-UserName` to `-Identity` for consistency.

**Steps:**
1. Create feature branch: `git checkout -b feature/rename-username-param`
2. Update function signature and all references
3. Update documentation and examples
4. Commit with breaking change marker:
   ```
   feat(users)!: rename UserName parameter to Identity
   
   BREAKING CHANGE: The -UserName parameter has been renamed to -Identity
   for consistency across all user-related functions.
   
   Migration: Replace all instances of -UserName with -Identity in scripts.
   ```
5. Update CHANGELOG.md with migration guide:
   ```markdown
   ## [Unreleased]
   
   ### BREAKING CHANGES
   - **User Functions**: Renamed `-UserName` parameter to `-Identity` across all functions
     - **Migration**: Update all scripts using `-UserName` to use `-Identity`
     - **Reason**: Consistency with Active Directory and other PowerShell modules
   ```
6. Merge to develop, then to main
7. GitVersion calculates: `2.0.0` (MAJOR increment)

**Result:** MAJOR version increment (breaking API change)

### Scenario 4: Multiple Changes in One Release

**Situation:** Release includes features, fixes, and documentation.

**Commits:**
```
feat(auth): add OAuth 2.0 support
fix(logging): correct timestamp format in logs
docs: update authentication examples +semver: none
test: add integration tests for OAuth +semver: none
```

**CHANGELOG.md:**
```markdown
## [Unreleased]

### Added
- OAuth 2.0 authentication support (#567)

### Fixed
- Timestamp format in log output now uses ISO 8601 (#589)

### Documentation
- Updated authentication examples with OAuth patterns
```

**Result:** MINOR version increment (highest impact is new feature)

## Resources and References

### Official Documentation

- **Semantic Versioning**: [https://semver.org/](https://semver.org/)
- **GitVersion**: [https://gitversion.net/](https://gitversion.net/)
- **Conventional Commits**: [https://www.conventionalcommits.org/](https://www.conventionalcommits.org/)
- **Keep a Changelog**: [https://keepachangelog.com/](https://keepachangelog.com/)

### PowerShell Specific

- **PowerShell Gallery SemVer 2.0 Support**: [Microsoft Docs](https://learn.microsoft.com/en-us/powershell/gallery/)
- **Module Manifest (psd1)**: [about_Module_Manifests](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_module_manifests)
- **Update-ModuleManifest**: [Command Reference](https://learn.microsoft.com/en-us/powershell/module/powershellget/update-modulemanifest)

### DSC Community Standards

- **DSC Community Guidelines**: [https://dsccommunity.org/](https://dsccommunity.org/)
- **Sample GitVersion Configurations**: [DSC Community Repos](https://github.com/dsccommunity)
- **ComputerManagementDsc**: Reference implementation example
- **SqlServerDsc**: Advanced versioning patterns

### CI/CD Integration

- **Azure Pipelines GitVersion Task**: [GitTools Extension](https://marketplace.visualstudio.com/items?itemName=gittools.gittools)
- **GitHub Actions GitVersion**: [GitTools Actions](https://github.com/GitTools/actions)
- **GitVersion Documentation**: [Configuration Examples](https://gitversion.net/docs/reference/configuration)

### Version Management Tools

- **GitVersion CLI**: Command-line version calculation tool
- **PSFramework**: PowerShell framework with versioning utilities
- **Pester**: Testing framework for version validation
- **PSScriptAnalyzer**: Static analysis for PowerShell code quality

---

**Document Version:** 1.0.0  
**Last Updated:** 2024-01-15  
**Maintained By:** AI Instruction Framework
