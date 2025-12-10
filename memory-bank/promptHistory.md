# Prompt History

## 2025-12-10 16:04 CET - PowerShell Best Practices Analysis

**User Request:**
Analyze existing PowerShell best practices file (`powershell.instructions.md`) and identify additional best practices from:
1. Web research (modern PowerShell community standards)
2. AutomatedLab codebase patterns

**Analysis Performed:**
- Read existing `.clinerules/instructions/powershell.instructions.md`
- Searched web for "PowerShell best practices 2024 2025 advanced coding standards"
- Scraped PoshCode PowerShellPracticeAndStyle repository (community-driven best practices)
- Scraped HotCakeX/Harden-Windows-Security wiki (modern PowerShell security practices)
- Analyzed AutomatedLab codebase structure and sample functions

**Key Findings:**
Successfully identified 10 major gaps in PowerShell best practices documentation:

1. **Type System Best Practices** - Explicit typing, full names vs accelerators
2. **String Quotation Standards** - Single vs double quotes for security/performance
3. **Advanced Parameter Patterns** - IValidateSetValuesGenerator, transformations
4. **Cross-Platform PowerShell** - Platform detection, path handling
5. **Logging and Debugging** - PSFramework, function entry/exit patterns
6. **Resource Management** - IDisposable, cleanup patterns
7. **Variable Scope Management** - Avoiding globals, module state
8. **User Experience Patterns** - Progress indicators, colored output
9. **C# Integration** - Performance optimization, custom types
10. **Advanced Error Handling** - Error categorization, detailed records

**Deliverable Created:**
New supplementary document: `.clinerules/instructions/powershell-advanced.instructions.md`

**Document Details:**
- 1,200+ lines of comprehensive advanced patterns
- Supplements existing `powershell.instructions.md`
- Based on:
  - PoshCode PowerShellPracticeAndStyle community guidelines
  - HotCakeX/Harden-Windows-Security security best practices
  - Microsoft official developer guidelines
  - AutomatedLab enterprise patterns (observed in codebase)

**Status:** ✅ Complete - Advanced patterns document created and ready for use

---

## 2025-12-10 16:22 CET - AutomatedLab Project-Specific Patterns

**User Follow-Up Request:**
Extract AutomatedLab-specific PowerShell patterns from the codebase to create project-specific best practices.

**Analysis Performed:**
1. Analyzed core `Install-Lab.ps1` function (650+ lines)
2. Searched for logging patterns (`Write-ProgressIndicator`, `Write-ScreenInfo`)
3. Read PSLog module implementations:
   - `Write-ScreenInfo.ps1` - User-facing hierarchical output
   - `Write-LogFunctionEntry.ps1` - Function entry logging with telemetry
4. Identified project-specific patterns used throughout 151 files

**Key AutomatedLab Patterns Discovered:**

1. **Logging Functions** (PSLog module):
   - `Write-LogFunctionEntry` - ALWAYS first line in public functions
   - `Write-LogFunctionExit` - ALWAYS before every return
   - `Write-LogFunctionExitWithError` - In catch blocks with error details
   - `Write-ScreenInfo` - Timestamped, hierarchical user feedback

2. **Progress Indication**:
   - `Write-ScreenInfo -TaskStart/-TaskEnd` for hierarchy
   - `Write-ProgressIndicator` for tight loops (lightweight spinner)
   - Standard `Write-Progress` for long operations

3. **Function Structure**:
   - Early return pattern with validation
   - Machine filtering by `SkipDeployment` property
   - Role-based parameter switches pattern

4. **Error Handling**:
   - Try-catch-finally with resource cleanup
   - Job error handling pattern
   - Lock file pattern for concurrent operations

5. **Task Execution**:
   - Sequential role installation (dependency order)
   - Pre-installation activity pattern
   - Machine startup pattern with progress indicators

**Deliverable Created:**
New project-specific document: `.clinerules/instructions/powershell-automatedlab.instructions.md`

**Document Details:**
- Comprehensive AutomatedLab-specific patterns
- Supplements both `powershell.instructions.md` and `powershell-advanced.instructions.md`
- Includes anti-patterns to avoid
- Based on analysis of real production code patterns

**Status:** ✅ Complete - Project-specific best practices documented
