# Prompts

## Prompt 1 - Initial setup

The PowerShell modules in the source folder need be checked for security and malicious code. Please start with a memory bank to outline the task and track the progress. Also create documentation to describe the overall purpose of the the project.

## Prompt 2.1 - Define Detection Rules

There are already some detection rules defined in the `scanner/rules` folder. Please extend and improve these rules based on your research.

Browse the web and learn about PowerShell security coding guidelines. Then create a Detection Rules file that combines the knowledge.

This is a sample how the detection rules should be formatted.

```
Id = 'PS001'
Name = 'Invoke-Expression Usage'
Severity = 'Medium'
Category = 'CodeExecution'
Description = 'Detects use of Invoke-Expression which can execute arbitrary code from strings'
ASTPattern = 'CommandAst'
CommandName = 'Invoke-Expression'
Remediation = 'Replace Invoke-Expression with safer alternatives like & operator or dot-sourcing'
CVSS = 5.3
```

Please also use the PowerShell module `PSScriptAnalyzer` as input. Also scan the web
for additional `PSScriptAnalyzer` rules that are available on GitHub for example in the organization
https://github.com/dsccommunity.

## Prompt 2.2 - Realign the detection rules

The source code is PowerShell. In PowerShell it is normal to deal with credentials in a
semi-secure way.

A rule like 'Sensitive Data in Logs' should be only treated as critical if it effects plaintext passwords, security keys or tokens. Writing user names or IDs to log files is essential for debugging.

A rule like 'High Entropy Strings' should be deemphasized. PowerShell by nature uses high entropy strings to express the intend in code. Findings should be analyzed further for security issues and not treated as critical by default.

## Prompt 2.3 - PowerShell security scanning scripts

In the directory `scanner`, there is already the scanner script you have created before. It was created to scan PowerShell code for the defined detection rules. Please scan it and improve it where needed. Also make use of the `PSScriptAnalyzer` and `Pester` to generate the scripts.

## Prompt 3 - Start the code review

Start the code review according to the process and the definitions in the memory bank.

The report should be created in the folder `Report`.

**Important**: Please create an executive summary covering all PowerShell modules and one detailed report per PowerShell module.

The finings in the detailed report should have the following structure:

```text
Rule: <Rule>
Category: <Category>
File: <Full File Path>
- Line: <All lines numbers>
  Code: <Code or line content>
- Line: <All lines numbers>
  Code: <Code or line content>
Description: <Description>
Remediation: <Suggestions for remediation>
CVSS Score: <CVSS Score>
```

Important notes:
- Report 'High Entropy Detection' with care. If it very likely that we generate a
  lot of false positives.
- Report on 'Hardcoded Credentials' or 'Credential Logging' only if you actually find hard coded
  credentials in the code or if the code very likely exposes the credentials in an inappropriate 
  way, for example writing them to a log file or write them to the console.
- Some cmdlets in PowerShell like `Where-Object` only work when providing a scriptblock. This is not a
  security flaw and should be taken into account when reporting on 'Script Block Injection'.
- When looking for 'Character Substitution Obfuscation', please  take into account that for
  solving string escaping issues in PowerShell, it is required to use character like `'`, `"` or `` ` `` in various orders. Doing this is not necessarily a security issue.
- 'Hostname or Domain Checks' are expected in code that configures machines. If you think that it is a security issue, please investigate given the context of the code.
- The rules PS009 (Hardcoded Credentials) and PS012 (Credential Logging) can create false positives in various scenarios. Please analyze the findings carefully before reporting them. Unless there is strong evidence that passwords or keys are hardcoded or logged inappropriately, please do not report them as issues.
- PS030 (Hostname or Domain Checks) should only be reported if the hostname or domain is used in a suspicious way, for example to whitelist or blacklist connections without proper validation.
- PS002 (Add-Type Usage) should be reported only if the usage of Add-Type introduces potential security risks, such as executing untrusted code or loading assemblies from unverified sources.
- PS014 (Weak Hash Algorithm) is an information and not a security issue. Please report it as info only.

## Prompt 4 - Pending tasks

Review the memory bank for pending tasks and print them out.

## Prompt 5 - Create additional documention

Please create a `readme.md` in each folder to describe the content. Also create a comprehensive `readme.md` in the root directory describing the project. The main readme should have references to the other readmes and relevant documentation documents.

## Prompt 6 - Optional tasks

Please run also the optional tasks.
