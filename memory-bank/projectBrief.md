# Project Brief: AutomatedLab

## Project Overview

**Project Name:** AutomatedLab  
**Started:** 2011/2012  
**Current Status:** Mature, actively maintained open-source project  
**Primary Authors:** Raimund Andree, Per Pedersen, Jan-Hendrik Peters  
**License:** MIT (https://github.com/AutomatedLab/AutomatedLab/blob/main/LICENSE)

## Purpose

AutomatedLab is a PowerShell-based lab automation framework that enables rapid deployment of complex test and lab environments on Hyper-V or Azure. It dramatically reduces the time required to set up infrastructure for testing, training, and development purposes.

## Core Value Proposition

- **Speed**: Deploy complete lab environments in minutes instead of hours/days
- **Reproducibility**: Define labs as code for consistent, repeatable deployments
- **Complexity**: Handle complex scenarios (multi-domain forests, SQL clusters, etc.) automatically
- **Flexibility**: Support both on-premises (Hyper-V) and cloud (Azure) deployments
- **Cross-platform**: Windows, Linux, and macOS support (Azure only for non-Windows)

## Key Requirements

### Functional Requirements

1. **Lab Definition**: Define lab environments declaratively using PowerShell cmdlets
2. **OS Support**: Deploy Windows (Server 2008 R2+, Windows 7+, 10, 11) and Linux VMs
3. **Role Installation**: Automate installation of enterprise roles (AD, SQL, Exchange, etc.)
4. **Networking**: Automatic virtual network creation and configuration
5. **Storage**: Efficient disk management with base images and differencing disks
6. **Multi-platform**: Support Hyper-V and Azure as virtualization engines

### Supported Technologies/Roles

- **Active Directory**: Root DCs, Child DCs, Additional DCs, ADFS, ADFS Proxy
- **Databases**: SQL Server 2012-2022
- **Microsoft Products**: Exchange, SharePoint, SCOM, SCVMM, Dynamics, Configuration Manager
- **Development**: Visual Studio, Team Foundation Server, Azure DevOps
- **Infrastructure**: PKI (CAs), DSC Pull Servers, Web Servers, File Servers, DHCP, Routing
- **Clustering**: Failover Clustering with shared storage
- **Remote Access**: RDS, Windows Admin Center
- **Office**: Office 2013, 2016, 2019

### Non-Functional Requirements

1. **Performance**: Minimize deployment time through parallelization and base images
2. **Resource Efficiency**: Use differencing disks to minimize storage usage
3. **Reliability**: Robust error handling and validation
4. **Maintainability**: Modular architecture with clear separation of concerns
5. **Compatibility**: Support PowerShell 5.1+ and PowerShell 7+
6. **Documentation**: Comprehensive help and sample scripts

## Current Challenge

The codebase has evolved organically since 2011/2012, resulting in:

1. **Code Quality Issues**: Does not fully align with current PowerShell best practices
2. **Inconsistent Standards**: Varying code styles across 660+ PowerShell files
3. **Documentation Gaps**: Documentation may not reflect current implementation
4. **Technical Debt**: Legacy patterns and practices from earlier PowerShell versions

## Project Goals (This Initiative)

### Primary Objective

Align the AutomatedLab codebase with modern PowerShell standards and best practices without breaking existing functionality.

### Specific Goals

1. **Code Standards Alignment**: 
   - Align with `.vscode/settings.json` formatting rules
   - Align with `scriptanalyzer/AutomatedLabRules.psd1` analysis rules
   - Follow PowerShell coding instructions in `.clinerules` folder

2. **Documentation**:
   - Create comprehensive memory bank for project knowledge
   - Document architecture, patterns, and design decisions
   - Identify alignment gaps between current code and standards

3. **Knowledge Capture**:
   - Understand how components fit together
   - Document module dependencies and interactions
   - Capture domain knowledge about lab automation

4. **Foundation for Refactoring**:
   - Establish baseline understanding before code changes
   - Create roadmap for systematic improvements
   - Preserve functionality while improving quality

## Constraints

1. **No Code Changes Yet**: This phase is analysis only - no modifications to existing code
2. **Maintain Compatibility**: Any future changes must preserve backward compatibility
3. **Preserve Functionality**: All existing features must continue to work
4. **Community Impact**: Large user base depends on stability

## Success Criteria

1. Complete memory bank created with all required files
2. Comprehensive understanding of project architecture documented
3. Gap analysis completed between current code and standards
4. Clear roadmap for alignment work identified
5. No functionality broken (analysis only, no code changes)

## Repository Information

- **Main Repository**: https://github.com/AutomatedLab/AutomatedLab
- **Documentation**: https://automatedlab.org
- **PowerShell Gallery**: https://www.powershellgallery.com/packages/AutomatedLab/
- **Build System**: AppVeyor CI/CD
- **Module Count**: 10+ PowerShell modules
- **Function Count**: 184 in AutomatedLabCore alone, 660+ total .ps1 files

## Key Stakeholders

1. **Core Team**: Raimund Andree (@raandree), Jan-Hendrik Peters (@nyanhp)
2. **Community**: Open-source contributors and users
3. **Sponsor**: Chocolatey (@chocolatey) - regular sponsor
4. **Users**: IT professionals, trainers, developers, testers

## Timeline

- **Start Date**: 2011/2012 (project inception)
- **Current Phase**: Code quality alignment initiative (2025)
- **This Task**: Analysis and documentation phase (no code changes)
