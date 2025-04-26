# Audit-DS

This repository contains the Audit-DS module.

## Description

This module is designed for DS auditing purposes. More details will be added soon.

## Usage

    ```powershell
    # Download 
    Invoke-WebRequest -Uri "https://github.com/Aabayoumy/Audit-DS/archive/refs/heads/main.zip" -OutFile "Audit-DS.zip"
    # Extract the Archive:
    Expand-Archive -Path "Audit-DS.zip" -DestinationPath ".\Audit-DS"
    # Allow run unsigned script 
    Set-ExecutionPolicy -scope process bypass
    # Import the Module:
    Import-Module -Name "AuditModule.psd1"
    Export-NTLMEvents
    Export-LDAPEvents
    
    ```
