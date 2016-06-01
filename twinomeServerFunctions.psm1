<# 
  _               _                                    
 / |_            (_)                                   
`| |-'_   _   __ __  _ .--.   .--.  _ .--..--.  .---.  
 | | [ \ [ \ [  |  |[ `.-. |/ .'`\ [ `.-. .-. |/ /__\\ 
 | |, \ \/\ \/ / | | | | | || \__. || | | | | || \__., 
 \__/  \__/\__/ [___|___||__]'.__.'[___||__||__]'.__.'                                         
 
/_____/_____/_____/_____/_____/_____/_____/_____/_____/

Script: twinomeServerFunctions.psm1
Author: Matt Warburton
Date: 01/06/16
Comments: Server PowerShell functions
#>

#REQUIRES -Version 4.0
#REQUIRES -RunAsAdministrator

Function Get-FolderPaths {
    <#
    .SYNOPSIS
        Gets all folder paths in particular area
    .DESCRIPTION
        Get-Paths
    .PARAMETER topPath
        Root
    .EXAMPLE
        Get-FolderPaths -topPath "path"
    #>
    [CmdletBinding()] 
    param (
        [string]$topPath
    )
      
    BEGIN {

        $ErrorActionPreference = 'Stop'    
    }
    
    PROCESS {

        try{
            $root = Test-Path $topPath

                if($root -eq $true) {
                    try {
                        $folders = Get-ChildItem -directory $topPath
                        
                            if($folders){
                                $paths = @()
                                $paths += "$topPath"
                                
                                    $folders | ForEach-Object{
                                        $paths += $_.FullName
                                    }
                                write-output $paths
                            }    
                    }
        
                    catch {
                        $error = $_
                        Write-Output "$($error.Exception.Message) - Line Number: $($error.InvocationInfo.ScriptLineNumber)"                   
                    }
                }

                else {
                    Write-Output "path $topPath doesn't exist"                
                }
        }

        catch{
            $error = $_
            Write-Output "$($error.Exception.Message) - Line Number: $($error.InvocationInfo.ScriptLineNumber)"  
        }
    }
}

Function Get-SecurityObject {
    <#
    .SYNOPSIS
        Gets all security objects matching filter in a partiulcar path 
    .DESCRIPTION
        Get-Groups
    .PARAMETER folderPath
        The folder path
    .PARAMETER match
        The filter        
    .EXAMPLE
        Get-SecurityObject -folderPath "C:\Users\user\Desktop" -match "akeyword"
    #>
    [CmdletBinding()] 
    param (
        [string]$folderPath,
        [string]$match
    )
      
    BEGIN {

        $ErrorActionPreference = 'Stop'    
    }
    
    PROCESS {

        try{
            $folder = Test-Path $folderPath

                if($folder -eq $true) {
                    try {
                        $acl = Get-Acl -Path $folderPath
                        
                            if($acl){
                                $objects = $acl.Access | Where-Object {$_.IdentityReference -like "*$match*"}
                                $ref = @()

                                    $objects | ForEach-Object{
                                        $ref += $_.IdentityReference    
                                    }
                                Write-Output $ref
                            }  
                    }
        
                    catch {
                        $error = $_
                        Write-Output "$($error.Exception.Message) - Line Number: $($error.InvocationInfo.ScriptLineNumber)"                   
                    }
                }

                else {
                    Write-Output "path $folderPath doesn't exist"                
                }
        }

        catch{
            $error = $_
            Write-Output "$($error.Exception.Message) - Line Number: $($error.InvocationInfo.ScriptLineNumber)"  
        }
    }
} 


Function Get-SecurityObjectStatus {
    <#
    .SYNOPSIS
        Gets inheritance status for security object
    .DESCRIPTION
        Get-Groups
    .PARAMETER folderPath
        The folder path
    .PARAMETER securityObject
        The object       
    .EXAMPLE
        Get-SecurityObjectStatus -folderPath "C:\Users\user\Desktop" -securityObject "domain\user"
    #>
    [CmdletBinding()] 
    param (
        [string]$folderPath,
        [string]$securityObject
    )
      
    BEGIN {

        $ErrorActionPreference = 'Stop'    
    }
    
    PROCESS {

        try{
            $folder = Test-Path $folderPath

                if($folder -eq $true) {
                    try {
                        $acl = Get-Acl -Path $folderPath
                        
                            if($acl){
                                $so = $acl.Access | Where-Object {$_.IdentityReference -eq "$securityObject"}
                                $status = $so.IsInherited
                                Write-Output $status
                            }
                            else{
                                Write-Output "security object $securityObject doesn't exist"    
                            }  
                    }
        
                    catch {
                        $error = $_
                        Write-Output "$($error.Exception.Message) - Line Number: $($error.InvocationInfo.ScriptLineNumber)"                   
                    }
                }

                else {
                    Write-Output "path $folderPath doesn't exist"                
                }
        }

        catch{
            $error = $_
            Write-Output "$($error.Exception.Message) - Line Number: $($error.InvocationInfo.ScriptLineNumber)"  
        }
    }
} 

Function Set-Permissions {
    <#
    .SYNOPSIS
        Sets permissions for security object
    .DESCRIPTION
        Set-Permissions
    .PARAMETER folderPath
        The folder path
    .PARAMETER securityObject
        The object
    .PARAMETER permissionLevel
        Permission level        
    .EXAMPLE
        Set-Permissions -folderPath "C:\Users\user\Desktop\Perms\3" -securityObject "domain\user" -permissionLevel "Read"
    #>
    [CmdletBinding()] 
    param (
        [string]$folderPath,
        [string]$securityObject,
        [string]$permissionLevel
    )
      
    BEGIN {

        $ErrorActionPreference = 'Stop'    
    }
    
    PROCESS {

        try{
            $folder = Test-Path $folderPath

                if($folder -eq $true) {
                    try {
                        $ObjAcl = Get-Acl $folderPath
                        $SetAccessRule = New-Object security.accesscontrol.filesystemaccessrule($securityObject,$permissionLevel, "ContainerInherit, ObjectInherit", "None", "Allow")
                        $ObjAcl.SetAccessRule($SetAccessRule)
                        Set-Acl $folderPath $ObjAcl
                    }
        
                    catch {
                        $error = $_
                        Write-Output "$($error.Exception.Message) - Line Number: $($error.InvocationInfo.ScriptLineNumber)"                   
                    }
                }

                else {
                    Write-Output "path $folderPath doesn't exist"                
                }
        }

        catch{
            $error = $_
            Write-Output "$($error.Exception.Message) - Line Number: $($error.InvocationInfo.ScriptLineNumber)"  
        }
    }
} 

