function Add-AiaLocation {
    <#
        .SYNOPSIS
            Formats URI for AIA and adds it with correct settings to CA registry.

        .DESCRIPTION
            Formats URI for AIA and adds it with correct settings to CA registry. 

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Christopher Ehrit
            GitHub:   https://github.com/ehrit/adcs-setup

        .EXAMPLE
            Add-AiaLocation -URI 'http://pki.abc.com/ica01.cer' -Settings 'PublishToLocation', 'IncludeInAiaExtension'
    #>

    # ----- [Initialisations] -----
    
    # Script parameters.
    param (
        #Params for Certsrv_Server
        [parameter(Mandatory = $true)]
        [ValidateScript(
           #<---Check for URI beginning (only http, filesystem, ldap)---># 
        )]
        [string]$URI,
    
        [parameter(Mandatory = $true)]
        [ValidateSet(#<---add different settings---->#
        )]
        [string]$Settings
    )

    # ----- [Execution] -----
}