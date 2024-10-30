#Allowed EKUs
[string[]]$AllowedEkuOids = '1.3.6.1.4.1.311.20.2.1','1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.3','1.3.6.1.4.1.311.10.3.13','1.3.6.1.4.1.311.10.3.12','1.3.6.1.4.1.311.80.1','1.3.6.1.4.1.311.10.3.4','1.3.6.1.4.1.311.10.3.4.1','1.3.6.1.5.5.7.3.5','1.3.6.1.5.5.8.2.2','1.3.6.1.5.5.7.3.6','1.3.6.1.5.5.7.3.7','1.3.6.1.4.1.311.10.3.11','1.3.6.1.5.2.3.5','1.3.6.1.4.1.311.10.3.1','1.3.6.1.4.1.311.10.3.10','1.3.6.1.4.1.311.10.3.9','1.3.6.1.5.5.7.3.4','1.3.6.1.5.5.7.3.1','1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.5.7.3.8','1.3.6.1.5.5.7.3.9','1.3.6.1.4.1.311.54.1.2','1.3.6.1.4.1.311.21.5','2.16.840.1.113741.1.2.3'
[string[]]$NameConstraintsOptions = 'include','exclude'
[string[]]$NameConstraintsDirectives = 'directoryName','dNSName','emailAddress','iPAddress','userPrincipalName'

function Export-CaPolicyFile {
    <#
        .SYNOPSIS
            Exports a formatted CA Policy file (capolicy.inf) to the a specified folder (by default %WINDOWS%) based on input values.

        .DESCRIPTION
            Exports a formatted CA Policy file (capolicy.inf) to the a specified folder (by default %WINDOWS%) based on input values.
            Technically allowed but unpractical properties like CRLDistributionPoint and AuthorityInformationAccess are omitted.

        .INPUTS
            None

        .OUTPUTS
            capolicy.inf in $OutPath.

        .NOTES
            Author:   Christopher Ehrit
            GitHub:   https://github.com/ehrit/adcs-setup

        .EXAMPLE
            Export-CaPolicyFile -RenewalKeyLength '2048' -RenewalValidityPeriod 'Years'
    #>

    # ----- [Initialisations] -----
    
    # Script parameters.
    param (
        #Params for Certsrv_Server
        [parameter(Mandatory = $false)]
        [ValidateSet('512','1024','2048','4096')]
        [string]$RenewalKeyLength,
    
        [parameter(Mandatory = $false)]
        [ValidateSet('Hours','Days','Weeks','Months','Years')]
        [string]$RenewalValidityPeriod,
    
        [parameter(Mandatory = $false)]
        [string]$RenewalValidityPeriodUnits,
        
        [parameter(Mandatory = $false)]
        [switch]$LoadDefaultTemplates,
    
        [parameter(Mandatory = $false)]
        [switch]$AlternateSignatureAlgorithm,
    
        [parameter(Mandatory = $false)]
        [switch]$ForceUTF8,
        
        #Parameter for path length constraints
        [parameter(Mandatory = $false)]
        [string]$PathLength,
        
        #Parameter for path Extended Key Usage constraints
        [parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_ -in $AllowedEkuOids) { return $true }
            throw "'$_' is not in the set of the supported values: $($AllowedEkuOids -join ', ')"
        })]
        $EKUExtension,
        
        #Params for name constraints 
        [parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_.option -in $NameConstraintsOptions) {          
                if ($_.directive -in $NameConstraintsDirectives) { return $true }
                else {
                    throw $_.directive + ' from constraint "' + $_.option + ", "+ $_.directive + ", " + $_.subtree + '" is not in the set of the supported Name Constraints directives:' + $($NameConstraintsDirectives -join ', ')
                }
            else {
                throw $_.option + ' from constraint "' + $_.option + ", "+ $_.directive + ", " + $_.subtree + '" is not in the set of the supported Name Constraints options: ' + $($NameConstraintsOptions -join ', ')
            }
          }
        })]
        [hashtable[]]$NameConstraints,
        
        #Parameter for file output path
        [parameter(Mandatory = $false)]
        [string]$OutPath = 'C:\Windows\capolicy.inf'
        )
        
    # ----- [Execution] -----

    #Adds Version section. Only mandatory section in the file
    $policyContent = "[Version]`n" + 'Signature="$Windows NT$"' + "`n`n"

    #Adds BasicConstraintsExtension for path length
    if ($PathLength){
        $policyContent += "[BasicConstraintsExtension]`nPathLength=$PathLength`nCritical=TRUE`n`n"
    }

    #Adds EnhancedKeyUsageExtension section if OIDs are given
    if ($EKUExtension.count -gt 0) {
        
        #Hashtable to match OIDs with friendly names in line 109
        $EkuOidMatch = @{
            '1.3.6.1.4.1.311.20.2.1'   = 'Certificate Request Agent'
            '1.3.6.1.5.5.7.3.2'        = 'Client Authentication'
            '1.3.6.1.5.5.7.3.3'        = 'Code Signing'
            '1.3.6.1.4.1.311.10.3.13'  = 'Lifetime Signing'
            '1.3.6.1.4.1.311.10.3.12'  = 'Document Signing'
            '1.3.6.1.4.1.311.80.1'     = 'Document Encryption'
            '1.3.6.1.4.1.311.10.3.4'   = 'Encrypting file system'
            '1.3.6.1.4.1.311.10.3.4.1' = 'File Recovery'
            '1.3.6.1.5.5.7.3.5'        = 'IP Security End System'
            '1.3.6.1.5.5.8.2.2'        = 'IP Security IKE Intermediate'
            '1.3.6.1.5.5.7.3.6'        = 'IP Security Tunnel Endpoint'
            '1.3.6.1.5.5.7.3.7'        = 'IP Security User'
            '1.3.6.1.4.1.311.10.3.11'  = 'Key Recovery'
            '1.3.6.1.5.2.3.5'          = 'KDC Authentication'
            '1.3.6.1.4.1.311.10.3.1'   = 'Microsoft Trust List Signing'
            '1.3.6.1.4.1.311.10.3.10'  = 'Qualified Subordination'
            '1.3.6.1.4.1.311.10.3.9'   = 'Root List Signer'
            '1.3.6.1.5.5.7.3.4'        = 'Secure E-mail'
            '1.3.6.1.5.5.7.3.1'        = 'Server Authentication'
            '1.3.6.1.4.1.311.20.2.2'   = 'Smartcard Logon'
            '1.3.6.1.5.5.7.3.8'        = 'Time Stamping'
            '1.3.6.1.5.5.7.3.9'        = 'OCSP Signing'
            '1.3.6.1.4.1.311.54.1.2'   = 'Remote Desktop Authentication'
            '1.3.6.1.4.1.311.21.5'     = 'Private Key Archival'
            '2.16.840.1.113741.1.2.3'  = 'Intel Advanced Management Technology (AMT) Provisioning'
        }
        $policyContent += "[EnhancedKeyUsageExtension]`n"
        foreach ($EkuOid in $EKUExtension) {
            $EkuFriendlyName = $EkuOidMatch[$EkuOid]
            $policyContent += "OID=$EkuOid ; $EkuFriendlyName`n"
        }

        $policyContent += "`n"
    }

    #Adds Extensions section for Name constraints and Key usage constraints
    if ($NameConstraints.count -gt 0 -or $true) {
        $policyContent += "[Extensions]`n"
    }

    #Adds Name Constraints section
        if ($NameConstraints.count -gt 0) {

            $DirectiveMatch = @{
                'directoryName'     = 'DirectoryName'
                'dNSName'     	    = 'DNS'
                'emailAddress'      = 'Email'
                'iPAddress'   	    = 'IPAddress'
                'userPrincipalName' = 'UPN'
            }
        $policyContent += "Critical = 2.5.29.30`n2.5.29.30 = "+'"{text}"'+"`n"
        $IncludeConstraint = '_continue_ = "SubTree=Include&"'+"`n"
        $ExcludeConstraint = '_continue_ = "SubTree=Exclude&"'+"`n"

        foreach ($NameConstraint in $NameConstraints){
            if ($NameConstraint.option -eq "include") {
                $IncludeConstraint += '_continue_ = "' + $DirectiveMatch[$NameConstraint.directive] + " = " + $NameConstraint.value + '&"' + "`n"
            } elseif ($NameConstraint.option -eq "exclude") {
                $ExcludeConstraint += '_continue_ = "' + $DirectiveMatch[$NameConstraint.directive] + " = " + $NameConstraint.value + '&"' + "`n"
            }
        }

        $policyContent += $IncludeConstraint
        $policyContent += $ExcludeConstraint
        $policyContent += "`n"
    }
    #Adds Certsrv section to define CA server settings
    $policyContent += "[Certsrv_Server]`n"

    if ($RenewalKeyLength){
        $policyContent += "RenewalKeyLength=$RenewalKeyLength`n"
    }

    if ($RenewalValidityPeriod){
        $FormattedRvp = ($RenewalValidityPeriod.toupper())[0] + $RenewalValidityPeriod.tolower().SubString(1)
        $policyContent += "RenewalValidityPeriod=$FormattedRvp`n"
    }
    
    if($LoadDefaultTemplates){
        $policyContent += "LoadDefaultTemplates=1`n"
    } else {
        $policyContent += "LoadDefaultTemplates=0`n"
    }

    if($AlternateSignatureAlgorithm){
        $policyContent += "AlternateSignatureAlgorithm=1`n"
    } else {
        $policyContent += "AlternateSignatureAlgorithm=0`n"
    }

    if($ForceUTF8){
        $policyContent += "ForceUTF8=1`n"
    } else {
        $policyContent += "ForceUTF8=0`n"
    }

    #Export capolicy.inf
    $policyContent | Out-File -FilePath $OutPath -Encoding ASCII -Force
}