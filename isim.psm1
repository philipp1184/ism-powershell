<#
    .SYNOPSIS
        PowerShell Module for IBM Security Identity Manager SOAP Web Service
    .DESCRIPTION
        This Module provides Methods to Access SOAP API from IBM Security Identity
		Manager (ISIM) from IBM. It gives the ability to script and automate
		administrative Tasks. 
#>


function Copy-ISIMObjectNamespace {
    param( 	
        [Parameter(Mandatory=$true)]
        $obj,
	    [Parameter(Mandatory=$true)]
	    [string]$targetNS
    )

    $myTypeName = $obj.getType().Name.Split("[")[0];

    $newObj = New-Object ( $targetNS+"."+$myTypeName)

    $obj.psobject.Properties | % { 
        $pname = $_.Name
        if ( $_.TypeNameOfValue.StartsWith("System.") ) {
            if( $newObj.psobject.Properties.Item($pname) -ne $null ) {
                $newObj.$pname = $_.Value
            } else {
                Write-Host -ForegroundColor Yellow "Property $pname Could not be set"
            }
        } else {
            if ( !$newObj.$pname ) {
                 $newObj.$pname = New-Object ( $targetNS+"."+($_.TypeNameOfValue.Split(".")[-1].Split("[")[0]))
            }
            $newObj.$pname = Copy-ISIMObjectNamespace $obj.$pname $targetNS
        }
    }
    return $newObj
}

function Test-ISIMSession {
    [CmdletBinding()]
    [OutputType([bool])]
    param ()
    process {

        if($script:session -eq $null) {
            Write-Error "No Active ISIM WS Session" -ErrorAction Stop
        }

    }
}

function Connect-ISIM {
    param( 	
        [Parameter(Mandatory=$true)]
        [string]$isimuid,
	    [Parameter(Mandatory=$true)]
	    [string]$isimpwd,
	    [Parameter(Mandatory=$true)]
	    [string]$isim_url,
	    [Parameter(Mandatory=$false)]
	    [string]$ou_name
    )

	## Initialize SOAP WSDL URLs
	$script:isim_url = $isim_url;
	$script:isim_wsdl_session=$isim_url+"/itim/services/WSSessionService/WEB-INF/wsdl/WSSessionService.wsdl";
	$script:isim_wsdl_person=$isim_url+"/itim/services/WSPersonServiceService/WEB-INF/wsdl/WSPersonService.wsdl";
	$script:isim_wsdl_searchdata=$isim_url+"/itim/services/WSSearchDataServiceService/WEB-INF/wsdl/WSSearchDataService.wsdl";
	$script:isim_wsdl_account=$isim_url+"/itim/services/WSAccountServiceService/WEB-INF/wsdl/WSAccountService.wsdl";
	$script:isim_wsdl_container=$isim_url+"/itim/services/WSOrganizationalContainerServiceService/WEB-INF/wsdl/WSOrganizationalContainerService.wsdl";
	$script:isim_wsdl_service=$isim_url+"/itim/services/WSServiceServiceService/WEB-INF/wsdl/WSServiceService.wsdl";
	$script:isim_wsdl_password=$isim_url+"/itim/services/WSPasswordServiceService/WEB-INF/wsdl/WSPasswordService.wsdl";
	$script:isim_wsdl_request=$isim_url+"/itim/services/WSRequestServiceService/WEB-INF/wsdl/WSRequestService.wsdl";
    $script:isim_wsdl_role=$isim_url+"/itim/services/WSRoleServiceService/WEB-INF/wsdl/WSRoleService.wsdl";


	$script:session_prx = New-WebServiceProxy -Uri $isim_wsdl_session # -Namespace "WebServiceProxy" -Class "Session"
	$script:person_prx = New-WebServiceProxy -Uri $isim_wsdl_person # -Namespace "WebServiceProxy" -Class "Person"
	$script:search_prx = New-WebServiceProxy -Uri $isim_wsdl_searchdata # -Namespace "WebServiceProxy" -Class "Search"
	$script:account_prx = New-WebServiceProxy -Uri $isim_wsdl_account # -Namespace "WebServiceProxy" -Class "Account"
	$script:container_prx = New-WebServiceProxy -Uri $isim_wsdl_container # -Namespace "WebServiceProxy" -Class "Container"
	$script:service_prx = New-WebServiceProxy -Uri $isim_wsdl_service # -Namespace "WebServiceProxy" -Class "Service"
	$script:password_prx = New-WebServiceProxy -Uri $isim_wsdl_password # -Namespace "WebServiceProxy" -Class "Password"
	$script:request_prx = New-WebServiceProxy -Uri $isim_wsdl_request # -Namespace "WebServiceProxy" -Class "Request"
    $script:role_prx = New-WebServiceProxy -Uri $isim_wsdl_role # -Namespace "WebServiceProxy" -Class "Role"


	$script:session_ns = $script:session_prx.GetType().Namespace
	$script:person_ns = $script:person_prx.GetType().Namespace
	$script:search_ns = $script:search_prx.GetType().Namespace
	$script:account_ns = $script:account_prx.GetType().Namespace
	$script:container_ns = $script:container_prx.GetType().Namespace
	$script:service_ns = $script:service_prx.GetType().Namespace
	$script:password_ns = $script:password_prx.GetType().Namespace
	$script:request_ns = $script:request_prx.GetType().Namespace
    $script:role_ns = $script:role_prx.GetType().Namespace


	# Login
	$script:session = $script:session_prx.login($isimuid,$isimpwd)

    if($script:session -eq $null) {
        Write-Error "Could not Login to WebService" -ErrorAction Stop
    }
    

	# Clone Objects to fit Namespaces
	$script:psession = Copy-ISIMObjectNamespace $script:session $person_ns
	$script:asession = Copy-ISIMObjectNamespace $script:session $account_ns
	$script:csession = Copy-ISIMObjectNamespace $script:session $container_ns
	$script:ssession = Copy-ISIMObjectNamespace $script:session $service_ns
	$script:pwsession = Copy-ISIMObjectNamespace $script:session $password_ns
	$script:rsession = Copy-ISIMObjectNamespace $script:session $request_ns
	$script:rlsession = Copy-ISIMObjectNamespace $script:session $role_ns

    $script:rootContainer = $container_prx.getOrganizations($script:csession) | Where-Object -Property "name" -EQ -Value $ou_name

}


function Get-ISIMServiceName2DN {
    [CmdletBinding()]
    [OutputType([string])]
    param ( 
        [Parameter(Mandatory=$true)]
        [string]$name
        )
    begin {
        Test-ISIMSession
    }
    process {

        $ldapFilter = "(erservicename=$name)"
        $container = Copy-ISIMObjectNamespace $script:rootContainer $service_ns
        $response = $service_prx.searchServices($ssession,$container,$ldapFilter)

        $response.itimDN;
    }
}

function Get-ISIMContainerName2DN {
    [CmdletBinding()]
    [OutputType([string])]
    param ( 
        [Parameter(Mandatory=$true)]
        [string]$name
        )
    begin {
        Test-ISIMSession
    }
    process {
        $response = $container_prx.searchContainerByName($csession, $rootContainer, "AdminDomain", $name)
        $response.itimDN;
    }
}

function Get-mapHash2WSAttr {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$hash, 
        [Parameter(Mandatory=$true)]
        [string]$namespace,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $inAttr
    )
    process {


        if ( $inAttr -NE $null ) { 
            $wsattr_array = $inAttr;

            $hash.GetEnumerator() | ForEach{ 
                $prop_name = $_.name;
                $prop_value = $_.value;

	            if ( ( $wsattr_array | Where-Object { $_.name -eq $prop_name }).Count -eq 1 ) {
		            ( $wsattr_array | Where-Object { $_.name -eq $prop_name }).values = $prop_value
	            } else {
                    $wsattr = New-Object ($namespace+".WSAttribute")
                    $wsattr.name = $prop_name
                    $wsattr.values +=  $prop_value
                    $wsattr_array += $wsattr
                }

            }

        } else {
            $wsattr_array = @();
            $hash.GetEnumerator() | ForEach{ 
                $wsattr = New-Object ($namespace+".WSAttribute")
                $wsattr.name = $_.name
                $wsattr.values +=  $_.value 
                $wsattr_array += $wsattr
            }
        }



        return $wsattr_array;
    }

}

function Get-ISIMPersonUID2DN {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$uid
    )
    begin {
        Test-ISIMSession
    }
    process {
        $person_dn = $null;
        $ldapFilter = "(uid="+$uid+")"; 
        #$attrList = nul; # Optional, supply an array of attribute names to be returned. 
        # A null value will return all attributes. 
        $persons = $person_prx.searchPersonsFromRoot($script:psession, $ldapFilter, $attrList); 

        if ( $persons.Count -ne 1 ) {
            Write-Host -ForegroundColor Red "Search Parameter uid=$uid has no unique results."
        } else {
            $person_dn = $persons.itimDN;
        }

        $person_dn

    }
}

function Get-ISIMPersonByFilter {
    [OutputType([string])]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$filter
    )
    begin {
        Test-ISIMSession
    }
    process {
        $person_dn = $null;
        #$attrList = nul; # Optional, supply an array of attribute names to be returned. 
        # A null value will return all attributes. 
        $persons = $person_prx.searchPersonsFromRoot($script:psession, $filter, $attrList); 

        if ( $persons.Count -lt 1 ) {
            Write-Host -ForegroundColor Red "Search Filter '$filter' has no results."
        } 

        $persons

    }
}


function Add-ISIMRoleToPerson {
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
        [psobject]$wsperson,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$roleDN
    )
    begin {
        Test-ISIMSession
    }
    process {

        $personDN = $wsperson.itimDN;

        $req = $person_prx.addRole($script:psession,$personDN,$roleDN,$null,$false,"no");

        Wait-ForRequestCompletion($req.requestId);

    }

}


function Remove-ISIMRoleFromPerson {
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
        [psobject]$wsperson,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$roleDN
    )
    begin {
        Test-ISIMSession
    }
    process {
        $personDN = $wsperson.itimDN;

        $req = $person_prx.removeRole($script:psession,$personDN,$roleDN,$null,$false,"no");

        Wait-ForRequestCompletion($req.requestId);
    }
}


function New-ISIMAccount {
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
        [psobject]$wsperson,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$Service,
        [Parameter(Mandatory=$false,Position=3)]
        [hashtable]$a_attr
    )
    begin {
        Test-ISIMSession
    }
    process {

        if($a_attr -eq $null) {
            $a_attr = @{}
        }

        $serviceDN = Get-ISIMServiceName2DN -name $service
        $personDN = $wsperson.itimDN

        $password = $script:password_prx.generatePasswordForService($script:pwsession,$serviceDN)
        $a_attr.Add("erpassword",$password);
        #$a_attr.Add("eraccountstatus","0");
        $a_attr.Add("owner",$personDN);

        $wsattr = $script:account_prx.getDefaultAccountAttributesByPerson($script:asession,$serviceDN,$personDN)    

        if(-not ($a_attr -eq $null)) {
            $wsattr = Get-mapHash2WSAttr -hash $a_attr -namespace $script:account_ns -inAttr $wsattr
        }




        $req = $account_prx.createAccount($asession, $serviceDN, $wsattr, $null, $false, "none")

        Wait-ForRequestCompletion($res.requestId);
    }
}


function Set-ISIMPasswordsForPerson {
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [psobject]$wsperson,
        [Parameter(Mandatory=$true)]
        [array]$services
    )
    begin {
        Test-ISIMSession
    }
    process {


        $result = @{ 'password' = $null; 'services' = $null }


        $personDN = $wsperson.itimDN

        $accounts = $script:person_prx.getAccountsByOwner($script:psession,$personDN)
        $pwd_accounts = @()

        foreach ($a in $accounts) {
        
            if ( $services.Contains($a.serviceName)) {
                $pwd_accounts += $a.itimDN
                Write-Host $a.serviceName
                $result['services'] += @{ $a.serviceName = $a.name }
            }
        }

        $initial_pwd = $password_prx.generatePassword($pwsession,$pwd_accounts)

        $result['password'] = $initial_pwd;

        $res = $password_prx.changePassword($pwsession,$pwd_accounts,$initial_pwd)

        Wait-ForRequestCompletion($res.requestId);

        $status = $request_prx.getRequest($rsession,$res.requestId);

        Write-Host "Password SET Request finished with Status" $status.statusString
    


        $initial_pwd

    }

}


function Wait-ForRequestCompletion {
    param (
        [Parameter(Mandatory=$true)]
        [long]$requestId
    )  
    begin {
        Test-ISIMSession
    }
    process {
        do {
            Write-Host -NoNewline "."
            Start-Sleep 3
            $status = $script:request_prx.getRequest($script:rsession,$requestId)
        } while( $status.processState -ne "C" )
        Write-Host "Finished"
    }
}


function Get-ISIMPerson {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $UID
    )
    begin {
        Test-ISIMSession
    }
    process {
        
        $p_dn = Get-ISIMPersonUID2DN -uid $UID
        $script:person_prx.lookupPerson($script:psession,$p_dn)


        
    }


}

function Get-ISIMRoleDN {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $RoleName
    )
    begin {
        Test-ISIMSession
    }
    process {
    
        $filter="(errolename=$($RoleName))"
        $script:role_prx.searchRoles($script:rlsession,$filter)

        #$script:person_prx.lookupPerson($script:psession,$p_dn)


        
    }


}

function Get-ISIMRole {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $filter
    )
    begin {
        Test-ISIMSession
    }
    process {
    
        $script:role_prx.searchRoles($script:rlsession,$filter)

        #$script:person_prx.lookupPerson($script:psession,$p_dn)


        
    }


}

function Get-ISIMRoleByDN {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $dn
    )
    begin {
        Test-ISIMSession
    }
    process {
    
        $script:role_prx.lookupRole($script:rlsession,$dn)

        #$script:person_prx.lookupPerson($script:psession,$p_dn)


        
    }


}
