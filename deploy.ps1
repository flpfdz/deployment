#declared variables
$ErrorActionPreference = 'Stop'
$script:date=get-date -uformat "%d%m%Y-%H%M%S"

$variables = Import-CliXml ~\Documents\varfile.xml
$clusterresgroup='MC_'+$variables.azure.clustername+'_'+$variables.azure.resgroup+'_'+$variables.azure.location
$password = '@uTo8Ot$PR1m3'
#$variables | Export-CliXml ~\Documents\varfile.xml
#scripts block

function documentation-start {
    add-content ($variables.deploymentdoc+$date) 'Deployment Report'
    $script:file=get-item ($variables.deploymentdoc+$date) 
    $script:file.Attributes="Hidden"
    add-content ($variables.deploymentdoc+$date) '-----------------'
    add-content ($variables.deploymentdoc+$date) 'deployment date: ' -nonewline
    add-content ($variables.deploymentdoc+$date) (get-date -uformat "%B %d, %Y")
    add-content ($variables.deploymentdoc+$date) 'method: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $funcname
    add-content ($variables.deploymentdoc+$date) '---'
    add-content ($variables.deploymentdoc+$date) 'repository used: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $variables.azure.containerregistry.repository -nonewline
    add-content ($variables.deploymentdoc+$date) '.azurecr.io'
    add-content ($variables.deploymentdoc+$date) '---'
    add-content ($variables.deploymentdoc+$date) ''
    add-content ($variables.deploymentdoc+$date) 'time breakdown:'
    add-content ($variables.deploymentdoc+$date) '---------------'
}
function error-catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host $ErrorMessage -ForegroundColor Yellow
    $ErrorMessage=""
    add-content ($variables.deploymentdoc+$date) " *** Failed on step $deplstep *** "
    add-content ($variables.deploymentdoc+$date) $_.Exception.Message
    add-content ($variables.deploymentdoc+$date) 'Failed in ' -nonewline
    add-content ($variables.deploymentdoc+$date) $time -nonewline
    add-content ($variables.deploymentdoc+$date) ' min.'
}
function documentation-finish {
    add-content ($variables.deploymentdoc+$date) '---------------'
    add-content ($variables.deploymentdoc+$date) 'Total elapsed time: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $totalelapsedtime -nonewline
    add-content ($variables.deploymentdoc+$date) ' minutes'
    add-content ($variables.deploymentdoc+$date) '---'
    add-content ($variables.deploymentdoc+$date) 'repository used: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $variables.azure.containerregistry.repository -nonewline
    add-content ($variables.deploymentdoc+$date) '.azurecr.io'
    add-content ($variables.deploymentdoc+$date) '---'
    add-content ($variables.deploymentdoc+$date) 'used tags:'
    add-content ($variables.deploymentdoc+$date) 'hbase: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $hbasetag
    add-content ($variables.deploymentdoc+$date) 'hdfs: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $hdfstag
    add-content ($variables.deploymentdoc+$date) 'kafka-connect: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $kafkaconnecttag
    add-content ($variables.deploymentdoc+$date) 'provisioning: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $provisioningtag
    add-content ($variables.deploymentdoc+$date) 'validation: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $validationtag
    add-content ($variables.deploymentdoc+$date) 'monitoring: ' -nonewline
    add-content ($variables.deploymentdoc+$date) $monitortag
    add-content ($variables.deploymentdoc+$date) '---'
    add-content ($variables.deploymentdoc+$date) 'keycloak address: https://' -nonewline
    add-content ($variables.deploymentdoc+$date) $kcpublicip -nonewline
    add-content ($variables.deploymentdoc+$date) '/auth'
    add-content ($variables.deploymentdoc+$date) 'username: '  -nonewline
    add-content ($variables.deploymentdoc+$date) $variables.secrets.kc.user
    add-content ($variables.deploymentdoc+$date) 'password: '
    add-content ($variables.deploymentdoc+$date) $variables.secrets.kc.psw
    $file.Attributes=''
    Rename-Item -Path ($variables.deploymentdoc+$date) -NewName $variables.filename'.txt'
}
function login($subscription) {
    if($subscription -eq '3esi'){
        $AzPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($variables.azure.password3esi));
        az login -u felipe.fedozzi@3esi-enersight.com -p $AzPass;
    }
    elseif($subscription -eq 'aucerna'){
        $AzPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($variables.azure.passwordAucerna));
        az login -u felipe.fedozzi@aucerna.com -p $AzPass;
    }
}
function connect-to-subscription($sub='local') {
    $deplstep='Connecting to subscription'
    "**$deplstep**"
  	$sw = [diagnostics.stopwatch]::startnew()
    if($sub -eq  'payg'){ az account set --subscription $variables.subscriptions.$sub.id }
    if($sub -eq 'local'){ az account set --subscription $selectedsubscription }
   	$sw.stop()
   	$script:time=[math]::round($sw.elapsed.totalminutes, 2)
   	$totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
	"Connected to the subscription. Elapsed time: $time min, total time: $totaltime min"
    
    add-content ($variables.deploymentdoc+$date) "$($deplstep): $time"
}
function connect-to-kubernates-subscription($sub='local') {
    $deplstep='Connecting and merging to subscription'
    "**$deplstep**"
   	$sw = [diagnostics.stopwatch]::startnew()
    if($sub -eq  'payg'){ az account set --subscription $variables.subscriptions.$sub.id }
    if($sub -eq 'local'){ az account set --subscription $selectedsubscription }
  	az aks get-credentials -g $variables.subscriptions.$sub.resgroup -n $variables.subscriptions.$sub.clustername | out-null
    $sw.stop()
   	$script:time=[math]::round($sw.elapsed.totalminutes, 2)
   	$totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
	"Connected to the subscription, merged to kubernetes. Elapsed time: $time min, total time: $totaltime min"
    
    add-content ($variables.deploymentdoc+$date) "$($deplstep): $time"
}
function create-resource-group {
    $deplstep="Create a Resource Group"
    Context $deplstep {
        try{
            $pass='y'
            $passmsg="  Resource Group already exists"
            az group show -n $variables.azure.resgroup -o tsv --query "name" | should be $variables.azure.resgroup
        }
        catch{
            $pass='n'
            Write-Host '** Creating Resource Group **' -ForegroundColor Green
            try{
   	            $sw = [diagnostics.stopwatch]::startnew()
   	            az group create -l $variables.azure.location -n $variables.azure.resgroup | out-null
   	            $sw.stop()
   	            $time=[math]::round($sw.elapsed.totalminutes, 2)
   	            $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
	            'Resource group '+$variables.azure.resgroup+' created. Elapsed time: '+$time+' min, total time:'+ $totaltime+' min.'
        
                add-content ($variables.deploymentdoc+$date) "$($deplstep): $time"
            }
            catch{ error-catch }
        }
        if($pass -eq 'y'){Write-Host $passmsg -ForegroundColor Green}
    }
}
function create-storage-account {
    $deplstep="Create a Storage Account"
    Context $deplstep {
        try{
            $pass='y'
            $passmsg="  Storage Account already exists"
            az storage account show -n $variables.azure.storageacct -o tsv --query "name" | should be $variables.azure.storageacct
        }
        catch{
            $pass='n'
            Write-Host '** Creating Storage Account **' -ForegroundColor Green
            #code
            try{
   	            $sw = [diagnostics.stopwatch]::startnew()
                az storage account create -n $variables.azure.storageacct -g $variables.azure.resgroup -l $variables.azure.location --sku standard_lrs | out-null
                $sw.stop()
   	            $time=[math]::round($sw.elapsed.totalminutes, 2)
   	            $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
   	            'Storage account '+$variables.azure.storageacct+' created. Elapsed time: '+$time+' min, total time: '+$totaltime+' min.'
                add-content ($variables.deploymentdoc+$date) " - $deplstep : $time "
            }
            catch{ error-catch }
            #code
        }
        if($pass -eq 'y'){Write-Host $passmsg -ForegroundColor Green}
    }
}
function create-cluster {
    $deplstep="Create Cluster"
    Context $deplstep {
        try{
            $pass='y'
            $passmsg="  Cluster already exists"
            az aks show --name $variables.azure.clustername --resource-group $variables.azure.resgroup -o tsv --query "name" | should be $variables.azure.clustername
        }
        catch{
            $pass='n'
            Write-Host '** Creating cluster. This might take some time, please be patient **' -ForegroundColor Green
            #code
            try{
                $sw = [diagnostics.stopwatch]::startnew()
                az aks create --name $variables.azure.clustername --resource-group $variables.azure.resgroup --generate-ssh-keys --kubernetes-version $variables.azure.kubeversion --location $variables.azure.location --node-count $variables.azure.nodes | out-null
                $sw.stop()
   	            $time=[math]::round($sw.elapsed.totalminutes, 2)
   	            $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
   	            'Cluster '+$variables.azure.clustername +'created. Elapsed time: '+$time+' min, total time: '+$totaltime+' min.'
                add-content ($variables.deploymentdoc+$date) " - $deplstep : $time "
            }
            catch{ error-catch }
            #code
        }
        if($pass -eq 'y'){ Write-Host $passmsg -ForegroundColor Green }
    }
}
function create-storage-account-files {
    try{
        $deplstep="Create Storage Account files"
	    '**Creating storage account files**'
   	    $sw = [diagnostics.stopwatch]::startnew()
   	    $storagekey=$(az storage account keys list --resource-group $variables.azure.resgroup --account-name $variables.azure.storageacct --query "[0].value")
        $count=1
	    do{
		    az storage share create --account-name $variables.azure.storageacct --account-key $storagekey --name $variables.storageacctfiles.Q10.$count --quota 10 | out-null
		    $count=$count+1
	    }while($count -le $variables.storageacctfiles.Q10.count)
        $count=1
	    do{
   		    az storage share create --account-name $variables.azure.storageacct --account-key $storagekey --name $variables.storageacctfiles.Q20.$count --quota 20 | out-null
		    $count=$count+1
	    }while($count -le $variables.storageacctfiles.Q20.count)
        $count=1
	    do{
		    az storage share create --account-name $variables.azure.storageacct --account-key $storagekey --name $variables.storageacctfiles.Q50.$count --quota 50 | out-null
		    $count=$count+1
	    }while($count -le $variables.storageacctfiles.Q50.count)
   	    $sw.stop()
   	    $time=[math]::round($sw.elapsed.totalminutes, 2)
   	    $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
   	    'Files successfully created in storage account '+$variables.azure.storageacct+'. Elapsed time: '+$time+' min, total time: '+$totaltime+' min.'
        add-content ($variables.deploymentdoc+$date) " - $deplstep : $time "
    }
    catch{ error-catch }
}
function create-public-ip {
    $deplstep="Create Public IP"
    Context $deplstep {
        try{
            $pass='y'
            $passmsg='  Public IP already exists ('+(az network public-ip show -g $clusterresgroup -n $variables.azure.publicipdns --query "{address: ipAddress}" -o tsv)+')'
            az network public-ip show -g $clusterresgroup -n $variables.azure.publicipdns --query "name" -o tsv | should be $variables.azure.publicipdns
        }
        catch{
            $pass='n'
            Write-Host '** Creating Public IP **' -ForegroundColor Green
            #code
            try{
   	            $sw = [diagnostics.stopwatch]::startnew()
   	            az network public-ip create -g $clusterresgroup -n $variables.azure.publicipdns --dns-name $variables.azure.publicipdns --allocation-method static | out-null
   	            $publicip=az network public-ip show -g $clusterresgroup -n $variables.azure.publicipdns --query "{address: ipAddress}" -o tsv
   	            $publicdns=az network public-ip show -g $clusterresgroup -n $variables.azure.publicipdns --query "{fqdn: dnsSettings.fqdn}" -o tsv
   	            $sw.stop()
   	            $time=[math]::round($sw.elapsed.totalminutes, 2)
   	            $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
   	            "IP address and dns name successfully created. Elapsed time: $time min, total time: $totaltime min"
                add-content ($variables.deploymentdoc+$date) " -  $deplstep : $time "
                add-content ($variables.deploymentdoc+$date) " -- IP: $publicip "
                add-content ($variables.deploymentdoc+$date) " -- DNS: $publicdns "
            }
            catch{ error-catch }
            #code
        }
        if($pass -eq 'y'){Write-Host $passmsg -ForegroundColor Green}
    }
}
function modify-vnet-subnet {
    $deplstep="Modify Vnet Subnet"
    Context $deplstep {
        try{
            $pass='y'
            $passmsg="  Vnet Subnet already modified"
            $vnetname = az network vnet list -g $clusterresgroup -o tsv --query "[?contains(name, 'aks-vnet')].name"
   	        az network vnet subnet show -g $clusterresgroup --vnet-name $vnetname -n qasubnet -o tsv --query "name" | should be 'qasubnet'
        }
        catch{
            $pass='n'
            Write-Host '** Modifying vnet subnet. This might take some time, please be patient **' -ForegroundColor Green
            #code
            try{
                $sw = [diagnostics.stopwatch]::startnew()
   	            $vnetname = az network vnet list -g $clusterresgroup -o tsv --query "[?contains(name, 'aks-vnet')].name"
   	            az network vnet subnet create -g $clusterresgroup --vnet-name $vnetname -n qasubnet --address-prefix 10.0.0.0/29 | out-null
   	            $sw.stop()
   	            $time=[math]::round($sw.elapsed.totalminutes, 2)
   	            $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
   	            "Vnet subnet modified. Elapsed time: $time min, total time: $totaltime min"
                add-content ($variables.deploymentdoc+$date) " - $deplstep : $time"
            }
            catch{ error-catch }
            #code
        }
        if($pass -eq 'y'){Write-Host $passmsg -ForegroundColor Green}
    }    
}
function create-application-gateway {
    $deplstep='Create Application Gateway'
    Context $deplstep {
        try{
            $pass='y'
            $passmsg="  Application Gateway already exists"
            az network application-gateway show -g $clusterresgroup -n $variables.azure.appgateway -o tsv --query "name" | should be $variables.azure.appgateway
        }
        catch{
            $pass='n'
            Write-Host '** Creating application gateway. This might take some time, please be patient **' -ForegroundColor Green
            #code
            try{
	            $sw = [diagnostics.stopwatch]::startnew()
                $vnetname = az network vnet list -g $clusterresgroup -o tsv --query "[?contains(name, 'aks-vnet')].name"
	            az network application-gateway create -g $clusterresgroup -n $variables.azure.appgateway --capacity 2 --sku standard_medium --vnet-name $vnetname --subnet qasubnet --public-ip-address newipaddress | out-null
   	            $sw.stop()
   	            $time=[math]::round($sw.elapsed.totalminutes, 2)
   	            $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
   	            "App gateway created. Elapsed time: $time min, total time: $totaltime min"
                add-content ($variables.deploymentdoc+$date) " - $deplstep : $time"
            }
            catch{ error-catch }
            #code
        }
        if($pass -eq 'y'){Write-Host $passmsg -ForegroundColor Green}
    }
}
function modify-app-gateway {
    try{
        $deplstep='Modify app gateway backend pool'
   	    '**Modifying app gateway backend pool. This might take some time, please be patient**'
   	    $sw = [diagnostics.stopwatch]::startnew()
   	    $i=0
        do{
            Set-Variable -Name vm$i -Value ((az vm list -o tsv --query "[?contains(name, '-')].name")[$i])
   	        $i++
        }while($i -lt $variables.azure.nodes)
        
        $i=0
        do{
            Set-Variable -Name privateipaddress$i -Value (az vm list-ip-addresses -g $clusterresgroup -n (Get-Variable -Name vm$i -ValueOnly) --query "[].virtualMachine.network.privateIpAddresses" -o tsv)
            $i++
        }while($i -lt $variables.azure.nodes)
        
        #create new backen pool
   	    az network application-gateway address-pool create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n provisioningBackendPool | out-null
        
        $i=0
        do{
            $vm = $vm + ' ' + (Get-Variable -Name privateipaddress$i -ValueOnly)
            $i++
        }while($i -lt $variables.azure.nodes)
        
        $gatewayname = $variables.azure.appgateway
        iex "az network application-gateway address-pool update -g $clusterresgroup --gateway-name $gatewayname -n provisioningBackendPool --servers$vm" | out-null
        
        #update existing backend pool
        az network application-gateway address-pool update -g $clusterresgroup --gateway-name $variables.azure.appgateway -n appGatewayBackendPool --server $variables.secrets.telemetry.kongIp | out-null

        #create probe
        az network application-gateway probe create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n probe --protocol http --host $variables.secrets.telemetry.kongIp --path /status --timeout 30 --match-status-codes 404 | out-null

        #update existing http settings
        az network application-gateway http-settings update -g $clusterresgroup --gateway-name $variables.azure.appgateway -n appgatewaybackendhttpsettings --probe probe | out-null

        #create and update new http settings
        az network application-gateway http-settings create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n provisioningHttpSettings --port=31222 | out-null
        
        #update existing listener
        az network application-gateway frontend-port create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n MyFrontendPort --port 81 | out-null
        az network application-gateway http-listener update -g $clusterresgroup --gateway-name $variables.azure.appgateway -n appGatewayHttpListener --frontend-port MyFrontendPort | out-null

        #create listener
        az network application-gateway http-listener create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n http-listener-pb --frontend-port appGatewayFrontendPort | out-null

        az network application-gateway rule delete -g $clusterresgroup --gateway-name $variables.azure.appgateway -n rule1

        #create telemetry rule
        az network application-gateway url-path-map create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n telemetry-rule --rule-name telemetry-rule --default-address-pool provisioningBackendPool --default-http-settings provisioningHttpSettings --address-pool appGatewayBackendPool --http-settings appgatewaybackendhttpsettings --paths /telemetry/* | out-null
        az network application-gateway url-path-map create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n cdm-rule       --rule-name cdm-rule       --default-address-pool provisioningBackendPool --default-http-settings provisioningHttpSettings --address-pool appGatewayBackendPool --http-settings appgatewaybackendhttpsettings --paths /cdm/* | out-null
        az network application-gateway url-path-map create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n grafana-rule   --rule-name grafana-rule   --default-address-pool provisioningBackendPool --default-http-settings provisioningHttpSettings --address-pool appGatewayBackendPool --http-settings appgatewaybackendhttpsettings --paths /grafana/* | out-null
        
        az network application-gateway rule create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n telemetry-pathbased `
            --rule-type PathBasedRouting `
            --http-listener appGatewayHttpListener `
            --http-settings provisioningHttpSettings `
            --address-pool provisioningBackendPool `
            --url-path-map telemetry-rule | out-null

        $etag = az network application-gateway rule show -g $clusterresgroup --gateway-name $variables.azure.appgateway -n telemetry-pathbased --query "etag" -o tsv

        iex "az network application-gateway url-path-map update -g $clusterresgroup --gateway-name $gatewayname -n telemetry-rule --set etag=$etag"
        iex "az network application-gateway url-path-map update -g $clusterresgroup --gateway-name $gatewayname -n cdm-rule --set etag=$etag"
        iex "az network application-gateway url-path-map update -g $clusterresgroup --gateway-name $gatewayname -n grafana-rule --set etag=$etag"

        az network application-gateway url-path-map show -g $clusterresgroup --gateway-name $variables.azure.appgateway -n telemetry-rule --query etag
        az network application-gateway url-path-map show -g $clusterresgroup --gateway-name $variables.azure.appgateway -n telemetry-rule --query pathRules[0].etag

        az network application-gateway url-path-map update -g $clusterresgroup --gateway-name $variables.azure.appgateway -n telemetry-rule --set ''="etag":$etag
        az network application-gateway url-path-map update -g $clusterresgroup --gateway-name $variables.azure.appgateway -n telemetry-rule --set pathRules[0].name="ABC123"

        az network public-ip update -g $clusterresgroup -n newipaddress --dns-name $variables.azure.publicipkcdns | out-null
   	    
	    
	    $kcpublicip=az network public-ip show -g $clusterresgroup -n newipaddress --query "{address: ipAddress}" -o tsv
   	    
   	    if((test-path c:\aucernaio.pfx) -eq $false)
   	    {	
   		    invoke-webrequest -uri https://aucernaiopfx.blob.core.windows.net/aucernaiopfx/aucernaio.pfx -outfile c:\aucernaio.pfx | out-null
   	    }
   	
   	    #{
   		#        new-selfsignedcertificate -certstorelocation cert:\localmachine\my -dnsname 'qa-aucerna-keycloak.westus2.cloudapp.azure.com'
   		#        $thumbprint = (get-childitem -path cert:\localmachine\my | where-object {$_.subject -match "cn=qa-aucerna-keycloak.westus2.cloudapp.azure.com"}).thumbprint;
   		#        $pwd = convertto-securestring -string ‘password’ -force -asplaintext
   		#        export-pfxcertificate -cert cert:\localmachine\my\$thumbprint -filepath c:\aucernaio.cer -password $pwd
   	    #}
   	    az network application-gateway ssl-cert create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n mysslcert --cert-file c:\aucernaio.cer --cert-password password  | out-null #--cert-password Tr@nsf0rm3rs <--for self-signed only
   	    az network application-gateway frontend-port create -g $clusterresgroup --gateway-name $variables.azure.appgateway -n myfrontendport2 --port 443 | out-null
   	    $listid=az network application-gateway frontend-port show -g $clusterresgroup --gateway-name $variables.azure.appgateway -n myfrontendport2  --query "{id: id}" -o tsv
   	    az network application-gateway http-listener update -g $clusterresgroup --gateway-name $variables.azure.appgateway -n appgatewayhttplistener --set protocol=https --set frontendPort.id=$listid --ssl-cert mysslcert | out-null
   	
   	    $sw.stop()
   	    $time=[math]::round($sw.elapsed.totalminutes, 2)
   	    $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
   	    "App gateway modified successfully. Elapsed time: $time min, total time: $totaltime min"
        add-content ($variables.deploymentdoc+$date) " - $deplstep : $time"
    }
    catch{ error-catch }
}
function clone-git {
    try{
        $deplstep='Clone the Platform-Deployment Code'
        '**Cloning the latest git**'
   	    $sw = [diagnostics.stopwatch]::startnew()
   	    cd $variables.gitclone.dir
   	    rm -r -fo platform-deployment | out-null
        try
        {
            git clone $variables.gitclone.url platform-deployment | out-null
        }
        catch
        {
          $ErrorMessage = $_.Exception.Message
          if($ErrorMessage -eq "Cloning into 'platform-deployment'...")
          {
            #do nothing
          }
          else{Write-Host $ErrorMessage -ForegroundColor Yellow}
          $ErrorMessage=""
        }
   	    $sw.stop()
   	    $time=[math]::round($sw.elapsed.totalminutes, 2)
	    $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
	    "Git cloned successfully. Elapsed time: $time min, total time: $totaltime min"
        add-content ($variables.deploymentdoc+$date) " - $deplstep : $time"
    }
    catch{ error-catch }
}
function create-service-accounts {
    try{
        $deplstep='Create Service Account'
   	    '**Create service account**'
   	    $sw = [diagnostics.stopwatch]::startnew()
   	    cd ~\documents\github\platform-deployment\helm\charts\cdm
   	    add-content svcacct.yaml 'apiversion: v1' | out-null
   	    add-content svcacct.yaml 'kind: ServiceAccount' | out-null
   	    add-content svcacct.yaml 'metadata:' | out-null
   	    add-content svcacct.yaml '  name: tiller' | out-null
   	    add-content svcacct.yaml '  namespace: kube-system' | out-null
   	    add-content svcacct.yaml '---' | out-null
   	    add-content svcacct.yaml 'apiversion: rbac.authorization.k8s.io/v1beta1' | out-null
   	    add-content svcacct.yaml 'kind: clusterrolebinding' | out-null
   	    add-content svcacct.yaml 'metadata:' | out-null
   	    add-content svcacct.yaml '  name: tiller' | out-null
   	    add-content svcacct.yaml 'roleref:' | out-null
   	    add-content svcacct.yaml '  apigroup: rbac.authorization.k8s.io' | out-null
   	    add-content svcacct.yaml '  kind: clusterrole' | out-null
   	    add-content svcacct.yaml '  name: cluster-admin' | out-null
   	    add-content svcacct.yaml 'subjects:' | out-null
   	    add-content svcacct.yaml '  - kind: ServiceAccount' | out-null
   	    add-content svcacct.yaml '    name: tiller' | out-null
   	    add-content svcacct.yaml '    namespace: kube-system' | out-null
   	    kubectl create -f svcacct.yaml --validate=false | out-null
   	    $sw.stop()
   	    $time=[math]::round($sw.elapsed.totalminutes, 2)
   	    $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
   	    "Service accounts created successfully. Elapsed time: $time min, total time: $totaltime min"
        add-content ($variables.deploymentdoc+$date) " - $deplstep : $time "
    }
    catch{ error-catch }
}
function helm-init-update {
    try{
        $deplstep='Helm Init / Update'
   	    '**Initializing helm**'
   	    $sw = [diagnostics.stopwatch]::startnew()
   	    #helm init --override 'spec.template.spec.containers[0].command'='{/tiller,--storage=secret}' --upgrade --service-account tiller --wait | out-null  #<--Only works in linux
   	    helm init --wait | out-null
   	    helm repo update | out-null
   	    try
        {
            kubectl create clusterrolebinding add-on-cluster-admin --clusterrole=cluster-admin --serviceaccount=kube-system:default | out-null
        }
        catch
        {
          $ErrorMessage = $_.Exception.Message
          if($ErrorMessage -eq 'Error from server (AlreadyExists): clusterrolebindings.rbac.authorization.k8s.io "add-on-cluster-admin" already exists')
          {
            #do nothing
          }
          else{Write-Host $ErrorMessage -ForegroundColor Yellow}
          $ErrorMessage=""
        }
   	    $sw.stop()
   	    $time=[math]::round($sw.elapsed.totalminutes, 2)
   	    $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
	    "Helm initialized, tiler ready. Elapsed time: $time min, total time: $totaltime min"
        add-content ($variables.deploymentdoc+$date) " - $deplstep : $time"
    }
    catch{ error-catch }
}
function secrets($all='y') {
    try{
        $deplstep='Create Secrets'
        $local="y" #only local deployments for now
        '**Create secrets**'
   	    $sw = [diagnostics.stopwatch]::startnew
        if($all -eq $null){ $all='y' }
        if($all -eq 'n'){
            $count=0
            cd ~\documents\github\platform-deployment\helm\charts\
            $dir=dir -Directory -Name -Include *secret* -Exclude secrets
            do
            {
                (($count)+1).ToString()+" - "+($dir)[$count]
                $count++
            }
            while($count -le (($dir).count)-1)
            $select=@()
            $select+=((read-host("Please select the number of the secret (separate the numbers with a comma, ENTER to all)")) -split ',')
            if(!$select){ $select=@(); do{$select+=$count; $count--}while($count -ge 1) }
            $count=0
            $list=@()
            do{
                $list+=$dir[($select[$count])-1]
                $count++
            }while($count -le ($select.count)-1)
        }
        elseif($all -eq 'y'){
            cd ~\documents\github\platform-deployment\helm\charts\
            $dir=dir -Directory -Name -Include *secret* -Exclude secrets
            $count=$dir.count
            $select=@(); $list=@(); do{$select+=$count; $count--}while($count -ge 1)
            do{
                $list+=$dir[($select[$count])-1]
                $count++
            }while($count -le ($select.count)-1)
        }
        else{ 'Please set the secrets to all (y) or not (n)' }
        $completed=@()
        $count=0
        #create container registry secret
        $ErrorMessage = $null
        try{
                kubectl get secrets acr-registry-secret | out-null
                "secrets acr-registry-secret already exists"
            }
        catch{
                $ErrorMessage = $_.Exception.Message
                if($ErrorMessage -ne $null) {
                    #connect-to-kubernates-subscription 'payg' 
                    $svr='platformdev.azurecr.io'#az acr show -n ($variables.azure.containerregistry.repository) --query loginServer -o tsv
                    $usr='platformdev'#az acr show -n ($variables.azure.containerregistry.repository) --query name -o tsv
                    $psw='gJBhHF4Om0fx2pmraDzAV+Sv0rttxSBw'#az acr credential show -n ($variables.azure.containerregistry.repository) --query passwords[0].value -o tsv
                    connect-to-kubernates-subscription 'local'
                }
            }
            
        do{
            if($list.Count -gt 1){ $name=$list[$count] }
            else{ $name=$list }
   	        $helmcheck=helm ls (($variables.helm.secretname)+'-'+$name)
            if($helmcheck -ne $null){ '**Deleting secret '+(($variables.helm.secretname)+'-'+$name)+'**'; helm delete --purge (($variables.helm.secretname)+'-'+$name) }
            "**Deploying secret $name**"
   	        $sw = [diagnostics.stopwatch]::startnew()
   	        if((test-path .\$name\original-values.yaml) -eq $false)
   	        {	
   		        copy-item .\$name\values.yaml -destination .\$name\original-values.yaml
   	        }
            
            #set namespaces
            if    ($name -eq 'cdm-storage-secret')       { $namespace='default'; $namespace2='monitoring' } #1: zkkkc 2: hbhd
            elseif($name -eq 'kongapigateway-db-secret') { $namespace='kong' } #krk
            elseif($name -eq 'provisioning-secret')      { $namespace='provisioning' }
            else                                         { $namespace='default' }

            $content=get-content -path .\$name\values.yaml
            if($name -eq 'telemetry-db-secret'){
                $linenumberdbusr = ($content | Select-String -Pattern 'dbUser: '      | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumberdbpsw = ($content | Select-String -Pattern 'dbPassword: '  | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumbertbscg = ($content | Select-String -Pattern 'tableSchema: ' | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumbertbnm  = ($content | Select-String -Pattern 'tableName: '   | Select-Object -ExpandProperty 'LineNumber')-1
                $content[$linenumberdbusr]='dbUser: "'+$variables.secrets.telemetry.dbuser+'"'
   	            $content[$linenumberdbpsw]='dbPassword: "'+$variables.secrets.telemetry.dbpsw+'"'
   	            $content[$linenumbertbscg]='tableSchema: "'+$variables.secrets.telemetry.tblschema+'"'
   	            $content[$linenumbertbnm]= 'tableName: "'+$variables.secrets.telemetry.tblname+'"'
                $secdeploy='n'
            }
            if($name -eq 'provisioning-secret'){
                $linenumberpostgres = ($content | Select-String -Pattern "postgres:" | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumberkeycloak = ($content | Select-String -Pattern 'keycloak:' | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumberjmxmonitor = ($content | Select-String -Pattern 'jmxmonitor:' | Select-Object -ExpandProperty 'LineNumber')-1
                $content[$linenumberpostgres+1]='  user: "'+$variables.secrets.postgres.user+'"'
   	            $content[$linenumberpostgres+2]='  password: "'+$variables.secrets.postgres.psw+'"'
   	            $content[$linenumberkeycloak+1]='  user: "'+$variables.secrets.kc.user+'"'
   	            $content[$linenumberkeycloak+2]='  password: "'+$variables.secrets.kc.psw+'"'
                $content[$linenumberjmxmonitor+1]='  user: "'+$variables.secrets.jmx.user+'"'
   	            $content[$linenumberjmxmonitor+2]='  password: "'+$variables.secrets.jmx.psw+'"'
                $secdeploy='n'
            }
            if($name -eq 'cdm-storage-secret'){
                $linenumberacnm = ($content | Select-String -Pattern 'storageAccountName:' -CaseSensitive | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumberacky = ($content | Select-String -Pattern 'storageAccountKey:' -CaseSensitive | Select-Object -ExpandProperty 'LineNumber')-1
                $content[$linenumberacnm]='storageAccountName: "'+$variables.azure.storageacct+'"'
   	            if($local -eq 'n')
   	            {
   		            $sub='payg'
       	            $key = az storage account keys list -g $variables.azure.$sub.resgroup -n $variables.azure.$sub.storageacct --query "[0].value" -o tsv
   	            }
   	            elseif($local -eq 'y')
   	            {
                    $sub='local'
       	            $key = az storage account keys list -g $variables.azure.resgroup -n $variables.azure.storageacct --query "[0].value" -o tsv
   	            }
                $content[$linenumberacky]='storageAccountKey: "'+$key+'"'
                $secdeploy='y'
            }
            if($name -eq 'grafana-secret'){
                [string]$1 = $content | Select-String -Pattern ('dbUser: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dbUser: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dbuser+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('dbPassword: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dbPassword: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dbpsw+'"')
                $content[$LineNumber1]=$1

                #[string]$1 = $content | Select-String -Pattern ('grafanaAdminPassword: ')
                #$LineNumber1 = ($content | Select-String -Pattern ('grafanaAdminPassword: ') | Select-Object -ExpandProperty 'LineNumber')-1
                #if($1.count -gt 1){ $1=$1[0] }
                #$1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.rptpswd+'"')
                #$content[$LineNumber1]=$1

                [string]$1 = $content | Select-String -Pattern ('adminUser: ')
                $LineNumber1 = ($content | Select-String -Pattern ('adminUser: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.admusr+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('adminPassword: ')
                $LineNumber1 = ($content | Select-String -Pattern ('adminPassword: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.admpsw+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('reportUser: ')
                $LineNumber1 = ($content | Select-String -Pattern ('reportUser: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.rptuser+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('reportPassword: ')
                $LineNumber1 = ($content | Select-String -Pattern ('reportPassword: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.rptpswd+'"')
                $content[$LineNumber1]=$1
                
                [string]$1 = $content | Select-String -Pattern ('adClientId: ')
                $LineNumber1 = ($content | Select-String -Pattern ('adClientId: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.adclientid+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('adClientSecret: ')
                $LineNumber1 = ($content | Select-String -Pattern ('adClientSecret: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.adclientsecret+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('adAuthUrl: ')
                $LineNumber1 = ($content | Select-String -Pattern ('adAuthUrl: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.adauthurl+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('adTokenUrl: ')
                $LineNumber1 = ($content | Select-String -Pattern ('adTokenUrl: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.adtokenurl+'"')
                $content[$LineNumber1]=$1
                
                [string]$1 = $content | Select-String -Pattern ('dsPgTelemetryHost: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dsPgTelemetryHost: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dstelhost+':5432"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('dsPgTelemetryDatabase: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dsPgTelemetryDatabase: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dsteldb+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('dsPgTelemetryUser: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dsPgTelemetryUser: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dstelusr+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('dsPgTelemetryPassword: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dsPgTelemetryPassword: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dstelpsw+'"')
                $content[$LineNumber1]=$1

                [string]$1 = $content | Select-String -Pattern ('dsPgDevstagingHost: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dsPgDevstagingHost: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dssthost+':5432"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('dsPgDevstagingDatabase: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dsPgDevstagingDatabase: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dsstdb+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('dsPgDevstagingUser: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dsPgDevstagingUser: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dsstusr+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('dsPgDevstagingPassword: ')
                $LineNumber1 = ($content | Select-String -Pattern ('dsPgDevstagingPassword: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dsstpsw+'"')
                $content[$LineNumber1]=$1

                $secdeploy='n'
            }
            if($name -eq 'kongapigateway-db-secret'){
                $linenumberdbhst = ($content | Select-String -Pattern 'dbHost' | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumberdbdb = ($content | Select-String -Pattern 'dbDatabase' | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumberdbprt = ($content | Select-String -Pattern 'dbPort' | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumberdbusr = ($content | Select-String -Pattern 'dbUser' | Select-Object -ExpandProperty 'LineNumber')-1
                $linenumberdbpsw = ($content | Select-String -Pattern 'dbPassword' | Select-Object -ExpandProperty 'LineNumber')-1
                $content[$linenumberdbhst]='  dbHost: "'+$variables.secrets.kongapigateway.dbHost+'"'
   	            $content[$linenumberdbdb]='  dbDatabase: "'+$variables.secrets.kongapigateway.dbDatabase+'"'
   	            $content[$linenumberdbprt]='  dbPort: "'+$variables.secrets.kongapigateway.dbPort+'"'
   	            $content[$linenumberdbusr]='  dbUser: "'+$variables.secrets.kongapigateway.dbUser+'"'
   	            $content[$linenumberdbpsw]='  dbPassword: "'+$variables.secrets.kongapigateway.dbPassword+'"'
                $secdeploy='n'
            }
            
            Set-content -path .\$name\values.yaml -Value $content
   	        
            helm install $name --name (($variables.helm.secretname)+'-'+$name) --namespace $namespace --wait | out-null

            try{
                kubectl create secret docker-registry "acr-registry-secret-$namespace" --docker-server=$svr --docker-username=$usr --docker-password=$psw --namespace $namespace --docker-email=felipe.fedozzi@3esi-enersight.com | out-null
   	            "Docker registry secret deployed in namespace $namespace."
            }
            catch{
                "Secret acr-registry-secret-$namespace already exists"
            }
            
            if($secdeploy -eq 'y') { helm install $name --name (($variables.helm.secretname)+'-'+$name+'-'+$namespace2) --namespace $namespace2 --wait | out-null;$secdeploy='n' }
            $count++
   	        $sw.stop()
   	        $time=[math]::round($sw.elapsed.totalminutes, 2)
   	        $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
	        "Secret $name deployed. Elapsed time: $time min, total time: $totaltime min"
            add-content ($variables.deploymentdoc+$date) " - $deplstep : $time "
        }while($count -le ($select.count)-1)
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        Write-Host $ErrorMessage+' - Rolling back deployment'(($variables.helm.secretname)+'-'+$name)'...' -ForegroundColor Yellow
        $ErrorMessage=""
        $variables.helmcheck=helm ls (($variables.helm.mainname)+'-'+$name)
        if($variables.helmcheck -ne $null){ '**Deleting secret '+(($variables.helm.mainname)+'-'+$name)+'**'; helm delete --purge (($variables.helm.secretname)+'-'+$name) }
        add-content ($variables.deploymentdoc+$date) " *** Failed on step $deplstep - $name *** "
        add-content ($variables.deploymentdoc+$date) $_.Exception.Message
        add-content ($variables.deploymentdoc+$date) "Failed in $time min"
    }
}
function repository-tags($latest='y') {
    try{
        $deplstep='Get Repositories tags'
        '**Get repositories tags**'
   	    $sw = [diagnostics.stopwatch]::startnew()
        if($latest -eq $null){ $latest='y' }
        if($latest -eq 'n'){
            $count=0
            $reg=az acr repository list -n $variables.azure.containerregistry.repository -o tsv
            do
            {
                (($count)+1).ToString()+" - "+($reg)[$count]
                $count++
            }while($count -le (($reg).count)-1)
            $select=@()
            $select+=((read-host("Please select the number of the tag (separate the numbers with a comma, ENTER to all)")) -split ',')
            if(!$select){ $select=@(); do{$select+=$count; $count--}while($count -ge 1) }
            $count=0
            $list=@()
            do{
                $list+=$reg[($select[$count])-1]
                $count++
            }while($count -le ($select.count)-1)
        }
        elseif($latest -eq 'y'){
            $reg=az acr repository list -n $variables.azure.containerregistry.repository -o tsv

            $reg=$reg.Where({$_ -notlike 'cdm*'})

            $count=$reg.count
            $select=@(); $list=@(); do{$select+=$count; $count--}while($count -ge 1)
            do{
                $list+=$reg[($select[$count])-1]
                $count++
            }while($count -le ($select.count)-1)
        }
        else{ cls;'Please set the tags to latest (y) or not (n)';repository-tags }
        for($count=0; $count -le ($select.count)-1; $count++ )
        {
            Write-Progress -Activity Updating -Status 'Progress' -PercentComplete ($count/$select.count*100);

            if($list.Count -gt 1){ $name=$list[$count] }
            else{ $name=$list }
            if($latest -eq 'y'){
                $value=az acr repository show-tags -n $variables.azure.containerregistry.name --repository $name --orderby time_desc --detail -o tsv --query [0].name
			}
            elseif($latest -eq 'n'){
                az acr repository show-tags -n $variables.azure.containerregistry.name --repository $name
                $value=Read-Host("Please enter a tag")
            }
            try{ Remove-Variable -Name ("$name"+'repname') -Scope script } catch{ "" }
            Set-Variable -Name ("$name"+'repname') -Value $name -Scope script
            try{ Remove-Variable -Name ("$name"+'tag') -Scope script } catch{ "" }
            Set-Variable -Name ("$name"+'tag') -Value $value -Scope script
            Get-Variable -Name ("$name"+'repname')
            Get-Variable -Name ("$name"+'tag')
        }
        $sw.stop()
   	    $time=[math]::round($sw.elapsed.totalminutes, 2)
   	    $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
	    "Tags selected. Elapsed time: $time min, total time: $totaltime min"
        add-content ($variables.deploymentdoc+$date) " - $deplstep : $time"
    }
    catch{ error-catch }
}
function deploy($full='n') {
    try{
	    $deplstep='Run Deployments'
        '**Run deployments**'
   	    $sw = [diagnostics.stopwatch]::startnew
        if($full -eq $null){ $full='y' }
        if($full -eq 'n'){
            $count=0
            cd ~\documents\github\platform-deployment\helm\charts\
            $dir=dir -Directory -Name -Exclude ($variables.exclude)
            do
            {
            (($count)+1).ToString()+" - "+($dir)[$count]
            $count++
            }
            while($count -le (($dir).count)-1)
            $select=@()
            $select+=((read-host("Please select the number of the deployment (separate the numbers with a comma, ENTER to all)")) -split ',')
            if(!$select){ $select=@(); do{$select+=$count; $count--}while($count -ge 1) }
            $listordered=@()
            $count=0
            if($select.Count -gt 1){
                do{
                    $listordered+=$dir[($select[$count])-1]
                    $count++
                }while($count -le ($select.count)-1)
                $listordered=$listordered | sort { $variables.order.IndexOf($_) }}
            else{ $listordered=$dir[($select[$count])-1] }
        } 
        elseif($full -eq 'y'){
            cd ~\documents\github\platform-deployment\helm\charts\
            $dir=dir -Directory -Name -Exclude ($variables.exclude)
            $count=$dir.count
            $select=@(); $listordered=@(); do{$select+=$count; $count--}while($count -ge 1)
            do{
                $listordered+=$dir[($select[$count])-1]
                $count++
                }while($count -le ($select.count)-1)
            $listordered=@($listordered | sort { $variables.order.IndexOf($_) })
        }
        else{ 'Please set the deployment to full (y) or not (n)' }
        $completed=@()
        $count=0
        #deploy kong namespace
        try{
            kubectl get namespace kong | out-null
            'Kong namespace already deployed'
        }
        catch{
            $ErrorMessage = $_.Exception.Message
            if($ErrorMessage -ne $null){
                $kongnamespace=$home+'\Documents\GitHub\platform-deployment\environment_setup\telemetry\apigatewayconfig\setup_kong_namespace.yaml'
                kubectl create -f ($kongnamespace)
            }
            $ErrorMessage=''
        }
        #apply cdm-ingress-rule
        try{
            kubectl get ingress cdm-ingress-rule | out-null
            "Ingress cdm-ingress-rule already applied"
        }
        catch{
            #Write-Host $_.Exception.Message -ForegroundColor Yellow
            $cdmingressrule=$home+'\Documents\GitHub\platform-deployment\environment_setup\telemetry\apigatewayconfig\ingressrules\cdm\cdmingressrules.yaml'
            $content=get-content -path $cdmingressrule
            
            [string]$1 = $content | Select-String -Pattern ('host: "')
            $LineNumber1 = ($content | Select-String -Pattern ('host: "') | Select-Object -ExpandProperty 'LineNumber')-1
            if($1.count -gt 1){ $1=$1[0] }
            $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "*.cloudapp.azure.com"')
            $content[$LineNumber1]=$1
            
            [string]$1 = $content | Select-String -Pattern ('serviceName: ')
            $LineNumber1 = ($content | Select-String -Pattern ('serviceName: ') | Select-Object -ExpandProperty 'LineNumber')-1
            if($1.count -gt 1){ $1=$1[0] }
            $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': kafka-rest-hs')
            $content[$LineNumber1]=$1

            [string]$1 = $content | Select-String -Pattern ('servicePort: ')
            $LineNumber1 = ($content | Select-String -Pattern ('servicePort: ') | Select-Object -ExpandProperty 'LineNumber')-1
            if($1.count -gt 1){ $1=$1[0] }
            $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': 8082')
            $content[$LineNumber1]=$1

            Set-content -path $cdmingressrule -Value $content

            kubectl apply -f ($cdmingressrule) | out-null
        }
        #apply telemetry-ingress-rule
        try{
            kubectl get ingress telemetry-ingress-rule | out-null
            "Ingress telemetry-ingress-rule already applied"
        }
        catch{
            #Write-Host $_.Exception.Message -ForegroundColor Yellow
            $telemetryingressrule=$home+'\Documents\GitHub\platform-deployment\environment_setup\telemetry\apigatewayconfig\ingressrules\telemetry\ingressrules.yaml'
            $content=get-content -path $telemetryingressrule
            
            [string]$1 = $content | Select-String -Pattern ('host: "')
            $LineNumber1 = ($content | Select-String -Pattern ('host: "') | Select-Object -ExpandProperty 'LineNumber')-1
            if($1.count -gt 1){ $1=$1[0] }
            $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "*.cloudapp.azure.com"')
            $content[$LineNumber1]=$1
            
            [string]$1 = $content | Select-String -Pattern ('serviceName: ')
            $LineNumber1 = ($content | Select-String -Pattern ('serviceName: ') | Select-Object -ExpandProperty 'LineNumber')-1
            if($1.count -gt 1){ $1=$1[0] }
            $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': kafka-rest-hs')
            $content[$LineNumber1]=$1

            [string]$1 = $content | Select-String -Pattern ('servicePort: ')
            $LineNumber1 = ($content | Select-String -Pattern ('servicePort: ') | Select-Object -ExpandProperty 'LineNumber')-1
            if($1.count -gt 1){ $1=$1[0] }
            $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': 8082')
            $content[$LineNumber1]=$1

            Set-content -path $telemetryingressrule -Value $content

            kubectl apply -f $telemetryingressrule | out-null
        }
        #apply grafana-ingress-rule
        try{
            kubectl get ingress grafana-ingress-rule | out-null
            "Ingress cdm-ingress-rule already applied"
        }
        catch{
            #Write-Host $_.Exception.Message -ForegroundColor Yellow
            $grafanaingressrule=$home+'\Documents\GitHub\platform-deployment\environment_setup\grafana\apigatewayconfig\ingressrules.yaml'
            $content=get-content -path $grafanaingressrule
            
            [string]$1 = $content | Select-String -Pattern ('host: "')
            $LineNumber1 = ($content | Select-String -Pattern ('host: "') | Select-Object -ExpandProperty 'LineNumber')-1
            if($1.count -gt 1){ $1=$1[0] }
            $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "*.cloudapp.azure.com"')
            $content[$LineNumber1]=$1
            
            Set-content -path $grafanaingressrule -Value $content

            kubectl apply -f ($grafanaingressrule) | out-null
        }
        Start-Sleep -s 2
        do{
            if($listordered.Count -gt 1){ $name=$listordered[$count] }
            else{ $name=$listordered }
            "**Deploying $name**"
            if(($name -like (get-variable "*$name*repname")) -eq $false) {
                if($name -like "kong*way"){ $namerep='kong-ingress-controller' } 
                elseif($name -like "kong*-db"){ $namerep='kong-custom' }
                else{ $namerep=$name }}
            else{ $namerep=$name }
            if($name -like (get-variable "*$name*repname")){ $namerep=get-variable "*$name*repname" -ValueOnly }
   	        $sw = [diagnostics.stopwatch]::startnew()
   	        if((test-path .\$name\original-values.yaml) -eq $false)
   	        {	
   		        copy-item .\$name\values.yaml -destination .\$name\original-values.yaml
   	        }
            $content=get-content -path .\$name\values.yaml
            if($name -like 'cdm-*'){ $namerep=$name -replace 'cdm-',''}
            #if($name -like 'kongapigateway-db'){ $name2=$name; $name='kong-custom'; $changed='y1' }
            #if($name -like 'kongapigateway'){ $name3=$name; $name='kong-ingress-controller'; $changed='y2' }
            #else{ $changed='n' }
            
            #set namespaces
            if    ($namerep -eq 'kafka' -or $namerep -eq 'zookeeper' -or $namerep -eq 'kafka-connect') { $namespace='default'; $kafkanamespace='default' } #zkkkc
            elseif($namerep -eq 'hbase' -or $namerep -eq 'hdfs')                                       { $namespace='default' } #hbhd
            elseif($namerep -eq 'kafka-rest')                                                          { $namespace='default' }
            elseif($namerep -eq 'kong-custom' -or $namerep -eq 'kong-ingress-controller')              { $namespace='kong'} 
            elseif($namerep -eq 'provisioning')                                                        { $namespace='provisioning' }    #
            elseif($namerep -eq 'prometheus-operator')                                                 { $namespace='monitoring' }    #
            else                                                                                       { $namespace='default' } #
            Start-Sleep -s 2
            $helmcheck=helm ls (($variables.helm.mainname)+'-'+$namerep+'-'+$namespace) --all
            if($helmcheck -ne $null){ 'Delete helm deployment '+(($variables.helm.mainname)+'-'+$namerep+'-'+$namespace)+'**'; helm delete --purge (($variables.helm.mainname)+'-'+$namerep+'-'+$namespace) }
            if((($content | Select-String -Pattern "repository: *confluentinc*") -eq $null) -or ($content | Select-String -Pattern !"repository: *$variables.azure.containerregistry.name*")){
                if(($content | Select-String -Pattern "repository: *grafana*") -eq $null){
                    if((Get-Variable -Name *$($namerep)repname -ValueOnly) -ne $null) {
                        [string]$1=($content | Select-String -Pattern ('repository: '+ $variables.azure.containerregistry.name +'.azurecr.io/'+$namerep))
                        if($1 -eq ""){ $1=($content | Select-String -Pattern ('repository: aucernadevregistry.azurecr.io/'+$namerep)) }
                        try{
                            $LineNumber1 = (($content | Select-String -Pattern ('repository: '+$variables.azure.containerregistry.name+'.azurecr.io/'+$namerep) | Select-Object -ExpandProperty 'LineNumber')[0])-1
                        }
                        catch{
                            $LineNumber1=($content | Select-String -Pattern ('repository: aucernadevregistry.azurecr.io') | Select-Object -ExpandProperty 'LineNumber')-1 
                        }
                    
                        if($1.count -gt 1){ $1=$1[0] }
                        $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+$variables.azure.containerregistry.repository+'.azurecr.io/'+$namerep)
                        $content[$LineNumber1]=$1
                    }
                    if((Get-Variable -Name *$($namerep)tag -ValueOnly) -ne $null) {
                        [string]$1=($content | Select-String -Pattern ('tag:') | Select-String -Pattern '-alpine' -NotMatch)[0]
                        $LineNumber1 = ((($content | Select-String -Pattern ('tag:') | Select-String -Pattern '-alpine' -NotMatch) | Select-Object -ExpandProperty 'LineNumber')[0])-1
                        if($1.count -gt 1){ $1=$1[0] }
                        if((Get-Variable -Name *$($namerep)tag -ValueOnly).count -gt 1){ $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+ (Get-Variable -Name *$($namerep)tag -ValueOnly)[0]) }
                        else{ $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+ (Get-Variable -Name *$($namerep)tag -ValueOnly)) }
                        $content[$LineNumber1]=$1
                    }
                }
            }
            [string]$1 = $content | Select-String -Pattern ('registrySecret')
            if($1 -notlike "*default" -and $1 -ne "") {
                $LineNumber1 = (($content | Select-String -Pattern ('registrySecret')) | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': acr-registry-secret-'+$namespace)
                $content[$LineNumber1]=$1
            }
            if($namerep -eq 'prometheus-operator'){
                [string]$1 = $content | Select-String -Pattern ('release: ')
                $LineNumber1 = ($content | Select-String -Pattern ('release: ') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+(($variables.helm.mainname)+'-'+$namerep+'-'+$namespace))
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('cleanupCustomResource:')
                $LineNumber1 = ($content | Select-String -Pattern ('cleanupCustomResource:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': true') #true to clean crd's in kubernetes, false to leave crd's in kubernetes
                $content[$LineNumber1]=$1
            }
            if($namerep -eq 'zookeeper'){
                [string]$1 = $content | Select-String -Pattern ('zkDns:')
                $LineNumber1 = ($content | Select-String -Pattern ('zkDns:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+$namespace+'.svc.cluster.local')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('enabled:')
                $LineNumber1 = ($content | Select-String -Pattern ('enabled:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': true')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('acr-registry-secret-')
                if($1 -eq ""){
                    $content = $content | Foreach-Object { $_ -replace "acr-registry-secret", "acr-registry-secret-$namespace" }
                }
            }
            if($namerep -eq 'hdfs'){
                if ($namespace -ne 'default'){ $namespace='zkkkc' }
                [string]$1 = $content | Select-String -Pattern ('zkDns:')
                $LineNumber1 = ($content | Select-String -Pattern ('zkDns:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+$namespace+'.svc.cluster.local')
                $content[$LineNumber1]=$1
                
                $contenttpl=Get-Content -path .\$name\templates\_helpers.tpl | Foreach-Object { $_ -replace "(\.default)", ('.'+$namespace) }
                Set-Content -path .\$name\templates\_helpers.tpl -Value $contenttpl
                
                $contenttpl=Get-Content -path .\$name\templates\configmap.yaml | Foreach-Object { $_ -replace "(n.default.)", ('n.'+$namespace+'.') }
                Set-Content -path .\$name\templates\configmap.yaml -Value $contenttpl

                $contenttpl=Get-Content -path .\$name\templates\hdfs-config.yaml | Foreach-Object { $_ -replace "(n.default.)", ('n.'+$namespace+'.') }
                Set-Content -path .\$name\templates\hdfs-config.yaml -Value $contenttpl

                if ($namespace -ne 'default'){ $namespace='hbhd' }
            }
            if($namerep -eq 'query'){
                [string]$1 = $content | Select-String -Pattern ('rootLevel:')
                $LineNumber1 = ($content | Select-String -Pattern ('rootLevel:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': TRACE') #DEBUG, INFO, TRACE and WARN
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('cdmLevel:')
                $LineNumber1 = ($content | Select-String -Pattern ('cdmLevel:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': TRACE') #DEBUG, INFO, TRACE and WARN
                $content[$LineNumber1]=$1
            }
            if($namerep -eq 'kafka'){
                [string]$1 = $content | Select-String -Pattern ('kafkaDns:')
                $LineNumber1 = ($content | Select-String -Pattern ('kafkaDns:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+$namespace+'.svc.cluster.local')
                $content[$LineNumber1]=$1

                $contenttpl=Get-Content -path .\$name\templates\_helpers.tpl | Foreach-Object { $_ -replace "(\.default)", ('.'+$namespace) }
                Set-Content -path .\$name\templates\_helpers.tpl -Value $contenttpl
            }
            if($namerep -eq 'kafka-connect'){
                [string]$1 = $content | Select-String -Pattern ('telemetrydatabasehost:')
                $LineNumber1 = ($content | Select-String -Pattern ('telemetrydatabasehost:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.keycloak.host+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('telemetrydatabasename:')
                $LineNumber1 = ($content | Select-String -Pattern ('telemetrydatabasename:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.keycloak.teledb+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('kafkaDns:')
                $LineNumber1 = ($content | Select-String -Pattern ('kafkaDns:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+$namespace+'.svc.cluster.local')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('zkDns:')
                $LineNumber1 = ($content | Select-String -Pattern ('zkDns:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+$namespace+'.svc.cluster.local')
                $content[$LineNumber1]=$1

                $contenttpl=Get-Content -path .\$name\templates\configmap.yaml | Foreach-Object { $_ -replace "(\.default)", ('.'+$namespace) }
                Set-Content -path .\$name\templates\configmap.yaml -Value $contenttpl
            }
            if($namerep -eq 'kafka-rest'){
                if($publicip -eq $null)
                {
                    $publicip=az network public-ip show -g $clusterresgroup -n $variables.azure.publicipdns --query "{address: ipAddress}" -o tsv
   	                $publicdns=az network public-ip show -g $clusterresgroup -n $variables.azure.publicipdns --query "{fqdn: dnsSettings.fqdn}" -o tsv
                }
                ($content | Select-String -Pattern ('ip:'))[1]
                $LineNumberip = (($content | Select-String -Pattern ('ip:'))[1] | Select-Object -ExpandProperty 'LineNumber')-1
                $LineNumberdns = ($content | Select-String -Pattern 'hostname: ' -CaseSensitive | Select-Object -ExpandProperty 'LineNumber')-1
                $content[$LineNumberip]='ip: '+$publicip
                $content[$LineNumberdns]='hostname: '+$publicdns
            }
            if($namerep -eq 'provisioning'){
                $LineNumbersrv = ($content | Select-String -Pattern 'server: "' | Select-Object -ExpandProperty 'LineNumber')-1
                $LineNumberdb = ($content | Select-String -Pattern 'database: "' | Select-Object -ExpandProperty 'LineNumber')-1
                $content[$LineNumbersrv]='  server: "'+$variables.keycloak.host+'"'
                $content[$LineNumberdb]='  database: "'+$variables.keycloak.db+'"'
                [string]$1 = $content | Select-String -Pattern ('kafkaBroker:')
                $LineNumber1 = ($content | Select-String -Pattern ('kafkaBroker:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': kafka-0.kafka-hs.'+$kafkanamespace+'.svc.cluster.local')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('enabled:')
                $LineNumber1 = ($content | Select-String -Pattern ('enabled:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': true')
                $content[$LineNumber1]=$1

                $contenttpl=Get-Content -path .\$name\templates\serviceaccount.yaml | Foreach-Object { $_ -replace "(default)", ($namespace) }
                Set-Content -path .\$name\templates\serviceaccount.yaml -Value $contenttpl
            }
            if($namerep -eq 'kong-custom'){
                [string]$1 = $content | Select-String -Pattern ('hostName:')
                $LineNumber1 = ($content | Select-String -Pattern ('hostName:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.kongapigateway.dbHost+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('postgresUser:')
                $LineNumber1 = ($content | Select-String -Pattern ('postgresUser:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.kongapigateway.dbUser+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('postgresPassword:')
                $LineNumber1 = ($content | Select-String -Pattern ('postgresPassword:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.kongapigateway.dbPassword+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('postgresDatabase:')
                $LineNumber1 = ($content | Select-String -Pattern ('postgresDatabase:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.kongapigateway.dbDatabase+'"')
                $content[$LineNumber1]=$1
            }
            if($namerep -eq 'kong-ingress-controller2'){
                [string]$1 = $content | Select-String -Pattern ('hostName:')
                $LineNumber1 = ($content | Select-String -Pattern ('hostName:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.kongapigateway.dbHost+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('postgresUser:')
                $LineNumber1 = ($content | Select-String -Pattern ('postgresUser:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.kongapigateway.dbUser+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('postgresPassword:')
                $LineNumber1 = ($content | Select-String -Pattern ('postgresPassword:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.kongapigateway.dbPassword+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('postgresDatabase:')
                $LineNumber1 = ($content | Select-String -Pattern ('postgresDatabase:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.kongapigateway.dbDatabase+'"')
                $content[$LineNumber1]=$1
            }
            if($namerep -eq 'grafana'){
                [string]$1 = $content | Select-String -Pattern ('storageAccount:')
                $LineNumber1 = ($content | Select-String -Pattern ('storageAccount:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.azure.storageacct+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('grafanaDatabaseHost:')
                $LineNumber1 = ($content | Select-String -Pattern ('grafanaDatabaseHost:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dbhost+'"')
                $content[$LineNumber1]=$1
                [string]$1 = $content | Select-String -Pattern ('grafanaDatabaseName:')
                $LineNumber1 = ($content | Select-String -Pattern ('grafanaDatabaseName:') | Select-Object -ExpandProperty 'LineNumber')-1
                if($1.count -gt 1){ $1=$1[0] }
                $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': "'+$variables.secrets.grafana.dbname+'"')
                $content[$LineNumber1]=$1
            }
            Set-content -Encoding UTF8 -path .\$name\values.yaml -Value $content
   	        if($namerep -eq 'prometheus-operator'){
                #latest stable version is 0.1.26 - o.1.27 is broken, don't point to this version
                helm install --name (($variables.helm.mainname)+'-'+$namerep+'-'+$namespace) stable/prometheus-operator --version "0.1.26" -f .\$name\values.yaml --namespace $namespace --wait
                #deploy prometheus-storage-volume
                try{
                    kubectl get pv prometheus-storage-volume -n monitoring | out-null
                    Write-Host("Persistentvolume prometheus-storage-volume already exists")
                }
                catch{
                    kubectl create -f .\$name\persistent-volume.yaml --namespace $namespace
                }
                #deploy keycloak-monitor
                try{
                    kubectl get servicemonitors keycloak-monitor -n monitoring
                    Write-Host("keycloak-monitor already exists")
                }
                catch{
                    $contentmonitor=get-content -path .\$name\servicemonitor\keycloak-monitor.yaml
                    [string]$1 = $contentmonitor | Select-String -Pattern ('release:')
                    $LineNumber1 = ($contentmonitor | Select-String -Pattern ('release:') | Select-Object -ExpandProperty 'LineNumber')-1
                    if($1.count -gt 1){ $1=$1[0] }
                    $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+(($variables.helm.mainname)+'-'+$namerep+'-'+$namespace))
                    $contentmonitor[$LineNumber1]=$1
                    Set-content -path .\$name\servicemonitor\keycloak-monitor.yaml -Value $contentmonitor
                    kubectl create -f .\$name\servicemonitor\keycloak-monitor.yaml --namespace $namespace
                }
                #deploy kafkaconnect-monitor
                try{
                    kubectl get servicemonitors kafkaconnect-monitor -n monitoring
                    Write-Host("kafkaconnect-monitor already exists")
                }
                catch{
                    $contentmonitor=get-content -path .\$name\servicemonitor\kafkaconnect-monitor.yaml
                    [string]$1 = $contentmonitor | Select-String -Pattern ('release:')
                    if($1 -ne ''){
                        $LineNumber1 = ($contentmonitor | Select-String -Pattern ('release:') | Select-Object -ExpandProperty 'LineNumber')-1
                        if($1.count -gt 1){ $1=$1[0] }
                        $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+(($variables.helm.mainname)+'-'+$namerep+'-'+$namespace))
                        $contentmonitor[$LineNumber1]=$1
                        Set-content -path .\$name\servicemonitor\kafkaconnect-monitor.yaml -Value $contentmonitor
                    }
                    kubectl create -f .\$name\servicemonitor\kafkaconnect-monitor.yaml --namespace $namespace
                }
                #deploy kafka-monitor
                try{
                    kubectl get servicemonitors kafka-monitor -n monitoring
                    Write-Host("kafka-monitor already exists")
                }
                catch{
                    $contentmonitor=get-content -path .\$name\servicemonitor\kafka-monitor.yaml
                    [string]$1 = $contentmonitor | Select-String -Pattern ('release:')
                    if($1 -ne ''){
                        $LineNumber1 = ($contentmonitor | Select-String -Pattern ('release:') | Select-Object -ExpandProperty 'LineNumber')-1
                        if($1.count -gt 1){ $1=$1[0] }
                        $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+(($variables.helm.mainname)+'-'+$namerep+'-'+$namespace))
                        $contentmonitor[$LineNumber1]=$1
                        Set-content -path .\$name\servicemonitor\kafka-monitor.yaml -Value $contentmonitor
                    }
                    kubectl create -f .\$name\servicemonitor\kafka-monitor.yaml --namespace $namespace
                }
                #deploy kong-monitor
                try{
                    kubectl get servicemonitors kong-monitor -n monitoring
                    Write-Host("kong-monitor already exists")
                }
                catch{
                    $contentmonitor=get-content -path .\$name\servicemonitor\kong-monitor.yaml
                    [string]$1 = $contentmonitor | Select-String -Pattern ('release:')
                    if($1 -ne ''){
                        $LineNumber1 = ($contentmonitor | Select-String -Pattern ('release:') | Select-Object -ExpandProperty 'LineNumber')-1
                        if($1.count -gt 1){ $1=$1[0] }
                        $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+(($variables.helm.mainname)+'-'+$namerep+'-'+$namespace))
                        $contentmonitor[$LineNumber1]=$1
                        Set-content -path .\$name\servicemonitor\kong-monitor.yaml -Value $contentmonitor
                    }
                    kubectl create -f .\$name\servicemonitor\kong-monitor.yaml --namespace $namespace
                }
                #deploy promitor-monitor
                try{
                    kubectl get servicemonitors promitor-monitor -n monitoring
                    Write-Host("promitor-monitor already exists")
                }
                catch{
                    $contentmonitor=get-content -path .\$name\servicemonitor\promitor-monitor.yaml
                    [string]$1 = $contentmonitor | Select-String -Pattern ('release:')
                    if($1 -ne ''){
                        $LineNumber1 = ($contentmonitor | Select-String -Pattern ('release:') | Select-Object -ExpandProperty 'LineNumber')-1
                        if($1.count -gt 1){ $1=$1[0] }
                        $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+(($variables.helm.mainname)+'-'+$namerep+'-'+$namespace))
                        $contentmonitor[$LineNumber1]=$1
                        Set-content -path .\$name\servicemonitor\promitor-monitor.yaml -Value $contentmonitor
                    }
                    kubectl create -f .\$name\servicemonitor\promitor-monitor.yaml --namespace $namespace
                }
                #deploy zookeeper-monitor
                try{
                    kubectl get servicemonitors zookeeper-monitor -n monitoring
                    Write-Host("zookeeper-monitor already exists")
                }
                catch{
                    $contentmonitor=get-content -path .\$name\servicemonitor\zookeeper-monitor.yaml
                    [string]$1 = $contentmonitor | Select-String -Pattern ('release:')
                    $LineNumber1 = ($contentmonitor | Select-String -Pattern ('release:') | Select-Object -ExpandProperty 'LineNumber')-1
                    if($1.count -gt 1){ $1=$1[0] }
                    $1=$1.split(':')[0]; $1=$1.Insert(($1.Length), ': '+(($variables.helm.mainname)+'-'+$namerep+'-'+$namespace))
                    $contentmonitor[$LineNumber1]=$1
                    Set-content -path .\$name\servicemonitor\zookeeper-monitor.yaml -Value $contentmonitor
                    kubectl create -f .\$name\servicemonitor\zookeeper-monitor.yaml --namespace $namespace
                }
            }
            elseif($namerep -eq 'grafana'){
                helm package -d .\$name .\grafana
                helm install .\$name\grafana-0.1.0.tgz --name (($variables.helm.mainname)+'-'+$namerep+'-'+$namespace) -f .\$name\values.yaml --set storageAccount=monclusterstorage --namespace $namespace --wait
            }
            else{
                helm install $name --name (($variables.helm.mainname)+'-'+$namerep+'-'+$namespace) --namespace $namespace --wait
            }
            
            $sw.stop()
   	        $time=[math]::round($sw.elapsed.totalminutes, 2)
   	        $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
	        "$name deployed. Elapsed time: $time min, total time: $totaltime min"
            add-content ($variables.deploymentdoc+$date) " - $deplstep $name : $time"
            $count++
        }while($count -le ($select.count)-1)
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        Write-Host $ErrorMessage ' - Rolling back deployment'(($variables.helm.mainname)+'-'+$namerep)'...' -ForegroundColor Yellow
        #$ErrorMessage=""
        #helm delete --purge (($variables.helm.mainname)+'-'+$namerep)
        add-content ($variables.deploymentdoc+$date) " *** Failed on step $deplstep - $name *** "
        add-content ($variables.deploymentdoc+$date) $_.Exception.Message
        add-content ($variables.deploymentdoc+$date) "Deployment $name rolled back"
        add-content ($variables.deploymentdoc+$date) "Failed in $time min"
    }
}
function delete-resource-groups {
    try{
        $deplstep='Delete Resource Groups'
        '**Deleting resource groups. this might take some time, please be patient**'
        $sw = [diagnostics.stopwatch]::startnew()
        az group delete -n $variables.azure.resgroup --yes
        #az group delete -n $clusterresgroup --yes
        $sw.stop()
        $time=[math]::round($sw.elapsed.totalminutes, 2)
        $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
        'Successfully deleted resource groups '+$variables.azure.resgroup+' and '+$clusterresgroup+'. Elapsed time: '+$time+' min, total time: '+$totaltime+' min'
        add-content ($variables.deploymentdoc+$date) " - $deplstep : $time "
    }
    catch{ error-catch }
}
function delete-deployments {
    try{
        $deplstep='Delete all deployments'
        '**Deleting existing deployments**'
        $sw = [diagnostics.stopwatch]::startnew()
        "--deleting deployments"
        helm del $(helm ls --all --short) --purge
        "--deleting secrets"
        kubectl delete secrets --all
        $sw.stop()
        $time=[math]::round($sw.elapsed.totalminutes, 2)
        $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
        'Deployments deleted. Elapsed time: '+$time+' min, total time: '+$totaltime+' min'
        add-content ($variables.deploymentdoc+$date) " - $deplstep : $time"
    }
    catch{error-catch }
}
function delete-storage-account-files {
    try{
	    $deplstep='Delete Storage Account files'
	    '**Deleting storage account files**'
   	    $sw = [diagnostics.stopwatch]::startnew()
   	    $storagekey=$(az storage account keys list --resource-group $variables.azure.resgroup --account-name $variables.azure.storageacct --query "[0].value")
        $count=1
	    do{
		    az storage share delete --account-name $variables.azure.storageacct --account-key $storagekey --name $variables.storageacctfiles.Q10.$count | out-null
		    $count=$count+1
	    }while($count -le $variables.storageacctfiles.Q10.count)
        $count=1
	    do{
   		    az storage share delete --account-name $variables.azure.storageacct --account-key $storagekey --name $variables.storageacctfiles.Q20.$count | out-null
		    $count=$count+1
	    }while($count -le $variables.storageacctfiles.Q20.count)
        $count=1
	    do{
		    az storage share delete --account-name $variables.azure.storageacct --account-key $storagekey --name $variables.storageacctfiles.Q50.$count | out-null
		    $count=$count+1
	    }while($count -le $variables.storageacctfiles.Q50.count)
   	    $sw.stop()
   	    $time=[math]::round($sw.elapsed.totalminutes, 2)
   	    $totaltime=[math]::round($swtotal.elapsed.totalminutes, 2)
   	    'Files successfully deleted from storage account '+$variables.azure.storageacct+'. Elapsed time: '+$time+' min, total time: '+$totaltime+' min'
        add-content ($variables.deploymentdoc+$date) " - $deplstep : $time min"
    }
    catch{ error-catch }
}

function full-deployment {
    cls
    Write-Host($funcname) -ForegroundColor Yellow
    #code
        #start stopwatch
        $swtotal = [diagnostics.stopwatch]::startnew()
        #documentation - start
        documentation-start
        error-catch
        #variables
        #pick subscription
        pick_subscription_id
        #deploy all secrets
        info-box 'all' 'Do you want to deploy all secrets?' 'Secrets'
        #deploy using latest tags
        info-box 'latest' 'Do you want to use the latest tags?' 'Tags'
        #confirm the start
        info-box 'confirm' 'Are you ready?' ''
        if($confirm -eq 'n'){ $selectedsubscription;$all;$latest;break }
        $full='y'
        $local='y'  #only local deployments
        #deploy
        connect-to-subscription 'local'
        create-resource-group
        create-storage-account
        create-cluster
        create-storage-account-files
        create-public-ip
        modify-vnet-subnet
        create-application-gateway
        modify-app-gateway
        clone-git
        connect-to-kubernates-subscription 'local'
        #create-service-accounts
        helm-init-update
        secrets $all
        connect-to-kubernates-subscription 'payg'
        repository-tags $latest
        connect-to-kubernates-subscription 'local'
        deploy $full
        #stop time
        $swtotal.stop() ##total run time
        $totalelapsedtime=[math]::round($swtotal.elapsed.totalminutes, 2)
        #documentation - finish
        documentation-finish
    #code
    function-end
}
function redeployment {
    cls
    #code
        #start stopwatch
        $swtotal = [diagnostics.stopwatch]::startnew()
        #documentation - start
        documentation-start
        error-catch
        #variables
        #pick subscription
        pick_subscription_id
        #deploy all secrets
        info-box 'all' 'Do you want to deploy all secrets?' 'Secrets'
        #deploy using latest tags
        info-box 'latest' 'Do you want to use the latest tags?' 'Tags'
        #deploy individual deployments
        info-box 'full' 'Do you want to run a full deployment (all charts)?' 'Deployment'
        #confirm the start
        info-box 'confirm' 'Are you ready?' ''
        if($confirm -eq 'n'){ "subscription $selectedsubscription"; "secrets $all"; "tags $latest"; "deployment $full";break }
        $local='y'  #only local deployments
        #deploy
        #check if any resource group exists
        if((az group list -o tsv) -eq $null)
        {
            info-box 'full' 'There are no resource groups linked to this subscription. Do you want to run a full deployment?' 'No Resource Group'
            if($full -eq 'y')
            {
                $funcname='Full Deployment'
                connect-to-subscription 'local'
                create-resource-group
                create-storage-account
                create-cluster
                create-storage-account-files
                create-public-ip
                modify-vnet-subnet
                create-application-gateway
                modify-app-gateway
                clone-git
                #create-service-accounts
                helm-init-update
                secrets $all
                connect-to-kubernates-subscription 'payg'
                repository-tags $latest
                connect-to-kubernates-subscription 'local'
                deploy $full
                #stop time
                $swtotal.stop() ##total run time
                $totalelapsedtime=[math]::round($swtotal.elapsed.totalminutes, 2)
                #documentation - finish
                documentation-finish
            }
            if($full -eq 'n'){ Write-Host('User selected No, deployment will not completed.') -ForegroundColor Yellow; timeout /t 5; main }
        }
        connect-to-subscription 'local'
        clone-git
        secrets $all
        connect-to-kubernates-subscription 'payg'
        repository-tags $latest
        connect-to-kubernates-subscription 'local'
        deploy $full
        #stop time
        $swtotal.stop() ##total run time
        $totalelapsedtime=[math]::round($swtotal.elapsed.totalminutes, 2)
        #documentation - finish
        documentation-finish
    #code
    function-end
}
function run-individual-deployments {
    cls
    Write-Host($funcname) -ForegroundColor Yellow
    #code
        #start stopwatch
        $swtotal = [diagnostics.stopwatch]::startnew()
        #documentation - start
        documentation-start
        error-catch
        #variables
        #pick subscription
        pick_subscription_id
        #deploy using latest tags
        info-box 'latest' 'Do you want to use the latest tags?' 'Tags'
        connect-to-kubernates-subscription 'payg'
        repository-tags $latest
        connect-to-kubernates-subscription 'local'
        deploy 'n'
        #stop time
        $swtotal.stop() ##total run time
        $totalelapsedtime=[math]::round($swtotal.elapsed.totalminutes, 2)
        #documentation - finish
        documentation-finish
    #code
    function-end
}
function delete-environment {
    #start stopwatch
    $swtotal = [diagnostics.stopwatch]::startnew()
    cls
    Write-Host($funcname) -ForegroundColor Yellow
    #code
        info-box 'confirm' 'Deletion can NOT be undone, and should not be stopped. Do you want to proceed?' 'DELETE WHOLE DEPLOYMENT'
        if ($confirm -eq 'n') { Write-Host('User selected No, deployment will not be deleted.') -ForegroundColor Yellow; timeout /t 5; function-end }
        #documentation - start
        documentation-start
        error-catch
        #variables
        #pick subscription
        pick_subscription_id
        connect-to-kubernates-subscription 'local'
        delete-deployments
        delete-storage-account-files
        delete-resource-groups
    #code
    function-end
} 
function delete-deployment {
    #start stopwatch
    $swtotal = [diagnostics.stopwatch]::startnew()
    cls
    Write-Host($funcname) -ForegroundColor Yellow
    #code
        documentation-start
        error-catch
        #variables
        #pick subscription
        pick_subscription_id
        connect-to-kubernates-subscription 'local'
        delete-deployments
    #code
    function-end
}
function change-variables {
    cls
    Write-Host($funcname) -ForegroundColor Yellow
        
        #code
        $MyInvocation.MyCommand.Path
        $content_variables=Get-Content $variables.var_test4.test5
        $linenumbervar = ($content_variables | Select-String -Pattern 'declared variables' | Select-Object -ExpandProperty 'LineNumber')[0]
        for($i=0;$i -le $variables.Count;$i++)
	    { $variables[$i] }
        #{$content_variables[($linenumbervar)+($i+1)]}

        #code

    function-end
    }
function pick_subscription_id {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Select a Subscription'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(75,120)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = 'OK'
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(150,120)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Please select a subscription:'
    $form.Controls.Add($label)

    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(260,20)
    $listBox.Height = 80

    $idlist=@()
    $idlist+=($variables.subscriptions.local.id).keys

    $i=0
    do{
        [void] $listBox.Items.Add($idlist[$i])
        $i++
    }while($i -lt ($variables.subscriptions.local.id).Count)
    
    $form.Controls.Add($listBox)

    $form.Topmost = $true

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $script:x = $listBox.SelectedItem
        $script:selectedsubscription=$variables.subscriptions.local.id.$x
    }
} #$selectedsubscription have the selected id
function function-end {
    cls
    Write-Host($funcname)
    Write-Host('Would you like to go (b)ack or (q)uit? ') -ForegroundColor Yellow -NoNewline
    $choice=$null
    if ($host.Name -ne 'Windows PowerShell ISE Host'){
        $choice=$Host.UI.RawUI.ReadKey()
        if($choice.Character -eq 'b'){ main }
        if($choice.Character -eq 'q'){ quit }
    }
    elseif($host.Name -eq 'Windows PowerShell ISE Host'){
        $choice = Read-Host
        while('b','q' -notcontains $choice ) {
            &($func)
        }
        if($choice -eq '1'){ main }
        if($choice -eq 'q'){ quit }
    }
}
function info-box($var, $msg, $title) {
    Add-Type -AssemblyName PresentationFramework
    $option=[System.Windows.MessageBox]::Show($msg, $title,'YesNo','Info')
    if ($option -eq 'Yes'){ $script:get='y' }
    if ($option -eq 'No'){ $script:get='n' }
    if ((Test-Path variable:global:idontexist) -ne $false) { Clear-Variable -Name $var }
    Set-Variable -Name $var -Value $get -Scope script
}
function quit {
    Add-Type -AssemblyName PresentationFramework
    $quit=[System.Windows.MessageBox]::Show('Do you want to quit?','Quit?','YesNo','Warning')
    switch  ($quit) { 'Yes' {
        cls
        Write-Host('Have a nice day!') -ForegroundColor Yellow
	    break 
        }
    'No' { cls; &($func) }
    }
}
function main {
    cls
    Write-Host('           Platform Deployment Tool') -ForegroundColor Yellow
    Write-Host('          ==========================') -ForegroundColor Red
    Write-Host('')
    Write-Host('What would you like to do today?') -ForegroundColor Yellow
    Write-Host('')
    Write-Host(' 1) Full Deployment')
    Write-Host(' 2) Redeployment')
    Write-Host(' 3) Run Individual Deployments')
    Write-Host(' 4) Delete a Deployment')
    Write-Host('')
    Write-Host(' 5) Delete the entire Environment') -ForegroundColor Yellow
    Write-Host('')
    Write-Host(' 6) Change variables')
    Write-Host('--------------------------------')
    Write-Host('Pick a number, or (q)uit: ') -NoNewLine
    $choice=$null
	if ($host.Name -ne 'Windows PowerShell ISE Host'){
        $choice=$Host.UI.RawUI.ReadKey()
        if($choice.Character -eq '1'){ $funcname='Full Deployment'; $func='function-end'; full-deployment }
        if($choice.Character -eq '2'){ $funcname='Redeployment'; $func='function-end';  redeployment }
        if($choice.Character -eq '3'){ $funcname='Run Individual Deployments'; $func='function-end';  run-individual-deployments }
        if($choice.Character -eq '4'){ $funcname='Delete a Deployment'; $func='delete-deployment';  delete-deployment }
        if($choice.Character -eq '5'){ $funcname='Delete an Environment'; $func='delete-environment';  delete-environment }
        if($choice.Character -eq '6'){ $funcname='Change Variables'; $func='function-end';  change-variables }
        if($choice.Character -eq 'q'){ $funcname='Quit'; $func='main';  quit }
    }
    elseif($host.Name -eq 'Windows PowerShell ISE Host'){
        $choice = Read-Host
        while('1','2','3','4','5','q' -notcontains $choice ) {
            main
        }
        if($choice -eq '1'){ $funcname='Full Deployment'; $func='full-deployment'; full-deployment }
        if($choice -eq '2'){ $funcname='Redeployment'; $func='redeployment';  redeployment }
        if($choice -eq '3'){ $funcname='Run Individual Deployments'; $func='run-individual-deployments';  run-individual-deployments }
        if($choice -eq '4'){ $funcname='Delete a Deployment'; $func='delete-deployment';  delete-deployment }
        if($choice -eq '5'){ $funcname='Change Variables'; $func='change-variables';  change-variables }
        if($choice -eq 'q'){ $funcname='Quit'; $func='quit';  quit }
    }
}
function Get-ODBCData{  
    param(
          [string]$query,
          [string]$dbServer = "platform-postgres.postgres.database.azure.com",   # DB Server (either IP or hostname)
          [string]$dbName   = "telemetrydb",                                     # Name of the database
          [string]$dbUser   = "platformAdmin@platform-postgres",                 # User we'll use to connect to the database/server
          [string]$dbPass   = '@uTo8Ot$PR1m3'                                    # Password for the $dbUser
         )

    $conn = New-Object System.Data.Odbc.OdbcConnection
    $conn.ConnectionString = "Driver={PostgreSQL Unicode(x64)};Server=$dbServer;Port=5432;Database=$dbName;Uid=$dbUser;Pwd=$dbPass;sslmode=require;"
    $conn.open()
    $cmd = New-object System.Data.Odbc.OdbcCommand($query,$conn) 
    $ds = New-Object system.Data.DataSet
    (New-Object system.Data.odbc.odbcDataAdapter($cmd)).fill($ds) | Out-Null 
    $conn.close()
    Return ,$ds.Tables[0]
}
function database-checks {
    Context "Check kafka-rest connection" {
        try{
            $pass='y'
            $passmsg="  kafka-rest connection - Passed"
            kubectl exec -it kafka-rest-0 curl localhost:8082/healthz | should be '{"error_code":404,"message":"HTTP 404 Not Found"}'
        }
        catch{
            $pass='n'
            $ErrorMessage = $_.Exception.Message
            Write-Host "  kafka-rest connection - FAILED" -ForegroundColor Red
            Write-Host $ErrorMessage -ForegroundColor Yellow
        }
        if($pass -eq 'y'){Write-Host $passmsg -ForegroundColor Green}
    }

     Context "Check kafka-rest service connection" {
        try{
            $pass='y'
            $passmsg="  kafka-rest service connection - Passed"
            kubectl exec -it kafka-rest-0 curl kafka-rest-0.kafka-rest-hs.default.svc.cluster.local:8082/test | should be '{"error_code":404,"message":"HTTP 404 Not Found"}'
        }
        catch{
            $pass='n'
            $ErrorMessage = $_.Exception.Message
            Write-Host "  kafka-rest service connection - FAILED" -ForegroundColor Red
            Write-Host $ErrorMessage -ForegroundColor Yellow
        }
        if($pass -eq 'y'){Write-Host $passmsg -ForegroundColor Green}
    }
}
function checks {
    Context "Check kafka-rest connection" {
        try{
            $pass='y'
            $passmsg="  kafka-rest connection - Passed"
            kubectl exec -it kafka-rest-0 curl localhost:8082/healthz | should be '{"error_code":404,"message":"HTTP 404 Not Found"}'
        }
        catch{
            $pass='n'
            $ErrorMessage = $_.Exception.Message
            Write-Host "  kafka-rest connection - FAILED" -ForegroundColor Red
            Write-Host $ErrorMessage -ForegroundColor Yellow
        }
        if($pass -eq 'y'){Write-Host $passmsg -ForegroundColor Green}
    }

     Context "Check kafka-rest service connection" {
        try{
            $pass='y'
            $passmsg="  kafka-rest service connection - Passed"
            kubectl exec -it kafka-rest-0 curl kafka-rest-0.kafka-rest-hs.default.svc.cluster.local:8082/test | should be '{"error_code":404,"message":"HTTP 404 Not Found"}'
        }
        catch{
            $pass='n'
            $ErrorMessage = $_.Exception.Message
            Write-Host "  kafka-rest service connection - FAILED" -ForegroundColor Red
            Write-Host $ErrorMessage -ForegroundColor Yellow
        }
        if($pass -eq 'y'){Write-Host $passmsg -ForegroundColor Green}
    }
}

create-resource-group
create-storage-account
create-cluster
create-storage-account-files
create-public-ip
modify-vnet-subnet
create-application-gateway
modify-app-gateway
clone-git
connect-to-kubernates-subscription($sub='local')
create-service-accounts
helm-init-update
secrets($all='y')
az logout --username felipe.fedozzi@3esi-enersight.com
login aucerna
connect-to-kubernates-subscription($sub='payg')
repository-tags($latest='y')
az logout --username felipe.fedozzi@aucerna.com
login 3esi
connect-to-kubernates-subscription($sub='local')
deploy($full='n')