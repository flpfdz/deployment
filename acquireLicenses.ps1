$realm = 'TestRealm'
$count=1
$url="https://"+(az network public-ip list -g (az group list --query "[?contains(name, 'MC')].name" -o tsv) --query "[?contains(dnsSettings.fqdn, 'keycloak')].dnsSettings.fqdn" -o tsv)+"/auth/"

function check-url {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $HTTP_Request = [System.Net.WebRequest]::Create($url)
    $HTTP_Response = $HTTP_Request.GetResponse()
    $HTTP_Status = [int]$HTTP_Response.StatusCode
    $HTTP_Response.Close()
    Context "check-url" {
        try{
            $passed='y'
            $HTTP_Status | should be 200
        }
        catch{
            $passed='n'
            Write-Host $_.Exception.Message
            
            Write-Host('URL is invalid')
            break
        }
        if ($passed -eq 'y') { Write-Host('   URL '+ $url +' is valid') -ForegroundColor Green }
    }
}

