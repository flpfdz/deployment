$app = @( 'grafana', 'prometheus', 'kafka-rest' )

function global:port-forward($app) {
    $ErrorActionPreference = "Stop"
    
    [int]$i=0
    if($app.Count -lt 2){
        try{
            $namespace = iex ("((kubectl get pods -l 'app={0}app' --all-namespaces) -like '*{0}*').split(' ')[0]" -f $app)
            $podName = iex ("((kubectl get pods -l 'app={0}app' -n {1}) -like '*{0}*').split(' ')[0]" -f $app,$namespace)
        }
        catch{
            $namespace = iex ("((kubectl get pods -l 'app={0}' --all-namespaces -o wide) -like '*{0}*').split(' ')[0]" -f $app)
            $podName = iex ("((kubectl get pods -l 'app={0}' -n {1}) -like '*{0}*').split(' ')[0]" -f $app,$namespace)
        }
    
        $describe = kubectl describe pod $podName -n $namespace
        $port = (($describe -like '*port:*/TCP*')[0].Split('/')[0] | Foreach-Object { $_ -replace 'port:', '' }) | Foreach-Object { $_ -replace ' ', '' }
        $url="http://localhost:$port"
        $name=$app.ToUpper()
        start-process powershell.exe -argument "-noexit -command `$host.ui.RawUI.WindowTitle = '$name PORT-FORWARD'; kubectl port-forward $podName $port`:$port -n $namespace"
        
        Start-Sleep -s 2

        start-Process -FilePath Chrome -ArgumentList "--new-window $url"
    }
    else{
        do{
            try{
                $namespace = iex ("((kubectl get pods -l 'app={0}app' --all-namespaces) -like '*{0}*').split(' ')[0]" -f $app[$i])
                $podName = iex ("((kubectl get pods -l 'app={0}app' -n {1}) -like '*{0}*').split(' ')[0]" -f $app[$i],$namespace)
            }
            catch{
                $namespace = iex ("((kubectl get pods -l 'app={0}' --all-namespaces -o wide) -like '*{0}*').split(' ')[0]" -f $app[$i])
                $podName = iex ("((kubectl get pods -l 'app={0}' -n {1}) -like '*{0}*').split(' ')[0]" -f $app[$i],$namespace)
            }
    
            $describe = kubectl describe pod $podName -n $namespace
            $port = (($describe -like '*port:*/TCP*')[0].Split('/')[0] | Foreach-Object { $_ -replace 'port:', '' }) | Foreach-Object { $_ -replace ' ', '' }
            $url="http://localhost:$port"
            $name=$app[$i].ToUpper()
            start-process powershell.exe -argument "-noexit -command `$host.ui.RawUI.WindowTitle = '$name PORT-FORWARD'; kubectl port-forward $podName $port`:$port -n $namespace"

            Start-Sleep -s 2

            start-Process -FilePath Chrome -ArgumentList "--new-window $url"
            $i++
        }while($i -lt $app.Count)
    }
}

port-forward($app='prometheus')