$url="http://localhost:8082"
$inputFile="query-values.json"
$outputFile="query-results.json"
$jsonFile = Get-Content $inputFile | Out-String | ConvertFrom-Json

function get-query-data {
    Write-Host($inputFile)
    Write-Host(" Realm: ")$jsonFile.partitionId.realm
    Write-Host(" Namespace: ")$jsonFile.partitionId.namespace
    Write-Host(" Kind: ")$jsonFile.kinds
    Write-Host(" Attributes: ")$jsonFile.attributes
    $i=0
    do{
        '  Filter '+($i+1)+': '+$jsonFile.filter.filters[$i].filterType+' '+$jsonFile.filter.filters[$i].attribute+' '+$jsonFile.filter.filters[$i].value.s
        $i++
    }while($i -lt $jsonFile.filter.filters.Count )
    Write-Host(" Filter Type: ")$jsonFile.filter.filterType
    Write-Host(" Projection Type: ")$jsonFile.periods.projectionType
    $i=0
    do{
        '  Order By: ' + $jsonFile.orderBy[$i].attribute
        $i++
    }while($i -lt $jsonFile.orderBy.Count )
}
function change-query-data {
        $tabName = "FilterTypeTable"
                
        #Create Table object
        $table = New-Object system.Data.DataTable “$tabName”
                
        #Define Columns
        $col1 = New-Object system.Data.DataColumn Type,([string])
        $col2 = New-Object system.Data.DataColumn Properties,([string])
        $col3 = New-Object system.Data.DataColumn Description,([string])
                
        #Add the Columns
        $table.columns.add($col1)
        $table.columns.add($col2)
        $table.columns.add($col3)

        #Create a rows
        #Line 1
        $row1 = $table.NewRow()
        $row1.Type = "or"
        $row1.Properties = "filters" 
        $row1.Description = "Tests if any of the child filters are met"
        $table.Rows.Add($row1)
        #Line 2
        $row2 = $table.NewRow()
        $row2.Type = "and" 
        $row2.Properties = "filters" 
        $row2.Description = "Tests if all of the child filters are met"
        $table.Rows.Add($row2)
        #Line 3
        $row3 = $table.NewRow()
        $row3.Type = "not" 
        $row3.Properties = "filter" 
        $row3.Description = "Negates the result of the child filter"
        $table.Rows.Add($row3)
        #Line 4
        $row4 = $table.NewRow()
        $row4.Type = "in"
        $row4.Properties = "attribute,value"
        $row4.Description = "Tests if the attribute value equals any of the specified values"
        $table.Rows.Add($row4)
        #Line 5
        $row5 = $table.NewRow()
        $row5.Type = "equals" 
        $row5.Properties = "attribute,value  " 
        $row5.Description = "Tests if the attribute value equals the specified value"
        $table.Rows.Add($row5)
        #Line 6
        $row6 = $table.NewRow()
        $row6.Type = "greaterThan"
        $row6.Properties = "attribute,value"
        $row6.Description = "Tests if the attribute value is greater than the specified value"
        $table.Rows.Add($row6)
        #Line 7
        $row7 = $table.NewRow()
        $row7.Type = "greaterThanOrEquals  " 
        $row7.Properties = "attribute,value" 
        $row7.Description = "Tests if the attribute value is greater than or equal to the specified value"
        $table.Rows.Add($row7)
        #Line 8
        $row8 = $table.NewRow()
        $row8.Type = "lessThan"
        $row8.Properties = "attribute,value"
        $row8.Description = "Tests if the attribute value is less than the specified value"
        $table.Rows.Add($row8)
        #Line 9
        $row9 = $table.NewRow()
        $row9.Type = "lessThanOrEquals" 
        $row9.Properties = "attribute,value" 
        $row9.Description = "Tests if the attribute value is less than or equal to the specified value"
        $table.Rows.Add($row9)
        #Line 10
        $row10 = $table.NewRow()
        $row10.Type = "isEmpty"
        $row10.Properties = "attribute"
        $row10.Description = "Tests if the attribute has no specified value (null)"
        $table.Rows.Add($row10)
        #Line 11
        $row11 = $table.NewRow()
        $row11.Type = "matchesKey" 
        $row11.Properties = "key" 
        $row11.Description = "Tests if the entity is for the specified key"
        $table.Rows.Add($row11)
        #Line 12
        $row12 = $table.NewRow()
        $row12.Type = "hasAncestor"
        $row12.Properties = "key"
        $row12.Description = "Tests if the entity has the specified key as one of its ancestors"
        $table.Rows.Add($row12)

        $table | format-table -AutoSize
        
}

cd ~\documents\cdm-query
.\Cdm.QueryRunner -u $url -i $inputFile -o $outputFile -v

get-query-data