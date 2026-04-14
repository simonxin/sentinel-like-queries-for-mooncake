
$exportpath = "C:\GitHub\Sentinalinsights"
$querypackfile_backup = "C:\GitHub\sentinel-like-queries-for-mooncake\template\securityquerypack_oringal.json"
$querypackfile = "C:\GitHub\sentinel-like-queries-for-mooncake\template\securityquerypack.json"


##################

# load the rule definition
$orignaldetection  = import-csv $exportpath\query\detectionquery.csv
$orignalhunting = import-csv $exportpath\query\huntingquery.csv

$related = [PSCustomObject]@{
    categories = @('security')
    resourceTypes = @('microsoft.operationalinsights/workspaces')
}

# update querypack: 
if (test-path $querypackfile) {
    # make a backup of original query pack.
      copy-item  -Destination $querypackfile_backup -path $querypackfile -force

      $templateobj = get-content $querypackfile | convertfrom-json

    # get last ruleId index (use guid() instead of newGuid() params to stay under ARM 256-param limit)
      $existingNames = $templateobj.resources | ForEach-Object { $_.name }
      $ruleIndices = $existingNames | ForEach-Object {
          if ($_ -match "guid\(resourceGroup\(\)\.id,\s*'rule(\d+)'\)") { [int]$Matches[1] }
      } | Where-Object { $_ -ne $null }
      $lastindex = if ($ruleIndices) { ($ruleIndices | Sort-Object | Select-Object -Last 1) + 1 } else { 1 }

    foreach ($detectionrule in $orignaldetection) {
      
       $rulename = $detectionrule.name
       $description = $detectionrule.description.trimstart("'").trimend("'").replace('"',"'")
       $source = $detectionrule.source
       $category = $detectionrule.category
       $severity = $detectionrule.severity
       $query = $detectionrule.query.trim()
       $supported = $detectionrule.supported
       $queryFrequency = $detectionrule.queryFrequency
       $queryPeriod =  $detectionrule.queryPeriod
       $type = 'Detection'
      

       $hasrule = $templateobj.resources | where {$_.properties.displayName -like $rulename}

       if ($hasrule) {
            # update existing rules
            write-host "processing rule: $rulename"
            $enabled = 'true'
            if ($hasrule.properties.properties.type -eq $type) {
                $hasrule.properties.properties = [PSCustomObject]@{
                    enabled = $enabled
                    type = $type
                    severity = $severity
                    category = $category
                    source = $source
                    queryFrequency = $queryFrequency
                    queryPeriod = $queryPeriod
                }


           } else {
                write-warning "duplicate rule name existing with different type. Rulename: $rulename"
           }

        } else {
            # add new rules if the query is marked as supported
            # add fully supported rule directly
            if ($supported -eq 'yes') {
                write-host "Add new rule: $rulename"
                $enabled = 'true'

                $templateobj.resources += [PSCustomObject]@{
                    
                    type = "Microsoft.OperationalInsights/querypacks/queries"
                    apiVersion = "2019-09-01-preview"
                    name = "[concat(parameters('querypacks_sentinel_like_security_queries_name'), '/', guid(resourceGroup().id, 'rule$lastindex'))]" 
                    dependsOn  = @("[resourceId('Microsoft.OperationalInsights/querypacks', parameters('querypacks_sentinel_like_security_queries_name'))]")
                    properties = [PSCustomObject]@{
                        displayName = $rulename
                        description = $description
                        body = $query

                        properties = [PSCustomObject]@{
                            enabled = $enabled
                            type = $type
                            severity = $severity
                            category = $category
                            source = $source
                            queryFrequency = $queryFrequency
                            queryPeriod = $queryPeriod               
                        }
                        related = $related 

                    }
                     
                }

                $lastindex = $lastindex+1

            } elseif ($supported -eq 'partial') {
                write-warning "rules are set as partial. Please review definition of $rulename and verify if it can be customized as well."
                
            } else {
                write-warning "rules are set as no support. Please review definition of $rulename."

            }


        }

    }

    
    foreach ($huntingrule in $orignalhunting) {
        $rulename = $huntingrule.name
        $description = $huntingrule.description.trimstart("'").trimend("'").replace('"',"'")
        $source = $huntingrule.table
        $category = $huntingrule.category
        $query = $huntingrule.query.trim()
        $supported = $huntingrule.supported
        $type = 'Hunting'
       
 
        $hasrule = $templateobj.resources | where {$_.properties.displayName -like $rulename}
 
        if ($hasrule) {
             # update existing rules
             write-host "processing rule: $rulename"
             if ($hasrule.properties.properties.type -eq $type) {
                 $enabled = 'true'
                 $hasrule.properties.properties = [PSCustomObject]@{
                     enabled = $enabled
                     type = $type
                     category = $category
                     source = $source
                 }


            } else {
                 write-warning "duplicate rule name existing with different type. Rulename: $rulename"
            }
 
         } else {
             # add new rules if the query is marked as supported
             # add fully supported rule directly
             
             if ($supported -eq 'yes') {
                write-host "Add new rule: $rulename"
                 $enabled = 'true'

                 $templateobj.resources += [PSCustomObject]@{
                     
                     type = "Microsoft.OperationalInsights/querypacks/queries"
                     apiVersion = "2019-09-01-preview"
                     name = "[concat(parameters('querypacks_sentinel_like_security_queries_name'), '/', guid(resourceGroup().id, 'rule$lastindex'))]" 
                     dependsOn  = @("[resourceId('Microsoft.OperationalInsights/querypacks', parameters('querypacks_sentinel_like_security_queries_name'))]")
                     properties = [PSCustomObject]@{
                         displayName = $rulename
                         description = $description
                         body = $query
 
                         properties = [PSCustomObject]@{
                             enabled = $enabled
                             type = $type
                             category = $category
                             source = $source
                         }
                         related = $related 
 
                     }
                      
                 }
 
                 $lastindex = $lastindex+1
 
             } elseif ($supported -eq 'partial') {
                 write-warning "rules are set as partial. Please review definition of $rulename and verify if it can be customized as well."
                 
             } else {
                 write-warning "rules are set as no support. Please review definition of $rulename."
 
             }
 
 
         }
 
     }

}

$templatecontent=$templateobj | convertto-json -depth 20
$templatecontent = $templatecontent.replace("\u0027","'").replace("\u003e",">").replace("\u003c","<").replace("\u0026","&")

$templatecontent | out-file -Encoding UTF8 $querypackfile
Write-Host "`nQuery pack updated: $querypackfile"