<#
TODO

More testing
test multiple users same report
test both domains
switch to live data (no more clixml import)
switch to not UAT SD
Email everyone not just me
#>

#Setup "globals"
$link = "https://portal.azure.com/#blade/Microsoft_AAD_IAM/RiskDetectionsBlade/userId/{0}/detectionTimeRangeType/last90days"
$lastweek = (Get-Date).AddDays(-1).ToString("o")
$list = [System.Collections.Generic.List[PSCustomobject]]::new()
$more = $true

#Disable user AD Account, add reason to accounts description
Function DisableAccount($upn) 
{
        $filter = "UserPrincipalName -eq '{0}'" -f $upn    
        $aduser = Get-ADUser -Filter $filter -Server [redacted]:3268 -Properties UserPrincipalName,Description,ObjectGUID 

        if($aduser -ne "" -and $aduser -ne $null)
        {
            $desc = $aduser.Description + "(Disabled Due to Azure risk detection)"
            $server = ($aduser.DistinguishedName.Substring($aduser.DistinguishedName.IndexOf("DC="))).replace(",",".").replace("DC=","")

            Set-ADUser $aduser -Description $desc -Server $server  
            Disable-ADAccount $aduser -Server $server 
        }
} 

#Create HEAT incident via C# and return the incident number for the report 
Function CreateINC($upn) 
{  
    $incidentnumber = ..\FactFindHEATUAT\FactFindHEATUAT\bin\Debug\FactFindHEATUAT.exe $upn
    return $incidentnumber
}

#Process risky users
Function ProcessData() {   
    #setup email body
    $body = "<h3>Azure Security Report For "+(Get-Date).ToLongDateString()+":</h3>"
    $encodedapilink = 'https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$orderby=detectedDateTime desc&$filter=riskLevel eq ' + "'high'" + "and detectedDateTime ge $lastweek"

    while($more)
    {
        #Uncomment for live data, otherwise will use exported test data
        $data = Invoke-RestMethod -Uri $encodedapilink -Headers $Headers | Select '@odata.context','@odata.nextLink',value         
	#$data = Import-Clixml  '.\TestData(LEARNING).xml'
        
        foreach($alert in $data.value)
        {       
           $body += "<h4>"+"<u>"+(Get-Date ($alert.detectedDateTime)).ToLongDateString()+" ("+(Get-Date ($alert.detectedDateTime)).ToLongTimeString()+")"+"</u>"+"</h4>"
           $body += "<b>"+"&nbsp"+"User: "+"</b>"+$alert.userPrincipalName+"<br />"
           $body += "<b>"+"&nbsp"+"Risk Level: "+"</b>"+$alert.riskLevel+"<br />"
           $body += "<b>"+"&nbsp"+"Risk Activity: "+"</b>"+$alert.activity+"<br />"
           $body += "<b>"+"&nbsp"+"Risk Type: "+"</b>"+$alert.riskEventType+"<br />"  
  
           if($alert.ipAddress -ne $null)
           {
                $body += "<b>"+"&nbsp"+"IP Address: "+"</b>"+$alert.ipAddress+"<br />"
           }

           if($alert.location -ne $null)
           {
                $body += "<b>"+"&nbsp"+"Location: "+"</b>"+$alert.location.city+", "+$alert.location.state+", "+$alert.location.countryOrRegion+"<br />"
           }
           
           $inc =""
           $inc = CreateINC($alert.userPrincipalName)
           $body += "<b>"+"&nbsp"+"Incident Number: "+"</b>"+$inc+"<br />" 
		   
		   #Include link to specific users risk report	
           $body += "&nbsp"+("<a href=`"https://portal.azure.com/#blade/Microsoft_AAD_IAM/RiskDetectionsBlade/userId/{0}/detectionTimeRangeType/last90days`">View Users Risk History</a>" -f $alert.userId)+"<br />"    
           $body += "<br /><br />"

           $list.Add($alert.userPrincipalName)
           DisableAccount($alert.userPrincipalName)
        }

        if($data.'@odata.nextLink' -eq $null -or $data.'@odata.nextLink' -eq "")
        {
            $more = $false
        }
        else 
        {           
            $encodedapilink = [System.Web.HttpUtility]::UrlDecode($data.'@odata.nextLink')
        }
    }
    return $body 
}
#Put together tenant info and request auth token
$reqBody = @{
    'tenant' = [redacted]
    'client_id' = [redacted]
    'scope' = 'https://graph.microsoft.com/.default'
    'client_secret' = [redacted]
    'grant_type' = 'client_credentials'
}

$Params = @{
    'Uri' = "https://login.microsoftonline.com/bd79c313-cdf7-458e-aaf9-06e1d7fd1889/oauth2/v2.0/token"
    'Method' = 'Post'
    'Body' = $reqBody
    'ContentType' = 'application/x-www-form-urlencoded'
}

$AuthResponse = Invoke-RestMethod @Params

$Headers = @{
    'Authorization' = "Bearer $($AuthResponse.access_token)"
}

#run the function and build the body
$emailbody = ProcessData

#Only send report if there's something to send!
if($list.Count -gt 0)
{      
    Send-MailMessage -BodyAsHtml -Priority High -SmtpServer [redacted] -From [redacted] -To [redacted] -Subject "Azure Security Report" -Body $emailbody
}

