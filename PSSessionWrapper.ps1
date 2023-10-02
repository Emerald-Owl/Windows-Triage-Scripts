
# inline execution
# If you just want to send a ps1 script. If youre using a module, youll also need to call the function after
# you only need the credential if youre not using your local account 

$computerName = ""
$scriptPath = ""
$credentials = Get-Credential
$session = Enter-Pssession -ComputerName $computerName -Credential $credentials
$scriptContent = Get-Content -Path $scriptPath -Raw

Invoke-Command -Session $session -ScriptBlock{
    Invoke-Expression $using:scriptContent
}

Exit-PSSession $session







