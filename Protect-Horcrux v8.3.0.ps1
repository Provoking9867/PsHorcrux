<#
.SYNOPSIS
    Secure file protection via Shamir's Secret Sharing (0x11D) and AES-256-CBC.
.DESCRIPTION
    v8.3: STRICT INPUT VALIDATION UI.
    - Replaced multiline text box with dynamically generated, strictly bound $k shard fields.
    - Added Regex character locks, index deduplication, and empty field blocking.
    - Replaced third-party AForge libraries with native Windows Camera app workflow.
    - SSSS standard polynomial 0x11D with strict lowercase hex formatting.
    - Fully inlined Horner's Method and Fractional Lagrange Accumulation.
    - DoD 5220.22-M 3-Pass Secure Shredder with Subfolder cleanup.
    - Recursive Manifest Integrity (Vault_Manifest.txt).
.NOTES
    Working Folder: %HOMEDRIVE%%HOMEPATH%\horcrux
#>

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# --- 1. THE HARD-GATE VALIDATION ---
$ScriptPath = $MyInvocation.MyCommand.Path
$HashFile = "$ScriptPath.sha256"
if (!(Test-Path $HashFile)) { [Windows.Forms.MessageBox]::Show("CRITICAL: .sha256 missing.", "Integrity Error"); exit }
$Global:CurrentHash = (Get-FileHash $ScriptPath -Algorithm SHA256).Hash
if ($Global:CurrentHash -ne (Get-Content $HashFile).Trim()) { [Windows.Forms.MessageBox]::Show("TAMPER DETECTED", "Security Error"); exit }

# --- 2. CONFIG & DEPENDENCIES ---
$WorkDir = Join-Path $env:HOMEDRIVE$env:HOMEPATH "horcrux"
if (!(Test-Path $WorkDir)) { New-Item $WorkDir -ItemType Directory | Out-Null }
$WordlistPath = Join-Path $WorkDir "eff_large_wordlist.txt"

function Find-OpenSSL {
    $Paths = @(
        "openssl",
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\Program Files\OpenSSL\bin\openssl.exe",
        "C:\Windows\System32\openssl.exe"
    )
    foreach ($p in $Paths) { 
        if (Get-Command $p -ErrorAction SilentlyContinue) { return $p } 
    }
    [Windows.Forms.MessageBox]::Show("OpenSSL not found. Please install OpenSSL and ensure it is in your PATH.", "Missing Dependency")
    return $null
}

function Import-Libraries {
    $Libs = @{ 
        "zxing.dll"="https://www.nuget.org/api/v2/package/ZXing.Net/0.16.9"
    }
    foreach ($Dll in $Libs.Keys) {
        $Path = Join-Path $WorkDir $Dll
        if (!(Test-Path $Path)) {
            $Zip = Join-Path $WorkDir "temp.zip"; Invoke-WebRequest $Libs[$Dll] -OutFile $Zip
            Expand-Archive $Zip -DestinationPath (Join-Path $WorkDir "temp_dir") -Force
            Get-ChildItem (Join-Path $WorkDir "temp_dir") -Filter $Dll -Recurse | Select-Object -First 1 | Move-Item -Destination $Path -Force
            Remove-Item (Join-Path $WorkDir "temp_dir") -Recurse -Force; Remove-Item $Zip -Force
        }
        Add-Type -Path $Path
    }
}

# --- 3. SSSS MATH ENGINE (GF 2^8 - SSSS Standard 0x11D) ---
$Global:EXP = New-Object Byte[] 512
$Global:LOG = New-Object Byte[] 256
$x = 1
for ($i = 0; $i -lt 255; $i++) { 
    $Global:EXP[$i] = [byte]$x
    $Global:LOG[$x] = [byte]$i
    
    $x = $x -shl 1
    if ($x -band 0x100) { $x = $x -bxor 0x11D } 
}
for ($i = 255; $i -lt 512; $i++) { $Global:EXP[$i] = $Global:EXP[$i - 255] }

# --- 4. SHREDDER ENGINE (DoD 5220.22-M) ---
function Invoke-SecureShred {
    param($Target, $ProgressBar)
    $isDir = Test-Path $Target -PathType Container
    $files = if ($isDir) { Get-ChildItem $Target -Recurse -File } else { Get-Item $Target }
    
    $fileCount = @($files).Count
    if ($ProgressBar -and $fileCount -gt 0) { $ProgressBar.Maximum = $fileCount * 3; $ProgressBar.Value = 0 }
    
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $buf = New-Object Byte[] 4096
    
    if ($fileCount -gt 0) {
        foreach ($f in $files) {
            $stream = [System.IO.File]::OpenWrite($f.FullName); $len = $stream.Length
            for ($pass=0; $pass -lt 3; $pass++) {
                $stream.Position = 0; $written = 0
                while ($written -lt $len) {
                    $rng.GetBytes($buf); $toWrite = [System.Math]::Min($buf.Length, $len - $written)
                    $stream.Write($buf, 0, $toWrite); $written += $toWrite
                }
                $stream.Flush(); if($ProgressBar){$ProgressBar.PerformStep()}
            }
            $stream.Close(); Remove-Item $f.FullName -Force
        }
    }
    
    if ($isDir) {
        Get-ChildItem $Target -Recurse -Directory | Sort-Object -Property @{Expression={$_.FullName.Length}; Descending=$true} | Remove-Item -Force
    }
}

function Show-ShredPreview {
    param($Path)
    $files = Get-ChildItem $Path -Recurse -File
    $msg = "WARNING: You are about to DoD-Shred $($files.Count) files in:`n$Path`n`nProceed?"
    return [Windows.Forms.MessageBox]::Show($msg, "Final Confirmation", "YesNo", "Warning")
}

# --- 5. INTERACTIVE DICEWARE & PROMPTS ---
function Get-InputBox {
    param($Title, $Prompt)
    $f = New-Object Windows.Forms.Form -Property @{Text=$Title; Size="300,150"; StartPosition="CenterScreen"; FormBorderStyle="FixedDialog"; MaximizeBox=$false}
    $l = New-Object Windows.Forms.Label -Property @{Text=$Prompt; Location="20,20"; Size="250,20"}
    $t = New-Object Windows.Forms.TextBox -Property @{Location="20,45"; Size="240,25"}
    $b = New-Object Windows.Forms.Button -Property @{Text="OK"; Location="180,80"; DialogResult="OK"}
    $f.Controls.AddRange(@($l,$t,$b)); $f.AcceptButton=$b
    $res = $f.ShowDialog()
    if ($res -eq "OK") { return $t.Text } else { return $null }
}

function Get-VaultConfig {
    param($PreFillID = "")
    $F = New-Object Windows.Forms.Form -Property @{Text="Vault Setup"; Size="350,280"; StartPosition="CenterScreen"}
    $L1 = New-Object Windows.Forms.Label -Property @{Text="Vault ID (2-digit Hex):"; Location="20,20"; Size="200,20"}
    $T1 = New-Object Windows.Forms.TextBox -Property @{Location="20,40"; Size="280,25"; MaxLength=2; Text=$PreFillID}
    $L2 = New-Object Windows.Forms.Label -Property @{Text="Shards (n) / Threshold (k):"; Location="20,80"; Size="250,20"}
    $Tn = New-Object Windows.Forms.TextBox -Property @{Location="20,100"; Size="130,25"}
    $Tk = New-Object Windows.Forms.TextBox -Property @{Location="170,100"; Size="130,25"}
    $B = New-Object Windows.Forms.Button -Property @{Text="PROCEED"; Location="20,160"; Size="280,45"; DialogResult="OK"}
    $F.Controls.AddRange(@($L1,$T1,$L2,$Tn,$Tk,$B)); $F.AcceptButton=$B
    if ($F.ShowDialog() -eq "OK") { 
        try {
            $nVal = [int]$Tn.Text; $kVal = [int]$Tk.Text
            if ($nVal -le 0 -or $kVal -le 1 -or $kVal -gt $nVal -or $nVal -gt 255) {
                [Windows.Forms.MessageBox]::Show("Invalid Parameters: Ensure 0 < n <= 255 and 1 < k <= n.", "Logic Error"); return $null
            }
            return @{ID=$T1.Text; n=$nVal; k=$kVal} 
        } catch { return $null }
    } else { return $null }
}

function Get-DicewareSecret {
    if (!(Test-Path $WordlistPath)) { Invoke-WebRequest "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt" -OutFile $WordlistPath }
    $Wds = New-Object System.Collections.Generic.List[string]
    $DF = New-Object Windows.Forms.Form -Property @{Text="Diceware Generator"; Size="420,520"; StartPosition="CenterScreen"}
    $I = New-Object Windows.Forms.TextBox -Property @{Location="20,40"; Size="150,30"; Font="Consolas, 14pt"; MaxLength=5}
    $BtnAdd = New-Object Windows.Forms.Button -Property @{Text="ADD WORD"; Location="185,40"; Size="180,35"}
    $LB = New-Object Windows.Forms.ListBox -Property @{Location="20,100"; Size="360,200"; Font="Consolas, 10pt"}
    $BtnUndo = New-Object Windows.Forms.Button -Property @{Text="Undo"; Location="20,310"; Size="175,35"}
    $BtnFinish = New-Object Windows.Forms.Button -Property @{Text="FINALIZE (0/5)"; Location="20,370"; Size="360,60"; Enabled=$false}
    $BtnAdd.Add_Click({ 
        $v=$I.Text.Trim(); if($v -match "^[1-6]{5}$"){ 
            $m = Select-String $WordlistPath -Pattern "^$v\s"
            if($m){ $word=($m.Line -split "\s+")[1]; $Wds.Add($word); [void]$LB.Items.Add("$v -> $word"); $I.Clear()
                if($Wds.Count -ge 5){$BtnFinish.Enabled=$true; $BtnFinish.Text="FINALIZE ($($Wds.Count) Words)"}
            } 
        } 
    })
    $BtnUndo.Add_Click({ if($Wds.Count -gt 0){ $Wds.RemoveAt($Wds.Count-1); $LB.Items.RemoveAt($LB.Items.Count-1); if($Wds.Count -lt 5){$BtnFinish.Enabled=$false} } })
    $BtnFinish.Add_Click({ $DF.Tag=$Wds -join "-"; $DF.DialogResult="OK"; $DF.Close() })
    $DF.Controls.AddRange(@($I,$LB,$BtnAdd,$BtnUndo,$BtnFinish)); $DF.AcceptButton=$BtnAdd
    if ($DF.ShowDialog() -eq "OK") { return $DF.Tag } else { return $null }
}

# --- 6. SSSS CRYPTO ENGINE (Strict Parity) ---
function Split-Secret ($Secret, $Total, $Threshold, $VaultDir, $VaultID, $PayloadPath) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $shares = New-Object "System.Byte[][]" $Total
    for($i=0; $i -lt $Total; $i++) { $shares[$i] = New-Object byte[] $bytes.Count }
    
    $totalRndBytes = ($Threshold - 1) * $bytes.Count
    $rndArray = New-Object byte[] $totalRndBytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($rndArray)
    $rng.Dispose()
    
    $rndIdx = 0
    
    foreach ($b in 0..($bytes.Count - 1)) {
        $coeffs = New-Object byte[] $Threshold
        $coeffs[0] = $bytes[$b]
        
        for($i=1; $i -lt $Threshold; $i++){ 
            $coeffs[$i] = $rndArray[$rndIdx]
            $rndIdx++ 
        }
        
        for ($x = 1; $x -le $Total; $x++) {
            [byte]$y = $coeffs[$Threshold - 1]
            for ($i = $Threshold - 2; $i -ge 0; $i--) {
                if ($y -eq 0) {
                    $y = $coeffs[$i]
                } else {
                    $y = $Global:EXP[$Global:LOG[$y] + $Global:LOG[$x]] -bxor $coeffs[$i]
                }
            }
            $shares[$x-1][$b] = $y
        }
    }
    
    $w = New-Object ZXing.BarcodeWriter -Property @{Format=[ZXing.BarcodeFormat]::QR_CODE}
    $w.Options = New-Object ZXing.QrCode.QrCodeEncodingOptions -Property @{Height=400; Width=400}
    for($i=1; $i -le $Total; $i++) {
        $SF = Join-Path $VaultDir "Shard_$i"
        New-Item $SF -ItemType Directory -Force | Out-Null
        Copy-Item $PayloadPath $SF -Force
        
        $hData = [BitConverter]::ToString($shares[$i-1]).Replace('-','').ToLower().Trim()
        $fullS = "$i-$hData"
        
        $fullS | Out-File (Join-Path $SF "$VaultID`_$i.txt") -Encoding ascii
        $w.Write($fullS).Save((Join-Path $SF "$VaultID`_$i.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        $instructions = @"
CRITICAL VAULT RECOVERY PROTOCOL

This file is a cryptographic shard. It contains a mathematical fraction of the master password required to decrypt Vault $VaultID. By itself, this shard is useless. 

To decrypt the payload, you must gather exactly $Threshold unique shards from this set.

RECOVERY STEPS:
1. Launch the Horcrux Master Script (v8.3) and click "2. RECOVER KEY".
2. When prompted, enter a threshold of $Threshold. 
3. The Recovery Room will open, displaying $Threshold empty input fields.
4. Input your shards using one of the following methods:
   - Digital: Click "Add Files" and select $Threshold .txt or .png shard files.
   - Physical: Click "Webcam Scanner". The Windows Camera will open. Hold the printed QR code to the lens, tap the text that appears on screen to copy it, and paste it into an empty field. Press "Tab" to move to the next field.
5. Click "JOIN". Ensure no duplicate shards were entered. 
6. The original master passkey will be reconstructed and displayed on the main menu.
7. Click "3. DECRYPT PAYLOAD", select the .enc file, and the vault will unlock.

FALLBACK / LINUX COMPATIBILITY:
This system utilizes standard Shamir's Secret Sharing (Polynomial 0x11D). If the Horcrux software is lost or destroyed, this key can be reconstructed on any Linux machine using the open-source 'ssss' utility. 
Command: ssss-combine -t $Threshold
"@
        $instructions | Out-File (Join-Path $SF "restore_instructions.txt") -Encoding utf8
    }
}

function Join-Secret ($Lines, $Threshold) {
    $parsed = New-Object System.Collections.Generic.List[object]
    foreach ($line in $Lines) { 
        $line = $line.Trim()
        if ($line -match '^(\d+)-([A-Fa-f0-9]+)$') { 
            $hex = $Matches[2]; $bin = New-Object byte[] ($hex.Length/2)
            for($i=0; $i -lt $hex.Length; $i+=2){ $bin[$i/2] = [Convert]::ToByte($hex.Substring($i,2),16) }
            $parsed.Add([PSCustomObject]@{ x = [byte][int]$Matches[1]; y = $bin })
        } 
    }
    if ($parsed.Count -lt $Threshold) { return $null }
    
    $useCount = $Threshold
    $len = $parsed[0].y.Count; $re = New-Object byte[] $len
    
    for ($b=0; $b -lt $len; $b++) {
        [byte]$v = 0
        
        for ($i=0; $i -lt $useCount; $i++) {
            [byte]$num = 1
            [byte]$den = 1
            for ($j=0; $j -lt $useCount; $j++) { 
                if ($i -ne $j) { 
                    [byte]$xj = $parsed[$j].x
                    if ($num -ne 0 -and $xj -ne 0) {
                        $num = $Global:EXP[$Global:LOG[$num] + $Global:LOG[$xj]]
                    } else { $num = 0 }
                    
                    [byte]$diff = $parsed[$i].x -bxor $parsed[$j].x
                    if ($den -ne 0 -and $diff -ne 0) {
                        $den = $Global:EXP[$Global:LOG[$den] + $Global:LOG[$diff]]
                    } else { $den = 0 }
                } 
            }
            
            [byte]$term = 0
            [byte]$yi = $parsed[$i].y[$b]
            if ($yi -ne 0 -and $num -ne 0) {
                [byte]$div = $Global:EXP[$Global:LOG[$num] - $Global:LOG[$den] + 255]
                $term = $Global:EXP[$Global:LOG[$yi] + $Global:LOG[$div]]
            }
            $v = $v -bxor $term
        }
        $re[$b] = $v
    }
    return [System.Text.Encoding]::UTF8.GetString($re).Trim()
}

# --- 7. UI & VAULT LOGIC ---
Import-Libraries
$Global:OSSL = Find-OpenSSL
$Main = New-Object Windows.Forms.Form -Property @{Text="Horcrux Master v8.3"; Size="450,650"; StartPosition="CenterScreen"}
$Disp = New-Object Windows.Forms.TextBox -Property @{Location="25,40"; Size="380,60"; ReadOnly=$true; Multiline=$true}
$Btn1 = New-Object Windows.Forms.Button -Property @{Text="1. CREATE VAULT"; Location="25,120"; Size="380,55"}
$Btn2 = New-Object Windows.Forms.Button -Property @{Text="2. RECOVER KEY"; Location="25,185"; Size="380,55"}
$Btn3 = New-Object Windows.Forms.Button -Property @{Text="3. DECRYPT PAYLOAD"; Location="25,250"; Size="380,55"; Enabled=$false}
$Btn4 = New-Object Windows.Forms.Button -Property @{Text="4. SECURE SHREDDER"; Location="25,315"; Size="380,55"}
$Prog = New-Object Windows.Forms.ProgressBar -Property @{Location="25,385"; Size="380,30"; Step=1}
$Main.Controls.AddRange(@($Disp,$Btn1,$Btn2,$Btn3,$Btn4,$Prog))

$Btn1.Add_Click({
    if(!$Global:OSSL){ $Global:OSSL = Find-OpenSSL; if(!$Global:OSSL){return} }
    $fb = New-Object Windows.Forms.FolderBrowserDialog; if($fb.ShowDialog() -ne "OK"){return}
    $ValidCfg = $false; $cfg = $null
    while (-not $ValidCfg) {
        $cfg = Get-VaultConfig -PreFillID ($cfg.ID)
        if (!$cfg) { return }
        $vPath = Join-Path $WorkDir "Vault_$($cfg.ID)"
        if (Test-Path $vPath) { [Windows.Forms.MessageBox]::Show("ID Collision: Choose unique Hex.", "Error") }
        elseif ($cfg.ID -notmatch '^[0-9A-Fa-f]{2}$') { [Windows.Forms.MessageBox]::Show("2-Digit Hex required.", "Error") }
        else { $ValidCfg = $true }
    }
    $pw = Get-DicewareSecret; if(!$pw){return}
    $man = Join-Path $fb.SelectedPath "Vault_Manifest.txt"
    "SCRIPT_HASH | $Global:CurrentHash" | Out-File $man -Encoding utf8
    Get-ChildItem $fb.SelectedPath -Recurse -File | ForEach-Object { if($_.Name -ne "Vault_Manifest.txt") { "$((Get-FileHash $_.FullName).Hash) | $($_.FullName.Replace($fb.SelectedPath,'').TrimStart('\'))" | Out-File $man -Append -Encoding utf8 } }
    New-Item $vPath -ItemType Directory | Out-Null
    $zip = Join-Path $env:TEMP "tmp.zip"; Compress-Archive -Path "$($fb.SelectedPath)\*" -DestinationPath $zip -Force
    $payloadPath = Join-Path $vPath "Vault_$($cfg.ID).enc"
    & $Global:OSSL aes-256-cbc -salt -pbkdf2 -iter 100000 -in "$zip" -out "$payloadPath" -pass "pass:$pw"
    Split-Secret $pw $cfg.n $cfg.k $vPath $cfg.ID $payloadPath
    Remove-Item $zip, $man, $payloadPath -Force; [Windows.Forms.MessageBox]::Show("Vault $($cfg.ID) Created.")
})

$Btn2.Add_Click({
    $kStr = Get-InputBox -Title "Recovery" -Prompt "Enter Threshold (k):"
    if ([string]::IsNullOrWhiteSpace($kStr)) { return }
    if ($kStr -notmatch '^[1-9]\d*$') { [Windows.Forms.MessageBox]::Show("Positive integer required.", "Input Error"); return }
    $k = [int]$kStr
    
    $RM = New-Object Windows.Forms.Form -Property @{Text="Recovery Room"; Size="420,440"; StartPosition="CenterScreen"}
    
    # UI Panel dynamically generates precisely $k dedicated input fields
    $Pnl = New-Object Windows.Forms.Panel -Property @{Location="15,15"; Size="375,200"; AutoScroll=$true; BorderStyle="Fixed3D"}
    $RM.Controls.Add($Pnl)
    
    $TBs = New-Object System.Collections.Generic.List[Windows.Forms.TextBox]
    for ($i = 0; $i -lt $k; $i++) {
        $lbl = New-Object Windows.Forms.Label -Property @{Text="Shard $($i+1):"; Location="10,$(( $i * 35 ) + 10)"; Size="60,20"}
        $tb = New-Object Windows.Forms.TextBox -Property @{Location="70,$(( $i * 35 ) + 10)"; Size="270,25"}
        $Pnl.Controls.AddRange(@($lbl, $tb))
        $TBs.Add($tb)
    }

    $BF = New-Object Windows.Forms.Button -Property @{Text="Add Files"; Location="20,230"; Size="175,45"}
    $BW = New-Object Windows.Forms.Button -Property @{Text="Webcam Scanner"; Location="205,230"; Size="175,45"}
    $BR = New-Object Windows.Forms.Button -Property @{Text="JOIN"; Location="20,290"; Size="360,60"}
    $RM.Controls.AddRange(@($BF,$BW,$BR))
    
    $BF.Add_Click({ 
        $of=New-Object Windows.Forms.OpenFileDialog -Property @{Multiselect=$true} 
        if($of.ShowDialog() -eq "OK"){ 
            $files = $of.FileNames
            $fIdx = 0
            foreach($tb in $TBs){
                if([string]::IsNullOrWhiteSpace($tb.Text) -and $fIdx -lt $files.Count){
                    $f = $files[$fIdx]
                    $t = if($f -match '\.png$'){
                        $bmp=New-Object System.Drawing.Bitmap($f)
                        $res=(New-Object ZXing.BarcodeReader).Decode($bmp)
                        $bmp.Dispose()
                        if($res){$res.Text}
                    } else {
                        (Get-Content $f -Raw).Trim()
                    }
                    if($t){$tb.Text = $t}
                    $fIdx++
                }
            }
        } 
    })
    
    $BW.Add_Click({ 
        $msg = "INSTRUCTIONS:`n`n1. The Windows Camera app will now open.`n2. Hold your Shard QR code up to the camera.`n3. Click the text/link that appears on the camera screen to copy the secret.`n4. Paste it into an empty Shard field.`n5. Repeat this for $k unique shards.`n`nThe camera will automatically close when you click JOIN and recovery is successful."
        [Windows.Forms.MessageBox]::Show($msg, "Webcam Scanner Instructions", "OK", "Information")
        try { Start-Process "microsoft.windows.camera:" -ErrorAction Stop }
        catch { [Windows.Forms.MessageBox]::Show("Could not launch the Windows Camera app. Ensure it is installed.", "Error") }
    })
    
    $BR.Add_Click({ 
        $validShards = @{}
        $rawLines = New-Object System.Collections.Generic.List[string]
        
        foreach ($tb in $TBs) {
            $val = $tb.Text.Trim()
            
            # 1. Empty Field Block
            if ([string]::IsNullOrWhiteSpace($val)) {
                [Windows.Forms.MessageBox]::Show("Validation Error: All $k fields must be filled.", "Validation Error")
                return
            }
            
            # 2. Strict Regex Character Lock (Blocks binary artifacts, spaces, invalid chars)
            if ($val -notmatch '^(\d+)-([A-Fa-f0-9]+)$') {
                [Windows.Forms.MessageBox]::Show("Invalid format detected: '$val'`n`nShards must strictly follow the 'Number-Hex' format with no spaces or special characters.", "Validation Error")
                return
            }
            
            $idx = $Matches[1]
            
            # 3. Index Deduplication
            if ($validShards.ContainsKey($idx)) {
                [Windows.Forms.MessageBox]::Show("Duplicate index detected: Shard #$idx.`n`nYou must provide $k UNIQUE shards.", "Validation Error")
                return
            }
            
            # 4. Literal Deduplication
            foreach ($v in $validShards.Values) {
                if ($v -eq $val) {
                    [Windows.Forms.MessageBox]::Show("Duplicate shard data detected.`n`nYou must provide $k UNIQUE shards.", "Validation Error")
                    return
                }
            }
            
            $validShards[$idx] = $val
            $rawLines.Add($val)
        }
        
        if ($rawLines.Count -lt $k) {
            [Windows.Forms.MessageBox]::Show("Validation Failed.`nYou need exactly $k unique shards.", "Validation Error")
            return
        }
        
        $script:res = Join-Secret $rawLines $k
        if($script:res){
            Get-Process WindowsCamera -ErrorAction SilentlyContinue | Stop-Process
            $RM.DialogResult="OK"; $RM.Close()
        } else {
            [Windows.Forms.MessageBox]::Show("Reconstruction Failed. The cryptographic math could not resolve the key. Ensure shards belong to the same vault.", "Error")
        } 
    })
    
    if($RM.ShowDialog() -eq "OK"){$Disp.Text=$script:res; $Btn3.Enabled=$true}
})

$Btn3.Add_Click({
    if(!$Global:OSSL){ $Global:OSSL = Find-OpenSSL; if(!$Global:OSSL){return} }
    $of = New-Object Windows.Forms.OpenFileDialog; if($of.ShowDialog() -eq "OK"){
        $tz = Join-Path $env:TEMP "dec.zip"; & $Global:OSSL aes-256-cbc -d -salt -pbkdf2 -iter 100000 -in "$($of.FileName)" -out "$tz" -pass "pass:$($Disp.Text)"
        if($LASTEXITCODE -eq 0){ 
            $dest = Join-Path (Split-Path $of.FileName) "Unlocked"
            New-Item $dest -ItemType Directory -Force | Out-Null; Expand-Archive $tz -DestinationPath $dest -Force
            $man = Join-Path $dest "Vault_Manifest.txt"
            if(Test-Path $man){ Get-Content $man | ForEach-Object { if($_ -match "(.+) \| (.+)" -and $_ -notmatch "SCRIPT_HASH"){ if((Get-FileHash (Join-Path $dest $Matches[2])).Hash -ne $Matches[1]){ [Windows.Forms.MessageBox]::Show("TAMPER ALERT: $($Matches[2])") } } } }
            Invoke-Item $dest; Remove-Item $tz -Force
        }
    }
})

$Btn4.Add_Click({ 
    $fb = New-Object Windows.Forms.FolderBrowserDialog; if($fb.ShowDialog() -eq "OK"){
        if((Show-ShredPreview $fb.SelectedPath) -eq "Yes"){ Invoke-SecureShred $fb.SelectedPath $Prog }
    }
})

$Main.ShowDialog()