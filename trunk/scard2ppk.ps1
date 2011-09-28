#!powershell -File

$pkcs15tool = "C:\Program Files\OpenSC\pkcs15-tool.exe"
$openssl = "C:\OpenSSL-Win32\bin\openssl.exe"

# interesting attributes of certs, keys and pins
$cert_interesting = @{"ID"=1; "Path"=1; "Object Flags"=1 }
$key_interesting = @{"ID"=1; "Path"=1; "Key ref"=1; "Auth ID"=1; "Usage"=1 }
$pin_interesting = @{"ID"=1; "Path"=1; "Reference"=1; "Tries left"=1 }

# temp items while they are being parsed
$cert = 0
$key = 0
$pin = 0

# empty hashes that collect the parsed items by their IDs as keys
$certs = @{}
$keys = @{}
$pins = @{}

# result array of valid certs
$valid_certs = @()

# parse the output of 'pkcs15-tool -D', that is, a full dump of the card
foreach ($line in &$pkcs15tool "-D") {
    if ($line -match "^X\.509 Certificate \[(.*)\]") {
        # this is the beginning of a new certificate -> create a new hash item for it
        $cert = @{"Name" = $matches[1]}
    }
    elseif ($line -match "^Private RSA Key \[(.*)\]") {
        # this is the beginning of a new key
        $key = @{"Name" = $matches[1]}
    }
    elseif ($line -match "^PIN \[(.*)\]") {
        # this is the beginning of a new pin
        $pin = @{"Name" = $matches[1]}
    }
    elseif ($line -match "^\s*(.*?)\s*:\s*(.*?)\s*`$") {
        # this is a 'name : value'  line -> if the attribute is interesting for the
        # item being parsed, then add the name+value pair to its hash item
        if ($cert -and $cert_interesting.ContainsKey($matches[1])) {
            $cert.Add($matches[1], $matches[2])
        }
        elseif ($key -and $key_interesting.ContainsKey($matches[1])) {
            $key.Add($matches[1], $matches[2])
        }
        elseif ($pin -and $pin_interesting.ContainsKey($matches[1])) {
            $pin.Add($matches[1], $matches[2])
        }
    }
    elseif (!$line) {
        # this is an empty line -> the item being parsed is complete
        if ($cert -and ($cert.Get_Item("Object Flags") -ne "[0x0]")) {
            # this is a valid cert -> add it to the certs' collector hash
            $cert.Remove("Object Flags")
            $certs.add($cert.Get_Item("ID"), $cert)
            $cert = ''
        }
        elseif ($key -and ($key.Get_Item("Usage") -match "encrypt")) {
            # this is a key
            $key.Remove("Usage")
            $keys.add($key.Get_Item("ID"), $key)
            $key = ''
        }
        elseif ($pin) {
            # this is a pin
            $pins.add($pin.Get_Item("ID"), $pin)
            $pin = ''
        }
    }
    else {
        $x = -join("This is something weird: ", $line)
        Write-Output $x
        exit
    }
}

# process the certs
foreach ($c in $certs.GetEnumerator()) {
    # add the attibutes of their keys and their pins to the cert hash
    $key = $keys.Get_Item($c.Key)
    if ($key) {
        $c.Value.Add("KeyPath", $key.Get_Item("Path"))
        $c.Value.Add("KeyRef", $key.Get_Item("Key ref"))
        $pin = $pins.Get_Item($key.Get_Item("Auth ID"))
        if ($pin) {
            $c.Value.Add("PinPath", $pin.Get_Item("Path"))
            if ($pin.Get_Item("Tries left") -eq 0) {
                $c.Value.Add("PinRef", 0)
            }
            else {
                $c.Value.Add("PinRef", $pin.Get_Item("Reference"))
            }
        }
    }

    # check if the cert has everything that is needed
    if ($c.Value.ContainsKey("PinRef")) {
        # check whether the prefix of Path, KeyPath and PinPath is the same
        $certpath = $c.Value.Get_Item("Path").Substring(0, 4)
        $keypath = $c.Value.Get_Item("KeyPath").Substring(0, 4)
        $pinpath = $c.Value.Get_Item("PinPath").Substring(0, 4)
        if ($certpath -eq $keypath -and $keypath -eq $pinpath) {
            # prepare the .ppk line items
            $keyref = "{0:x2}" -f [System.Convert]::ToByte($c.Value.Get_Item("KeyRef"), 10)
            $pinref = "{0:x2}" -f [System.Convert]::ToByte($c.Value.Get_Item("PinRef"), 10)
            $certsuffix  = $c.Value.Get_Item("Path").Substring(4, 4)
            # assemble the .ppk line
            $c.Value.Add("ppk", -join($certpath, ",", $keyref, ",", $pinref, ",", $certsuffix))
            $valid_certs += $c.Value
        }
    }
}

foreach ($c in $valid_certs) {
    $subject = &$pkcs15tool "-r" $c.Get_Item("ID")  2>$null | &$openssl "x509" "-noout" "-subject" 2>$null | %{$_ -replace "^.*emailAddress=([^/]*).*", "`$1" -replace "[@.]", "_"}

    $filename = -join("SC_", $subject, ".ppk")
    -join("Generating file ", $filename) | Write-Output 
    $content = -join("PuTTYcard,PuTTYiso7816.dll,", $c.Get_Item("ppk"))
    Write-Output $content >$filename

    $filename = -join("SC_", $subject, ".pub")
    -join("Generating file ", $filename) | Write-Output 
    &$pkcs15tool "-r" $c.Get_Item("ID")  2>$null | &$openssl "x509" "-noout" "-pubkey" >$filename
}

