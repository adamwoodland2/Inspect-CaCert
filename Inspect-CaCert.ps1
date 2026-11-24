<#
.SYNOPSIS
    Dumps and checks the properties of a CA certificate (root or subordinate) against RFC 5280 and,
    optionally, the CA/Browser Forum TLS Baseline Requirements and the ASD ISM.
    Uses only built-in .NET classes - no OpenSSL.

.DESCRIPTION
    Works with Windows PowerShell 5.1 and PowerShell 7.x.
    Accepts a single DER (.cer/.crt) or Base64/PEM encoded certificate. PFX/PKCS#12 and PKCS#7 files
    are rejected (nothing is imported into a key store); if a PEM file holds several certificates
    only the first is inspected, with a warning.

    The certificate, its public key and the extensions it checks are parsed with a strict DER
    reader, so the results don't depend on the .NET version's own decoders. RSA keys are checked
    for a valid structure and modulus; EC points on P-256/P-384/P-521 are decoded and checked to
    lie on the curve. Signatures are verified directly with .NET cryptography against the
    certificate's own key (to decide whether it is really self-signed) and against the -IssuerPath
    certificate. Names are compared byte-for-byte where the CA/B Forum requires that, and
    otherwise with RFC 5280 7.1 name matching: RFC 4518 string preparation using RFC 3454's
    Unicode 3.2 tables (B.2 case folding, A.1 unassigned code points, C.3/C.4/C.5/C.8), which are
    embedded because .NET's casing follows newer Unicode. TeletexString values and non-string values
    are compared as bytes. nameConstraints, CRL Distribution Points, Authority Information Access
    and certificatePolicies are decoded and checked by the script itself.

    The script is read-only: it reads the input files, and it does not write to any certificate
    store, cache or file. The platform chain engine (X509Chain) runs as a secondary check (for
    example for unsupported critical extensions or name-constraint errors) only on PowerShell 7.1+
    (.NET 5+), where DisableCertificateDownloads stops it fetching issuer certificates from AIA URLs
    and updating the Windows root store. It is anchored to the supplied root (CustomRootTrust) when
    there is one. On Windows PowerShell 5.1 and PowerShell 7.0 those downloads can't be turned off,
    so the chain step is skipped and only the script's own checks run. Revocation is NOT checked
    (use certutil -verify -urlfetch for that).

    Every finding records the rule(s) behind it in the Basis column, e.g. "RFC:SHOULD BR:MUST".
    Its level depends on which policies are selected with -Policy:
      FAIL - a MUST / MUST NOT in a selected policy
      WARN - a SHOULD / SHOULD NOT / (NOT) RECOMMENDED in a selected policy, or a possible breach of
             a MUST that the certificate alone can't prove (marked with '?', e.g. "BR:MUST?")
      NOTE - advisory, or a rule from a policy that was not selected
    Basis sources:
      Gen - always applied: failures any relying party would reject (bad signature, invalid public
            key, expired, MD5/SHA-1 signature from an issuer, RSA < 2048, chain engine rejection).
            A root's own MD5/SHA-1 self-signature and a critical extension this script doesn't
            recognise are WARNs: relying parties don't verify a trust anchor's signature, and an
            unknown extension may still be understood by the relying parties that need it.
      RFC - RFC 5280 and the algorithm RFCs it relies on (3279, 4055, 5480, 5758); always applied
      BR  - CA/Browser Forum TLS Baseline Requirements (-Policy CABF-TLS). Subordinates are
            assessed against the TLS Subordinate CA profile (BR 7.1.2.6).
      ISM - ASD Information Security Manual cryptography guidance (-Policy ISM)

.PARAMETER Path
    The CA certificate to inspect.

.PARAMETER IssuerPath
    The certificate of the CA that issued -Path. Required to check a subordinate or key-rollover
    certificate's signature, issuer name, AKI linkage and validity nesting. Ignored for a root.

.PARAMETER Policy
    Which policies count towards the result: one or more of RFC5280 (always applied), CABF-TLS and
    ISM, or All for all three. Rules from policies not selected are still listed, under "Other
    policies", but don't become FAIL/WARN or change the exit code. Select CABF-TLS for a publicly
    trusted TLS CA and ISM for Australian government systems; private CAs routinely and legitimately
    break rules in both.

.NOTES
    Exit codes, for automation (powershell -File / pwsh -File, or $LASTEXITCODE in a session):
      0 - no FAIL findings, and the certificate's signature was verified
      3 - no FAIL findings, but the signature was NOT verified, so validation is incomplete: no
          -IssuerPath was given, or the algorithm or key is one .NET can't verify and the platform
          chain engine didn't confirm the signature on the supplied path (or didn't run)
      2 - at least one FAIL finding
      1 - the inspection could not be completed (unreadable file, not a certificate, ...)
    Read 0 as "no FAIL findings, signature verified", not as "the certificate is valid for use".
    Revocation is never checked, and only the platform chain check (PowerShell 7.1+) applies
    path-level rules such as name constraints to the path. WARN findings never change the exit code.

.EXAMPLE
    .\Inspect-CaCert.ps1 -Path .\root.cer

.EXAMPLE
    .\Inspect-CaCert.ps1 -Path .\intermediate.cer -IssuerPath .\root.cer -Policy CABF-TLS, ISM

.EXAMPLE
    .\Inspect-CaCert.ps1 -Path .\intermediate.cer -IssuerPath .\root.cer -Policy All
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$IssuerPath,
    [string[]]$Policy = @('RFC5280')
)

$ErrorActionPreference = 'Stop'
# Set explicitly so the script behaves the same whatever strict mode the calling session uses
Set-StrictMode -Version Latest
$X = 'System.Security.Cryptography.X509Certificates'

# Validated by hand rather than with ValidateSet: "powershell -File ... -Policy CABF-TLS,ISM" passes
# the list as ONE string, which ValidateSet would reject before it could be split. Values are trimmed,
# matched case-insensitively, stored in their canonical spelling and de-duplicated; All expands to
# every policy.
$validPolicies = @('RFC5280', 'CABF-TLS', 'ISM')
$badPolicy = @()
$Policy = @(@(foreach ($name in @($Policy -split ',')) {
    $name = $name.Trim()
    if (-not $name) { continue }
    if ($name -eq 'All') { $validPolicies; continue }
    $canonical = @($validPolicies | Where-Object { $_ -eq $name })
    if ($canonical.Count) { $canonical[0] } else { $badPolicy += $name }
}) | Select-Object -Unique)
if ($badPolicy.Count) { throw "Unknown -Policy value(s): $($badPolicy -join ', '). Valid values: $($validPolicies -join ', '), or All." }

# ======================= Policy scope and findings =======================
$inScope = @{ GEN = $true; RFC = $true; BR = ($Policy -contains 'CABF-TLS'); ISM = ($Policy -contains 'ISM') }
$sourceLabel = @{ GEN = 'Gen'; RFC = 'RFC'; BR = 'BR'; ISM = 'ISM' }
$reqRank = @{ MUST = 0; SHOULD = 1; INFO = 2 }
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding([hashtable]$Rules, [string]$Message, [switch]$Unproven, [switch]$Coverage) {
    # $Rules maps a source (GEN/RFC/BR/ISM) to MUST, SHOULD or INFO. The level is the strongest
    # requirement among the selected sources; anything only backed by unselected sources is a NOTE.
    # -Unproven: the certificate suggests, but can't prove, a breach of the rule. The level is then
    # at most WARN and the basis is marked with '?'.
    # -Coverage: the message is about what this run did or couldn't check, not about the certificate.
    # Kind decides where the report shows it: Problem (FAIL/WARN), Note (advice), OtherPolicy (a NOTE
    # only because the rule's policy wasn't selected) or Coverage.
    $best = 2; $overall = 3; $scoped = 3
    $mark = if ($Unproven) { '?' } else { '' }
    $basis = foreach ($k in 'GEN', 'RFC', 'BR', 'ISM') {
        if ($Rules.ContainsKey($k)) {
            $req = $Rules[$k]
            if (-not $reqRank.ContainsKey($req)) { throw "Add-Finding: bad requirement '$req'" }
            if ($inScope[$k] -and $reqRank[$req] -lt $best) { $best = $reqRank[$req] }
            if ($reqRank[$req] -lt $overall) { $overall = $reqRank[$req] }
            if ($inScope[$k] -and $reqRank[$req] -lt $scoped) { $scoped = $reqRank[$req] }
            "$($sourceLabel[$k]):$req$mark"
        }
    }
    if ($Unproven -and $best -lt 1) { $best = 1 }
    $level = @('FAIL', 'WARN', 'NOTE')[$best]
    $kind = if ($Coverage) { 'Coverage' } elseif ($level -ne 'NOTE') { 'Problem' } elseif ($overall -lt $scoped) { 'OtherPolicy' } else { 'Note' }
    # Seq keeps findings in check order within a level (Sort-Object is not stable in Windows PowerShell 5.1)
    $findings.Add([pscustomobject]@{ Level = $level; Kind = $kind; Basis = ($basis -join ' '); Finding = $Message; Seq = $findings.Count })
}

# ======================= Generic helpers =======================
function Get-Ext($Cert, [string]$Oid) {
    $Cert.Extensions | Where-Object { $_.Oid.Value -eq $Oid } | Select-Object -First 1
}

function ConvertTo-Hex([byte[]]$Bytes) {
    # Not "-not $Bytes": PowerShell judges a one-element array by its element, so @(0x00) would look empty
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    [BitConverter]::ToString($Bytes).Replace('-', '')
}

# ASCII decoder that throws on bytes above 0x7F instead of silently substituting '?'
$strictAscii = [System.Text.Encoding]::GetEncoding('us-ascii', [System.Text.EncoderFallback]::ExceptionFallback, [System.Text.DecoderFallback]::ExceptionFallback)

function Get-Sha256Hex([byte[]]$Bytes) {
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { ConvertTo-Hex $h.ComputeHash($Bytes) } finally { $h.Dispose() }
}

function Get-Slice([byte[]]$B, [int]$Start, [int]$Len) {
    $r = New-Object byte[] $Len
    if ($Len -gt 0) { [Array]::Copy($B, $Start, $r, 0, $Len) }
    , $r
}

function Test-BytesEqual([byte[]]$A, [byte[]]$B) {
    # Exact comparison. Comparing Base64 or other strings with -eq/-ne is not: PowerShell compares
    # strings case-insensitively by default, so different bytes could compare equal.
    if ($null -eq $A -or $null -eq $B) { return ($null -eq $A -and $null -eq $B) }
    if ($A.Length -ne $B.Length) { return $false }
    for ($k = 0; $k -lt $A.Length; $k++) { if ($A[$k] -ne $B[$k]) { return $false } }
    $true
}

function ConvertTo-BigInt([byte[]]$Magnitude) {
    # Unsigned big-endian bytes -> non-negative BigInteger (the constructor wants little-endian two's complement)
    $le = New-Object byte[] ($Magnitude.Length + 1)
    for ($k = 0; $k -lt $Magnitude.Length; $k++) { $le[$k] = $Magnitude[$Magnitude.Length - 1 - $k] }
    [System.Numerics.BigInteger]::new($le)
}

function Get-BitLength([byte[]]$Magnitude) {
    # Bit length of an unsigned big-endian value (0 for zero)
    $j = 0
    while ($j -lt $Magnitude.Length -and $Magnitude[$j] -eq 0) { $j++ }
    if ($j -eq $Magnitude.Length) { return 0 }
    ($Magnitude.Length - $j - 1) * 8 + [Convert]::ToString($Magnitude[$j], 2).Length
}

# ======================= Strict DER reader =======================
function Read-Tlv([byte[]]$B, [int]$Offset, [int]$End = -1) {
    # Reads one DER TLV, rejecting truncation, indefinite or non-minimal lengths, and overruns
    if ($End -lt 0) { $End = $B.Length }
    if ($Offset + 2 -gt $End) { throw "DER: truncated header at offset $Offset" }
    $tag = [int]$B[$Offset]
    if (($tag -band 0x1F) -eq 0x1F) { throw "DER: high-tag-number form at offset $Offset" }
    $len = [int]$B[$Offset + 1]
    $hdr = 2
    if ($len -band 0x80) {
        $n = $len -band 0x7F
        if ($n -eq 0) { throw "DER: indefinite length at offset $Offset" }
        if ($n -gt 3) { throw "DER: length too large at offset $Offset" }
        if ($Offset + 2 + $n -gt $End) { throw "DER: truncated length at offset $Offset" }
        if ($B[$Offset + 2] -eq 0) { throw "DER: non-minimal length at offset $Offset" }
        $len = 0
        for ($k = 0; $k -lt $n; $k++) { $len = $len * 256 + [int]$B[$Offset + 2 + $k] }
        if ($len -lt 128) { throw "DER: non-minimal length at offset $Offset" }
        $hdr += $n
    }
    $start = $Offset + $hdr
    if ($start + $len -gt $End) { throw "DER: content overruns its container at offset $Offset" }
    [pscustomobject]@{ Tag = $tag; Offset = $Offset; Start = $start; Length = $len; End = $start + $len }
}

function Get-TlvChildren([byte[]]$B, $Parent) {
    $list = New-Object System.Collections.Generic.List[object]
    $p = $Parent.Start
    while ($p -lt $Parent.End) {
        $t = Read-Tlv $B $p $Parent.End
        $list.Add($t)
        $p = $t.End
    }
    , $list.ToArray()
}

function Get-TlvEncoding([byte[]]$B, $T) { Get-Slice $B $T.Offset ($T.End - $T.Offset) }

function ConvertFrom-DerOid([byte[]]$Der) {
    # Decodes a DER OBJECT IDENTIFIER (06 len ...) to dotted form; $null if the bytes are not a valid one.
    # Arcs are BigIntegers because UUID-based OIDs (2.25.x) have 128-bit arcs, which overflow an Int64.
    if ($null -eq $Der -or $Der.Length -lt 3 -or $Der[0] -ne 0x06) { return $null }
    $len = [int]$Der[1]
    if (($len -band 0x80) -or ($len + 2 -ne $Der.Length) -or ($Der[$Der.Length - 1] -band 0x80)) { return $null }
    $arcs = New-Object System.Collections.Generic.List[string]
    $v = [System.Numerics.BigInteger]::Zero
    $first = $true
    $atArcStart = $true
    for ($k = 2; $k -lt 2 + $len; $k++) {
        # A subidentifier that starts with 0x80 has a redundant leading zero group (not DER)
        if ($atArcStart -and $Der[$k] -eq 0x80) { return $null }
        $v = $v * 128 + ($Der[$k] -band 0x7F)
        $atArcStart = -not ($Der[$k] -band 0x80)
        if ($atArcStart) {
            if ($first) {
                if ($v -lt 40) { $arcs.Add('0'); $arcs.Add("$v") }
                elseif ($v -lt 80) { $arcs.Add('1'); $arcs.Add("$($v - 40)") }
                else { $arcs.Add('2'); $arcs.Add("$($v - 80)") }
                $first = $false
            } else { $arcs.Add("$v") }
            $v = [System.Numerics.BigInteger]::Zero
        }
    }
    $arcs -join '.'
}

function Read-SmallInt([byte[]]$B, $T) {
    # A non-negative, minimally encoded INTEGER of at most 4 octets
    if ($T.Tag -ne 0x02 -or $T.Length -lt 1 -or $T.Length -gt 4) { throw 'expected a small INTEGER' }
    if ($B[$T.Start] -band 0x80) { throw 'INTEGER is negative' }
    if ($T.Length -gt 1 -and $B[$T.Start] -eq 0 -and $B[$T.Start + 1] -lt 0x80) { throw 'INTEGER is not minimally encoded' }
    [long]$v = 0
    for ($k = $T.Start; $k -lt $T.End; $k++) { $v = $v * 256 + [int]$B[$k] }
    $v
}

function Read-UnsignedInt([byte[]]$B, $T, [string]$What) {
    # Magnitude bytes (no sign octet) of a non-negative, minimally encoded INTEGER of any size
    if ($T.Tag -ne 0x02) { throw "$What is not an INTEGER" }
    if ($T.Length -lt 1) { throw "$What is an empty INTEGER" }
    if ($B[$T.Start] -band 0x80) { throw "$What is negative" }
    if ($T.Length -gt 1 -and $B[$T.Start] -eq 0 -and $B[$T.Start + 1] -lt 0x80) { throw "$What is not minimally encoded (not DER)" }
    if ($T.Length -gt 1 -and $B[$T.Start] -eq 0) { return , (Get-Slice $B ($T.Start + 1) ($T.Length - 1)) }
    , (Get-Slice $B $T.Start $T.Length)
}

function Read-AlgId([byte[]]$B, $T) {
    # AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
    if ($T.Tag -ne 0x30) { throw 'AlgorithmIdentifier is not a SEQUENCE' }
    $k = Get-TlvChildren $B $T
    if ($k.Count -lt 1 -or $k.Count -gt 2 -or $k[0].Tag -ne 0x06) { throw 'malformed AlgorithmIdentifier' }
    $oid = ConvertFrom-DerOid (Get-TlvEncoding $B $k[0])
    if (-not $oid) { throw 'malformed OID in AlgorithmIdentifier' }
    $params = $null
    if ($k.Count -eq 2) { $params = $k[1] }
    [pscustomobject]@{ Oid = $oid; Params = $params; Hex = (ConvertTo-Hex (Get-TlvEncoding $B $T)); Source = $B }
}

$hashByOid = @{ '1.3.14.3.2.26' = 'SHA1'; '2.16.840.1.101.3.4.2.4' = 'SHA224'; '2.16.840.1.101.3.4.2.1' = 'SHA256'; '2.16.840.1.101.3.4.2.2' = 'SHA384'; '2.16.840.1.101.3.4.2.3' = 'SHA512' }
$hashLen = @{ SHA1 = 20; SHA224 = 28; SHA256 = 32; SHA384 = 48; SHA512 = 64 }

function Get-HashName([string]$Oid) {
    if ($Oid -and $hashByOid.ContainsKey($Oid)) { $hashByOid[$Oid] } else { "unknown($Oid)" }
}

function Read-PssParams($Alg) {
    # RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm (default SHA-1), [1] maskGenAlgorithm
    #   (default MGF1-SHA-1), [2] saltLength (default 20), [3] trailerField (default 1) }
    $B = $Alg.Source
    $p = $Alg.Params
    if (-not $p -or $p.Tag -ne 0x30) { throw 'RSASSA-PSS parameters are missing or not a SEQUENCE (RFC 4055 3.1: MUST be present)' }
    $r = [ordered]@{ Hash = 'SHA1'; MgfOid = '1.2.840.113549.1.1.8'; MgfHash = 'SHA1'; Salt = 20; Trailer = 1 }
    $last = -1
    foreach ($f in (Get-TlvChildren $B $p)) {
        $n = $f.Tag - 0xA0
        if ($n -lt 0 -or $n -gt 3 -or $n -le $last) { throw 'unexpected, repeated or out-of-order field in RSASSA-PSS parameters' }
        $last = $n
        $inner = Get-TlvChildren $B $f
        if ($inner.Count -ne 1) { throw 'malformed RSASSA-PSS parameter field' }
        $v = $inner[0]
        if ($n -eq 0) { $r.Hash = Get-HashName (Read-AlgId $B $v).Oid }
        elseif ($n -eq 1) {
            $mgf = Read-AlgId $B $v
            $r.MgfOid = $mgf.Oid
            if (-not $mgf.Params) { throw 'maskGenAlgorithm has no hash parameter' }
            $r.MgfHash = Get-HashName (Read-AlgId $B $mgf.Params).Oid
        }
        elseif ($n -eq 2) { $r.Salt = Read-SmallInt $B $v }
        else { $r.Trailer = Read-SmallInt $B $v }
    }
    [pscustomobject]$r
}

function Get-SigScheme($Alg) {
    $s = [ordered]@{ Kind = 'Unknown'; Hash = $null; Name = $null; Pss = $null; PssError = $null }
    $pkcs1 = @{ '1.2.840.113549.1.1.2' = 'MD2'; '1.2.840.113549.1.1.4' = 'MD5'; '1.2.840.113549.1.1.5' = 'SHA1'; '1.2.840.113549.1.1.14' = 'SHA224'
                '1.2.840.113549.1.1.11' = 'SHA256'; '1.2.840.113549.1.1.12' = 'SHA384'; '1.2.840.113549.1.1.13' = 'SHA512' }
    $ecdsa = @{ '1.2.840.10045.4.1' = 'SHA1'; '1.2.840.10045.4.3.1' = 'SHA224'; '1.2.840.10045.4.3.2' = 'SHA256'; '1.2.840.10045.4.3.3' = 'SHA384'; '1.2.840.10045.4.3.4' = 'SHA512' }
    $dsa = @{ '1.2.840.10040.4.3' = 'SHA1'; '2.16.840.1.101.3.4.3.1' = 'SHA224'; '2.16.840.1.101.3.4.3.2' = 'SHA256' }
    # Recognised by name only (no separate hash); .NET can't verify these
    $named = @{ '1.3.101.112' = 'Ed25519'; '1.3.101.113' = 'Ed448'
                '2.16.840.1.101.3.4.3.17' = 'ML-DSA-44'; '2.16.840.1.101.3.4.3.18' = 'ML-DSA-65'; '2.16.840.1.101.3.4.3.19' = 'ML-DSA-87' }
    if ($pkcs1.ContainsKey($Alg.Oid)) { $s.Kind = 'RSA-PKCS1'; $s.Hash = $pkcs1[$Alg.Oid] }
    elseif ($ecdsa.ContainsKey($Alg.Oid)) { $s.Kind = 'ECDSA'; $s.Hash = $ecdsa[$Alg.Oid] }
    elseif ($dsa.ContainsKey($Alg.Oid)) { $s.Kind = 'DSA'; $s.Hash = $dsa[$Alg.Oid] }
    elseif ($named.ContainsKey($Alg.Oid)) { $s.Kind = $named[$Alg.Oid] }
    elseif ($Alg.Oid -eq '1.2.840.113549.1.1.10') {
        $s.Kind = 'RSA-PSS'
        try { $s.Pss = Read-PssParams $Alg; $s.Hash = $s.Pss.Hash } catch { $s.PssError = $_.Exception.Message }
    }
    $s.Name = switch ($s.Kind) {
        'Unknown' { "unrecognised ($($Alg.Oid))" }
        'RSA-PSS' { if ($s.Pss) { "RSASSA-PSS ($($s.Pss.Hash), MGF1-$($s.Pss.MgfHash), salt $($s.Pss.Salt))" } else { 'RSASSA-PSS (unparseable parameters)' } }
        default { if ($s.Hash) { "$($s.Kind) with $($s.Hash)" } else { $s.Kind } }
    }
    [pscustomobject]$s
}

function Read-Name([byte[]]$B, $NameT) {
    # Name ::= SEQUENCE OF RDN; RDN ::= SET OF SEQUENCE { type OID, value ANY }. Walking the DER means
    # text inside a value (e.g. CN="x, O=y") can never be mistaken for another attribute.
    # Returns the RDNs in order, each an array of attributes: Oid, Tag (of the value), Value (content
    # bytes) and Der (the value's full encoding).
    if ($NameT.Tag -ne 0x30) { throw 'Name is not a SEQUENCE' }
    $rdns = New-Object System.Collections.Generic.List[object]
    foreach ($rdn in (Get-TlvChildren $B $NameT)) {
        if ($rdn.Tag -ne 0x31) { throw 'RDN is not a SET' }
        $atvs = Get-TlvChildren $B $rdn
        if ($atvs.Count -eq 0) { throw 'empty RDN' }
        $rdns.Add(@(foreach ($atv in $atvs) {
            if ($atv.Tag -ne 0x30) { throw 'AttributeTypeAndValue is not a SEQUENCE' }
            $f = Get-TlvChildren $B $atv
            if ($f.Count -ne 2 -or $f[0].Tag -ne 0x06) { throw 'malformed AttributeTypeAndValue' }
            $oid = ConvertFrom-DerOid (Get-TlvEncoding $B $f[0])
            if (-not $oid) { throw 'malformed attribute type OID in Name' }
            [pscustomobject]@{ Oid = $oid; Tag = $f[1].Tag; Value = (Get-Slice $B $f[1].Start $f[1].Length); Der = (Get-TlvEncoding $B $f[1]) }
        }))
    }
    , $rdns.ToArray()
}

# ======================= RFC 4518 string preparation (Unicode 3.2 tables) =======================
# RFC 5280 7.1 compares names after RFC 4518 string preparation, whose repertoire is Unicode 3.2. .NET's
# own case mapping and character data follow newer Unicode versions and differ from RFC 3454 Table B.2
# (e.g. U+0130, U+1FB3, U+0131, Georgian and Cherokee letters), so the tables are embedded, extracted
# from the RFC 3454 text. Encoding:
#   ranges : comma-separated hex code points or a-b ranges, sorted and non-overlapping
#   B.2    : S=M1.M2 (code point S maps to that sequence) or S-E/kSD (every k-th code point from S to E
#            maps to itself plus the hex delta D, S being the sign + or -)
$prepB2Data = @(
'41-5A/1+20,B5=3BC,C0-D6/1+20,D8-DE/1+20,DF=73.73,100-12E/2+1,130=69.307,132-136/2+1,139-147/2+1,'
'149=2BC.6E,14A-176/2+1,178=FF,179-17D/2+1,17F=73,181=253,182=183,184=185,186=254,187=188,189=256,'
'18A=257,18B=18C,18E=1DD,18F=259,190=25B,191=192,193=260,194=263,196=269,197=268,198=199,19C=26F,19D=272,'
'19F=275,1A0-1A4/2+1,1A6=280,1A7=1A8,1A9=283,1AC=1AD,1AE=288,1AF=1B0,1B1=28A,1B2=28B,1B3=1B4,1B5=1B6,'
'1B7=292,1B8=1B9,1BC=1BD,1C4=1C6,1C5=1C6,1C7=1C9,1C8=1C9,1CA=1CC,1CB-1DB/2+1,1DE-1EE/2+1,1F0=6A.30C,'
'1F1=1F3,1F2=1F3,1F4=1F5,1F6=195,1F7=1BF,1F8-21E/2+1,220=19E,222-232/2+1,345=3B9,37A=20.3B9,386=3AC,'
'388-38A/1+25,38C=3CC,38E=3CD,38F=3CE,390=3B9.308.301,391-3A1/1+20,3A3-3AB/1+20,3B0=3C5.308.301,3C2=3C3,'
'3D0=3B2,3D1=3B8,3D2=3C5,3D3=3CD,3D4=3CB,3D5=3C6,3D6=3C0,3D8-3EE/2+1,3F0=3BA,3F1=3C1,3F2=3C3,3F4=3B8,'
'3F5=3B5,400-40F/1+50,410-42F/1+20,460-480/2+1,48A-4BE/2+1,4C1-4CD/2+1,4D0-4F4/2+1,4F8=4F9,500-50E/2+1,'
'531-556/1+30,587=565.582,1E00-1E94/2+1,1E96=68.331,1E97=74.308,1E98=77.30A,1E99=79.30A,1E9A=61.2BE,'
'1E9B=1E61,1EA0-1EF8/2+1,1F08-1F0F/1-8,1F18-1F1D/1-8,1F28-1F2F/1-8,1F38-1F3F/1-8,1F48-1F4D/1-8,'
'1F50=3C5.313,1F52=3C5.313.300,1F54=3C5.313.301,1F56=3C5.313.342,1F59-1F5F/2-8,1F68-1F6F/1-8,'
'1F80=1F00.3B9,1F81=1F01.3B9,1F82=1F02.3B9,1F83=1F03.3B9,1F84=1F04.3B9,1F85=1F05.3B9,1F86=1F06.3B9,'
'1F87=1F07.3B9,1F88=1F00.3B9,1F89=1F01.3B9,1F8A=1F02.3B9,1F8B=1F03.3B9,1F8C=1F04.3B9,1F8D=1F05.3B9,'
'1F8E=1F06.3B9,1F8F=1F07.3B9,1F90=1F20.3B9,1F91=1F21.3B9,1F92=1F22.3B9,1F93=1F23.3B9,1F94=1F24.3B9,'
'1F95=1F25.3B9,1F96=1F26.3B9,1F97=1F27.3B9,1F98=1F20.3B9,1F99=1F21.3B9,1F9A=1F22.3B9,1F9B=1F23.3B9,'
'1F9C=1F24.3B9,1F9D=1F25.3B9,1F9E=1F26.3B9,1F9F=1F27.3B9,1FA0=1F60.3B9,1FA1=1F61.3B9,1FA2=1F62.3B9,'
'1FA3=1F63.3B9,1FA4=1F64.3B9,1FA5=1F65.3B9,1FA6=1F66.3B9,1FA7=1F67.3B9,1FA8=1F60.3B9,1FA9=1F61.3B9,'
'1FAA=1F62.3B9,1FAB=1F63.3B9,1FAC=1F64.3B9,1FAD=1F65.3B9,1FAE=1F66.3B9,1FAF=1F67.3B9,1FB2=1F70.3B9,'
'1FB3=3B1.3B9,1FB4=3AC.3B9,1FB6=3B1.342,1FB7=3B1.342.3B9,1FB8=1FB0,1FB9=1FB1,1FBA=1F70,1FBB=1F71,'
'1FBC=3B1.3B9,1FBE=3B9,1FC2=1F74.3B9,1FC3=3B7.3B9,1FC4=3AE.3B9,1FC6=3B7.342,1FC7=3B7.342.3B9,'
'1FC8-1FCB/1-56,1FCC=3B7.3B9,1FD2=3B9.308.300,1FD3=3B9.308.301,1FD6=3B9.342,1FD7=3B9.308.342,1FD8=1FD0,'
'1FD9=1FD1,1FDA=1F76,1FDB=1F77,1FE2=3C5.308.300,1FE3=3C5.308.301,1FE4=3C1.313,1FE6=3C5.342,'
'1FE7=3C5.308.342,1FE8=1FE0,1FE9=1FE1,1FEA=1F7A,1FEB=1F7B,1FEC=1FE5,1FF2=1F7C.3B9,1FF3=3C9.3B9,'
'1FF4=3CE.3B9,1FF6=3C9.342,1FF7=3C9.342.3B9,1FF8=1F78,1FF9=1F79,1FFA=1F7C,1FFB=1F7D,1FFC=3C9.3B9,'
'20A8=72.73,2102=63,2103=B0.63,2107=25B,2109=B0.66,210B=68,210C=68,210D=68,2110=69,2111=69,2112=6C,'
'2115=6E,2116=6E.6F,2119-211B/1-20A9,211C=72,211D=72,2120=73.6D,2121=74.65.6C,2122=74.6D,2124=7A,'
'2126=3C9,2128=7A,212A=6B,212B=E5,212C=62,212D=63,2130=65,2131=66,2133=6D,213E=3B3,213F=3C0,2145=64,'
'2160-216F/1+10,24B6-24CF/1+1A,3371=68.70.61,3373=61.75,3375=6F.76,3380=70.61,3381=6E.61,3382=3BC.61,'
'3383=6D.61,3384=6B.61,3385=6B.62,3386=6D.62,3387=67.62,338A=70.66,338B=6E.66,338C=3BC.66,3390=68.7A,'
'3391=6B.68.7A,3392=6D.68.7A,3393=67.68.7A,3394=74.68.7A,33A9=70.61,33AA=6B.70.61,33AB=6D.70.61,'
'33AC=67.70.61,33B4=70.76,33B5=6E.76,33B6=3BC.76,33B7=6D.76,33B8=6B.76,33B9=6D.76,33BA=70.77,33BB=6E.77,'
'33BC=3BC.77,33BD=6D.77,33BE=6B.77,33BF=6D.77,33C0=6B.3C9,33C1=6D.3C9,33C3=62.71,33C6=63.2215.6B.67,'
'33C7=63.6F.2E,33C8=64.62,33C9=67.79,33CB=68.70,33CD=6B.6B,33CE=6B.6D,33D7=70.68,33D9=70.70.6D,'
'33DA=70.72,33DC=73.76,33DD=77.62,FB00=66.66,FB01=66.69,FB02=66.6C,FB03=66.66.69,FB04=66.66.6C,'
'FB05=73.74,FB06=73.74,FB13=574.576,FB14=574.565,FB15=574.56B,FB16=57E.576,FB17=574.56D,FF21-FF3A/1+20,'
'10400-10425/1+28,1D400-1D419/1-1D39F,1D434-1D44D/1-1D3D3,1D468-1D481/1-1D407,1D49C=61,1D49E=63,1D49F=64,'
'1D4A2=67,1D4A5=6A,1D4A6=6B,1D4A9-1D4AC/1-1D43B,1D4AE-1D4B5/1-1D43B,1D4D0-1D4E9/1-1D46F,1D504=61,'
'1D505=62,1D507-1D50A/1-1D4A3,1D50D-1D514/1-1D4A3,1D516-1D51C/1-1D4A3,1D538=61,1D539=62,'
'1D53B-1D53E/1-1D4D7,1D540-1D544/1-1D4D7,1D546=6F,1D54A-1D550/1-1D4D7,1D56C-1D585/1-1D50B,'
'1D5A0-1D5B9/1-1D53F,1D5D4-1D5ED/1-1D573,1D608-1D621/1-1D5A7,1D63C-1D655/1-1D5DB,1D670-1D689/1-1D60F,'
'1D6A8-1D6B8/1-1D2F7,1D6B9=3B8,1D6BA-1D6C0/1-1D2F7,1D6D3=3C3,1D6E2-1D6F2/1-1D331,1D6F3=3B8,'
'1D6F4-1D6FA/1-1D331,1D70D=3C3,1D71C-1D72C/1-1D36B,1D72D=3B8,1D72E-1D734/1-1D36B,1D747=3C3,'
'1D756-1D766/1-1D3A5,1D767=3B8,1D768-1D76E/1-1D3A5,1D781=3C3,1D790-1D7A0/1-1D3DF,1D7A1=3B8,'
'1D7A2-1D7A8/1-1D3DF,1D7BB=3C3'
) -join ''
# Table A.1: code points unassigned in Unicode 3.2
$prepA1Data = @(
'221,234-24F,2AE-2AF,2EF-2FF,350-35F,370-373,376-379,37B-37D,37F-383,38B,38D,3A2,3CF,3F7-3FF,487,4CF,'
'4F6-4F7,4FA-4FF,510-530,557-558,560,588,58B-590,5A2,5BA,5C5-5CF,5EB-5EF,5F5-60B,60D-61A,61C-61E,620,'
'63B-63F,656-65F,6EE-6EF,6FF,70E,72D-72F,74B-77F,7B2-900,904,93A-93B,94E-94F,955-957,971-980,984,98D-98E,'
'991-992,9A9,9B1,9B3-9B5,9BA-9BB,9BD,9C5-9C6,9C9-9CA,9CE-9D6,9D8-9DB,9DE,9E4-9E5,9FB-A01,A03-A04,A0B-A0E,'
'A11-A12,A29,A31,A34,A37,A3A-A3B,A3D,A43-A46,A49-A4A,A4E-A58,A5D,A5F-A65,A75-A80,A84,A8C,A8E,A92,AA9,AB1,'
'AB4,ABA-ABB,AC6,ACA,ACE-ACF,AD1-ADF,AE1-AE5,AF0-B00,B04,B0D-B0E,B11-B12,B29,B31,B34-B35,B3A-B3B,B44-B46,'
'B49-B4A,B4E-B55,B58-B5B,B5E,B62-B65,B71-B81,B84,B8B-B8D,B91,B96-B98,B9B,B9D,BA0-BA2,BA5-BA7,BAB-BAD,BB6,'
'BBA-BBD,BC3-BC5,BC9,BCE-BD6,BD8-BE6,BF3-C00,C04,C0D,C11,C29,C34,C3A-C3D,C45,C49,C4E-C54,C57-C5F,C62-C65,'
'C70-C81,C84,C8D,C91,CA9,CB4,CBA-CBD,CC5,CC9,CCE-CD4,CD7-CDD,CDF,CE2-CE5,CF0-D01,D04,D0D,D11,D29,D3A-D3D,'
'D44-D45,D49,D4E-D56,D58-D5F,D62-D65,D70-D81,D84,D97-D99,DB2,DBC,DBE-DBF,DC7-DC9,DCB-DCE,DD5,DD7,DE0-DF1,'
'DF5-E00,E3B-E3E,E5C-E80,E83,E85-E86,E89,E8B-E8C,E8E-E93,E98,EA0,EA4,EA6,EA8-EA9,EAC,EBA,EBE-EBF,EC5,EC7,'
'ECE-ECF,EDA-EDB,EDE-EFF,F48,F6B-F70,F8C-F8F,F98,FBD,FCD-FCE,FD0-FFF,1022,1028,102B,1033-1035,103A-103F,'
'105A-109F,10C6-10CF,10F9-10FA,10FC-10FF,115A-115E,11A3-11A7,11FA-11FF,1207,1247,1249,124E-124F,1257,'
'1259,125E-125F,1287,1289,128E-128F,12AF,12B1,12B6-12B7,12BF,12C1,12C6-12C7,12CF,12D7,12EF,130F,1311,'
'1316-1317,131F,1347,135B-1360,137D-139F,13F5-1400,1677-167F,169D-169F,16F1-16FF,170D,1715-171F,'
'1737-173F,1754-175F,176D,1771,1774-177F,17DD-17DF,17EA-17FF,180F,181A-181F,1878-187F,18AA-1DFF,'
'1E9C-1E9F,1EFA-1EFF,1F16-1F17,1F1E-1F1F,1F46-1F47,1F4E-1F4F,1F58,1F5A,1F5C,1F5E,1F7E-1F7F,1FB5,1FC5,'
'1FD4-1FD5,1FDC,1FF0-1FF1,1FF5,1FFF,2053-2056,2058-205E,2064-2069,2072-2073,208F-209F,20B2-20CF,'
'20EB-20FF,213B-213C,214C-2152,2184-218F,23CF-23FF,2427-243F,244B-245F,24FF,2614-2615,2618,267E-267F,'
'268A-2700,2705,270A-270B,2728,274C,274E,2753-2755,2757,275F-2760,2795-2797,27B0,27BF-27CF,27EC-27EF,'
'2B00-2E7F,2E9A,2EF4-2EFF,2FD6-2FEF,2FFC-2FFF,3040,3097-3098,3100-3104,312D-3130,318F,31B8-31EF,'
'321D-321F,3244-3250,327C-327E,32CC-32CF,32FF,3377-337A,33DE-33DF,33FF,4DB6-4DFF,9FA6-9FFF,A48D-A48F,'
'A4C7-ABFF,D7A4-D7FF,FA2E-FA2F,FA6B-FAFF,FB07-FB12,FB18-FB1C,FB37,FB3D,FB3F,FB42,FB45,FBB2-FBD2,'
'FD40-FD4F,FD90-FD91,FDC8-FDCF,FDFD-FDFF,FE10-FE1F,FE24-FE2F,FE47-FE48,FE53,FE67,FE6C-FE6F,FE75,'
'FEFD-FEFE,FF00,FFBF-FFC1,FFC8-FFC9,FFD0-FFD1,FFD8-FFD9,FFDD-FFDF,FFE7,FFEF-FFF8,10000-102FF,1031F,'
'10324-1032F,1034B-103FF,10426-10427,1044E-1CFFF,1D0F6-1D0FF,1D127-1D129,1D1DE-1D3FF,1D455,1D49D,'
'1D4A0-1D4A1,1D4A3-1D4A4,1D4A7-1D4A8,1D4AD,1D4BA,1D4BC,1D4C1,1D4C4,1D506,1D50B-1D50C,1D515,1D51D,1D53A,'
'1D53F,1D545,1D547-1D549,1D551,1D6A4-1D6A7,1D7CA-1D7CD,1D800-1FFFD,2A6D7-2F7FF,2FA1E-2FFFD,30000-3FFFD,'
'40000-4FFFD,50000-5FFFD,60000-6FFFD,70000-7FFFD,80000-8FFFD,90000-9FFFD,A0000-AFFFD,B0000-BFFFD,'
'C0000-CFFFD,D0000-DFFFD,E0000,E0002-E001F,E0080-EFFFD'
) -join ''
# Tables C.3 (private use), C.4 (non-characters), C.5 (surrogates), C.8 (display-changing/deprecated), U+FFFD
$prepProhibitedData = '340-341,200E-200F,202A-202E,206A-206F,D800-F8FF,FDD0-FDEF,FFFD-FFFF,1FFFE-1FFFF,2FFFE-2FFFF,3FFFE-3FFFF,4FFFE-4FFFF,5FFFE-5FFFF,6FFFE-6FFFF,7FFFE-7FFFF,8FFFE-8FFFF,9FFFE-9FFFF,AFFFE-AFFFF,BFFFE-BFFFF,CFFFE-CFFFF,DFFFE-DFFFF,EFFFE-10FFFF'
# RFC 4518 2.2: mapped to nothing (incl. every control code point it lists) and mapped to SPACE. Its
# "FF00-FE0F" for the variation selectors is a typo for FE00-FE0F.
$prepToNothingData = '0-8,E-1F,7F-84,86-9F,AD,34F,6DD,70F,1806,180B-180E,200B-200F,202A-202E,2060-2063,206A-206F,FE00-FE0F,FEFF,FFF9-FFFC,1D173-1D17A,E0001,E0020-E007F'
$prepToSpaceData = '9-D,20,85,A0,1680,2000-200A,2028-2029,202F,205F,3000'

function ConvertFrom-RangeList([string]$Data) {
    $starts = New-Object System.Collections.Generic.List[int]
    $ends = New-Object System.Collections.Generic.List[int]
    foreach ($item in $Data.Split(',')) {
        $ab = $item.Split('-')
        $starts.Add([Convert]::ToInt32($ab[0], 16)); $ends.Add([Convert]::ToInt32($ab[-1], 16))
    }
    [pscustomobject]@{ Starts = $starts.ToArray(); Ends = $ends.ToArray() }
}

function Test-InRanges([int]$Cp, $Ranges) {
    # Binary search of a sorted, non-overlapping range list
    $lo = 0; $hi = $Ranges.Starts.Length - 1
    while ($lo -le $hi) {
        $mid = ($lo + $hi) -shr 1
        if ($Cp -lt $Ranges.Starts[$mid]) { $hi = $mid - 1 }
        elseif ($Cp -gt $Ranges.Ends[$mid]) { $lo = $mid + 1 }
        else { return $true }
    }
    $false
}

function ConvertFrom-FoldTable([string]$Data) {
    $map = @{}
    foreach ($e in $Data.Split(',')) {
        if ($e.Contains('=')) {
            $kv = $e.Split('=')
            $map[[Convert]::ToInt32($kv[0], 16)] = -join @($kv[1].Split('.') | ForEach-Object { [char]::ConvertFromUtf32([Convert]::ToInt32($_, 16)) })
        } elseif ($e -match '^([0-9A-F]+)-([0-9A-F]+)/([0-9])([+-])([0-9A-F]+)$') {
            $d = [Convert]::ToInt32($Matches[5], 16)
            if ($Matches[4] -eq '-') { $d = -$d }
            for ($c = [Convert]::ToInt32($Matches[1], 16); $c -le [Convert]::ToInt32($Matches[2], 16); $c += [int]$Matches[3]) { $map[$c] = [char]::ConvertFromUtf32($c + $d) }
        } else { throw "bad RFC 3454 B.2 table entry '$e'" }
    }
    $map
}

$prepB2 = ConvertFrom-FoldTable $prepB2Data
$prepA1 = ConvertFrom-RangeList $prepA1Data
$prepProhibited = ConvertFrom-RangeList $prepProhibitedData
$prepToNothing = ConvertFrom-RangeList $prepToNothingData
$prepToSpace = ConvertFrom-RangeList $prepToSpaceData

function Get-NameValueKey($Atv) {
    # Comparison key for one attribute value under RFC 5280 7.1: RFC 4518 string preparation for
    # caseIgnoreMatch, treating values as stored strings. Values that aren't strings, TeletexString
    # (support for it is optional in RFC 5280 and its mapping to Unicode is "a local matter" in RFC 4518)
    # and strings that fail preparation are compared by their DER bytes. NFKC is .NET's, which agrees with
    # Unicode 3.2 for every assigned 3.2 character except a handful whose normalisation Unicode later corrected.
    $binary = 'bin:' + (ConvertTo-Hex $Atv.Der)
    $enc = switch ($Atv.Tag) {
        0x0C { [System.Text.UTF8Encoding]::new($false, $true) }           # UTF8String
        0x13 { $strictAscii }                                              # PrintableString
        0x16 { $strictAscii }                                              # IA5String
        0x1E { [System.Text.UnicodeEncoding]::new($true, $false, $true) }  # BMPString (UCS-2, big-endian)
        0x1C { [System.Text.UTF32Encoding]::new($true, $false, $true) }    # UniversalString (UCS-4, big-endian)
        default { $null }
    }
    if (-not $enc) { return $binary }
    try {
        $s = $enc.GetString($Atv.Value)
        # 2.2 Map: to nothing, to SPACE, then case folding with RFC 3454 B.2. A code point unassigned in
        # Unicode 3.2 would pass through mapping and normalisation unchanged and fail 2.4, so it fails here,
        # before .NET's newer Unicode data could transform it.
        $sb = New-Object System.Text.StringBuilder
        $i = 0
        while ($i -lt $s.Length) {
            $cp = [char]::ConvertToUtf32($s, $i)    # throws on a lone surrogate, which is prohibited
            $width = if ($cp -gt 0xFFFF) { 2 } else { 1 }
            if (Test-InRanges $cp $prepA1) { return $binary }
            if (Test-InRanges $cp $prepToNothing) { }
            elseif (Test-InRanges $cp $prepToSpace) { [void]$sb.Append(' ') }
            elseif ($prepB2.ContainsKey($cp)) { [void]$sb.Append($prepB2[$cp]) }
            else { [void]$sb.Append($s.Substring($i, $width)) }
            $i += $width
        }
        # 2.3 Normalize (NFKC); 2.4 Prohibit
        $p = $sb.ToString().Normalize([System.Text.NormalizationForm]::FormKC)
        $i = 0
        while ($i -lt $p.Length) {
            $cp = [char]::ConvertToUtf32($p, $i)
            if ((Test-InRanges $cp $prepA1) -or (Test-InRanges $cp $prepProhibited)) { return $binary }
            $i += $(if ($cp -gt 0xFFFF) { 2 } else { 1 })
        }
        # 2.6.1 Insignificant space handling. A space is U+0020 not followed by a combining mark. A value
        # with no non-space character becomes two SPACEs; otherwise it starts and ends with one SPACE and
        # each inner run of spaces becomes two SPACEs.
        $marks = @('NonSpacingMark', 'SpacingCombiningMark', 'EnclosingMark')
        $out = New-Object System.Text.StringBuilder
        $pending = $false; $seen = $false
        for ($i = 0; $i -lt $p.Length; $i++) {
            $isSpace = ($p[$i] -eq ' ') -and -not ($i + 1 -lt $p.Length -and ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($p, $i + 1) -in $marks))
            if ($isSpace) { if ($seen) { $pending = $true }; continue }
            if ($pending) { [void]$out.Append('  '); $pending = $false }
            [void]$out.Append($p[$i]); $seen = $true
        }
        if ($seen) { 'str: ' + $out.ToString() + ' ' } else { 'str:  ' }
    } catch { $binary }
}

function Test-NameMatch($A, $B) {
    # RFC 5280 7.1: two DNs match if they have the same number of RDNs and the RDNs match in order; two
    # RDNs match if they have the same number of attributes and each attribute has a match (same type,
    # same prepared value) in the other. Keys are compared ordinally: PowerShell's -eq/-ceq on strings
    # use culture rules, under which some different strings compare equal.
    if ($A.Count -ne $B.Count) { return $false }
    for ($r = 0; $r -lt $A.Count; $r++) {
        if (@($A[$r]).Count -ne @($B[$r]).Count) { return $false }
        $ka = [string[]]@(foreach ($atv in $A[$r]) { "$($atv.Oid)=$(Get-NameValueKey $atv)" })
        $kb = [string[]]@(foreach ($atv in $B[$r]) { "$($atv.Oid)=$(Get-NameValueKey $atv)" })
        [Array]::Sort($ka, [StringComparer]::Ordinal)
        [Array]::Sort($kb, [StringComparer]::Ordinal)
        for ($j = 0; $j -lt $ka.Length; $j++) { if (-not [string]::Equals($ka[$j], $kb[$j], [StringComparison]::Ordinal)) { return $false } }
    }
    $true
}

function Get-CertParts($Cert) {
    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
    $b = $Cert.RawData
    $top = Read-Tlv $b 0
    if ($top.Tag -ne 0x30 -or $top.End -ne $b.Length) { throw 'certificate is not exactly one DER SEQUENCE' }
    $c = Get-TlvChildren $b $top
    if ($c.Count -ne 3 -or $c[0].Tag -ne 0x30) { throw 'certificate SEQUENCE does not hold tbsCertificate, signatureAlgorithm, signatureValue' }
    $sigT = $c[2]
    if ($sigT.Tag -ne 0x03 -or $sigT.Length -lt 2) { throw 'signatureValue is not a BIT STRING' }
    $t = Get-TlvChildren $b $c[0]
    $i = 0
    if ($t.Count -gt 0 -and $t[0].Tag -eq 0xA0) { $i = 1 }
    if ($t.Count -lt $i + 6) { throw 'tbsCertificate has too few fields' }
    $serialT = $t[$i]
    if ($serialT.Tag -ne 0x02 -or $serialT.Length -lt 1) { throw 'serialNumber is not an INTEGER' }
    if ($t[$i + 2].Tag -ne 0x30) { throw 'issuer is not a SEQUENCE' }
    if ($t[$i + 3].Tag -ne 0x30) { throw 'validity is not a SEQUENCE' }
    if ($t[$i + 5].Tag -ne 0x30) { throw 'subjectPublicKeyInfo is not a SEQUENCE' }
    $spki = Get-TlvChildren $b $t[$i + 5]
    if ($spki.Count -ne 2 -or $spki[1].Tag -ne 0x03 -or $spki[1].Length -lt 1) { throw 'malformed SubjectPublicKeyInfo' }
    # Anything after the SPKI must be, in order: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
    $hasUniqueIds = $false
    $lastOptional = 0
    for ($n = $i + 6; $n -lt $t.Count; $n++) {
        $o = switch ($t[$n].Tag) { 0x81 { 1 } 0x82 { 2 } 0xA3 { 3 } default { -1 } }
        if ($o -le $lastOptional) { throw ('unexpected, repeated or out-of-order field (tag 0x{0:X2}) in tbsCertificate' -f $t[$n].Tag) }
        $lastOptional = $o
        if ($o -lt 3) { $hasUniqueIds = $true }
    }

    $outer = Read-AlgId $b $c[1]
    $tbsBytes = Get-TlvEncoding $b $c[0]
    $sigBytes = Get-Slice $b ($sigT.Start + 1) ($sigT.Length - 1)
    $serial = Get-Slice $b $serialT.Start $serialT.Length
    $issuerName = Read-Name $b $t[$i + 2]
    $subjectName = Read-Name $b $t[$i + 4]
    [pscustomobject]@{
        Tbs            = $tbsBytes
        OuterAlg       = $outer
        InnerAlg       = (Read-AlgId $b $t[$i + 1])
        SpkiAlg        = (Read-AlgId $b $spki[0])
        SpkiUnusedBits = [int]$b[$spki[1].Start]
        SpkiKey        = (Get-Slice $b ($spki[1].Start + 1) ($spki[1].Length - 1))   # subjectPublicKey, without the unused-bits octet
        Scheme         = (Get-SigScheme $outer)
        UnusedBits     = [int]$b[$sigT.Start]
        Signature      = $sigBytes
        Serial         = $serial
        IssuerName     = $issuerName
        IssuerNameDer  = (Get-TlvEncoding $b $t[$i + 2])
        SubjectName    = $subjectName
        SubjectNameDer = (Get-TlvEncoding $b $t[$i + 4])
        SubjectAttrs   = @(foreach ($rdn in $subjectName) { foreach ($atv in $rdn) { $atv.Oid } })
        HasUniqueIds   = $hasUniqueIds
    }
}

# ======================= Loading certificates =======================
function Resolve-InputFile([string]$File) {
    # FileInfo.FullName is a plain file-system path. (Resolve-Path).Path is not: it keeps PowerShell
    # drive names ("Work:\ca.cer") and adds a provider prefix to UNC paths, which .NET can't open.
    $item = Get-Item -LiteralPath $File -Force
    if ($item -isnot [System.IO.FileInfo]) { throw "'$File' is not a file." }
    $item.FullName
}

function Get-Cert([string]$File) {
    # The file is decoded here instead of being handed to the X509Certificate2(path) constructor, which
    # also accepts PFX/PKCS#7 files (importing a PFX's private key into the key store) and silently
    # drops trailing data and any further certificates in a PEM file.
    $bytes = [System.IO.File]::ReadAllBytes($File)
    if ($bytes.Length -eq 0) { throw "'$File' is empty." }
    if ($bytes[0] -ne 0x30) {
        # PEM or bare Base64. ReadAllText honours a UTF-8/UTF-16/UTF-32 byte order mark, so a file saved
        # by Windows PowerShell 5.1's Out-File (UTF-16) is read correctly.
        $text = [System.IO.File]::ReadAllText($File)
        $pem = [regex]::Matches($text, '-----BEGIN (?:X509 )?CERTIFICATE-----(?<b64>[^-]*)-----END (?:X509 )?CERTIFICATE-----')
        if ($pem.Count -gt 0) {
            if ($pem.Count -gt 1) { Add-Finding @{ GEN = 'INFO' } "$(Split-Path -Leaf $File) holds $($pem.Count) PEM certificates; only the first one was inspected." -Coverage }
            $b64 = $pem[0].Groups['b64'].Value
        } elseif ($text -match '-----BEGIN ([A-Z0-9 ]+)-----') {
            throw "'$File' holds a PEM '$($Matches[1])' block, not a CERTIFICATE."
        } else { $b64 = $text }
        try { $bytes = [Convert]::FromBase64String(($b64 -replace '\s', '')) }
        catch { throw "'$File' is not a DER or PEM/Base64 certificate." }
        if ($bytes.Length -eq 0) { throw "'$File' holds an empty certificate." }
    }
    # Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm SEQUENCE, signatureValue BIT STRING }
    try {
        $top = Read-Tlv $bytes 0
        if ($top.Tag -ne 0x30) { throw 'it does not start with a SEQUENCE' }
        $kids = Get-TlvChildren $bytes $top
    } catch { throw "'$File' is not a DER certificate: $($_.Exception.Message)" }
    if ($kids.Count -ne 3 -or $kids[0].Tag -ne 0x30 -or $kids[1].Tag -ne 0x30 -or $kids[2].Tag -ne 0x03) {
        $hint = ''
        if ($kids.Count -ge 1 -and $kids[0].Tag -eq 0x02) { $hint = ' It looks like a PKCS#12/PFX file.' }
        elseif ($kids.Count -ge 1 -and $kids[0].Tag -eq 0x06) { $hint = ' It looks like a PKCS#7 (.p7b) or other CMS file.' }
        throw "'$File' is not an X.509 certificate.$hint Export the single certificate as a DER or Base64 .cer file."
    }
    if ($top.End -lt $bytes.Length) {
        Add-Finding @{ GEN = 'INFO' } "$(Split-Path -Leaf $File) has $($bytes.Length - $top.End) byte(s) of data after the certificate; they were ignored." -Coverage
        $bytes = Get-Slice $bytes 0 $top.End
    }
    try {
        # .NET 9+: X509CertificateLoader only ever loads a certificate; the X509Certificate2 constructors are obsolete there
        $loader = 'System.Security.Cryptography.X509Certificates.X509CertificateLoader' -as [type]
        if ($loader) { $loader::LoadCertificate($bytes) }
        else { [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes) }
    } catch { throw "'$File' could not be loaded by .NET: $($_.Exception.GetBaseException().Message.Trim().TrimEnd('.'))" }
}

# ======================= Keys and signatures =======================
# NIST prime curves (FIPS 186-4 D.1.2, SEC 2): field prime p and coefficient b; a = p - 3 for all three
$nistCurves = @{
    'P-256' = @{ Oid = '1.2.840.10045.3.1.7'; Bits = 256; Bytes = 32
                 P = 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'
                 B = '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B' }
    'P-384' = @{ Oid = '1.3.132.0.34'; Bits = 384; Bytes = 48
                 P = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF'
                 B = 'B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF' }
    'P-521' = @{ Oid = '1.3.132.0.35'; Bits = 521; Bytes = 66
                 P = '01' + ('FF' * 65)
                 B = '0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00' }
}

function Read-RsaPublicKey([byte[]]$Key) {
    # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } (RFC 3279 2.3.1)
    $seq = Read-Tlv $Key 0
    if ($seq.Tag -ne 0x30 -or $seq.End -ne $Key.Length) { throw 'RSAPublicKey is not exactly one DER SEQUENCE' }
    $f = Get-TlvChildren $Key $seq
    if ($f.Count -ne 2) { throw 'RSAPublicKey does not hold exactly a modulus and a publicExponent' }
    [pscustomobject]@{ Modulus = (Read-UnsignedInt $Key $f[0] 'the modulus'); Exponent = (Read-UnsignedInt $Key $f[1] 'the public exponent') }
}

function Test-EcPoint([byte[]]$Point, $Curve) {
    # Public-key validation for a NIST prime curve (SEC 1 3.2.2.1, NIST SP 800-56A 5.6.2.3.3): the point
    # must decode, have coordinates in [0, p-1] and satisfy y^2 = x^3 - 3x + b (mod p). These curves have
    # cofactor 1, so any such point (it can't be the identity) has the full prime order.
    $r = [ordered]@{ Error = $null; Compressed = $false }
    try {
        $BI = [System.Numerics.BigInteger]
        $hex = [System.Globalization.NumberStyles]::AllowHexSpecifier
        $p = $BI::Parse('0' + $Curve.P, $hex)
        $b = $BI::Parse('0' + $Curve.B, $hex)
        $L = $Curve.Bytes
        if ($Point.Length -eq 0) { throw 'the key is empty' }
        $fmt = [int]$Point[0]
        $rhsOf = { param($x) $BI::Remainder($BI::Add($BI::Add($BI::ModPow($x, 3, $p), $BI::Multiply($BI::Subtract($p, 3), $x)), $b), $p) }
        if ($Point.Length -eq 1 -and $fmt -eq 0) { throw 'it is the point at infinity' }
        if ($fmt -eq 4) {
            if ($Point.Length -ne 1 + 2 * $L) { throw "an uncompressed point must be $(1 + 2 * $L) octets, not $($Point.Length)" }
            $x = ConvertTo-BigInt (Get-Slice $Point 1 $L)
            $y = ConvertTo-BigInt (Get-Slice $Point (1 + $L) $L)
        } elseif ($fmt -in 2, 3) {
            $r.Compressed = $true
            if ($Point.Length -ne 1 + $L) { throw "a compressed point must be $(1 + $L) octets, not $($Point.Length)" }
            $x = ConvertTo-BigInt (Get-Slice $Point 1 $L)
            if ($x -ge $p) { throw 'x is not less than the field prime' }
            # p = 3 (mod 4) for all three curves, so a square root of a is a^((p+1)/4)
            $rhs = & $rhsOf $x
            $y = $BI::ModPow($rhs, $BI::Divide($BI::Add($p, 1), 4), $p)
            if ($BI::Remainder($BI::Multiply($y, $y), $p) -ne $rhs) { throw 'x is not the x-coordinate of any point on the curve' }
            if ($y.IsEven -ne ($fmt -eq 2)) { $y = $BI::Subtract($p, $y) }
        } elseif ($fmt -in 6, 7) { throw 'it uses the hybrid point form, which RFC 5480 2.2 prohibits' }
        else { throw ('the point format octet is 0x{0:X2}; only 04 (uncompressed) and 02/03 (compressed) are valid (RFC 5480 2.2)' -f $fmt) }
        if ($x -ge $p -or $y -ge $p) { throw 'a coordinate is not less than the field prime' }
        if ($BI::Remainder($BI::Multiply($y, $y), $p) -ne (& $rhsOf $x)) { throw 'the point is not on the curve' }
    } catch { $r.Error = $_.Exception.Message }
    [pscustomobject]$r
}

function Get-KeyInfo($Cert, $Parts) {
    # Decodes and validates the subjectPublicKey from the certificate's own DER.
    #   Invalid       - the key is malformed or mathematically invalid, so the certificate is unusable
    #   PlatformError - .NET on this machine can't load a key that decoded and validated correctly
    $info = [ordered]@{ Algorithm = $null; KeySize = $null; Curve = $null; CurveOid = $null; Exponent = $null; ExponentBytes = $null
                        ExponentOdd = $null; Compressed = $false; Invalid = $null; PlatformError = $null }
    $algOid = $Parts.SpkiAlg.Oid
    $keyBits = $Parts.SpkiKey
    $loadKey = $null   # .NET loader to try once the key has validated
    switch ($algOid) {
        '1.2.840.113549.1.1.1' {
            $info.Algorithm = 'RSA'
            try {
                if ($Parts.SpkiUnusedBits) { throw "the subjectPublicKey BIT STRING declares $($Parts.SpkiUnusedBits) unused bits" }
                $k = Read-RsaPublicKey $keyBits
                # Exact modulus bit length (a provider's KeySize may be rounded, hiding a non-multiple-of-8 modulus)
                $info.KeySize = Get-BitLength $k.Modulus
                $info.ExponentBytes = $k.Exponent.Length
                $info.ExponentOdd = [bool]($k.Exponent[-1] -band 1)
                if ($k.Exponent.Length -le 7) { [long]$e = 0; foreach ($byte in $k.Exponent) { $e = $e * 256 + $byte }; $info.Exponent = $e }
                else { $info.Exponent = '0x' + (ConvertTo-Hex $k.Exponent) }
                if (-not ($k.Modulus[-1] -band 1)) { throw 'the modulus is even, so it is not a product of two odd primes' }
                if ((ConvertTo-BigInt $k.Exponent) -ge (ConvertTo-BigInt $k.Modulus)) { throw 'the public exponent is not smaller than the modulus' }
            } catch { $info.Invalid = $_.Exception.Message }
            $loadKey = { [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Cert) }
        }
        '1.2.840.10045.2.1' {
            $info.Algorithm = 'ECDSA'
            # The namedCurve OID comes straight from the SPKI parameters (.NET's ECParameters.Curve.Oid.Value
            # is $null on Windows PowerShell 5.1, because CNG only sets FriendlyName)
            $prm = $Parts.SpkiAlg.Params
            if ($prm -and $prm.Tag -eq 0x06) { $info.CurveOid = ConvertFrom-DerOid (Get-TlvEncoding $Parts.SpkiAlg.Source $prm) }
            $named = @($nistCurves.Keys | Where-Object { $nistCurves[$_].Oid -eq $info.CurveOid })
            if ($info.CurveOid -and $named.Count) {
                $info.Curve = $named[0]
                $info.KeySize = $nistCurves[$info.Curve].Bits
                if ($Parts.SpkiUnusedBits) { $info.Invalid = "the subjectPublicKey BIT STRING declares $($Parts.SpkiUnusedBits) unused bits" }
                else {
                    $pt = Test-EcPoint $keyBits $nistCurves[$info.Curve]
                    $info.Compressed = $pt.Compressed
                    if ($pt.Error) { $info.Invalid = "the EC public key is not a valid $($info.Curve) point: $($pt.Error)" }
                }
                $loadKey = { [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Cert) }
            } else {
                $info.Curve = if ($info.CurveOid) { 'Unrecognised / not a NIST named curve' } else { 'Not a namedCurve (explicit/implicit parameters)' }
                # Best effort only: the size is informational, and the curve findings come from the OID
                $ec = $null
                try {
                    $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Cert)
                    $info.KeySize = $ec.KeySize
                } catch { } finally { if ($ec) { $ec.Dispose() } }
            }
        }
        default {
            $names = @{ '2.16.840.1.101.3.4.3.17' = 'ML-DSA-44'; '2.16.840.1.101.3.4.3.18' = 'ML-DSA-65'; '2.16.840.1.101.3.4.3.19' = 'ML-DSA-87'
                        '1.3.101.112' = 'Ed25519'; '1.3.101.113' = 'Ed448'; '1.2.840.10040.4.1' = 'DSA'; '1.2.840.113549.1.1.10' = 'RSASSA-PSS' }
            $info.Algorithm = if ($names.ContainsKey($algOid)) { $names[$algOid] } else { "Other ($(([System.Security.Cryptography.Oid]::new($algOid)).FriendlyName) $algOid)" }
        }
    }
    if ($loadKey -and -not $info.Invalid) {
        $obj = $null
        try {
            $obj = & $loadKey
            if (-not $obj) { throw 'no key was returned' }
        } catch { $info.PlatformError = $_.Exception.GetBaseException().Message.Trim().TrimEnd('.') }
        finally { if ($obj) { $obj.Dispose() } }
    }
    [pscustomobject]$info
}

function ConvertTo-P1363([byte[]]$DerSig, [int]$FieldBytes) {
    # Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } -> r||s, each left-padded to the field size
    $seq = Read-Tlv $DerSig 0
    if ($seq.Tag -ne 0x30 -or $seq.End -ne $DerSig.Length) { throw 'ECDSA signature is not exactly one DER SEQUENCE' }
    $ints = Get-TlvChildren $DerSig $seq
    if ($ints.Count -ne 2 -or $ints[0].Tag -ne 0x02 -or $ints[1].Tag -ne 0x02) { throw 'ECDSA signature is not SEQUENCE { r INTEGER, s INTEGER }' }
    $out = New-Object byte[] (2 * $FieldBytes)
    for ($n = 0; $n -lt 2; $n++) {
        # r and s must be positive and minimally encoded (RFC 5480 / X.690 DER)
        $v = Read-UnsignedInt $DerSig $ints[$n] "ECDSA $(@('r', 's')[$n])"
        if ($v.Length -gt $FieldBytes) { throw 'ECDSA r or s is larger than the curve order' }
        [Array]::Copy($v, 0, $out, ($n + 1) * $FieldBytes - $v.Length, $v.Length)
    }
    , $out
}

function Test-CertSignature($Parts, $Signer) {
    # Verifies $Parts' signature with $Signer's public key. Result: Valid, Invalid or Unverifiable.
    $out = [ordered]@{ Result = 'Unverifiable'; Reason = $null }
    $sch = $Parts.Scheme
    if ($sch.Kind -notin @('RSA-PKCS1', 'RSA-PSS', 'ECDSA')) { $out.Reason = "$($sch.Name) is not supported for verification"; return [pscustomobject]$out }
    if ($sch.PssError) { $out.Reason = "the RSASSA-PSS parameters are malformed ($($sch.PssError))"; return [pscustomobject]$out }
    if ($sch.Hash -notin @('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')) { $out.Reason = "hash $($sch.Hash) is not supported by .NET"; return [pscustomobject]$out }
    if ($Parts.UnusedBits -ne 0) { $out.Result = 'Invalid'; $out.Reason = 'signatureValue BIT STRING has unused bits'; return [pscustomobject]$out }
    if ($sch.Kind -eq 'RSA-PSS') {
        $p = $sch.Pss
        if ($p.MgfOid -ne '1.2.840.113549.1.1.8' -or $p.MgfHash -ne $p.Hash -or $p.Salt -ne $hashLen[$p.Hash] -or $p.Trailer -ne 1) {
            $out.Reason = '.NET can only verify RSASSA-PSS that uses MGF1 with the same hash and salt length = hash length'
            return [pscustomobject]$out
        }
    }
    $keyOid = $Signer.PublicKey.Oid.Value
    if ($keyOid -eq '1.2.840.113549.1.1.10') {
        # id-RSASSA-PSS SubjectPublicKeyInfo: an RSA key restricted to PSS, which .NET can't load
        if ($sch.Kind -eq 'RSA-PKCS1') { $out.Result = 'Invalid'; $out.Reason = 'PKCS#1 v1.5 signature, but the signer key is restricted to RSASSA-PSS (RFC 4055)' }
        else { $out.Reason = '.NET cannot load RSASSA-PSS (id-RSASSA-PSS) public keys' }
        return [pscustomobject]$out
    }
    $rsa = $null; $ec = $null
    try {
        $han = New-Object System.Security.Cryptography.HashAlgorithmName -ArgumentList $sch.Hash
        if ($sch.Kind -like 'RSA-*') {
            if ($keyOid -ne '1.2.840.113549.1.1.1') { $out.Result = 'Invalid'; $out.Reason = "RSA signature but the signer key is not RSA ($keyOid)"; return [pscustomobject]$out }
            $pad = if ($sch.Kind -eq 'RSA-PSS') { [System.Security.Cryptography.RSASignaturePadding]::Pss } else { [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 }
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Signer)
            $ok = $rsa.VerifyData($Parts.Tbs, $Parts.Signature, $han, $pad)
        } else {
            if ($keyOid -ne '1.2.840.10045.2.1') { $out.Result = 'Invalid'; $out.Reason = "ECDSA signature but the signer key is not EC ($keyOid)"; return [pscustomobject]$out }
            $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Signer)
            try { $p1363 = ConvertTo-P1363 $Parts.Signature ([int][math]::Ceiling($ec.KeySize / 8)) }
            catch { $out.Result = 'Invalid'; $out.Reason = $_.Exception.Message; return [pscustomobject]$out }
            $ok = $ec.VerifyData($Parts.Tbs, $p1363, $han)
        }
        if ($ok) { $out.Result = 'Valid' } else { $out.Result = 'Invalid'; $out.Reason = 'signature does not verify' }
    } catch { $out.Reason = $_.Exception.GetBaseException().Message.Trim().TrimEnd('.') }
    finally {
        if ($rsa) { $rsa.Dispose() }
        if ($ec) { $ec.Dispose() }
    }
    [pscustomobject]$out
}

function Get-AkiInfo([byte[]]$Raw) {
    # AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL, authorityCertIssuer [1] OPTIONAL,
    #                                       authorityCertSerialNumber [2] OPTIONAL }
    $info = [ordered]@{ KeyId = $null; HasKeyId = $false; HasIssuer = $false; HasSerial = $false; Empty = $false; Error = $null }
    try {
        $seq = Read-Tlv $Raw 0
        if ($seq.Tag -ne 0x30 -or $seq.End -ne $Raw.Length) { throw 'not exactly one DER SEQUENCE' }
        $fields = Get-TlvChildren $Raw $seq
        $info.Empty = ($fields.Count -eq 0)
        $last = -1
        foreach ($t in $fields) {
            $n = switch ($t.Tag) { 0x80 { 0 } 0xA1 { 1 } 0x82 { 2 } default { -1 } }
            if ($n -lt 0) { throw ('unexpected tag 0x{0:X2}' -f $t.Tag) }
            if ($n -le $last) { throw 'fields repeated or out of order' }
            $last = $n
            if ($n -eq 0) {
                if ($t.Length -eq 0) { throw 'keyIdentifier is empty' }
                $info.HasKeyId = $true
                $info.KeyId = ConvertTo-Hex (Get-Slice $Raw $t.Start $t.Length)
            }
            elseif ($n -eq 1) { $info.HasIssuer = $true }
            else { $info.HasSerial = $true }
        }
        if ($info.HasIssuer -ne $info.HasSerial) { throw 'authorityCertIssuer and authorityCertSerialNumber must be both present or both absent' }
    } catch { $info.Error = $_.Exception.Message }
    [pscustomobject]$info
}

# Extension values are decoded with the strict DER reader rather than the .NET extension classes:
# those throw on malformed input in PowerShell 7 (ending the run), but in Windows PowerShell 5.1 they
# quietly return defaults (a malformed basicConstraints reads as cA = FALSE). Each decoder returns
# Error for content that can't be interpreted, and DerIssue for content that can be read but isn't DER.
function Read-Ski([byte[]]$Raw) {
    # SubjectKeyIdentifier ::= KeyIdentifier ::= OCTET STRING
    $r = [ordered]@{ KeyId = $null; Error = $null }
    try {
        $t = Read-Tlv $Raw 0
        if ($t.Tag -ne 0x04 -or $t.End -ne $Raw.Length) { throw 'not exactly one DER OCTET STRING' }
        $r.KeyId = ConvertTo-Hex (Get-Slice $Raw $t.Start $t.Length)
    } catch { $r.Error = $_.Exception.Message }
    [pscustomobject]$r
}

function Read-BasicConstraints([byte[]]$Raw) {
    # BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }
    $r = [ordered]@{ CA = $false; HasPathLen = $false; PathLen = $null; DerIssue = $null; Error = $null }
    try {
        $seq = Read-Tlv $Raw 0
        if ($seq.Tag -ne 0x30 -or $seq.End -ne $Raw.Length) { throw 'not exactly one DER SEQUENCE' }
        $f = Get-TlvChildren $Raw $seq
        $n = 0
        if ($n -lt $f.Count -and $f[$n].Tag -eq 0x01) {
            if ($f[$n].Length -ne 1) { throw 'cA BOOLEAN is not one octet' }
            $v = $Raw[$f[$n].Start]
            $r.CA = ($v -ne 0)
            if ($v -eq 0) { $r.DerIssue = 'cA is encoded explicitly as FALSE; DER requires a DEFAULT value to be omitted' }
            elseif ($v -ne 0xFF) { $r.DerIssue = ('cA TRUE is encoded as 0x{0:X2}; DER requires 0xFF' -f $v) }
            $n++
        }
        if ($n -lt $f.Count -and $f[$n].Tag -eq 0x02) { $r.PathLen = Read-SmallInt $Raw $f[$n]; $r.HasPathLen = $true; $n++ }
        if ($n -ne $f.Count) { throw 'unexpected or out-of-order field' }
    } catch { $r.Error = $_.Exception.Message }
    [pscustomobject]$r
}

function Read-KeyUsage([byte[]]$Raw) {
    # KeyUsage ::= BIT STRING { digitalSignature (0), nonRepudiation (1), keyEncipherment (2), dataEncipherment (3),
    #                           keyAgreement (4), keyCertSign (5), cRLSign (6), encipherOnly (7), decipherOnly (8) }
    $names = @('DigitalSignature', 'NonRepudiation', 'KeyEncipherment', 'DataEncipherment', 'KeyAgreement', 'KeyCertSign', 'CrlSign', 'EncipherOnly', 'DecipherOnly')
    $r = [ordered]@{ Bits = @(); DerIssue = $null; Error = $null }
    try {
        $t = Read-Tlv $Raw 0
        if ($t.Tag -ne 0x03 -or $t.End -ne $Raw.Length -or $t.Length -lt 1) { throw 'not exactly one DER BIT STRING' }
        $unused = [int]$Raw[$t.Start]
        $nBits = ($t.Length - 1) * 8 - $unused
        if ($unused -gt 7 -or $nBits -lt 0) { throw "invalid unused-bits count ($unused)" }
        $set = @(for ($b = 0; $b -lt $nBits; $b++) {
            if ($Raw[$t.Start + 1 + ($b -shr 3)] -band (0x80 -shr ($b -band 7))) { $b }
        })
        if ($unused -and ($Raw[$t.End - 1] -band ((1 -shl $unused) - 1))) { $r.DerIssue = 'its unused bits are not zero' }
        elseif ($nBits -gt 0 -and $set -notcontains ($nBits - 1)) { $r.DerIssue = 'it has trailing zero bits, which DER requires to be removed' }
        $r.Bits = @($set | ForEach-Object { if ($_ -lt $names.Count) { $names[$_] } else { "UndefinedBit$_" } })
    } catch { $r.Error = $_.Exception.Message }
    [pscustomobject]$r
}

function Read-Eku([byte[]]$Raw) {
    # ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId (OBJECT IDENTIFIER)
    $r = [ordered]@{ Oids = @(); Error = $null }
    try {
        $seq = Read-Tlv $Raw 0
        if ($seq.Tag -ne 0x30 -or $seq.End -ne $Raw.Length) { throw 'not exactly one DER SEQUENCE' }
        $kids = Get-TlvChildren $Raw $seq
        if ($kids.Count -eq 0) { throw 'empty SEQUENCE; at least one KeyPurposeId is required' }
        $r.Oids = @(foreach ($kid in $kids) {
            $o = $null
            if ($kid.Tag -eq 0x06) { $o = ConvertFrom-DerOid (Get-TlvEncoding $Raw $kid) }
            if (-not $o) { throw 'a KeyPurposeId is not a valid OBJECT IDENTIFIER' }
            $o
        })
    } catch { $r.Error = $_.Exception.Message }
    [pscustomobject]$r
}

function ConvertFrom-GeneralName([byte[]]$Raw, $G) {
    # GeneralName: the tag, and the text of a uniformResourceIdentifier [6] IA5String ($null if not ASCII)
    $uri = $null
    if ($G.Tag -eq 0x86) { try { $uri = $strictAscii.GetString((Get-Slice $Raw $G.Start $G.Length)) } catch { } }
    [pscustomobject]@{ Tag = $G.Tag; Uri = $uri; Der = (ConvertTo-Hex (Get-TlvEncoding $Raw $G)) }
}

function Read-GeneralNames([byte[]]$Raw, $T) {
    # GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName (here IMPLICITly tagged, so $T's tag varies)
    $names = @(foreach ($g in (Get-TlvChildren $Raw $T)) { ConvertFrom-GeneralName $Raw $g })
    if ($names.Count -eq 0) { throw 'empty GeneralNames' }
    , $names
}

function Read-Cdp([byte[]]$Raw) {
    # CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
    # DistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL,
    #                                  reasons [1] ReasonFlags OPTIONAL, cRLIssuer [2] GeneralNames OPTIONAL }
    # DistributionPointName ::= CHOICE { fullName [0] GeneralNames, nameRelativeToCRLIssuer [1] RDN }
    $r = [ordered]@{ Points = @(); Error = $null }
    try {
        $seq = Read-Tlv $Raw 0
        if ($seq.Tag -ne 0x30 -or $seq.End -ne $Raw.Length) { throw 'not exactly one DER SEQUENCE' }
        $dps = Get-TlvChildren $Raw $seq
        if ($dps.Count -eq 0) { throw 'it holds no DistributionPoint' }
        $r.Points = @(foreach ($dp in $dps) {
            if ($dp.Tag -ne 0x30) { throw 'a DistributionPoint is not a SEQUENCE' }
            $point = [ordered]@{ NameForm = $null; Names = @(); HasReasons = $false; HasCrlIssuer = $false }
            $last = -1
            foreach ($f in (Get-TlvChildren $Raw $dp)) {
                $n = switch ($f.Tag) { 0xA0 { 0 } 0x81 { 1 } 0xA2 { 2 } default { -1 } }
                if ($n -le $last) { throw ('unexpected, repeated or out-of-order field (tag 0x{0:X2}) in a DistributionPoint' -f $f.Tag) }
                $last = $n
                if ($n -eq 0) {
                    $c = Get-TlvChildren $Raw $f
                    if ($c.Count -ne 1) { throw 'distributionPoint does not hold exactly one DistributionPointName' }
                    if ($c[0].Tag -eq 0xA0) { $point.NameForm = 'fullName'; $point.Names = Read-GeneralNames $Raw $c[0] }
                    elseif ($c[0].Tag -eq 0xA1) { $point.NameForm = 'nameRelativeToCRLIssuer' }
                    else { throw 'unknown DistributionPointName form' }
                }
                elseif ($n -eq 1) { $point.HasReasons = $true }
                else { $point.HasCrlIssuer = $true; [void](Read-GeneralNames $Raw $f) }
            }
            [pscustomobject]$point
        })
    } catch { $r.Error = $_.Exception.Message }
    [pscustomobject]$r
}

function Read-Aia([byte[]]$Raw) {
    # AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
    # AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName }
    $r = [ordered]@{ Entries = @(); Error = $null }
    try {
        $seq = Read-Tlv $Raw 0
        if ($seq.Tag -ne 0x30 -or $seq.End -ne $Raw.Length) { throw 'not exactly one DER SEQUENCE' }
        $ads = Get-TlvChildren $Raw $seq
        if ($ads.Count -eq 0) { throw 'it holds no AccessDescription' }
        $r.Entries = @(foreach ($ad in $ads) {
            if ($ad.Tag -ne 0x30) { throw 'an AccessDescription is not a SEQUENCE' }
            $f = Get-TlvChildren $Raw $ad
            if ($f.Count -ne 2 -or $f[0].Tag -ne 0x06) { throw 'malformed AccessDescription' }
            $method = ConvertFrom-DerOid (Get-TlvEncoding $Raw $f[0])
            if (-not $method) { throw 'an accessMethod is not a valid OBJECT IDENTIFIER' }
            $g = ConvertFrom-GeneralName $Raw $f[1]
            [pscustomobject]@{ Method = $method; Tag = $g.Tag; Uri = $g.Uri; LocationDer = $g.Der }
        })
    } catch { $r.Error = $_.Exception.Message }
    [pscustomobject]$r
}

function Read-CertPolicies([byte[]]$Raw) {
    # certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
    # PolicyInformation ::= SEQUENCE { policyIdentifier OBJECT IDENTIFIER,
    #                                  policyQualifiers SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
    # PolicyQualifierInfo ::= SEQUENCE { policyQualifierId OBJECT IDENTIFIER, qualifier ANY }
    $r = [ordered]@{ Policies = @(); Error = $null }
    try {
        $seq = Read-Tlv $Raw 0
        if ($seq.Tag -ne 0x30 -or $seq.End -ne $Raw.Length) { throw 'not exactly one DER SEQUENCE' }
        $infos = Get-TlvChildren $Raw $seq
        if ($infos.Count -eq 0) { throw 'it holds no PolicyInformation' }
        $r.Policies = @(foreach ($info in $infos) {
            if ($info.Tag -ne 0x30) { throw 'a PolicyInformation is not a SEQUENCE' }
            $f = Get-TlvChildren $Raw $info
            if ($f.Count -lt 1 -or $f.Count -gt 2 -or $f[0].Tag -ne 0x06) { throw 'malformed PolicyInformation' }
            $oid = ConvertFrom-DerOid (Get-TlvEncoding $Raw $f[0])
            if (-not $oid) { throw 'a policyIdentifier is not a valid OBJECT IDENTIFIER' }
            $quals = @()
            if ($f.Count -eq 2) {
                if ($f[1].Tag -ne 0x30) { throw 'policyQualifiers is not a SEQUENCE' }
                $qs = Get-TlvChildren $Raw $f[1]
                if ($qs.Count -eq 0) { throw 'policyQualifiers is empty' }
                $quals = @(foreach ($q in $qs) {
                    if ($q.Tag -ne 0x30) { throw 'a PolicyQualifierInfo is not a SEQUENCE' }
                    $qf = Get-TlvChildren $Raw $q
                    if ($qf.Count -ne 2 -or $qf[0].Tag -ne 0x06) { throw 'malformed PolicyQualifierInfo' }
                    $qid = ConvertFrom-DerOid (Get-TlvEncoding $Raw $qf[0])
                    if (-not $qid) { throw 'a policyQualifierId is not a valid OBJECT IDENTIFIER' }
                    $text = $null
                    if ($qf[1].Tag -eq 0x16) { try { $text = $strictAscii.GetString((Get-Slice $Raw $qf[1].Start $qf[1].Length)) } catch { } }
                    [pscustomobject]@{ Id = $qid; Tag = $qf[1].Tag; Text = $text }
                })
            }
            [pscustomobject]@{ Oid = $oid; Qualifiers = $quals }
        })
    } catch { $r.Error = $_.Exception.Message }
    [pscustomobject]$r
}

function Read-NameConstraints([byte[]]$Raw) {
    # NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL,
    #                                excludedSubtrees  [1] GeneralSubtrees OPTIONAL }
    # GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
    # GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] BaseDistance DEFAULT 0, maximum [1] BaseDistance OPTIONAL }
    # Error: can't be parsed. Issues: RFC 5280 4.2.1.10 MUSTs broken. Discouraged: name forms CAs SHOULD NOT constrain.
    # Permitted/Excluded: each constraint in readable form, for the report
    $r = [ordered]@{ Permitted = @(); Excluded = @(); Issues = @(); Discouraged = @(); Error = $null }
    $issues = New-Object System.Collections.Generic.List[string]
    $discouraged = New-Object System.Collections.Generic.List[string]
    $shown = @((New-Object System.Collections.Generic.List[string]), (New-Object System.Collections.Generic.List[string]))
    $forms = @{ 0xA0 = 'otherName'; 0x81 = 'rfc822Name'; 0x82 = 'dNSName'; 0xA3 = 'x400Address'; 0xA4 = 'directoryName'
                0xA5 = 'ediPartyName'; 0x86 = 'uniformResourceIdentifier'; 0x87 = 'iPAddress'; 0x88 = 'registeredID' }
    try {
        $seq = Read-Tlv $Raw 0
        if ($seq.Tag -ne 0x30 -or $seq.End -ne $Raw.Length) { throw 'not exactly one DER SEQUENCE' }
        $last = -1
        foreach ($f in (Get-TlvChildren $Raw $seq)) {
            $n = switch ($f.Tag) { 0xA0 { 0 } 0xA1 { 1 } default { -1 } }
            if ($n -le $last) { throw ('unexpected, repeated or out-of-order field (tag 0x{0:X2})' -f $f.Tag) }
            $last = $n
            $which = @('permittedSubtrees', 'excludedSubtrees')[$n]
            $subtrees = Get-TlvChildren $Raw $f
            if ($subtrees.Count -eq 0) { throw "$which is empty (GeneralSubtrees needs at least one GeneralSubtree)" }
            foreach ($st in $subtrees) {
                if ($st.Tag -ne 0x30) { throw "a GeneralSubtree in $which is not a SEQUENCE" }
                $sf = Get-TlvChildren $Raw $st
                if ($sf.Count -lt 1) { throw "a GeneralSubtree in $which has no base" }
                $base = $sf[0]
                $k = 1
                if ($k -lt $sf.Count -and $sf[$k].Tag -eq 0x80) {
                    # minimum [0] IMPLICIT INTEGER, read as an INTEGER
                    $v = Read-SmallInt $Raw ([pscustomobject]@{ Tag = 0x02; Start = $sf[$k].Start; End = $sf[$k].End; Length = $sf[$k].Length })
                    if ($v -eq 0) { $issues.Add("a $which entry encodes minimum 0 explicitly (DER requires the DEFAULT to be omitted)") }
                    else { $issues.Add("a $which entry has minimum $v (MUST be zero)") }
                    $k++
                }
                if ($k -lt $sf.Count -and $sf[$k].Tag -eq 0x81) { $issues.Add("a $which entry has a maximum (MUST be absent)"); $k++ }
                if ($k -ne $sf.Count) { throw "unexpected field in a GeneralSubtree in $which" }
                if (-not $forms.ContainsKey($base.Tag)) { throw ('a constraint in {0} has an unknown GeneralName tag 0x{1:X2}' -f $which, $base.Tag) }
                $form = $forms[$base.Tag]
                $label = $form
                if ($base.Tag -in 0x81, 0x82, 0x86) {
                    $text = $null
                    try { $text = $strictAscii.GetString((Get-Slice $Raw $base.Start $base.Length)) } catch { }
                    if ($null -ne $text) { $label = "$(@{ 0x81 = 'email'; 0x82 = 'DNS'; 0x86 = 'URI' }[$base.Tag]) $(if ($text) { $text } else { '(empty: all names)' })" }
                    if ($null -eq $text) { $issues.Add("a $form constraint in $which is not an IA5String") }
                    elseif ($base.Tag -eq 0x86 -and $text -match '[:/?#@]') { $issues.Add("uniformResourceIdentifier constraint '$text' in $which is a URI, not a host or domain name") }
                }
                elseif ($base.Tag -eq 0xA4) {
                    $inner = Get-TlvChildren $Raw $base
                    if ($inner.Count -ne 1) { throw "a directoryName constraint in $which does not hold exactly one Name" }
                    [void](Read-Name $Raw $inner[0])
                    $label = 'dirName ' + ([System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new([byte[]](Get-TlvEncoding $Raw $inner[0]))).Name
                }
                elseif ($base.Tag -eq 0x87) {
                    if ($base.Length -notin 8, 32) { $issues.Add("an iPAddress constraint in $which is $($base.Length) octets; it MUST be 8 (IPv4) or 32 (IPv6): an address and a mask") }
                    else {
                        $mask = Get-Slice $Raw ($base.Start + $base.Length / 2) ($base.Length / 2)
                        $zero = $false; $contiguous = $true
                        foreach ($byte in $mask) { for ($bit = 7; $bit -ge 0; $bit--) { if (($byte -shr $bit) -band 1) { if ($zero) { $contiguous = $false } } else { $zero = $true } } }
                        if (-not $contiguous) { $issues.Add("an iPAddress constraint in $which has a non-contiguous mask, so it isn't a CIDR range") }
                        $addr = [System.Net.IPAddress]::new([byte[]](Get-Slice $Raw $base.Start ($base.Length / 2)))
                        $ones = 0; foreach ($byte in $mask) { for ($bit = 7; $bit -ge 0; $bit--) { if (($byte -shr $bit) -band 1) { $ones++ } } }
                        $label = if ($contiguous) { "IP $addr/$ones" } else { "IP $addr mask $([System.Net.IPAddress]::new([byte[]]$mask))" }
                    }
                }
                elseif ($base.Tag -in 0xA3, 0xA5, 0x88) { $discouraged.Add($form) }
                $shown[$n].Add($label)
            }
        }
        if ($last -lt 0) { $issues.Add('it is an empty SEQUENCE: permittedSubtrees or excludedSubtrees MUST be present') }
    } catch { $r.Error = $_.Exception.Message }
    $r.Issues = @($issues | Select-Object -Unique)
    $r.Discouraged = @($discouraged | Select-Object -Unique)
    $r.Permitted = $shown[0].ToArray()
    $r.Excluded = $shown[1].ToArray()
    [pscustomobject]$r
}

function Test-HttpUrl([string]$Text, [string[]]$Schemes) {
    # $null when $Text is a well-formed absolute URL with one of $Schemes and a non-empty host (RFC 3986
    # syntax; RFC 9110 forbids an http(s) URI with an empty host), otherwise the reason it isn't.
    if ([string]::IsNullOrEmpty($Text)) { return 'it is empty or not an ASCII string' }
    if ($Text -cnotmatch '^[A-Za-z0-9\-._~:/?#\[\]@!$&''()*+,;=%]+$') { return 'it contains characters that must be percent-encoded' }
    if ($Text -match '%(?![0-9A-Fa-f]{2})') { return 'it has a malformed percent-encoding' }
    if ($Text -notmatch '^([A-Za-z][A-Za-z0-9+.\-]*):') { return 'it has no scheme' }
    $scheme = $Matches[1].ToLowerInvariant()
    if ($scheme -notin $Schemes) { return "its scheme is '$scheme', not $($Schemes -join ' or ')" }
    if ($Text -notmatch '^[A-Za-z][A-Za-z0-9+.\-]*://([^/?#]*)') { return 'it has no //host part' }
    $hostPart = $Matches[1] -replace '^.*@', '' -replace ':[0-9]*$', ''
    if (-not $hostPart) { return 'it has no host' }
    $u = $null
    if (-not [System.Uri]::TryCreate($Text, [System.UriKind]::Absolute, [ref]$u) -or -not $u.Host) { return 'it is not a valid absolute URI' }
    $null
}

function Get-SkiValue($Cert) {
    # The certificate's SKI as hex, or $null if it is absent, malformed or empty
    $e = Get-Ext $Cert '2.5.29.14'
    if (-not $e) { return $null }
    $s = Read-Ski $e.RawData
    if ($s.Error -or -not $s.KeyId) { return $null }
    $s.KeyId
}

# ======================= Platform chain engine (secondary check) =======================
# Read-only guarantee: X509Chain.Build() may only run where it can be stopped from fetching issuer
# certificates from AIA URLs and triggering Windows root-store updates. DisableCertificateDownloads
# (.NET 5+, so PowerShell 7.1+) does both on Windows (CERT_CHAIN_DISABLE_AIA and
# CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE). Without it the chain step is skipped.
$chainIsReadOnly = $null -ne [System.Security.Cryptography.X509Certificates.X509ChainPolicy].GetProperty('DisableCertificateDownloads')

function ConvertTo-StatusNames($StatusList) {
    # X509ChainStatus entries -> flag names (an entry can carry several flags). The leading comma keeps
    # a one-element result an array.
    , @($StatusList | ForEach-Object { $_.Status.ToString() -split ',\s*' } | Where-Object { $_ } | Sort-Object -Unique)
}

function Invoke-PlatformChain($Subject, $Issuer, [bool]$IssuerIsAnchor) {
    # Everything is read out before the chain is disposed, because disposing it also disposes the
    # element certificates. Elements are identified by SHA-256 rather than the SHA-1 Thumbprint.
    # Build() can throw (e.g. "Invalid algorithm specified" for an Ed25519 key on Windows); that is
    # returned as Error so the rest of the report is still produced.
    $chain = New-Object "$X.X509Chain"
    try {
        $pol = $chain.ChainPolicy
        $pol.RevocationMode = 'NoCheck'
        $pol.VerificationFlags = 'AllowUnknownCertificateAuthority'
        $pol.DisableCertificateDownloads = $true   # only called when $chainIsReadOnly
        if ($IssuerIsAnchor -and $pol.PSObject.Properties['TrustMode']) {
            # Trust only the supplied root, not the machine's root store
            $pol.TrustMode = 'CustomRootTrust'
            [void]$pol.CustomTrustStore.Add($Issuer)
        }
        [void]$pol.ExtraStore.Add($Issuer)
        try { $built = [bool]$chain.Build($Subject) }
        catch { return [pscustomobject]@{ Error = $_.Exception.GetBaseException().Message.Trim().TrimEnd('.'); Built = $false; ChainStatus = @(); Elements = @() } }
        $els = @(foreach ($el in $chain.ChainElements) {
            [pscustomobject]@{
                Hash     = Get-Sha256Hex $el.Certificate.RawData
                Subject  = $el.Certificate.Subject
                Statuses = ConvertTo-StatusNames $el.ChainElementStatus
            }
        })
        [pscustomobject]@{ Error = $null; Built = $built; ChainStatus = (ConvertTo-StatusNames $chain.ChainStatus); Elements = $els }
    } finally {
        if ($chain -is [System.IDisposable]) { $chain.Dispose() }
    }
}

function Add-ChainFindings($Chain, [string[]]$Expected, [string[]]$Labels, [bool[]]$SigVerified) {
    # Per-certificate statuses are interpreted only when the engine built the supplied path. Flags for
    # missing trust, revocation and validity periods are expected or reported by this script's own
    # checks; anything else means the platform rejects it. Build()'s result and the chain-level
    # ChainStatus are always accounted for, so a rejection can't silently drop out of the report.
    # $Expected holds the SHA-256 of each certificate in the supplied path, subject first.
    # Returns Evaluated (the supplied path was evaluated) and SubjectSignatureOk (the engine found no
    # fault with the subject's signature on that path).
    $result = [pscustomobject]@{ Evaluated = $false; SubjectSignatureOk = $false }
    if ($Chain.Error) {
        Add-Finding @{ GEN = 'SHOULD' } "Platform chain engine failed to process the certificate ($($Chain.Error)), so this platform can't validate it; no chain engine results are available."
        return $result
    }
    $Elements = @($Chain.Elements)
    $chainStatus = @($Chain.ChainStatus | Where-Object { $_ })
    $benign = @('NoError', 'UntrustedRoot', 'PartialChain', 'RevocationStatusUnknown', 'OfflineRevocation', 'NotTimeValid', 'NotTimeNested')
    $outcome = if ($Chain.Built) { 'Build() succeeded' } else { 'Build() failed' }
    $chainBad = @($chainStatus | Where-Object { $_ -notin $benign })

    $samePath = ($Elements.Count -ge $Expected.Count)
    for ($n = 0; $samePath -and $n -lt $Expected.Count; $n++) { if ($Elements[$n].Hash -ne $Expected[$n]) { $samePath = $false } }
    if (-not $samePath) {
        # The engine preferred installed or cached certificates, so the supplied path wasn't evaluated
        $path = ($Elements | ForEach-Object { $_.Subject }) -join ' -> '
        $st = if ($chainStatus.Count) { $chainStatus -join ', ' } else { 'NoError' }
        $level = if ($chainBad.Count) { 'SHOULD' } else { 'INFO' }
        $verdict = if ($chainBad.Count) { "it rejected that path ($($chainBad -join ', '))" } else { 'it found no problems with that path that this script doesn''t report itself' }
        Add-Finding @{ GEN = $level } "Platform chain engine could not evaluate the supplied path: it built $path from installed or cached certificates instead. $outcome, chain status: $st; $verdict. Its per-certificate results describe that path and were not used." -Coverage:($level -eq 'INFO')
        return $result
    }
    $result.Evaluated = $true
    $result.SubjectSignatureOk = (@($Elements[0].Statuses) -notcontains 'NotSignatureValid')

    $accounted = New-Object System.Collections.Generic.List[string]   # flags reported per certificate
    $rejected = $false
    for ($n = 0; $n -lt $Expected.Count; $n++) {
        $st = @($Elements[$n].Statuses)
        foreach ($s in $st) { $accounted.Add($s) }
        # The direct signature check already reported this element's signature result
        if ($SigVerified[$n]) { $st = @($st | Where-Object { $_ -ne 'NotSignatureValid' }) }
        $bad = @($st | Where-Object { $_ -notin $benign })
        $expectedFlags = @($st | Where-Object { $_ -in $benign -and $_ -ne 'NoError' })
        if ($bad.Count) { $rejected = $true; Add-Finding @{ GEN = 'MUST' } "Platform chain engine rejected $($Labels[$n]): $($bad -join ', ')." }
        if ($expectedFlags.Count) { Add-Finding @{ GEN = 'INFO' } "Platform chain engine flags on $($Labels[$n]) that are expected here or reported separately: $($expectedFlags -join ', ')." -Coverage }
    }
    if ($Elements.Count -gt $Expected.Count) {
        $extraEls = @($Elements[$Expected.Count..($Elements.Count - 1)])
        foreach ($s in @($extraEls | ForEach-Object { $_.Statuses })) { $accounted.Add($s) }
        $extraBad = @($extraEls | ForEach-Object { $_.Statuses } | Where-Object { $_ -notin $benign } | Sort-Object -Unique)
        $names = ($extraEls | ForEach-Object { $_.Subject }) -join '; '
        if ($extraBad.Count) {
            $rejected = $true
            Add-Finding @{ GEN = 'SHOULD' } "Platform chain engine continued the path above the supplied issuer using this machine's certificate stores ($names) and rejected it there ($($extraBad -join ', ')). Those certificates were not assessed, but this machine won't accept the chain."
        } else { Add-Finding @{ GEN = 'INFO' } "Platform chain engine continued the path above the supplied issuer using this machine's certificate stores ($names); those certificates were not assessed." -Coverage }
    }
    # Chain-level flags that no certificate carries (e.g. Cyclic, or name/policy constraint failures)
    $chainOnly = @($chainBad | Where-Object { $_ -notin $accounted })
    if ($chainOnly.Count) { $rejected = $true; Add-Finding @{ GEN = 'MUST' } "Platform chain engine rejected the chain as a whole: $($chainOnly -join ', ')." }
    if (-not $Chain.Built -and -not $rejected) {
        $why = @($chainStatus | Where-Object { $_ -ne 'NoError' })
        $whyText = if ($why.Count) { $why -join ', ' } else { 'no status given' }
        Add-Finding @{ GEN = 'INFO' } "Platform chain engine's Build() returned false; every reason it gave is expected here or reported separately ($whyText)." -Coverage
    }
    $result
}

function Invoke-ChainCheck($Subject, $Issuer, [bool]$IssuerIsAnchor, [string[]]$Expected, [string[]]$Labels, [bool[]]$SigVerified) {
    # Returns the Add-ChainFindings result (Evaluated / SubjectSignatureOk), or Skipped when not run
    if (-not $chainIsReadOnly) {
        Add-Finding @{ GEN = 'INFO' } "Platform chain check skipped: on PowerShell $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) it can't be kept read-only (X509Chain may download issuer certificates and update the Windows root store). Run under PowerShell 7.1+ to include it; the script's own checks don't need it." -Coverage
        return [pscustomobject]@{ Evaluated = $false; SubjectSignatureOk = $false; Skipped = $true }
    }
    $r = Add-ChainFindings (Invoke-PlatformChain $Subject $Issuer $IssuerIsAnchor) $Expected $Labels $SigVerified
    $r | Add-Member -NotePropertyName Skipped -NotePropertyValue $false -PassThru
}

# ======================= Report formatting =======================
# The report is plain text written to the output stream, so it can be redirected or piped. Lines are
# word-wrapped to the console width.
function Get-ReportWidth {
    $w = 0
    try { $w = [int]$Host.UI.RawUI.WindowSize.Width } catch { }
    if ($w -lt 60) { return 100 }   # no console (e.g. a CI log)
    [math]::Min($w - 1, 110)        # longer lines are hard to read
}

function Format-Wrapped([string]$Text, [int]$Width, [string]$First = '', $Rest = $null) {
    # Word-wraps $Text: $First prefixes the first line and $Rest (default: as many spaces) the others.
    # A word longer than a line (a URL, a hex string) is split. ($Rest is untyped because a [string]
    # parameter turns $null into '', which would lose the default.)
    if ($null -eq $Rest) { $Rest = ' ' * $First.Length }
    $lines = New-Object System.Collections.Generic.List[string]
    $prefix = $First; $line = ''
    foreach ($word in ($Text -split ' +')) {
        if (-not $word) { continue }
        while ($word.Length -gt [math]::Max(10, $Width - $prefix.Length)) {
            if ($line) { $lines.Add($prefix + $line); $prefix = $Rest; $line = '' }
            $n = [math]::Max(10, $Width - $prefix.Length)
            # Prefer to break a path or URL just after a separator in the second half of the line
            $cut = $word.Substring(0, $n).LastIndexOfAny([char[]]'\/,;')
            if ($cut -ge $n / 2) { $n = $cut + 1 }
            $lines.Add($prefix + $word.Substring(0, $n)); $prefix = $Rest
            $word = $word.Substring($n)
        }
        if (-not $word) { continue }
        if (-not $line) { $line = $word }
        elseif ($prefix.Length + $line.Length + 1 + $word.Length -le $Width) { $line += ' ' + $word }
        else { $lines.Add($prefix + $line); $prefix = $Rest; $line = $word }
    }
    if ($line -or $lines.Count -eq 0) { $lines.Add($prefix + $line) }
    $lines.ToArray()
}

function Format-Heading([string]$Title) {
    ''
    $Title
    '-' * $Title.Length
}

function Format-Count([int]$N, [string]$Word) { if ($N -eq 1) { "1 $Word" } else { "$N ${Word}s" } }

function Format-Field([string]$Label, [string]$Value, [int]$Width) { Format-Wrapped $Value $Width ('  ' + $Label.PadRight(14)) }

function Get-ExtensionText($Ext) {
    # A short, readable description of an extension's value, from this script's own decoders where it has
    # one; otherwise .NET's description, or the raw bytes for an extension neither recognises
    $raw = $Ext.RawData
    $text = $null
    switch ($Ext.Oid.Value) {
        '2.5.29.19' {
            $v = Read-BasicConstraints $raw
            $text = if ($v.Error) { "malformed ($($v.Error))" } elseif (-not $v.CA) { 'not a CA' } elseif ($v.HasPathLen) { "CA, path length $($v.PathLen)" } else { 'CA, no path length limit' }
        }
        '2.5.29.15' {
            $v = Read-KeyUsage $raw
            $rfcNames = @{ DigitalSignature = 'digitalSignature'; NonRepudiation = 'nonRepudiation'; KeyEncipherment = 'keyEncipherment'; DataEncipherment = 'dataEncipherment'
                           KeyAgreement = 'keyAgreement'; KeyCertSign = 'keyCertSign'; CrlSign = 'cRLSign'; EncipherOnly = 'encipherOnly'; DecipherOnly = 'decipherOnly' }
            $text = if ($v.Error) { "malformed ($($v.Error))" } elseif (-not $v.Bits.Count) { '(no bits set)' }
                    else { @($v.Bits | ForEach-Object { if ($rfcNames.ContainsKey($_)) { $rfcNames[$_] } else { $_ } }) -join ', ' }
        }
        '2.5.29.14' {
            $v = Read-Ski $raw
            $text = if ($v.Error) { "malformed ($($v.Error))" } elseif ($v.KeyId) { $v.KeyId } else { '(empty)' }
        }
        '2.5.29.35' {
            $v = Get-AkiInfo $raw
            $text = if ($v.Error) { "malformed ($($v.Error))" } else { @($(if ($v.HasKeyId) { "keyid $($v.KeyId)" }), $(if ($v.HasIssuer) { 'issuer name and serial' }) | Where-Object { $_ }) -join ', ' }
            if (-not $text) { $text = '(empty)' }
        }
        '2.5.29.37' {
            $v = Read-Eku $raw
            $ekuNames = @{ '1.3.6.1.5.5.7.3.1' = 'serverAuth'; '1.3.6.1.5.5.7.3.2' = 'clientAuth'; '1.3.6.1.5.5.7.3.3' = 'codeSigning'; '1.3.6.1.5.5.7.3.4' = 'emailProtection'
                           '1.3.6.1.5.5.7.3.8' = 'timeStamping'; '1.3.6.1.5.5.7.3.9' = 'OCSPSigning'; '2.5.29.37.0' = 'anyExtendedKeyUsage'; '1.3.6.1.4.1.11129.2.4.4' = 'precertificateSigning' }
            $text = if ($v.Error) { "malformed ($($v.Error))" } else { @($v.Oids | ForEach-Object { if ($ekuNames.ContainsKey($_)) { $ekuNames[$_] } else { $_ } }) -join ', ' }
        }
        '2.5.29.32' {
            $v = Read-CertPolicies $raw
            $policyNames = @{ '2.23.140.1.2.1' = 'BR DV'; '2.23.140.1.2.2' = 'BR OV'; '2.23.140.1.2.3' = 'BR IV'; '2.23.140.1.1' = 'EV'; '2.5.29.32.0' = 'anyPolicy' }
            $text = if ($v.Error) { "malformed ($($v.Error))" } else {
                @(foreach ($pol in $v.Policies) {
                    $s = if ($policyNames.ContainsKey($pol.Oid)) { "$($pol.Oid) ($($policyNames[$pol.Oid]))" } else { $pol.Oid }
                    $q = @(foreach ($x in $pol.Qualifiers) { if ($x.Id -eq '1.3.6.1.5.5.7.2.1') { "CPS $($x.Text)" } elseif ($x.Id -eq '1.3.6.1.5.5.7.2.2') { 'user notice' } else { "qualifier $($x.Id)" } })
                    if ($q.Count) { "$s [$($q -join ', ')]" } else { $s }
                }) -join '; '
            }
        }
        '2.5.29.31' {
            $v = Read-Cdp $raw
            $text = if ($v.Error) { "malformed ($($v.Error))" } else {
                @(foreach ($dp in $v.Points) {
                    $s = if ($dp.NameForm -eq 'fullName') { @($dp.Names | ForEach-Object { if ($_.Uri) { $_.Uri } else { 'GeneralName tag 0x{0:X2}' -f $_.Tag } }) -join ', ' }
                         elseif ($dp.NameForm) { $dp.NameForm } else { '(no distributionPoint)' }
                    $extra = @($(if ($dp.HasReasons) { 'reasons' }), $(if ($dp.HasCrlIssuer) { 'cRLIssuer' }) | Where-Object { $_ })
                    if ($extra.Count) { "$s [$($extra -join ', ')]" } else { $s }
                }) -join '; '
            }
        }
        '1.3.6.1.5.5.7.1.1' {
            $v = Read-Aia $raw
            $methods = @{ '1.3.6.1.5.5.7.48.1' = 'OCSP'; '1.3.6.1.5.5.7.48.2' = 'caIssuers' }
            $text = if ($v.Error) { "malformed ($($v.Error))" } else {
                @(foreach ($ad in $v.Entries) {
                    $m = if ($methods.ContainsKey($ad.Method)) { $methods[$ad.Method] } else { $ad.Method }
                    $loc = if ($ad.Uri) { $ad.Uri } else { 'GeneralName tag 0x{0:X2}' -f $ad.Tag }
                    "$m $loc"
                }) -join '; '
            }
        }
        '2.5.29.30' {
            $v = Read-NameConstraints $raw
            $text = if ($v.Error) { "malformed ($($v.Error))" } else {
                $lists = @($(if ($v.Permitted.Count) { "permitted: $($v.Permitted -join ', ')" }), $(if ($v.Excluded.Count) { "excluded: $($v.Excluded -join ', ')" }) | Where-Object { $_ })
                if ($lists.Count) { $lists -join '; ' } else { '(empty)' }
            }
        }
        default {
            $t = $null
            if ($Ext.Oid.FriendlyName) { try { $t = $Ext.Format($false) } catch { } }
            if ($t) {
                $text = ($t -replace '\s+', ' ').Trim()
                if ($text.Length -gt 300) { $text = $text.Substring(0, 297) + '...' }
            } else {
                $hex = ConvertTo-Hex $raw
                $text = "unrecognised, $(Format-Count $raw.Length 'byte'): $(if ($hex.Length -gt 48) { $hex.Substring(0, 48) + '...' } else { $hex })"
            }
        }
    }
    $text
}

# =====================================================================
$certFile = Resolve-InputFile $Path
$cert     = Get-Cert $certFile
$issuer   = $null; $issuerFile = $null
if ($IssuerPath) { $issuerFile = Resolve-InputFile $IssuerPath; $issuer = Get-Cert $issuerFile }

try { $parts = Get-CertParts $cert } catch { throw "Certificate '$certFile' is not valid DER: $($_.Exception.Message)" }
$key = Get-KeyInfo $cert $parts
$skiRaw = Get-Ext $cert '2.5.29.14'
$skiInfo = $null
if ($skiRaw) { $skiInfo = Read-Ski $skiRaw.RawData }
$ski = Get-SkiValue $cert
$akiRaw = Get-Ext $cert '2.5.29.35'
$aki = $null
if ($akiRaw) { $aki = Get-AkiInfo $akiRaw.RawData }

# ---- Role: self-issued (subject = issuer) is not the same as self-signed (RFC 5280 3.2) ----
# Self-issued means the names match under RFC 5280 7.1 (RFC 5280 4.1.2.4), not that the bytes are equal
$namesIdentical = Test-BytesEqual $parts.SubjectNameDer $parts.IssuerNameDer
$selfIssued = $namesIdentical -or (Test-NameMatch $parts.SubjectName $parts.IssuerName)
$selfSig = $null
if ($selfIssued) { $selfSig = Test-CertSignature $parts $cert }

# ---- Issuer and signature verification ----
$issuerParts = $null; $issuerKey = $null; $issuerSelfSig = $null; $issuerSelfSigned = $false; $issuerSig = $null
if ($issuer -and -not ($selfSig -and $selfSig.Result -eq 'Valid')) {
    try { $issuerParts = Get-CertParts $issuer } catch { throw "Issuer certificate '$issuerFile' is not valid DER: $($_.Exception.Message)" }
    $issuerKey = Get-KeyInfo $issuer $issuerParts
    $issuerSig = Test-CertSignature $parts $issuer
    if ((Test-BytesEqual $issuerParts.SubjectNameDer $issuerParts.IssuerNameDer) -or (Test-NameMatch $issuerParts.SubjectName $issuerParts.IssuerName)) {
        $issuerSelfSig = Test-CertSignature $issuerParts $issuer
        $issuerSelfSigned = ($issuerSelfSig.Result -eq 'Valid')
    }
}

# ---- Role ----
# Self-issued (subject = issuer) is not the same as self-signed (RFC 5280 3.2): a CA key-rollover
# certificate has identical names but is signed by the previous key. Evidence, strongest first:
#   1. the signature verifies with its own key                       -> root
#   2. the signature verifies with the supplied issuer's key         -> rollover / cross-certificate
#   3. the AKI keyIdentifier names a different key from its own SKI  -> rollover / cross-certificate
#   4. otherwise it claims to be a root (its self-signature is broken or unverifiable)
$akiPointsElsewhere = [bool]($aki -and $aki.HasKeyId -and $ski -and $aki.KeyId -ne $ski)
$isRoot = $false
if ($selfIssued) {
    if ($selfSig.Result -eq 'Valid') { $isRoot = $true }
    elseif ($issuerSig -and $issuerSig.Result -eq 'Valid') { $isRoot = $false }
    elseif ($akiPointsElsewhere) { $isRoot = $false }
    else { $isRoot = $true }
}
$role = if ($isRoot -and $selfSig.Result -eq 'Valid') { 'Root (self-signed)' }
        elseif ($isRoot) { "Root (self-issued; self-signature $($selfSig.Result.ToLower()))" }
        elseif ($selfIssued) { 'Self-issued but not self-signed (e.g. CA key rollover)' }
        else { 'Subordinate CA' }

# ---- Serial (from the DER INTEGER content) ----
$serial = $parts.Serial
$serialOctets = $serial.Length
$sigByte = 0
while ($sigByte -lt $serial.Length -and $serial[$sigByte] -eq 0) { $sigByte++ }
$serialIsZero = ($sigByte -eq $serial.Length)
$serialBits = 0
if (-not $serialIsZero) { $serialBits = ($serial.Length - $sigByte - 1) * 8 + [Convert]::ToString($serial[$sigByte], 2).Length }

$nowUtc = (Get-Date).ToUniversalTime()
$nbUtc = $cert.NotBefore.ToUniversalTime()
$naUtc = $cert.NotAfter.ToUniversalTime()
$lifeDays = [math]::Round(($naUtc - $nbUtc).TotalDays, 1)
$remainingDays = [math]::Round(($naUtc - $nowUtc).TotalDays, 1)
$sha256 = Get-Sha256Hex $cert.RawData

# ======================= Checks: all CA certificates =======================
if ($cert.Version -ne 3) { Add-Finding @{ RFC = 'MUST' } "Version is v$($cert.Version); a certificate with extensions must be v3 (RFC 5280 4.1.2.1)." }
if ($parts.HasUniqueIds) { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "Certificate contains issuerUniqueID/subjectUniqueID; RFC 5280 4.1.2.8 says conforming CAs MUST NOT generate them." }
if ($naUtc -lt $nowUtc) { Add-Finding @{ GEN = 'MUST' } "Certificate expired on $($naUtc.ToString('yyyy-MM-dd')) UTC." }
elseif ($nbUtc -gt $nowUtc) { Add-Finding @{ GEN = 'SHOULD' } "Certificate is not valid until $($nbUtc.ToString('yyyy-MM-dd')) UTC." }

# ---- Serial number ----
if ($serialOctets -gt 1 -and (($serial[0] -eq 0x00 -and $serial[1] -lt 0x80) -or ($serial[0] -eq 0xFF -and $serial[1] -ge 0x80))) {
    Add-Finding @{ RFC = 'MUST' } "Serial number INTEGER is not minimally encoded (DER, RFC 5280 4.1)."
}
if ($serialIsZero) { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "Serial number is zero; RFC 5280 4.1.2.2 requires a positive integer." }
elseif ($serial[0] -ge 0x80) { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "Serial number is negative (high bit set without a 00 sign byte); RFC 5280 4.1.2.2 requires a positive integer." }
if ($serialOctets -gt 20) { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "Serial number is $serialOctets octets; RFC 5280 4.1.2.2 allows at most 20." }
if (-not $serialIsZero -and $serialBits -lt 64) {
    # A serial's length can't prove how it was generated: a value holding 64 bits of CSPRNG output is
    # k bits shorter than 64 with probability 2^-k. So a short serial is at most an unproven WARN.
    $k = 64 - $serialBits
    $msg = "Serial number has $serialBits significant bits. A random 64-bit value is this short with probability 2^-$k"
    if ($serialBits -le 48) {
        $odds = if ($serialBits -le 32) { 'very unlikely' } else { 'unlikely' }
        Add-Finding @{ BR = 'MUST' } "$msg, which is $odds if it contains the 64 bits of CSPRNG output BR 7.1 requires. One certificate can't prove that requirement was broken; confirm how the CA generates serials." -Unproven
    }
    else { Add-Finding @{ BR = 'INFO' } "$msg - consistent with a random serial that happens to have leading zero bits. One certificate can't show whether BR 7.1's 64-bit CSPRNG requirement is met." }
}

# ---- Name encoding: a self-issued certificate whose names match only after RFC 5280 7.1 matching ----
if ($selfIssued -and -not $namesIdentical) {
    $what = if ($isRoot) { "For a root its own subject is the issuing CA's subject, and BR 7.1.4.1 requires the issuer field to be byte-for-byte identical to it." } else { 'BR 7.1.4.1 requires the issuer field to be byte-for-byte identical to the issuing CA''s subject.' }
    Add-Finding @{ RFC = 'INFO'; BR = 'MUST' } "Subject and issuer match under RFC 5280 7.1 name comparison (so the certificate is self-issued) but are encoded differently. $what"
}

# ---- Public key ----
$brSpki = @('300D06092A864886F70D0101010500', '301306072A8648CE3D020106082A8648CE3D030107', '301006072A8648CE3D020106052B81040022', '301006072A8648CE3D020106052B81040023')
if ($key.Invalid) { Add-Finding @{ GEN = 'MUST'; RFC = 'MUST' } "Public key is invalid: $($key.Invalid). No relying party can use this certificate's key." }
elseif ($key.Compressed) { Add-Finding @{ GEN = 'SHOULD' } "EC public key uses the compressed point form. RFC 5480 2.2 only requires implementations to support the uncompressed form, so many relying parties can't use it." }
if ($key.PlatformError) { Add-Finding @{ GEN = 'SHOULD' } "The public key is valid, but .NET on this machine can't load it ($($key.PlatformError)); relying parties on similar platforms may not be able to use it." }
switch ($key.Algorithm) {
    'RSA' {
        if ($parts.SpkiAlg.Hex -ne '300D06092A864886F70D0101010500') { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "RSA SubjectPublicKeyInfo algorithm parameters are not NULL ($($parts.SpkiAlg.Hex)); RFC 3279 2.3.1 / BR 7.1.3.1.1." }
        if ($null -eq $key.KeySize) { break }   # the key didn't decode, so size and exponent are unknown
        if ($key.KeySize -lt 2048) { Add-Finding @{ GEN = 'MUST'; BR = 'MUST'; ISM = 'MUST' } "RSA $($key.KeySize) bits is below the 2048-bit minimum (NIST SP 800-131A, BR 6.1.5, ISM)." }
        elseif ($key.KeySize -lt 3072) { Add-Finding @{ ISM = 'SHOULD' } "RSA $($key.KeySize) bits meets the 2048-bit minimum but is below the ISM preferred 3072 bits (and the ISM minimum for SECRET/TOP SECRET)." }
        if ($key.KeySize % 8 -ne 0) { Add-Finding @{ BR = 'MUST' } "RSA modulus is $($key.KeySize) bits, not divisible by 8 (BR 6.1.5)." }
        # Exponent is an Int64 up to 7 octets, otherwise a hex string; parity is taken from the bytes either way
        $smallExponent = ($key.Exponent -is [long])
        if (-not $key.ExponentOdd -or ($smallExponent -and $key.Exponent -lt 3)) { Add-Finding @{ GEN = 'MUST'; BR = 'MUST' } "RSA public exponent $($key.Exponent) is invalid: it must be odd and at least 3 (BR 6.1.6)." }
        elseif ($smallExponent -and $key.Exponent -lt 65537) { Add-Finding @{ BR = 'SHOULD' } "RSA public exponent $($key.Exponent) is below 2^16+1 (BR 6.1.6)." }
        elseif ($key.ExponentBytes -gt 32) { Add-Finding @{ BR = 'SHOULD' } "RSA public exponent is larger than 2^256-1 (BR 6.1.6)." }
    }
    'ECDSA' {
        if (-not $key.CurveOid) { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "EC key uses explicit or implicit curve parameters; RFC 5480 2.1.1 requires a namedCurve." }
        elseif ($key.Curve -notin @('P-256', 'P-384', 'P-521')) { Add-Finding @{ BR = 'MUST'; ISM = 'MUST' } "EC key is not on P-256/P-384/P-521 (curve OID $($key.CurveOid))." }
        elseif ($key.Curve -eq 'P-256') { Add-Finding @{ ISM = 'SHOULD' } "P-256 is acceptable but ISM prefers P-384 (and requires P-384/P-521 for TOP SECRET)." }
        if ($key.CurveOid -and $parts.SpkiAlg.Hex -notin $brSpki) { Add-Finding @{ BR = 'MUST' } "EC SubjectPublicKeyInfo algorithm is not one of the encodings BR 7.1.3.1.2 permits ($($parts.SpkiAlg.Hex))." }
    }
    default {
        Add-Finding @{ BR = 'MUST' } "Key algorithm $($key.Algorithm) is not permitted by BR 6.1.5 (RSA or ECDSA P-256/P-384/P-521 only)."
        $mldsa = if ($key.Algorithm -like 'ML-DSA-*') { ' ISM prefers ML-DSA-87.' } else { '' }
        Add-Finding @{ GEN = 'INFO' } "Key algorithm $($key.Algorithm) is not assessed further by this script.$mldsa" -Coverage
    }
}

# ---- Signature algorithm: encoding, inner/outer agreement, hash strength ----
$sch = $parts.Scheme
$outerAlg = $parts.OuterAlg
if ($parts.InnerAlg.Hex -ne $outerAlg.Hex) { Add-Finding @{ RFC = 'MUST' } "tbsCertificate.signature ($($parts.InnerAlg.Hex)) differs from Certificate.signatureAlgorithm ($($outerAlg.Hex)); RFC 5280 4.1.1.2 requires them to be identical." }
if ($parts.UnusedBits -ne 0) { Add-Finding @{ GEN = 'MUST' } "signatureValue BIT STRING declares $($parts.UnusedBits) unused bits; it must be 0." }
switch ($sch.Kind) {
    'RSA-PKCS1' {
        if (-not $outerAlg.Params -or $outerAlg.Params.Tag -ne 0x05 -or $outerAlg.Params.Length -ne 0) { Add-Finding @{ RFC = 'MUST' } "PKCS#1 v1.5 signature algorithm parameters are not NULL; RFC 4055 5 / RFC 3279 2.2.1 require NULL." }
    }
    'ECDSA' {
        if ($outerAlg.Params) { Add-Finding @{ RFC = 'MUST' } "ECDSA signature algorithm has parameters; RFC 5758 3.2 requires them to be absent." }
    }
    'RSA-PSS' {
        if ($sch.PssError) { Add-Finding @{ RFC = 'MUST' } "RSASSA-PSS parameters are malformed: $($sch.PssError)." }
        else {
            $p = $sch.Pss
            if ($p.Trailer -ne 1) { Add-Finding @{ RFC = 'MUST' } "RSASSA-PSS trailerField is $($p.Trailer); RFC 4055 3.1 requires 1." }
            if ($p.MgfOid -ne '1.2.840.113549.1.1.8') { Add-Finding @{ RFC = 'MUST' } "RSASSA-PSS mask generation function $($p.MgfOid) is not MGF1 (RFC 4055 3.1)." }
            elseif ($p.MgfHash -ne $p.Hash) { Add-Finding @{ RFC = 'SHOULD'; BR = 'MUST' } "RSASSA-PSS uses $($p.Hash) for the message but MGF1-$($p.MgfHash); RFC 4055 3.1 recommends (BR requires) the same hash." }
            if ($hashLen.ContainsKey($p.Hash) -and $p.Salt -ne $hashLen[$p.Hash]) { Add-Finding @{ BR = 'MUST' } "RSASSA-PSS salt length is $($p.Salt); BR 7.1.3.2.1 requires the hash length ($($hashLen[$p.Hash]))." }
        }
    }
    'Unknown' { Add-Finding @{ GEN = 'INFO' } "Signature algorithm $($outerAlg.Oid) is not recognised by this script - check it manually." -Coverage }
}
if ($sch.Hash -in @('MD2', 'MD5', 'SHA1')) {
    # Relying parties don't verify a trust anchor's own signature (SHA-1 deprecation programmes exempted
    # roots), so for a root this is a hygiene issue rather than something that stops it validating.
    if ($isRoot) { Add-Finding @{ GEN = 'SHOULD'; BR = 'MUST'; ISM = 'MUST' } "Self-signature uses $($sch.Name). Relying parties don't check a root's own signature, so it still validates, but MD2/MD5/SHA-1 should not be used to sign new certificates." }
    else { Add-Finding @{ GEN = 'MUST'; BR = 'MUST'; ISM = 'MUST' } "Signature uses $($sch.Name); MD2/MD5/SHA-1 are not acceptable for certificate signatures." }
}
elseif ($sch.Hash -eq 'SHA224') { Add-Finding @{ BR = 'MUST' } "Signature uses $($sch.Name); SHA-224 is not permitted by BR 7.1.3.2." }
elseif ($sch.Hash -eq 'SHA256') { Add-Finding @{ ISM = 'INFO' } "Signature uses SHA-256: acceptable now, but ISM prefers SHA-384/512 and states SHA-256 will not be approved beyond 2030." }
$brSigAlgs = @(
    '300D06092A864886F70D01010B0500', '300D06092A864886F70D01010C0500', '300D06092A864886F70D01010D0500',
    '304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A203020120',
    '304106092A864886F70D01010A3034A00F300D06096086480165030402020500A11C301A06092A864886F70D010108300D06096086480165030402020500A203020130',
    '304106092A864886F70D01010A3034A00F300D06096086480165030402030500A11C301A06092A864886F70D010108300D06096086480165030402030500A203020140',
    '300A06082A8648CE3D040302', '300A06082A8648CE3D040303', '300A06082A8648CE3D040304'
)
if ($outerAlg.Hex -notin $brSigAlgs) { Add-Finding @{ BR = 'MUST' } "Signature AlgorithmIdentifier is not byte-for-byte one of the encodings BR 7.1.3.2 permits ($($outerAlg.Hex))." }

# ECDSA curve/hash pairing depends on the SIGNING key (issuer's key; own key for a root)
if ($sch.Kind -eq 'ECDSA') {
    $signer = $null
    if ($isRoot) { $signer = $key } elseif ($issuerKey) { $signer = $issuerKey }
    if ($signer -and $signer.Algorithm -eq 'ECDSA') {
        $expected = @{ 'P-256' = 'SHA256'; 'P-384' = 'SHA384'; 'P-521' = 'SHA512' }[$signer.Curve]
        if ($expected -and $expected -ne $sch.Hash) { Add-Finding @{ BR = 'MUST' } "ECDSA signing key is $($signer.Curve) but the signature hash is $($sch.Hash); BR 7.1.3.2.2 requires $expected with $($signer.Curve)." }
    } elseif (-not $signer) { Add-Finding @{ BR = 'INFO' } "Supply -IssuerPath to check the ECDSA curve/hash pairing against the issuer's key." -Coverage }
}

# ---- Extensions: duplicates and criticality ----
$cert.Extensions | Group-Object { $_.Oid.Value } | Where-Object { $_.Count -gt 1 } | ForEach-Object {
    Add-Finding @{ RFC = 'MUST' } "Extension $($_.Name) appears $($_.Count) times; RFC 5280 4.2 says it MUST NOT appear more than once."
}
# Criticality that RFC 5280 requires or recommends (Critical/Req/Sec; entries without them may be
# either), and the criticality the BR certificate profile requires. basicConstraints and keyUsage
# criticality are checked in their own sections.
$extInfo = @{
    '2.5.29.35'               = @{ Name = 'authorityKeyIdentifier';     Sec = '4.2.1.1';  Critical = $false; Req = 'MUST' }
    '2.5.29.14'               = @{ Name = 'subjectKeyIdentifier';       Sec = '4.2.1.2';  Critical = $false; Req = 'MUST' }
    '2.5.29.9'                = @{ Name = 'subjectDirectoryAttributes'; Sec = '4.2.1.8';  Critical = $false; Req = 'MUST' }
    '2.5.29.46'               = @{ Name = 'freshestCRL';                Sec = '4.2.1.15'; Critical = $false; Req = 'MUST' }
    '1.3.6.1.5.5.7.1.1'       = @{ Name = 'authorityInfoAccess';        Sec = '4.2.2.1';  Critical = $false; Req = 'MUST' }
    '1.3.6.1.5.5.7.1.11'      = @{ Name = 'subjectInfoAccess';          Sec = '4.2.2.2';  Critical = $false; Req = 'MUST' }
    '2.5.29.31'               = @{ Name = 'cRLDistributionPoints';      Sec = '4.2.1.13'; Critical = $false; Req = 'SHOULD' }
    '2.5.29.18'               = @{ Name = 'issuerAltName';              Sec = '4.2.1.7';  Critical = $false; Req = 'SHOULD' }
    '2.5.29.30'               = @{ Name = 'nameConstraints';            Sec = '4.2.1.10'; Critical = $true;  Req = 'MUST'; Note = ' (BR 7.1.2.10.8 tolerates non-critical)' }
    '2.5.29.36'               = @{ Name = 'policyConstraints';          Sec = '4.2.1.11'; Critical = $true;  Req = 'MUST' }
    '2.5.29.54'               = @{ Name = 'inhibitAnyPolicy';           Sec = '4.2.1.14'; Critical = $true;  Req = 'MUST' }
    '2.5.29.33'               = @{ Name = 'policyMappings';             Sec = '4.2.1.5';  Critical = $true;  Req = 'SHOULD' }
    '2.5.29.19'               = @{ Name = 'basicConstraints' }
    '2.5.29.15'               = @{ Name = 'keyUsage' }
    '2.5.29.37'               = @{ Name = 'extKeyUsage' }
    '2.5.29.32'               = @{ Name = 'certificatePolicies' }
    '2.5.29.17'               = @{ Name = 'subjectAltName' }
    '1.3.6.1.4.1.11129.2.4.2' = @{ Name = 'Signed Certificate Timestamp List' }
}
# The extensions each BR profile lists, with the criticality it requires ($null: no stipulation, or
# the extension's presence is reported on its own below)
if ($isRoot) {
    $brProfileName = 'BR 7.1.2.1.2 (Root CA)'
    $brProfile = @{ '2.5.29.35' = $false; '2.5.29.19' = $true; '2.5.29.15' = $true; '2.5.29.14' = $false; '2.5.29.32' = $false
                    '1.3.6.1.4.1.11129.2.4.2' = $false; '2.5.29.37' = $null; '2.5.29.31' = $null }
} else {
    $brProfileName = 'BR 7.1.2.6.1 (TLS Subordinate CA)'
    $brProfile = @{ '2.5.29.35' = $false; '2.5.29.19' = $true; '2.5.29.32' = $false; '2.5.29.31' = $false; '2.5.29.15' = $true
                    '2.5.29.14' = $false; '2.5.29.37' = $false; '1.3.6.1.5.5.7.1.1' = $false; '2.5.29.30' = $null
                    '1.3.6.1.4.1.11129.2.4.2' = $false }
}
$outsideProfile = New-Object System.Collections.Generic.List[string]
foreach ($e in $cert.Extensions) {
    $oid = $e.Oid.Value
    $label = if ($extInfo.ContainsKey($oid)) { $extInfo[$oid].Name } elseif ($e.Oid.FriendlyName) { "$($e.Oid.FriendlyName) ($oid)" } else { $oid }
    if (-not $brProfile.ContainsKey($oid)) { $outsideProfile.Add($label) }
    if ($oid -in '2.5.29.19', '2.5.29.15') { continue }
    $state = if ($e.Critical) { 'marked critical' } else { 'not marked critical' }
    $rules = @{}
    $why = @()
    if ($extInfo.ContainsKey($oid) -and $extInfo[$oid].ContainsKey('Critical') -and $e.Critical -ne $extInfo[$oid].Critical) {
        $x = $extInfo[$oid]
        $want = if ($x.Critical) { 'critical' } else { 'non-critical' }
        $note = if ($x.ContainsKey('Note')) { $x.Note } else { '' }
        $rules.RFC = $x.Req
        $why += "RFC 5280 $($x.Sec) says it $($x.Req) be $want$note"
    }
    if ($brProfile.ContainsKey($oid) -and $null -ne $brProfile[$oid] -and $e.Critical -ne $brProfile[$oid]) {
        $want = if ($brProfile[$oid]) { 'critical' } else { 'non-critical' }
        $rules.BR = 'MUST'
        $why += "$brProfileName requires it to be $want"
    }
    if ($rules.Count) { Add-Finding $rules "$label is $state; $($why -join '; ')." }
    elseif ($e.Critical -and -not $extInfo.ContainsKey($oid)) {
        Add-Finding @{ GEN = 'SHOULD' } "Critical extension $label isn't one this script recognises (it isn't defined in RFC 5280). A relying party that doesn't recognise it must reject the certificate (RFC 5280 4.2), so check that every platform that has to accept it does."
    }
}
if ($outsideProfile.Count) { Add-Finding @{ BR = 'SHOULD' } "Extension(s) not in the $brProfileName profile: $($outsideProfile -join ', '). The BRs say any other extension is NOT RECOMMENDED." }

# '2030-12-31' alone means midnight at the START of that day, so compare against 2031-01-01
if ($key.Algorithm -in @('RSA', 'ECDSA') -and $naUtc -ge [datetime]'2031-01-01') {
    Add-Finding @{ GEN = 'INFO'; ISM = 'INFO' } "Certificate is valid beyond 2030 with a quantum-vulnerable key ($($key.Algorithm)). ISM: not approved beyond 2030; NIST IR 8547: deprecated after 2030, disallowed after 2035. Needs a PQC migration plan."
}

# ---- Basic Constraints ----
$bcRaw = Get-Ext $cert '2.5.29.19'
$bc = $null
if (-not $bcRaw) { Add-Finding @{ RFC = 'MUST' } "basicConstraints extension missing (RFC 5280 4.2.1.9)." }
else {
    $bc = Read-BasicConstraints $bcRaw.RawData
    if (-not $bcRaw.Critical) { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "basicConstraints is not marked critical (RFC 5280 4.2.1.9; $brProfileName)." }
    if ($bc.Error) { Add-Finding @{ GEN = 'MUST'; RFC = 'MUST' } "basicConstraints is malformed ($($bc.Error)), so relying parties can't treat this as a CA certificate." }
    else {
        if ($bc.DerIssue) { Add-Finding @{ RFC = 'MUST' } "basicConstraints is not DER-encoded: $($bc.DerIssue)." }
        if (-not $bc.CA) { Add-Finding @{ GEN = 'MUST'; RFC = 'MUST' } "basicConstraints cA is FALSE - this is not a CA certificate." }
        if ($isRoot -and $bc.HasPathLen) { Add-Finding @{ BR = 'SHOULD' } "Root has pathLenConstraint=$($bc.PathLen); BR 7.1.2.1.4 says NOT RECOMMENDED for roots." }
        if (-not $isRoot -and -not $bc.HasPathLen) { Add-Finding @{ GEN = 'INFO' } "Subordinate has no pathLenConstraint; consider pathlen:0 if it only issues end-entity certificates (common practice, not a BR requirement)." }
        if (-not $isRoot -and $bc.HasPathLen) { Add-Finding @{ GEN = 'INFO' } "Subordinate pathLenConstraint = $($bc.PathLen)." }
    }
}

# ---- Key Usage ----
$kuRaw = Get-Ext $cert '2.5.29.15'
if (-not $kuRaw) { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "keyUsage extension missing (RFC 5280 4.2.1.3)." }
else {
    $ku = Read-KeyUsage $kuRaw.RawData
    if (-not $kuRaw.Critical) { Add-Finding @{ RFC = 'SHOULD'; BR = 'MUST' } "keyUsage is not marked critical (RFC 5280 4.2.1.3: SHOULD; BR 7.1.2.10.7: MUST)." }
    if ($ku.Error) { Add-Finding @{ GEN = 'MUST'; RFC = 'MUST' } "keyUsage is malformed ($($ku.Error)), so this key can't be relied on to verify certificate signatures." }
    else {
        if ($ku.DerIssue) { Add-Finding @{ RFC = 'MUST' } "keyUsage BIT STRING is not DER-encoded: $($ku.DerIssue)." }
        if ($ku.Bits.Count -eq 0) { Add-Finding @{ RFC = 'MUST' } "keyUsage has no bits set; RFC 5280 4.2.1.3 requires at least one." }
        if ($ku.Bits -notcontains 'KeyCertSign') { Add-Finding @{ GEN = 'MUST'; RFC = 'MUST' } "keyUsage lacks keyCertSign, so this key can't be used to verify certificate signatures." }
        if ($ku.Bits -notcontains 'CrlSign') { Add-Finding @{ BR = 'MUST' } "keyUsage lacks cRLSign (BR 7.1.2.10.7)." }
        if ($ku.Bits -contains 'DigitalSignature') { Add-Finding @{ GEN = 'INFO' } "keyUsage includes digitalSignature - only needed if this CA key signs OCSP responses directly." }
        foreach ($bad in @($ku.Bits | Where-Object { $_ -notin @('KeyCertSign', 'CrlSign', 'DigitalSignature') })) {
            Add-Finding @{ BR = 'MUST' } "keyUsage includes $bad, which BR 7.1.2.10.7 does not permit for CA certificates."
        }
    }
}

# ---- Subject Key Identifier (criticality is checked with the other extensions) ----
if (-not $skiRaw) { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "subjectKeyIdentifier missing (RFC 5280 4.2.1.2: MUST appear in all CA certificates)." }
elseif ($skiInfo.Error) { Add-Finding @{ RFC = 'MUST' } "subjectKeyIdentifier is malformed ($($skiInfo.Error))." }
elseif (-not $skiInfo.KeyId) { Add-Finding @{ RFC = 'MUST' } "subjectKeyIdentifier is empty." }

# ---- Authority Key Identifier (structure; presence rules depend on role, below) ----
if ($akiRaw) {
    if ($aki.Error) { Add-Finding @{ RFC = 'MUST' } "authorityKeyIdentifier is malformed: $($aki.Error)." }
    else {
        if (-not $aki.HasKeyId) {
            $what = if ($aki.Empty) { 'is an empty SEQUENCE' } else { 'has no keyIdentifier' }
            Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "authorityKeyIdentifier $what; RFC 5280 4.2.1.1 requires keyIdentifier whenever the extension is present."
        }
        if ($aki.HasIssuer -or $aki.HasSerial) { Add-Finding @{ BR = 'MUST' } "authorityKeyIdentifier contains authorityCertIssuer/authorityCertSerialNumber; BR 7.1.2.11.1 says these MUST NOT be present." }
    }
}

# ---- Subject DN (attribute types read from the DER, so quoted values can't spoof attributes) ----
$attrs = $parts.SubjectAttrs
if ($attrs.Count -eq 0) { Add-Finding @{ RFC = 'MUST' } "Subject DN is empty; RFC 5280 4.1.2.6 requires a non-empty subject for CA certificates." }
else {
    if ($attrs -notcontains '2.5.4.3')  { Add-Finding @{ BR = 'MUST' } "Subject has no commonName (BR 7.1.2.10.2)." }
    if ($attrs -notcontains '2.5.4.10') { Add-Finding @{ BR = 'MUST' } "Subject has no organizationName (BR 7.1.2.10.2)." }
    if ($attrs -notcontains '2.5.4.6')  { Add-Finding @{ BR = 'MUST' } "Subject has no countryName (BR 7.1.2.10.2)." }
    if ($attrs -contains '2.5.4.11')    { Add-Finding @{ BR = 'MUST' } "Subject contains organizationalUnitName; BR 7.1.2.10.2 says it MUST NOT be included in CA certificates." }
}

$ekuRaw = Get-Ext $cert '2.5.29.37'
$eku = $null
$ekuOids = @()
if ($ekuRaw) {
    $eku = Read-Eku $ekuRaw.RawData
    if ($eku.Error) { Add-Finding @{ GEN = 'MUST'; RFC = 'MUST' } "extKeyUsage is malformed ($($eku.Error)); relying parties will reject or misread it." }
    else { $ekuOids = $eku.Oids }
}
$cdp      = Get-Ext $cert '2.5.29.31'
$aia      = Get-Ext $cert '1.3.6.1.5.5.7.1.1'
$policies = Get-Ext $cert '2.5.29.32'
$nc       = Get-Ext $cert '2.5.29.30'

# ---- CRL Distribution Points, Authority Information Access, Certificate Policies: structure ----
# (their BR content rules are checked in the subordinate section)
$cdpInfo = $null; $aiaInfo = $null; $cpInfo = $null; $ncInfo = $null
if ($cdp) {
    $cdpInfo = Read-Cdp $cdp.RawData
    if ($cdpInfo.Error) { Add-Finding @{ RFC = 'MUST' } "cRLDistributionPoints is malformed ($($cdpInfo.Error)) (RFC 5280 4.2.1.13)." }
    elseif (@($cdpInfo.Points | Where-Object { -not $_.NameForm -and -not $_.HasCrlIssuer }).Count) {
        Add-Finding @{ RFC = 'MUST' } "cRLDistributionPoints has a DistributionPoint with neither distributionPoint nor cRLIssuer; RFC 5280 4.2.1.13 requires one of them."
    }
}
if ($aia) {
    $aiaInfo = Read-Aia $aia.RawData
    if ($aiaInfo.Error) { Add-Finding @{ RFC = 'MUST' } "authorityInfoAccess is malformed ($($aiaInfo.Error)) (RFC 5280 4.2.2.1)." }
}
if ($nc) {
    # Decoded here rather than left to the platform chain engine, which may not run
    $ncInfo = Read-NameConstraints $nc.RawData
    if ($ncInfo.Error) { Add-Finding @{ GEN = 'MUST'; RFC = 'MUST' } "nameConstraints is malformed ($($ncInfo.Error)); relying parties will reject the certificate or misapply the constraints (RFC 5280 4.2.1.10)." }
    else {
        if ($ncInfo.Issues.Count) { Add-Finding @{ RFC = 'MUST' } "nameConstraints doesn't meet RFC 5280 4.2.1.10: $($ncInfo.Issues -join '; ')." }
        if ($ncInfo.Discouraged.Count) { Add-Finding @{ RFC = 'SHOULD' } "nameConstraints constrains $($ncInfo.Discouraged -join ', '), which RFC 5280 4.2.1.10 says CAs SHOULD NOT constrain." }
    }
}
if ($policies) {
    $cpInfo = Read-CertPolicies $policies.RawData
    if ($cpInfo.Error) { Add-Finding @{ RFC = 'MUST' } "certificatePolicies is malformed ($($cpInfo.Error)) (RFC 5280 4.2.1.4)." }
    else {
        $dupPolicies = @($cpInfo.Policies | Group-Object Oid | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
        if ($dupPolicies.Count) { Add-Finding @{ RFC = 'MUST' } "certificatePolicies lists $($dupPolicies -join ', ') more than once; RFC 5280 4.2.1.4 says a policy OID MUST NOT appear more than once." }
    }
}

# Set by the role sections below: what verified the certificate's signature, or why nothing did
$signatureVerifiedBy = $null
$signatureGap = $null

# ======================= Root (self-signed) =======================
if ($isRoot) {
    if ($selfSig.Result -eq 'Invalid') {
        $alt = if (-not $issuer) { 'If this is really a key-rollover certificate, re-run with -IssuerPath <issuing CA certificate>.' }
               elseif ($issuerSig.Result -eq 'Invalid') { 'It does not verify with the supplied issuer either.' }
               else { "It could not be checked against the supplied issuer either ($($issuerSig.Reason))." }
        Add-Finding @{ GEN = 'MUST' } "Self-signature does not verify with the certificate's own public key ($($selfSig.Reason)). $alt"
    }
    elseif ($selfSig.Result -ne 'Valid') {
        Add-Finding @{ GEN = 'INFO' } "Could not verify the self-signature ($($selfSig.Reason)); classified as a root because subject = issuer and the AKI doesn't name a different key." -Coverage
    }
    if ($lifeDays -lt 2922 -or $lifeDays -gt 9132) {
        if ($nbUtc -ge [datetime]'2023-09-15') { Add-Finding @{ BR = 'MUST' } "Root lifetime is $lifeDays days; BR 7.1.2.1.1 requires 2922-9132 days." }
        else { Add-Finding @{ BR = 'INFO' } "Root lifetime is $lifeDays days, outside BR 7.1.2.1.1's 2922-9132 days; that profile applies to roots issued from 2023-09-15." }
    }
    if ($ekuRaw) { Add-Finding @{ BR = 'MUST' } "Root contains extKeyUsage ($($ekuOids -join ', ')); BR 7.1.2.1.2 says MUST NOT be present." }
    if ($cdp) { Add-Finding @{ BR = 'SHOULD' } "Root contains CRL Distribution Points; BR 7.1.2.11.2 says it SHOULD NOT be present in a root." }
    if ($policies) { Add-Finding @{ BR = 'SHOULD' } "Root contains certificatePolicies; BR 7.1.2.1.2 says NOT RECOMMENDED for roots." }
    if (-not $akiRaw) { Add-Finding @{ BR = 'SHOULD' } "Root has no authorityKeyIdentifier (BR 7.1.2.1.2: RECOMMENDED)." }
    elseif ($aki.HasKeyId -and $ski -and ($aki.KeyId -ne $ski)) {
        # A self-signed certificate is issued by its own subject, so RFC 5280 4.2.1.2 applies to it too
        Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "Root AKI keyIdentifier ($($aki.KeyId)) does not match its own SKI ($ski); RFC 5280 4.2.1.2 and BR 7.1.2.1.3 require them to be equal."
    }

    if ($selfSig.Result -eq 'Valid') { $signatureVerifiedBy = 'its own key (self-signed)' }
    elseif ($selfSig.Result -eq 'Unverifiable') { $signatureGap = "its self-signature couldn't be verified ($($selfSig.Reason))" }
    # Chain-engine evidence isn't used for a root's signature: not every platform checks a trust anchor's own signature
    [void](Invoke-ChainCheck $cert $cert $true @($sha256) @('this certificate') @(($selfSig.Result -ne 'Unverifiable')))
    if ($IssuerPath -and $selfSig.Result -eq 'Valid') { Add-Finding @{ GEN = 'INFO' } "-IssuerPath was ignored: the certificate is self-signed, so it is checked as a root." -Coverage }
}
# ======================= Subordinate (incl. self-issued, not self-signed) =======================
else {
    if ($selfIssued) {
        $why = if ($issuerSig -and $issuerSig.Result -eq 'Valid') { "its signature verifies with the supplied issuer's key, not its own" } else { "its AKI ($($aki.KeyId)) names a different key from its SKI ($ski)" }
        Add-Finding @{ GEN = 'INFO' } "Subject = issuer, but $why, so it is assessed as a key-rollover / cross-certificate rather than a root (RFC 5280 3.2: self-issued is not self-signed)."
    }

    if (-not $akiRaw) { Add-Finding @{ RFC = 'MUST'; BR = 'MUST' } "No authorityKeyIdentifier; RFC 5280 4.2.1.1 requires it (with keyIdentifier) in every certificate that isn't self-signed." }
    if (-not $cdp) { Add-Finding @{ BR = 'MUST' } "No CRL Distribution Points (BR 7.1.2.6 / 7.1.2.11.2), so relying parties can't find out whether this CA certificate has been revoked." }
    if (-not $aia) { Add-Finding @{ BR = 'SHOULD' } "No authorityInformationAccess (BR 7.1.2.10.3: HTTP caIssuers / OCSP)." }
    if (-not $policies) { Add-Finding @{ BR = 'MUST' } "No certificatePolicies (BR 7.1.2.6 / 7.1.2.10.5; optional for many private PKIs)." }

    # ---- BR contents of CDP (7.1.2.11.2), AIA (7.1.2.10.3) and certificatePolicies (7.1.2.10.5) ----
    if ($cdpInfo -and -not $cdpInfo.Error) {
        $points = @($cdpInfo.Points)
        if ($points.Count -gt 1) { Add-Finding @{ BR = 'SHOULD' } "cRLDistributionPoints holds $($points.Count) DistributionPoints; BR 7.1.2.11.2 says more than one is NOT RECOMMENDED." }
        $issues = New-Object System.Collections.Generic.List[string]
        foreach ($dp in $points) {
            if ($dp.NameForm -ne 'fullName') { $issues.Add('a DistributionPoint has no distributionPoint fullName') }
            if ($dp.HasReasons) { $issues.Add('reasons is present') }
            if ($dp.HasCrlIssuer) { $issues.Add('cRLIssuer is present') }
            foreach ($g in @($dp.Names)) {
                if ($g.Tag -ne 0x86) { $issues.Add(('a fullName entry is not a uniformResourceIdentifier (tag 0x{0:X2})' -f $g.Tag)); continue }
                $bad = Test-HttpUrl $g.Uri @('http')
                if ($bad) { $issues.Add("'$($g.Uri)' is not a valid http URL: $bad") }
            }
        }
        if ($issues.Count) { Add-Finding @{ BR = 'MUST' } "cRLDistributionPoints doesn't meet BR 7.1.2.11.2 (one or more DistributionPoints, each a fullName of http:// URIs, without reasons or cRLIssuer): $(@($issues | Select-Object -Unique) -join '; ')." }
    }
    if ($aiaInfo -and -not $aiaInfo.Error) {
        $issues = New-Object System.Collections.Generic.List[string]
        $notHttp = New-Object System.Collections.Generic.List[string]
        foreach ($ad in $aiaInfo.Entries) {
            if ($ad.Method -notin '1.3.6.1.5.5.7.48.1', '1.3.6.1.5.5.7.48.2') { $issues.Add("accessMethod $($ad.Method) is neither id-ad-ocsp nor id-ad-caIssuers") }
            elseif ($ad.Tag -ne 0x86) { $issues.Add(('an accessLocation is not a uniformResourceIdentifier (tag 0x{0:X2})' -f $ad.Tag)) }
            else {
                $bad = Test-HttpUrl $ad.Uri @('http')
                if ($bad) { $notHttp.Add("'$($ad.Uri)' ($bad)") }
            }
        }
        # Uniqueness applies within each accessMethod: the same URL may serve OCSP and caIssuers
        $dupes = @($aiaInfo.Entries | Group-Object { "$($_.Method)|$($_.LocationDer)" } -CaseSensitive | Where-Object { $_.Count -gt 1 })
        foreach ($d in $dupes) {
            $m = if ($d.Group[0].Method -eq '1.3.6.1.5.5.7.48.1') { 'id-ad-ocsp' } elseif ($d.Group[0].Method -eq '1.3.6.1.5.5.7.48.2') { 'id-ad-caIssuers' } else { $d.Group[0].Method }
            $loc = if ($d.Group[0].Uri) { "'$($d.Group[0].Uri)'" } else { 'an accessLocation' }
            $issues.Add("$loc appears $($d.Count) times for $m (each accessLocation MUST be unique)")
        }
        if ($issues.Count) { Add-Finding @{ BR = 'MUST' } "authorityInfoAccess doesn't meet BR 7.1.2.10.3: $(@($issues | Select-Object -Unique) -join '; ')." }
        if ($notHttp.Count) { Add-Finding @{ BR = 'SHOULD' } "authorityInfoAccess location(s) $(@($notHttp | Select-Object -Unique) -join ', ') are not valid HTTP URLs; BR 7.1.2.10.3 describes each OCSP and caIssuers location as an HTTP URL." }
    }
    if ($cpInfo -and -not $cpInfo.Error) {
        $policyIds = @($cpInfo.Policies | ForEach-Object { $_.Oid })
        $reservedIds = @('2.23.140.1.2.1', '2.23.140.1.2.2', '2.23.140.1.2.3', '2.23.140.1.1')   # DV, OV, IV, EV (BR 7.1.6.1)
        $issues = New-Object System.Collections.Generic.List[string]
        if ($policyIds -contains '2.5.29.32.0') {
            if ($policyIds.Count -gt 1) { $issues.Add('it holds anyPolicy with other policies, but anyPolicy MUST be the only PolicyInformation') }
            else { Add-Finding @{ BR = 'INFO' } "certificatePolicies is anyPolicy. BR 7.1.2.10.5 allows that only when this subordinate CA is an Affiliate of its issuer, which the certificate can't show." }
        } else {
            $reserved = @($policyIds | Where-Object { $_ -in $reservedIds })
            if ($reserved.Count -ne 1) { $issues.Add("it holds $($reserved.Count) Reserved Certificate Policy Identifiers (2.23.140.1.1 / 2.23.140.1.2.x); a policy-restricted CA certificate MUST hold exactly one") }
            elseif ($policyIds[0] -notin $reservedIds) { Add-Finding @{ BR = 'SHOULD' } "The first certificatePolicies entry isn't the Reserved Certificate Policy Identifier; BR 7.1.2.10.5 RECOMMENDS putting it first." }
        }
        $quals = @($cpInfo.Policies | ForEach-Object { $_.Qualifiers })
        if ($quals.Count) {
            Add-Finding @{ BR = 'SHOULD' } "certificatePolicies contains policyQualifiers; BR 7.1.2.10.5 says they are NOT RECOMMENDED."
            foreach ($q in $quals) {
                if ($q.Id -ne '1.3.6.1.5.5.7.2.1') { $issues.Add("policy qualifier $($q.Id) is not id-qt-cps (no other qualifier is permitted)") }
                elseif ($q.Tag -ne 0x16 -or $null -eq $q.Text) { $issues.Add('an id-qt-cps qualifier is not an IA5String') }
                else {
                    $bad = Test-HttpUrl $q.Text @('http', 'https')
                    if ($bad) { Add-Finding @{ BR = 'SHOULD' } "id-qt-cps qualifier '$($q.Text)' is not a valid HTTP or HTTPS URL ($bad), which BR 7.1.2.10.5 describes it as." }
                }
            }
        }
        if ($issues.Count) { Add-Finding @{ BR = 'MUST' } "certificatePolicies doesn't meet BR 7.1.2.10.5: $(@($issues | Select-Object -Unique) -join '; ')." }
    }

    # ---- EKU: BR 7.1.2.6 (TLS subordinate) and 7.1.2.10.6 (a malformed EKU was reported above) ----
    if ($eku -and $eku.Error) { }
    elseif (-not $ekuRaw) {
        if ($selfIssued) { Add-Finding @{ BR = 'INFO' } "No extKeyUsage. For a key-rollover / cross-certificate BR 7.1.2.2 allows an unrestricted EKU in some cases - check which profile applies." }
        else {
            Add-Finding @{ BR = 'MUST' } "No extKeyUsage; a TLS subordinate CA certificate MUST include one with id-kp-serverAuth (BR 7.1.2.6, 7.1.2.10.6). Cross-certificates (7.1.2.2) may differ."
            Add-Finding @{ GEN = 'INFO' } "Without extKeyUsage this CA is unrestricted for every purpose; consider restricting it to what it actually issues."
        }
    } else {
        $ekuNames = @{ '2.5.29.37.0' = 'anyExtendedKeyUsage'; '1.3.6.1.5.5.7.3.3' = 'codeSigning'; '1.3.6.1.5.5.7.3.4' = 'emailProtection'
                       '1.3.6.1.5.5.7.3.8' = 'timeStamping'; '1.3.6.1.5.5.7.3.9' = 'OCSPSigning'; '1.3.6.1.4.1.11129.2.4.4' = 'Precertificate Signing' }
        $tlsOk = @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
        if ($ekuOids -notcontains '1.3.6.1.5.5.7.3.1') { Add-Finding @{ BR = 'MUST' } "extKeyUsage does not include id-kp-serverAuth, which a TLS subordinate CA MUST include (BR 7.1.2.10.6)." }
        $prohibited = @($ekuOids | Where-Object { $ekuNames.ContainsKey($_) } | ForEach-Object { $ekuNames[$_] })
        if ($prohibited.Count) { Add-Finding @{ BR = 'MUST' } "extKeyUsage includes $($prohibited -join ', '), which BR 7.1.2.10.6 prohibits in a TLS subordinate CA certificate." }
        if ($ekuOids -contains '1.3.6.1.5.5.7.3.9') { Add-Finding @{ GEN = 'SHOULD' } "OCSPSigning in a CA certificate lets this CA's key sign OCSP responses on behalf of its issuer (the 2020 delegated-responder problem)." }
        if ($ekuOids -contains '2.5.29.37.0') { Add-Finding @{ GEN = 'INFO' } "anyExtendedKeyUsage makes the EKU unrestricted." }
        $other = @($ekuOids | Where-Object { $_ -notin $tlsOk -and -not $ekuNames.ContainsKey($_) })
        if ($other.Count) { Add-Finding @{ BR = 'SHOULD' } "extKeyUsage includes $($other -join ', '); BR 7.1.2.10.6 says other values are NOT RECOMMENDED." }
    }

    # (nameConstraints criticality is checked with the other extensions)
    if (-not $nc) { Add-Finding @{ GEN = 'INFO' } "No nameConstraints - optional, but useful to limit a private subordinate to internal namespaces." }

    if ($issuer) {
        # ---- Name and key linkage ----
        # Byte comparison for the BR rule; RFC 5280 7.1 name matching for whether the names link at all
        if (-not (Test-BytesEqual $parts.IssuerNameDer $issuerParts.SubjectNameDer)) {
            if (Test-NameMatch $parts.IssuerName $issuerParts.SubjectName) { Add-Finding @{ RFC = 'INFO'; BR = 'MUST' } "Issuer DN matches the supplied issuer's subject under RFC 5280 7.1 name comparison but is encoded differently; BR 7.1.4.1 requires byte-for-byte identical encoding." }
            else { Add-Finding @{ GEN = 'MUST'; RFC = 'MUST' } "Issuer DN ($($cert.Issuer)) does not match the supplied issuer's subject ($($issuer.Subject)) under RFC 5280 7.1 name comparison - wrong -IssuerPath?" }
        }
        $issuerSki = Get-SkiValue $issuer
        if ($aki -and $aki.HasKeyId) {
            if (-not $issuerSki) { Add-Finding @{ GEN = 'INFO' } "Supplied issuer has no usable subjectKeyIdentifier, so AKI linkage can't be checked." -Coverage }
            elseif ($aki.KeyId -ne $issuerSki) { Add-Finding @{ GEN = 'MUST'; RFC = 'MUST' } "AKI keyIdentifier ($($aki.KeyId)) does not match the supplied issuer's SKI ($issuerSki). RFC 5280 4.2.1.2 requires the issuer's SKI to be the value placed here, and path building fails on many platforms." }
        }

        # ---- Signature, checked directly against the supplied issuer's key ----
        switch ($issuerSig.Result) {
            'Valid'   { }
            'Invalid' { Add-Finding @{ GEN = 'MUST' } "Signature does not verify with the supplied issuer's public key ($($issuerSig.Reason))." }
            default   { Add-Finding @{ GEN = 'INFO' } "Signature could not be verified directly with the supplied issuer's key ($($issuerSig.Reason))." -Coverage }
        }
        if ($issuerSelfSig -and $issuerSelfSig.Result -eq 'Invalid') {
            Add-Finding @{ GEN = 'MUST' } "The supplied issuer's own self-signature does not verify. That is a defect in the ISSUER certificate, not this one."
        }

        # ---- Issuer is usable as a CA for this certificate ----
        $ibcRaw = Get-Ext $issuer '2.5.29.19'
        $ibc = $null
        if ($ibcRaw) { $ibc = Read-BasicConstraints $ibcRaw.RawData }
        if (-not $ibc -or $ibc.Error -or -not $ibc.CA) { Add-Finding @{ GEN = 'MUST' } "The supplied issuer is not a CA certificate (its basicConstraints is missing, malformed or has cA FALSE)." }
        elseif (-not $selfIssued -and $ibc.HasPathLen -and $ibc.PathLen -eq 0) {
            # pathLenConstraint counts the non-self-issued intermediate CA certificates that may follow
            # the issuer; the last certificate in a path isn't counted (RFC 5280 4.2.1.9, 6.1.4 (l))
            Add-Finding @{ GEN = 'SHOULD' } "The supplied issuer has pathLenConstraint=0, so no non-self-issued CA certificate may follow it as an intermediate (RFC 5280 4.2.1.9, 6.1.4 (l)). This certificate is still valid as the last certificate in a path, but it can't be used as an intermediate below this issuer, so certificates it issues won't validate through this issuer."
        }
        $ikuRaw = Get-Ext $issuer '2.5.29.15'
        if ($ikuRaw) {
            $iku = Read-KeyUsage $ikuRaw.RawData
            if ($iku.Error) { Add-Finding @{ GEN = 'MUST' } "The supplied issuer's keyUsage is malformed ($($iku.Error))." }
            elseif ($iku.Bits -notcontains 'KeyCertSign') { Add-Finding @{ GEN = 'MUST' } "The supplied issuer's keyUsage lacks keyCertSign." }
        }
        $inbUtc = $issuer.NotBefore.ToUniversalTime()
        $inaUtc = $issuer.NotAfter.ToUniversalTime()
        if ($inaUtc -lt $nowUtc) { Add-Finding @{ GEN = 'MUST' } "The supplied issuer expired on $($inaUtc.ToString('yyyy-MM-dd')) UTC." }
        elseif ($inbUtc -gt $nowUtc) { Add-Finding @{ GEN = 'SHOULD' } "The supplied issuer is not valid until $($inbUtc.ToString('yyyy-MM-dd')) UTC." }
        if ($nbUtc -lt $inbUtc) { Add-Finding @{ GEN = 'INFO' } "notBefore is earlier than the issuer's notBefore; the certificate can't be used before the issuer becomes valid." }
        if ($naUtc -gt $inaUtc) { Add-Finding @{ GEN = 'INFO' } "notAfter is later than the issuer's notAfter; most relying parties stop accepting it when the issuer expires." }

        # ---- Platform chain engine: only elements [this, issuer] are interpreted ----
        $chainEvidence = Invoke-ChainCheck $cert $issuer $issuerSelfSigned @($sha256, (Get-Sha256Hex $issuer.RawData)) @('this certificate', 'the supplied issuer (a problem in the ISSUER certificate, not this one)') @(($issuerSig.Result -ne 'Unverifiable'), ($null -ne $issuerSelfSig -and $issuerSelfSig.Result -ne 'Unverifiable'))

        # ---- Was the signature verified, by this script or by the platform on the supplied path? ----
        if ($issuerSig.Result -eq 'Valid') { $signatureVerifiedBy = "the supplied issuer's key" }
        elseif ($issuerSig.Result -eq 'Unverifiable') {
            if ($chainEvidence.Evaluated -and $chainEvidence.SubjectSignatureOk) {
                $signatureVerifiedBy = 'the platform chain engine, on the supplied path'
                Add-Finding @{ GEN = 'INFO' } "The platform chain engine verified the signature with the supplied issuer's key, which this script couldn't do directly." -Coverage
            } else {
                $how = if ($chainEvidence.Skipped) { 'and the platform chain check was skipped' } elseif ($chainEvidence.Evaluated) { 'and the platform chain engine reported it invalid' } else { "and the platform chain engine didn't evaluate the supplied path" }
                $signatureGap = "its signature couldn't be verified with the supplied issuer's key ($($issuerSig.Reason)), $how"
            }
        }
    } else {
        $signatureGap = 'no -IssuerPath was supplied, so its signature was not checked'
        Add-Finding @{ GEN = 'INFO' } "No -IssuerPath, so the signature, issuer name, AKI/SKI link and validity nesting weren't checked. Supply the issuing CA's certificate to check them." -Coverage
    }
}

Add-Finding @{ GEN = 'INFO' } 'Revocation was not checked; use certutil -verify -urlfetch (Windows) or OpenSSL to check it.' -Coverage

# ======================= Report =======================
$W = Get-ReportWidth
$problems = @($findings | Where-Object { $_.Kind -eq 'Problem' } | Sort-Object @{ Expression = { if ($_.Level -eq 'FAIL') { 0 } else { 1 } } }, Seq)
$notes = @($findings | Where-Object { $_.Kind -eq 'Note' } | Sort-Object Seq)
$otherPolicy = @($findings | Where-Object { $_.Kind -eq 'OtherPolicy' } | Sort-Object Seq)
$limits = @($findings | Where-Object { $_.Kind -eq 'Coverage' } | Sort-Object Seq)
$nFail = @($problems | Where-Object { $_.Level -eq 'FAIL' }).Count
$nWarn = $problems.Count - $nFail

# Exit code for automation (see .NOTES)
$exitCode = if ($nFail) { 2 } elseif ($signatureGap) { 3 } else { 0 }
$warnText = if ($nWarn) { ", $(Format-Count $nWarn 'warning')" } else { '' }
$resultText = switch ($exitCode) {
    2 { "FAIL: $(Format-Count $nFail 'failure')$warnText" }
    3 { "INCOMPLETE: no failures, but the signature was not verified$warnText" }
    0 { if ($nWarn) { "PASSED with $(Format-Count $nWarn 'warning')" } else { 'PASSED' } }
}
$signatureText = if ($signatureVerifiedBy) { "verified with $signatureVerifiedBy" }
                 elseif ($signatureGap) { "NOT verified: $signatureGap" }
                 else { 'does NOT verify (see Problems)' }
$policyNames = @{ 'RFC5280' = 'RFC 5280'; 'CABF-TLS' = 'CA/B Forum TLS Baseline Requirements'; 'ISM' = 'ASD ISM' }
$checkedAgainst = (@('RFC5280') + @($Policy | Where-Object { $_ -ne 'RFC5280' }) | ForEach-Object { $policyNames[$_] }) -join ', '
$notSelected = @($validPolicies | Where-Object { $_ -ne 'RFC5280' -and $Policy -notcontains $_ })

$title = "Inspect-CaCert: $(Split-Path -Leaf $certFile)"
$title
'=' * [math]::Min($W, [math]::Max($title.Length, 60))
Format-Field 'Result' "$resultText (exit code $exitCode)" $W
Format-Field 'Signature' $signatureText $W
Format-Field 'Checked' $checkedAgainst $W

# ---- Certificate ----
Format-Heading 'Certificate'
$daysLeft = [int][math]::Floor($remainingDays)
$validityState = if ($naUtc -lt $nowUtc) { "expired $(Format-Count (-$daysLeft) 'day') ago" }
                 elseif ($nbUtc -gt $nowUtc) { "not valid for another $(Format-Count ([int][math]::Ceiling(($nbUtc - $nowUtc).TotalDays)) 'day')" }
                 else { "$(Format-Count $daysLeft 'day') left" }
$keyText = switch ($key.Algorithm) {
    'RSA'   { if ($key.KeySize) { "RSA $($key.KeySize)-bit, exponent $($key.Exponent)" } else { 'RSA (could not be decoded)' } }
    'ECDSA' { if ($key.CurveOid -and $key.Curve -like 'P-*') { "ECDSA $($key.Curve)" } else { "ECDSA, $($key.Curve)$(if ($key.CurveOid) { " ($($key.CurveOid))" })" } }
    default { $key.Algorithm }
}
if ($key.Compressed) { $keyText += ', compressed point' }
if ($key.Invalid) { $keyText += ' - INVALID (see Problems)' }
Format-Field 'File' $certFile $W
if ($issuerFile) { Format-Field 'Issuer file' $issuerFile $W }
Format-Field 'Role' $role $W
Format-Field 'Subject' $cert.Subject $W
Format-Field 'Issuer' $cert.Issuer $W
Format-Field 'Serial' "$($cert.SerialNumber) ($(Format-Count $serialBits 'bit'))" $W
Format-Field 'Valid' "$($nbUtc.ToString('yyyy-MM-dd HH:mm:ss')) to $($naUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC ($(Format-Count ([int][math]::Round($lifeDays)) 'day'); $validityState)" $W
Format-Field 'Public key' $keyText $W
Format-Field 'Signature alg' $parts.Scheme.Name $W
Format-Field 'Version' "v$($cert.Version)" $W
Format-Field 'SHA-256' $sha256 $W
Format-Field 'SHA-1' "$($cert.Thumbprint) (the Windows thumbprint)" $W

# ---- Extensions ----
Format-Heading 'Extensions'
$extRows = @(foreach ($e in $cert.Extensions) {
    $oid = $e.Oid.Value
    $name = if ($extInfo.ContainsKey($oid)) { $extInfo[$oid].Name } elseif ($e.Oid.FriendlyName) { $e.Oid.FriendlyName } else { $oid }
    [pscustomobject]@{ Name = $name; Critical = $e.Critical; Text = (Get-ExtensionText $e) }
})
if ($extRows.Count -eq 0) { '  (none)' }
else {
    Format-Wrapped '"critical": software that doesn''t understand the extension must reject the whole certificate. It may ignore a non-critical one it doesn''t understand (RFC 5280 4.2).' $W '  '
    ''
    $nameWidth = [math]::Min(34, ($extRows | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum)
    foreach ($row in $extRows) {
        $first = '  ' + $row.Name.PadRight($nameWidth) + '  ' + $(if ($row.Critical) { 'critical' } else { '        ' }) + '  '
        if ($row.Name.Length -gt $nameWidth) { '  ' + $row.Name; $first = ' ' * ($nameWidth + 4) + $(if ($row.Critical) { 'critical' } else { '        ' }) + '  ' }
        Format-Wrapped $row.Text $W $first (' ' * $first.Length)
    }
}

# ---- Findings ----
function Format-Basis($Finding) {
    # The rule tags, e.g. [BR:MUST]; a plain Gen:INFO note doesn't need one
    $tags = @($Finding.Basis -split ' ' | Where-Object { $_ -and $_ -ne 'Gen:INFO' })
    if ($tags.Count) { " [$($tags -join ' ')]" } else { '' }
}
$problemCounts = if ($problems.Count) { ": $nFail FAIL, $nWarn WARN" } else { ': none' }
Format-Heading "Problems$problemCounts"
foreach ($f in $problems) { Format-Wrapped "$($f.Finding)$(Format-Basis $f)" $W ('  ' + $f.Level.PadRight(6)) }
if ($notes.Count) {
    Format-Heading 'Notes'
    foreach ($f in $notes) { Format-Wrapped "$($f.Finding)$(Format-Basis $f)" $W '  - ' }
}
if ($otherPolicy.Count) {
    $hint = if ($notSelected.Count) { ' (run with -Policy All to apply them)' } else { '' }
    Format-Heading 'Other policies'
    Format-Wrapped "Rules from policies that weren't selected, for information only$hint." $W '  '
    foreach ($f in $otherPolicy) { Format-Wrapped "$($f.Finding)$(Format-Basis $f)" $W '  - ' }
}
Format-Heading 'Limits of this run'
foreach ($f in $limits) { Format-Wrapped $f.Finding $W '  - ' }

Format-Heading 'Key'
Format-Wrapped 'Levels: FAIL breaks a MUST in a selected policy. WARN breaks a SHOULD, or possibly a MUST that the certificate alone can''t prove (marked ?).' $W '  '
Format-Wrapped 'Tags give the rule''s source and strength: Gen = general practice, RFC = RFC 5280 and the algorithm RFCs it uses, BR = CA/B Forum TLS Baseline Requirements, ISM = ASD ISM.' $W '  '
Format-Wrapped 'Exit codes: 0 passed, 2 failures, 3 signature not verified, 1 could not inspect.' $W '  '

# A dot-sourced run only sets $LASTEXITCODE, because 'exit' there would end the caller's session
if ($MyInvocation.InvocationName -eq '.') { $global:LASTEXITCODE = $exitCode }
else { exit $exitCode }
