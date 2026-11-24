# Inspect-CaCert

A read-only PowerShell script that inspects a CA certificate, root or subordinate, and checks it
against RFC 5280 and, optionally, the CA/Browser Forum TLS Baseline Requirements and the ASD
Information Security Manual (ISM). It uses only built-in .NET classes: there is no OpenSSL and no
module to install.

```powershell
.\Inspect-CaCert.ps1 -Path .\issuing-ca.cer -IssuerPath .\root-ca.cer -Policy All
```

## What it checks

- **Structure**: the certificate, its public key and the extensions it checks are parsed with a
  strict DER reader, so malformed or non-DER encodings are reported rather than silently accepted.
- **Public key**: RSA modulus and exponent; EC points are decoded and checked to lie on P-256,
  P-384 or P-521; key sizes and curves.
- **Signature**: verified with the certificate's own key (for a root) or the issuing CA's key
  (`-IssuerPath`); signature algorithm encodings and hash strength.
- **Names**: issuer and subject compared with RFC 5280 §7.1 name matching (RFC 4518 string
  preparation using RFC 3454's Unicode 3.2 tables), and byte-for-byte where the Baseline
  Requirements demand it.
- **Extensions**: presence, criticality and contents of basicConstraints, keyUsage, extKeyUsage,
  the key identifiers, certificatePolicies, CRL Distribution Points, Authority Information Access
  and nameConstraints, plus duplicate and unrecognised critical extensions.
- **The issuer** (with `-IssuerPath`): the AKI/SKI link, whether the issuer is a CA that may issue
  this certificate, path length constraints and validity nesting.
- **Policy profiles**: the Baseline Requirements Root CA (7.1.2.1) or TLS Subordinate CA (7.1.2.6)
  profile with `-Policy CABF-TLS`, and ISM cryptography guidance with `-Policy ISM`.
- **Platform chain check**: on PowerShell 7.1 or later, the operating system's chain engine also
  validates the supplied path, as a secondary check.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.x. Nothing else to install.
- Developed and tested on Windows PowerShell 5.1 on Windows 11. PowerShell 7.1 or later also
  enables the platform chain check.

If Windows blocks the script because it was downloaded, unblock it once:

```powershell
Unblock-File .\Inspect-CaCert.ps1
```

## Usage

```powershell
# A root CA
.\Inspect-CaCert.ps1 -Path .\root-ca.cer

# A subordinate CA, checked against the CA that issued it
.\Inspect-CaCert.ps1 -Path .\issuing-ca.cer -IssuerPath .\root-ca.cer

# A publicly trusted TLS CA: also apply the CA/B Forum Baseline Requirements
.\Inspect-CaCert.ps1 -Path .\issuing-ca.cer -IssuerPath .\root-ca.cer -Policy CABF-TLS

# Every policy
.\Inspect-CaCert.ps1 -Path .\issuing-ca.cer -IssuerPath .\root-ca.cer -Policy All
```

The input is a single certificate, DER (`.cer`/`.crt`) or PEM/Base64. PFX/PKCS#12 and PKCS#7
(`.p7b`) files are rejected, so nothing is ever imported into a key store. If a PEM file holds
several certificates, only the first is inspected and the report says so.

To inspect a certificate from a Windows certificate store, export it first, for example:

```powershell
Get-ChildItem Cert:\LocalMachine\CA\<thumbprint> | Export-Certificate -FilePath .\issuing-ca.cer
```

### Parameters

| Parameter     | Description |
| ------------- | ----------- |
| `-Path`       | The CA certificate to inspect. Required. |
| `-IssuerPath` | The certificate of the CA that issued `-Path`. Needed to verify a subordinate's signature and to check the issuer name, AKI/SKI link, path length and validity nesting. Ignored for a self-signed root. |
| `-Policy`     | Which policies count towards the result: `RFC5280` (the default, always applied), `CABF-TLS`, `ISM`, or `All`. Values can be combined: `-Policy CABF-TLS,ISM`. |

### Choosing policies

RFC 5280 applies to every X.509 certificate, so it is always applied. The other two only bind some
CAs, so you select the ones yours must meet:

- **`CABF-TLS`**: the CA/Browser Forum TLS Baseline Requirements, for CAs that browsers trust for
  public TLS. Private and enterprise CAs (Active Directory Certificate Services, for example)
  routinely and legitimately break these rules, such as by publishing CRLs over LDAP.
- **`ISM`**: the ASD Information Security Manual's cryptography guidance, for Australian
  government systems.

Every policy is checked on every run. Rules from policies you didn't select are still listed, under
**Other policies**, for information, but they don't become failures or warnings and don't change
the exit code.

## Reading the report

The report is plain text, so it can be redirected to a file or piped. It leads with the result:

| Section            | Contents |
| ------------------ | -------- |
| Result             | `PASSED`, `FAIL` or `INCOMPLETE`, how the signature was verified, and the policies applied |
| Certificate        | Role, names, serial, validity, key, signature algorithm and fingerprints |
| Extensions         | Each extension, whether it's critical, and its value in readable form |
| Problems           | `FAIL` and `WARN` findings, each tagged with the rule behind it |
| Notes              | Advice that isn't a rule violation |
| Other policies     | Rules from policies that weren't selected |
| Limits of this run | What wasn't checked, and why |

- **FAIL** breaks a MUST in a selected policy.
- **WARN** breaks a SHOULD, or possibly a MUST that the certificate alone can't prove. Those are
  marked `?`: a short serial number, for example, suggests but can't prove that it lacks the
  random bits the Baseline Requirements demand.
- **Tags** such as `[BR:MUST]` give each rule's source and strength. `Gen` is general practice,
  `RFC` is RFC 5280 and the algorithm RFCs it relies on, `BR` is the CA/B Forum Baseline
  Requirements and `ISM` is the ASD ISM.
- **critical** next to an extension means that software which doesn't understand the extension must
  reject the whole certificate. It may ignore a non-critical extension it doesn't understand
  (RFC 5280 §4.2).

Example: a private issuing CA that publishes its CRL over both HTTP and LDAP, checked with
`-Policy All`. Under the Baseline Requirements a CRL address must use `http://`, so the LDAP URL is
a failure. With the default policy the same certificate passes, and this finding appears under
Other policies instead.

```text
Inspect-CaCert: issuing-ca.cer
============================================================
  Result        FAIL: 1 failure, 1 warning (exit code 2)
  Signature     verified with the supplied issuer's key
  Checked       RFC 5280, CA/B Forum TLS Baseline Requirements, ASD ISM

Certificate
-----------
  File          C:\pki\issuing-ca.cer
  Issuer file   C:\pki\root-ca.cer
  Role          Subordinate CA
  Subject       CN=Example Issuing CA 1, O=Example Pty Ltd, C=AU
  Issuer        CN=Example Root CA, O=Example Pty Ltd, C=AU
  Serial        40E2FB85293BAEF27BC7CFC049DCF29CBEB9A61F (159 bits)
  Valid         2026-11-24 09:14:48 to 2036-11-23 09:14:48 UTC (3652 days; 3652 days left)
  Public key    RSA 3072-bit, exponent 65537
  Signature alg RSA-PKCS1 with SHA384
  Version       v3
  SHA-256       04ABC9BD682176B3BECE834F2EEED897FC3311B6169E937BC58E060FE65F09A7
  SHA-1         EA52CFAF73038A46A912FDAEB836C9C792A457AD (the Windows thumbprint)

Extensions
----------
  "critical": software that doesn't understand the extension must reject the whole certificate. It may ignore
  a non-critical one it doesn't understand (RFC 5280 4.2).

  basicConstraints        critical  CA, path length 0
  keyUsage                critical  keyCertSign, cRLSign
  subjectKeyIdentifier              1CF9BBE1C562A78BF4AAF3512BE7AD6C7BCE7A63
  authorityKeyIdentifier            keyid 5995802113FF0C4C5A3D00FCC214EC76EF082DFC
  extKeyUsage                       serverAuth, clientAuth
  certificatePolicies               2.23.140.1.2.2 (BR OV)
  cRLDistributionPoints             http://pki.example.com/root.crl;
                                    ldap://ldap.example.com/cn=Example%20Root%20CA?certificateRevocationList
  authorityInfoAccess               caIssuers http://pki.example.com/root.crt

Problems: 1 FAIL, 1 WARN
------------------------
  FAIL  cRLDistributionPoints doesn't meet BR 7.1.2.11.2 (one or more DistributionPoints, each a fullName of
        http:// URIs, without reasons or cRLIssuer):
        'ldap://ldap.example.com/cn=Example%20Root%20CA?certificateRevocationList' is not a valid http URL:
        its scheme is 'ldap', not http. [BR:MUST]
  WARN  cRLDistributionPoints holds 2 DistributionPoints; BR 7.1.2.11.2 says more than one is NOT RECOMMENDED.
        [BR:SHOULD]

Notes
-----
  - Certificate is valid beyond 2030 with a quantum-vulnerable key (RSA). ISM: not approved beyond 2030; NIST
    IR 8547: deprecated after 2030, disallowed after 2035. Needs a PQC migration plan. [ISM:INFO]
  - Subordinate pathLenConstraint = 0.
  - No nameConstraints - optional, but useful to limit a private subordinate to internal namespaces.

Limits of this run
------------------
  - Platform chain check skipped: on PowerShell 5.1 it can't be kept read-only (X509Chain may download issuer
    certificates and update the Windows root store). Run under PowerShell 7.1+ to include it; the script's own
    checks don't need it.
  - Revocation was not checked; use certutil -verify -urlfetch (Windows) or OpenSSL to check it.

Key
---
  Levels: FAIL breaks a MUST in a selected policy. WARN breaks a SHOULD, or possibly a MUST that the
  certificate alone can't prove (marked ?).
  Tags give the rule's source and strength: Gen = general practice, RFC = RFC 5280 and the algorithm RFCs it
  uses, BR = CA/B Forum TLS Baseline Requirements, ISM = ASD ISM.
  Exit codes: 0 passed, 2 failures, 3 signature not verified, 1 could not inspect.
```

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | No FAIL findings, and the certificate's signature was verified |
| `2`  | At least one FAIL finding |
| `3`  | No FAIL findings, but the signature was **not** verified: no `-IssuerPath` was given, or the algorithm is one .NET can't verify. Treat this as incomplete. |
| `1`  | The inspection couldn't run (file not found, not a certificate, ...) |

An exit code of 0 means "no failures and the signature verified", not "valid for use":
revocation is never checked, and warnings never change the exit code. For automation:

```powershell
powershell -NoProfile -File .\Inspect-CaCert.ps1 -Path .\issuing-ca.cer -IssuerPath .\root-ca.cer -Policy CABF-TLS
if ($LASTEXITCODE -ne 0) { throw "CA certificate check failed or was incomplete (exit code $LASTEXITCODE)" }
```

## Read-only by design

- The script reads the input files and writes nothing to certificate stores, caches or disk.
- Certificates are decoded by the script itself rather than handed to the `X509Certificate2` file
  constructor, which would accept a PFX and import its private key into the key store.
- It doesn't fetch anything from the network. The platform chain check runs only on PowerShell 7.1
  or later (.NET 5+), with `DisableCertificateDownloads` set, which stops issuer certificate
  downloads from AIA URLs and Windows root-store updates. On Windows PowerShell 5.1 and PowerShell
  7.0 those can't be turned off, so the chain check is skipped and the report says so.

## Limitations

- Revocation isn't checked. Use `certutil -verify -urlfetch` on Windows, or OpenSSL.
- It inspects one certificate (and its issuer) at a time. Rules that apply across a whole path,
  such as name constraints on the certificates below, are only applied by the platform chain check.
- Subordinates are assessed against the Baseline Requirements TLS Subordinate CA profile.
  Cross-certificates (BR 7.1.2.2) and other profiles, such as S/MIME or code signing, aren't
  modelled.
- nameConstraints is checked against RFC 5280, but not against the Baseline Requirements' own rules
  for its contents (7.1.2.10.8).
- Names encoded as TeletexString are compared byte-for-byte, because RFC 5280 makes their support
  optional and RFC 4518 leaves their conversion to Unicode undefined.

## Licence

MIT. See [LICENCE](LICENCE).
