# FAPI Cryptographic Profile

Cryptographic profiles determine the cryptographic algorithms and parameters for
all keys and operations of a specific TPM interaction. The values affected by
these profiles are:

* the name hash algorithm
* asymmetric signature algorithm, scheme and parameters (such as curve, keysize, default padding, hash, etc)
* PCR bank selection (which PCR banks shall be extended, quoted and read)

Two exemplary profiles for RSA and ECC are installed with the TSS. By default,
the RSA cryptographic profile is activated. The user is free to create own
cryptographic profiles according to his needs.

Specific profiles are activated in the FAPI configuration file.
If not otherwise specified during TSS installation, the default location for the
exemplary profiles is /etc/tpm2-tss/fapi-profiles/ and /etc/tpm2-tss/ for the FAPI
configuration file.

The parameters of the profile are:

* type: The asymmetric algorithm used for this profile.
* nameAlg: The hash algorithm which will be used for sessions and keys.
* srk_template: The type definition for the /SRK object. See the type parameter of Fapi_CreateKey.
* srk_description: The description to be set for the /EK object. See Fapi_GetDescription.
* ek_template: The type definition for the /EK object. See the type parameter of Fapi_CreateKey.
* ek_description: The description to be set for the /SRK object. See Fapi_GetDescription.
* ecc_signing_scheme: The signing scheme used for ECC keys.
* rsa_signing_scheme: The signing scheme used for RSA keys.
* keyBits: The key size for RSA keys.
* exponent: The exponent of RSA keys.
* sym_mode: The block cipher mode for symmetric encryption.
* sym_parameters: The algorithm and parameters used for symmetric encryption.
* sym_block_size: The block size used for symmetric encryption.
* session_symmetric: The algorithm and parameters used for parameter encryption of
  a session (The same format and default as sym_parameters).
* pcr_selection: The PCR registers and banks used by FAPI.
* curveID: The curve ID for ECC keys.
* ek_policy: The JSON encoded policy for the /EK object.
* srk_policy: The JSON encoded policy for the /SRK object.
* eh_policy: The JSON encoded policy for the endorsement hierarchy /HE.
* sh_policy: The JSON encoded policy for the owner hierarchy /HS.
* lockout_policy: The JSON encoded policy for the lockout hierarchy /LOCKOUT.
* newMaxTries: Count of authorization failures before the lockout is imposed. If not set the default is 5.
* newRecoveryTime: Time in seconds before the authorization failure count is automatically decremented.
  A value of zero indicates that DA protection is disabled. If not set the default is 1000.
* lockoutRecovery: Time in seconds after a lockoutAuth failure before use of lockoutAuth is allowed
  A value of zero indicates that a reboot is required. If not set the default is 1000.
* ignore_ek_template: Ignore EK template stored in NV ram.
  If not set the default is "no".

# EXAMPLES
The following JSON encoded example shows the standard profile for ECC keys:

```
{
    "type": "ecc",
    "nameAlg":"sha256",
    "srk_template": "system,restricted,decrypt,0x81000001",
    "srk_description": "Storage root key SRK",
    "ek_template":  "system,restricted,decrypt",
    "ek_description": "Endorsement key EK",
    "ecc_signing_scheme": {
        "scheme":"ecdsa",
        "details":{
            "hashAlg":"sha256"
        },
    },
    "sym_mode":"cfb",
    "sym_parameters": {
        "algorithm":"aes",
        "keyBits":"128",
        "mode":"cfb"
    },
    "sym_block_size": 16,
    "pcr_selection": [
       { "hash": "sha1",
         "pcrSelect": [ ],
       },
       { "hash": "sha256",
         "pcrSelect": [ 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 ]
       }
    ],
    "curveID": "nist_p256",
    "ek_policy": {
        "description": "Endorsement hierarchy used for policy secret.",
        "policy":[
            {
                "type":"policysecret",
                "objectName": "4000000b",
            }
        ]
    }
}
```
Beside the cryptographic parameters descriptions for the storage root key and the
endorsement key can be set.
For the endorsement hierarchy the policy "ek_policy" is set according to the
TCG Credential profile EK 2.0. The values of the constants are the same as the
constants defined in the TSS header files, where the prefix TPM2_ can be omitted.

The key type of the storage root key and the endorsement key is defined by the
JSON fields srk_template and ek_template.
The type consists of a list of comma and/or space separated keywords. If a
keyword is not present the inverse of the reference TPM attribute bits SHALL be set or cleared.
The keywords are:

* sign: Sets the sign attribute of a key.
* decrypt: Sets the decrypt attribute of a key.
* If neither sign nor decrypt are provided, both attributes SHALL be set.
* restricted: Sets the restricted attribute of a key.
* If restricted is set, either sign or decrypt (but not both) SHALL be set.
* noda: Sets the noda attribute of a key or NV index.
* A hexadecimal number: Marks a key object to be made persistent and sets the persistent object handle to
  this value.
* unique_zero=n: Initialization of the unique field with n zeros for RSA and for the x and y
  ECC unique field.
* unique=hexstring: Initialization of the RSA unique field with a hextring (e.g. 0c0a0f0f0e).
* unique_x=hexstring: Initialization of the ECC x unique field with a hextring (e.g. 0c0a0f0f0e).
* unique_y=hexstring: Initialization of the ECC x unique field with a hextring (e.g. 0c0a0f0f0e).

The RSA profile has specific values for the signing scheme and the decrypt scheme:

```
    "rsa_signing_scheme": {
        "scheme":"rsapss",
        "details":{
            "hashAlg":"sha256"
        }


    "rsa_decrypt_scheme": {
        "scheme":"oaep",
        "details":{
            "hashAlg":"sha256"
        }
    },
```
Possible values for the signing schemes are:

* RSA: RSASSA, RSAPSS
* ECC: ECDSA, ECDAA

Possible modes for symmetric encryption are:

* CTR, OFB, CBC, CFB, ECB, NULL

Possible modes for the RSA decrypt scheme are:

* RSAES, OAEP

The following curve ids can be used:

* ECC_NIST_P192, ECC_NIST_P224, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521, ECC_BN_P256, ECC_BN_P638, ECC_SM2_P256

If the PCR registers 0 to 10 are extended by BIOS and IMA in the SHA1 bank the following PCR selection should
be used to enable the use of FAPI quote and verify quote:
```
    "pcr_selection": [
       { "hash": "sha1",
         "pcrSelect": [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ],
       },
       { "hash": "sha256",
         "pcrSelect": [ 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 ]
       }
    ],
 ```

The directory containing the FAPI profiles includes templates for various
ECC and RSA keys. For ECC P-256 and RSA 2048-bit keys, there are three
distinct profile templates.
The .low-range profile corresponds to the low-range EK templates defined
in the TCG EK Credential Profile and the TCG TPM 2.0 Provisioning Guidance.
The .high-range profile corresponds to the high-range EK templates.
The .legacy profile, currently the default, reflects the FAPI template
used up to TSS version 4.1.3.

The table below illustrates the key differences:
* low-range: noDa: 1, unique field set to zero (key size length).
* high-range: noDa: 1, unique key size set to zero.
* legacy: noDa: 0, unique key size set to zero.

This work is licensed under the
[Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
