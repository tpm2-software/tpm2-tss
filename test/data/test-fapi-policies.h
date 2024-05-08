/* SPDX-FileCopyrightText: 2022, Intel */
/* SPDX-FileCopyrightText: 2022, Fraunhofer SIT sponsored by Infineon */
/* SPDX-FileCopyrightText: 2022, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TEST_FAPI_POLICIES_H
#define TEST_FAPI_POLICIES_H

typedef struct policy_digests policy_digests;
struct policy_digests {
    char *path;
    char *sha1;
    char *sha256;
    char *sha384;
};

/*
 * Table with expected policy digests.
 * If computation is not possible sha256 and sha384 has to be set to NULL.
 * If a policy digest will be computed for these cases an error will be signalled.
 */
static policy_digests _test_fapi_policy_policies[] = {
    { .path = "/policy/pol_action",
      .sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
      .sha384 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    { .path = "/policy/pol_pcr16_0_ecc_authorized",
      .sha256 = "bff2d58e9813f97cefc14f72ad8133bc7092d652b7c877959254af140c841f36",
      .sha384 = "c1923346b6d44a154b58b57b4327ee70c29ac536f9209d94880de6834f370587846a2834e3e88af61efd8679fcccedd5" },
    { .path = "/policy/pol_pcr16_0_ecc_authorized_sha384",
      .sha256 = "bff2d58e9813f97cefc14f72ad8133bc7092d652b7c877959254af140c841f36",
      .sha384 = "c1923346b6d44a154b58b57b4327ee70c29ac536f9209d94880de6834f370587846a2834e3e88af61efd8679fcccedd5" },
    { .path = "/policy/pol_authorize_ecc_pem",
      .sha256 = "b9b370c6b4f84887518634ab408ce23dfc092ae42281a1b8438b3f34d9ceb18e",
      .sha384 = "117b1812194dd8764a3a44c98126fc41ec4b07eead537c29bb3da3712a4aaec5393d4a26442f354b235060d99793fe40" },
    { .path = "/policy/pol_nv_counter", .sha256 = NULL, .sha384 = NULL },
    { .path = "/policy/pol_authorize_rsa_pem",
      .sha256 = "5164b89fcfdc398806c0fde7a3eb52371595fcbec1b1fcea57524c56fff67f46",
      .sha384 = "e424b7ebd622258a40af3a89e541a84fcccff93a54cd9605fda545c650462c4d2d4c7f385b58975bc9b63355b0ca78f9" },
    { .path = "/policy/pol_locality",
      .sha256 = "ddee6af14bf3c4e8127ced87bcf9a57e1c0c8ddb5e67735c8505f96f07b8dbb8",
      .sha384 = "3c6a526ff03d42da670f1cba535f9f1ea8a27e3c810fdb56f4470432b1da5f9ded3e5e330fc094026082a7018a1005ae" },
    { .path = "/policy/pol_nv_change_auth",
      .sha256 = "363ac945b6457c47c31f3355dba0db27de8db213d6250c6bf79685003f9fe7ab",
      .sha384 = "ff675514b27969d171ad33e1ecca800819aca8af2636ce1dcf8a6f91193fb0fc55a19726ec85b795cf6ec14114bfda71" },
    { .path = "/policy/pol_password",
      .sha256 = "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e",
      .sha384 = "0eb13321e885c9603d394e1c33976d4660517111f440d377585f66a94a0eee0a7f73d10b68edc48f61bd3c8385dcddf5" },
    { .path = "/policy/pol_pcr16_0_or",
      .sha256 = "04b01d728fc1ea060d943b3ca6e3e5ea9d3bbb61126542677ad7591c092eafba",
      .sha384 = "2ec9bcccab324ba5f50eedb045853993a37a9eab65bc00b742f85ac5ac809d234e4ac82ac70c10c3aff8196a6cf78515" },
    { .path = "/policy/pol_physical_presence",
      .sha256 = "0d7c6747b1b9facbba03492097aa9d5af792e5efc07346e05f9daa8b3d9e13b5",
      .sha384 = "f743b33cdfcad64b6f85105907895732ca9d4002b5167d52ca82cb65879665e29ef753b5f548eb894b1b2d67a1376ff8" },
    { .path = "/policy/pol_secret", .sha256 = NULL, .sha384 = NULL },
    { .path = "/policy/pol_authorize", .sha256 = NULL, .sha384 = NULL },
    { .path = "/policy/pol_authorize_nv", .sha256 = NULL, .sha384 = NULL },
    { .path = "/policy/pol_auth_value",
      .sha256 = "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e",
      .sha384 = "0eb13321e885c9603d394e1c33976d4660517111f440d377585f66a94a0eee0a7f73d10b68edc48f61bd3c8385dcddf5" },
    { .path = "/policy/pol_command_code",
      .sha256 = "cc6918b226273b08f5bd406d7f10cf160f0a7d13dfd83b7770ccbcd1aa80d811",
      .sha384 = "5093ebce18eacac2fef5a1f4dcb9c8167ee1f45479b189ea362e20f9f86cc93deb6ca4270098915db6dec7d56c9f1979" },
    { .path = "/policy/pol_duplicate", .sha256 = NULL, .sha384 = NULL },
    { .path = "/policy/pol_pcr16_0",
      .sha256 = "bff2d58e9813f97cefc14f72ad8133bc7092d652b7c877959254af140c841f36",
      .sha384 = "c1923346b6d44a154b58b57b4327ee70c29ac536f9209d94880de6834f370587846a2834e3e88af61efd8679fcccedd5" },
    { .path = "/policy/pol_nv", .sha256 = NULL, .sha384 = NULL },
    { .path = "/policy/pol_authorize_outer", .sha256 = NULL, .sha384 = NULL },
    { .path = "/policy/pol_countertimer",
      .sha256 = "7c67802209683d17c1d94f3fc9df7afb2a0d7955c3c5d0fa3f602d58ffdaf984",
      .sha384 = "5735b3080af6597ba9249c692fbb9689da67937d167850a9bdd3e82f08e02bb85eb1f451899bfd5607702257cc68a0ce" },
    { .path = "/policy/pol_cphash",
      .sha256 = "2d7038734b12258ae7108ab70d0e7ee36f4e64c64d53f8adb6c2bed602c95d09",
      .sha384 = "cc26ea5fef3eff5ebc2c1e1c143039bb4c4c20e80ac2480857182623ac29c18e3cb82792dc20ebacf9ca9e32b3eae9b7" },
    { .path = "/policy/pol_name_hash", .sha256 = NULL, .sha384 = NULL },
    { .path = "/policy/pol_nv_written",
      .sha256 = "3c326323670e28ad37bd57f63b4cc34d26ab205ef22f275c58d47fab2485466e",
      .sha384 = "0e017d9a6f87b88af9d8497937e825f688a4bd6681da533191a5fa6d0825ef2e3de21ef2bd4e20578313c6ec5137e79c" },
    { .path = "/policy/pol_pcr16_0_fail",
      .sha256 = "b740077197d46009b9c18f5ad181b7a3ac5bef1d9a881cc5dde808f1a6b8c787",
      .sha384 = "2f5c390f14e2587d26f1b7853703208999ca6e66da38b1c7990bce478c08662c560ae74b41003b3cdb58999b365b0e82" },
    { .path = "/policy/pol_pcr16_read",
      .sha256 = "bff2d58e9813f97cefc14f72ad8133bc7092d652b7c877959254af140c841f36",
      .sha384 = "c1923346b6d44a154b58b57b4327ee70c29ac536f9209d94880de6834f370587846a2834e3e88af61efd8679fcccedd5" },
    { .path = "/policy/pol_pcr8_0",
      .sha256 = "2a90ac03196573f129e70a9e04485bff581d2890fe5882d3c2667290d84b497b",
      .sha384 = "895abaad2fc5af9828963a4f7d093e35f004ab4ab9819ff44745c4d8fcb9df1deca5a7d4503f93335a110042943aeb6c" },
    { .path = "/policy/pol_signed_ecc",
      .sha256 = "07aefc36fb098f5f59f2f74d8854235a29d1f93b4ddd488f6ec667d9c1d716b6",
      .sha384 = "2ba2487836fdaf772ba152469aec86218a068ce9cbc1e8343be81b927cfa178533ab5d663d1498d0c20d6bb91fc5fc58" },
    { .path = "/policy/pol_signed",
      .sha256 = "b1969529af7796c5b4f5e4781713f4525049f36cb12ec63f996dad1c4401c068",
      .sha384 = "33645e642e0a9c249d8cba8690a87cea08069b96d1680061a2c754866af3d8928740f79681fbb8b051afe643cfc200ba" },
    { .path = "/policy/pol_ek_high_range_sha256",
      .sha256 = "ca3d0a99a2b93906f7a3342414efcfb3a385d44cd1fd459089d19b5071c0b7a0",
      .sha384 = "ad6634775155ce801c6d8371f24e570a5b4f3955c07146d7f3c476c8ac48ab30b922e1d7854b79e21c6e7287385e841e" },
    { .path = "/policy/pol_ek_high_range_sha384",
      .sha256 = "c1c7fbac75abb45675550fcf2e2128eb2f4f2bb57b291de05a87f380ecfb1261",
      .sha384 = "02feb9362e0c8a1b2074daf9fc51d82a142732365887b985c118874988004ed22cfe7bb484671b38286b8ccc9cec824e" },
    { .path = "/policy/pol_template",
      .sha256 = "8beacb2d1cb3318856f9a51bbdede1499892b5bbe7fc491f37cf5c6ed56c7d73",
      .sha384 = "48e4538b32d25890d49e8f695c2eae3b1a523bc162d1e82a4842fb7da260e51e8f615e38b3ae18f41899b339bc590f70" },
};
#endif
