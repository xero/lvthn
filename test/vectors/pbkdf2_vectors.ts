///////////////////////////////////////////////////////////////////////////////
//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          This file is part of the
//        ▄██████████████████████ ▀████▄      leviathan crypto library
//      ▄█████████▀▀▀     ▀███████▄▄███████▌
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌  Repository
//     ████████      ███▀▀     ████▀  █▀ █▀   https://github.com/xero/leviathan
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      Author: xero (https://x-e.ro)
//       ▀██████   ▄▄██            ▀▀  ██▄    License: MIT
//         ▀█████▄   ▄██▄             ▄▀▄▀
//            ▀████▄   ▄██▄                   +---------------+
//              ▐████   ▐███                  |   TEST SPEC   |
//       ▄▄██████████    ▐███         ▄▄      +---------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// Test vectors — PBKDF2-HMAC-SHA1 and PBKDF2-HMAC-SHA256
//
// SHA1 values: RFC 6070 (PKCS #5 PBKDF2 test vectors)
// @see https://www.rfc-editor.org/rfc/rfc6070
// Date: January 2011
//
// SHA256 values: RFC 7914 §11 (scrypt RFC, PBKDF2-SHA256 appendix)
// @see https://www.rfc-editor.org/rfc/rfc7914
// Date: August 2016
// Note: The original header cited RFC 6070 for all vectors, but RFC 6070
//       only defines PBKDF2-HMAC-SHA1. The sha256 values match RFC 7914.
//
// Verification: sha256 TC1 confirmed via Python hashlib.pbkdf2_hmac.
// Audit status: PARTIAL — TC1 SHA256 verified; remainder UNVERIFIED.
///////////////////////////////////////////////////////////////////////////////

export const vector = [
  {
    key:    "password",
    salt:   "salt",
    c:      1,
    sha1:   "0c60c80f961f0e71f3a9b524af6012062fe037a6",
    sha256: "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
  },
  {
    key:    "password",
    salt:   "salt",
    c:      2,
    sha1:   "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
    sha256: "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
  },
  {
    key:    "password",
    salt:   "salt",
    c:      4096,
    sha1:   "4b007901b765489abead49d926f721d065a429c1",
    sha256: "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
  },
/*
 * this testcase takes very long time!
  {
    key:    "password",
    salt:   "salt",
    c:      16777216,
    sha1:   "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984",
    sha256: "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46"
  },
*/
  {
    key:    "passwordPASSWORDpassword",
    salt:   "saltSALTsaltSALTsaltSALTsaltSALTsalt",
    c:      4096,
    sha1:   "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
    sha256: "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"
  },
  {
    key:    "pass\0word",
    salt:   "sa\0lt",
    c:      4096,
    sha1:   "56fa6aa75548099dcc37d7f03425e0c3",
    sha256: "89b69d0516f829893c696226650a8687"
  }
];
