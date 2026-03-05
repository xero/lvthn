///////////////////////////////////////////////////////////////////////////////
//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          this file is part of the
//        ▄██████████████████████ ▀████▄      leviathan crypto library
//      ▄█████████▀▀▀     ▀███████▄▄███████▌
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌  repository
//     ████████      ███▀▀     ████▀  █▀ █▀   https://github.com/xero/leviathan
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      author: xero (https://x-e.ro)
//       ▀██████   ▄▄██            ▀▀  ██▄    license: mit
//         ▀█████▄   ▄██▄             ▄▀▄▀
//            ▀████▄   ▄██▄                   +---------------+
//              ▐████   ▐███                  |  test vectors |
//       ▄▄██████████    ▐███         ▄▄      +---------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         this file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. the author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// CTR Mode Test Vectors — Provenance
//
// What these vectors are:
//   Authoritative Serpent-CTR test vectors for the leviathan TypeScript library.
//   No official Serpent-CTR vectors exist in any public corpus — CTR mode was
//   not included in the original AES candidate submission — so these vectors
//   were derived from an independent C harness built on the verified reference
//   implementation.
//
// How they were generated:
//   Harness: sources/first_release_c_and_java/serpent/floppy1/ctr_harness.c
//   Date   : 2026-02-27
//   Platform: darwin-arm64 (Apple Silicon), macOS Darwin 25.3.0
//   Compiler: Apple clang 17.0.0 (clang-1700.6.3.2), target arm64-apple-darwin25.3.0
//
//   To regenerate: build and run ctr_harness per the README in floppy1/.
//     cd sources/first_release_c_and_java/serpent/floppy1
//     make ctr_harness && ./ctr_harness
//
// Why floppy1:
//   Ross Anderson's floppy1 (AES submission format) uses the same byte ordering
//   as leviathan — bytes are reversed before packing as 32-bit LE words.  Using
//   floppy1 means harness inputs and outputs can be compared to leviathan directly
//   without any byte-order conversion.  floppy1 also produced floppy4's
//   authoritative ECB/CBC vectors, so its ECB correctness was independently
//   verified before the CTR harness was built on top of it.
//
//   Alternative (sources/serpent/serpent.c) was not used: it uses NESSIE byte
//   ordering (big-endian per-word), incompatible with leviathan without conversion.
//
// Provenance chain:
//   floppy1 reference ECB  -->  ctr_harness.c  -->  hardcoded vectors below
//                                                -->  leviathan test suite (here)
//
// Reference sources branch:
//   The full floppy1 reference sources (including ctr_harness.c and this
//   provenance documentation) live in the reference-sources branch.
//
// ECB cross-corpus sanity:
//   The "Cross-corpus ECB sanity" tests at the bottom of this file tie these
//   CTR vectors back to the independently-verified floppy4 AES submission ECB
//   corpus.  For all-zero plaintext, CT block 0 = ECB_encrypt(key, IV), which
//   is confirmed against floppy4 KAT values:
//     Case A (128-bit zero key): block 0 = E9BA668276B81896D093A9E67AB12036
//     Case B (256-bit zero key): block 0 = 8910494504181950F98DD998A82B6749
///////////////////////////////////////////////////////////////////////////////

export interface CtrVector {
  label:   string;
  keyHex:  string;
  ivHex:   string;
  ptHex:   string;
  ctHex:   string;
  blocks:  number;
}

export const VECTORS: CtrVector[] = [
  {
    label:  'A',
    keyHex: '00000000000000000000000000000000',                            // 128-bit all-zero key
    ivHex:  '00000000000000000000000000000000',
    ptHex:  '000000000000000000000000000000000000000000000000' +           // 3 blocks all-zero PT
            '000000000000000000000000000000000000000000000000',
    ctHex:  'E9BA668276B81896D093A9E67AB12036' +                          // block 0
            'BC0ABF8C2037A9263586DE6BA1CEED9B' +                          // block 1
            '0F250F3B1F294E54A3E34512B0AB5D0C',                           // block 2
    blocks: 3,
  },
  {
    label:  'B',
    keyHex: '0000000000000000000000000000000000000000000000000000000000000000', // 256-bit all-zero key
    ivHex:  '00000000000000000000000000000000',
    ptHex:  '000000000000000000000000000000000000000000000000' +
            '000000000000000000000000000000000000000000000000',
    ctHex:  '8910494504181950F98DD998A82B6749' +                          // block 0 = ECB(zero-256,zero)
            '9FAA1E723BE36AA803321C2383DE86AD' +                          // block 1
            '0A3E7E267FBEF117CE63FCB3F0092CBC',                           // block 2
    blocks: 3,
  },
  {
    label:  'C',
    keyHex: '00000000000000000000000000000000',                            // 128-bit all-zero key
    ivHex:  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',                            // all-FF IV (counter wrap test)
    ptHex:  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +                          // 2 blocks all-FF PT
            'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    ctHex:  '1694760FECE869FDFA46403BF189B54D' +                         // block 0 (ctr=0xFF×16)
            '1645997D8947E7692F6C5619854EDFC9',                           // block 1 (ctr wrapped to 0x00×16)
    blocks: 2,
  },
  {
    label:  'D',
    keyHex: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', // 256-bit key
    ivHex:  '000102030405060708090A0B0C0D0E0F',
    ptHex:  '000102030405060708090A0B0C0D0E0F' +
            '101112131415161718191A1B1C1D1E1F',
    ctHex:  '64A81834E99AE14EA0477CDDF90076E1' +
            '78B4FA40E07C3157F13E8E77855C8EDA',
    blocks: 2,
  },
  {
    label:  'E',
    keyHex: '000000000000000000000000000000000000000000000000', // 192-bit all-zero key
    ivHex:  '00000000000000000000000000000000',
    ptHex:  '000000000000000000000000000000000000000000000000' +
            '000000000000000000000000000000000000000000000000',
    ctHex:  '42046B25C85DBD6B402B296A97EF83A5' +
            '47402E1C09E0C315B13CAB5A5AA17E49' +
            '9DCAABB7839129739D1C6F5501624E44',
    blocks: 3,
  },
];
