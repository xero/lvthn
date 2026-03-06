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
//            ▀████▄   ▄██▄                   +----------------+
//              ▐████   ▐███                  |    ARGON2ID    |
//       ▄▄██████████    ▐███         ▄▄      +----------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// Argon2id — memory-hardened password hashing and key derivation.
//
// Argon2id is the recommended replacement for the deprecated {@link PBKDF2}.
// Unlike PBKDF2, which is purely CPU-bound, Argon2id forces each guess to
// allocate and fill a large RAM buffer, making GPU/ASIC parallel attacks
// orders of magnitude more expensive.
//
// Thin TypeScript wrapper around the `argon2id` npm package (v1.0.1), a
// WASM-based RFC 9106-compliant implementation by the OpenPGP.js team.
//
// The WASM binaries are embedded as base64 constants so this module works
// in any environment that supports WebAssembly: Node.js, Bun (including
// compiled standalone binaries), and browsers. No filesystem access is
// required at runtime.
//
// @see https://www.rfc-editor.org/rfc/rfc9106  RFC 9106 — Argon2 (2021)
// @see https://github.com/openpgpjs/argon2id  Package source (argon2id@1.0.1)
import setupWasm from 'argon2id/lib/setup.js';
import { constantTimeEqual } from './base';
// ---------------------------------------------------------------------------
// Embedded WASM binaries — argon2id@1.0.1 dist/simd.wasm and dist/no-simd.wasm
//
// Embedded as base64 so the module works in compiled Bun binaries, browsers,
// and any environment where loading from disk at runtime is not possible.
// Regenerate with: node -e "console.log(require('fs').readFileSync('node_modules/argon2id/dist/simd.wasm').toString('base64'))"
// ---------------------------------------------------------------------------
// dist/simd.wasm — argon2id@1.0.1
const SIMD_WASM_B64 = 'AGFzbQEAAAABKwdgBH9/f38AYAABf2AAAGADf39/AGAJf39/f39/f39/AX9gAX8AYAF/AX8CEwED' +
    'ZW52Bm1lbW9yeQIBkAiAgAQDCgkCAwAABAEFBgEEBQFwAQICBgkBfwFBkIjAAgsHfQoDeG9yAAEB' +
    'RwACAkcyAAMFZ2V0TFoABBlfX2luZGlyZWN0X2Z1bmN0aW9uX3RhYmxlAQALX2luaXRpYWxpemUA' +
    'ABBfX2Vycm5vX2xvY2F0aW9uAAgJc3RhY2tTYXZlAAUMc3RhY2tSZXN0b3JlAAYKc3RhY2tBbGxv' +
    'YwAHCQcBAEEBCwEACs0gCQMAAQtYAQJ/A0AgACAEQQR0IgNqIAIgA2r9AAQAIAEgA2r9AAQA/VH9' +
    'CwQAIAAgA0EQciIDaiACIANq/QAEACABIANq/QAEAP1R/QsEACAEQQJqIgRBwABHDQALC7ceAgt7' +
    'A38DQCADIBFBBHQiD2ogASAPav0ABAAgACAPav0ABAD9USIF/QsEACACIA9qIAX9CwQAIAMgD0EQ' +
    'ciIPaiABIA9q/QAEACAAIA9q/QAEAP1RIgX9CwQAIAIgD2ogBf0LBAAgEUECaiIRQcAARw0ACwNA' +
    'IAMgEEEHdGoiAEEQaiAA/QAEcCAA/QAEMCIFIAD9AAQQIgT9zgEgBSAF/Q0AAQIDCAkKCwABAgMI' +
    'CQoLIAQgBP0NAAECAwgJCgsAAQIDCAkKC/3eAUEB/csB/c4BIgT9USIJQSD9ywEgCUEg/c0B/VAi' +
    'CSAA/QAEUCIG/c4BIAkgCf0NAAECAwgJCgsAAQIDCAkKCyAGIAb9DQABAgMICQoLAAECAwgJCgv9' +
    '3gFBAf3LAf3OASIGIAX9USIFQSj9ywEgBUEY/c0B/VAiCCAE/c4BIAggCP0NAAECAwgJCgsAAQID' +
    'CAkKCyAEIAT9DQABAgMICQoLAAECAwgJCgv93gFBAf3LAf3OASIKIAogCf1RIgVBMP3LASAFQRD9' +
    'zQH9UCIFIAb9zgEgBSAF/Q0AAQIDCAkKCwABAgMICQoLIAYgBv0NAAECAwgJCgsAAQIDCAkKC/3e' +
    'AUEB/csB/c4BIgkgCP1RIgRBAf3LASAEQT/9zQH9UCIMIAD9AARgIAD9AAQgIgQgAP0ABAAiBv3O' +
    'ASAEIAT9DQABAgMICQoLAAECAwgJCgsgBiAG/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9ywH9zgEi' +
    'Bv1RIghBIP3LASAIQSD9zQH9UCIIIABBQGsiAf0ABAAiB/3OASAIIAj9DQABAgMICQoLAAECAwgJ' +
    'CgsgByAH/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9ywH9zgEiByAE/VEiBEEo/csBIARBGP3NAf1Q' +
    'IgsgBv3OASALIAv9DQABAgMICQoLAAECAwgJCgsgBiAG/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9' +
    'ywH9zgEiBiAI/VEiBEEw/csBIARBEP3NAf1QIgQgB/3OASAEIAT9DQABAgMICQoLAAECAwgJCgsg' +
    'ByAH/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9ywH9zgEiCCAL/VEiB0EB/csBIAdBP/3NAf1QIg0g' +
    'Df0NAAECAwQFBgcQERITFBUWF/0NCAkKCwwNDg8YGRobHB0eHyIH/c4BIAcgB/0NAAECAwgJCgsA' +
    'AQIDCAkKCyAKIAr9DQABAgMICQoLAAECAwgJCgv93gFBAf3LAf3OASIKIAQgBSAF/Q0AAQIDBAUG' +
    'BxAREhMUFRYX/Q0ICQoLDA0ODxgZGhscHR4f/VEiC0Eg/csBIAtBIP3NAf1QIgsgCP3OASALIAv9' +
    'DQABAgMICQoLAAECAwgJCgsgCCAI/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9ywH9zgEiCCAH/VEi' +
    'B0Eo/csBIAdBGP3NAf1QIgcgCv3OASAHIAf9DQABAgMICQoLAAECAwgJCgsgCiAK/Q0AAQIDCAkK' +
    'CwABAgMICQoL/d4BQQH9ywH9zgEiDv0LBAAgACAGIA0gDCAM/Q0AAQIDBAUGBxAREhMUFRYX/Q0I' +
    'CQoLDA0ODxgZGhscHR4fIgr9zgEgCiAK/Q0AAQIDCAkKCwABAgMICQoLIAYgBv0NAAECAwgJCgsA' +
    'AQIDCAkKC/3eAUEB/csB/c4BIgYgBSAEIAT9DQABAgMEBQYHEBESExQVFhf9DQgJCgsMDQ4PGBka' +
    'GxwdHh/9USIFQSD9ywEgBUEg/c0B/VAiBSAJ/c4BIAUgBf0NAAECAwgJCgsAAQIDCAkKCyAJIAn9' +
    'DQABAgMICQoLAAECAwgJCgv93gFBAf3LAf3OASIJIAr9USIEQSj9ywEgBEEY/c0B/VAiCiAG/c4B' +
    'IAogCv0NAAECAwgJCgsAAQIDCAkKCyAGIAb9DQABAgMICQoLAAECAwgJCgv93gFBAf3LAf3OASIE' +
    '/QsEACAAIAQgBf1RIgVBMP3LASAFQRD9zQH9UCIFIA4gC/1RIgRBMP3LASAEQRD9zQH9UCIEIAT9' +
    'DQABAgMEBQYHEBESExQVFhf9DQgJCgsMDQ4PGBkaGxwdHh/9CwRgIAAgBCAFIAX9DQABAgMEBQYH' +
    'EBESExQVFhf9DQgJCgsMDQ4PGBkaGxwdHh/9CwRwIAEgBCAI/c4BIAQgBP0NAAECAwgJCgsAAQID' +
    'CAkKCyAIIAj9DQABAgMICQoLAAECAwgJCgv93gFBAf3LAf3OASIE/QsEACAAIAUgCf3OASAFIAX9' +
    'DQABAgMICQoLAAECAwgJCgsgCSAJ/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9ywH9zgEiCf0LBFAg' +
    'ACAEIAf9USIFQQH9ywEgBUE//c0B/VAiBSAJIAr9USIEQQH9ywEgBEE//c0B/VAiBCAE/Q0AAQID' +
    'BAUGBxAREhMUFRYX/Q0ICQoLDA0ODxgZGhscHR4f/QsEICAAIAQgBSAF/Q0AAQIDBAUGBxAREhMU' +
    'FRYX/Q0ICQoLDA0ODxgZGhscHR4f/QsEMCAQQQFqIhBBCEcNAAtBACEQA0AgAyAQQQR0aiIAQYAB' +
    'aiAA/QAEgAcgAP0ABIADIgUgAP0ABIABIgT9zgEgBSAF/Q0AAQIDCAkKCwABAgMICQoLIAQgBP0N' +
    'AAECAwgJCgsAAQIDCAkKC/3eAUEB/csB/c4BIgT9USIJQSD9ywEgCUEg/c0B/VAiCSAA/QAEgAUi' +
    'Bv3OASAJIAn9DQABAgMICQoLAAECAwgJCgsgBiAG/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9ywH9' +
    'zgEiBiAF/VEiBUEo/csBIAVBGP3NAf1QIgggBP3OASAIIAj9DQABAgMICQoLAAECAwgJCgsgBCAE' +
    '/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9ywH9zgEiCiAKIAn9USIFQTD9ywEgBUEQ/c0B/VAiBSAG' +
    '/c4BIAUgBf0NAAECAwgJCgsAAQIDCAkKCyAGIAb9DQABAgMICQoLAAECAwgJCgv93gFBAf3LAf3O' +
    'ASIJIAj9USIEQQH9ywEgBEE//c0B/VAiDCAA/QAEgAYgAP0ABIACIgQgAP0ABAAiBv3OASAEIAT9' +
    'DQABAgMICQoLAAECAwgJCgsgBiAG/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9ywH9zgEiBv1RIghB' +
    'IP3LASAIQSD9zQH9UCIIIAD9AASABCIH/c4BIAggCP0NAAECAwgJCgsAAQIDCAkKCyAHIAf9DQAB' +
    'AgMICQoLAAECAwgJCgv93gFBAf3LAf3OASIHIAT9USIEQSj9ywEgBEEY/c0B/VAiCyAG/c4BIAsg' +
    'C/0NAAECAwgJCgsAAQIDCAkKCyAGIAb9DQABAgMICQoLAAECAwgJCgv93gFBAf3LAf3OASIGIAj9' +
    'USIEQTD9ywEgBEEQ/c0B/VAiBCAH/c4BIAQgBP0NAAECAwgJCgsAAQIDCAkKCyAHIAf9DQABAgMI' +
    'CQoLAAECAwgJCgv93gFBAf3LAf3OASIIIAv9USIHQQH9ywEgB0E//c0B/VAiDSAN/Q0AAQIDBAUG' +
    'BxAREhMUFRYX/Q0ICQoLDA0ODxgZGhscHR4fIgf9zgEgByAH/Q0AAQIDCAkKCwABAgMICQoLIAog' +
    'Cv0NAAECAwgJCgsAAQIDCAkKC/3eAUEB/csB/c4BIgogBCAFIAX9DQABAgMEBQYHEBESExQVFhf9' +
    'DQgJCgsMDQ4PGBkaGxwdHh/9USILQSD9ywEgC0Eg/c0B/VAiCyAI/c4BIAsgC/0NAAECAwgJCgsA' +
    'AQIDCAkKCyAIIAj9DQABAgMICQoLAAECAwgJCgv93gFBAf3LAf3OASIIIAf9USIHQSj9ywEgB0EY' +
    '/c0B/VAiByAK/c4BIAcgB/0NAAECAwgJCgsAAQIDCAkKCyAKIAr9DQABAgMICQoLAAECAwgJCgv9' +
    '3gFBAf3LAf3OASIO/QsEACAAIAYgDSAMIAz9DQABAgMEBQYHEBESExQVFhf9DQgJCgsMDQ4PGBka' +
    'GxwdHh8iCv3OASAKIAr9DQABAgMICQoLAAECAwgJCgsgBiAG/Q0AAQIDCAkKCwABAgMICQoL/d4B' +
    'QQH9ywH9zgEiBiAFIAQgBP0NAAECAwQFBgcQERITFBUWF/0NCAkKCwwNDg8YGRobHB0eH/1RIgVB' +
    'IP3LASAFQSD9zQH9UCIFIAn9zgEgBSAF/Q0AAQIDCAkKCwABAgMICQoLIAkgCf0NAAECAwgJCgsA' +
    'AQIDCAkKC/3eAUEB/csB/c4BIgkgCv1RIgRBKP3LASAEQRj9zQH9UCIKIAb9zgEgCiAK/Q0AAQID' +
    'CAkKCwABAgMICQoLIAYgBv0NAAECAwgJCgsAAQIDCAkKC/3eAUEB/csB/c4BIgT9CwQAIAAgBCAF' +
    '/VEiBUEw/csBIAVBEP3NAf1QIgUgDiAL/VEiBEEw/csBIARBEP3NAf1QIgQgBP0NAAECAwQFBgcQ' +
    'ERITFBUWF/0NCAkKCwwNDg8YGRobHB0eH/0LBIAGIAAgBCAFIAX9DQABAgMEBQYHEBESExQVFhf9' +
    'DQgJCgsMDQ4PGBkaGxwdHh/9CwSAByAAIAQgCP3OASAEIAT9DQABAgMICQoLAAECAwgJCgsgCCAI' +
    '/Q0AAQIDCAkKCwABAgMICQoL/d4BQQH9ywH9zgEiBP0LBIAEIAAgBSAJ/c4BIAUgBf0NAAECAwgJ' +
    'CgsAAQIDCAkKCyAJIAn9DQABAgMICQoLAAECAwgJCgv93gFBAf3LAf3OASIJ/QsEgAUgACAEIAf9' +
    'USIFQQH9ywEgBUE//c0B/VAiBSAJIAr9USIEQQH9ywEgBEE//c0B/VAiBCAE/Q0AAQIDBAUGBxAR' +
    'EhMUFRYX/Q0ICQoLDA0ODxgZGhscHR4f/QsEgAIgACAEIAUgBf0NAAECAwQFBgcQERITFBUWF/0N' +
    'CAkKCwwNDg8YGRobHB0eH/0LBIADIBBBAWoiEEEIRw0AC0EAIRADQCACIBBBBHQiAGoiASAAIANq' +
    '/QAEACAB/QAEAP1R/QsEACACIABBEHIiAWoiDyABIANq/QAEACAP/QAEAP1R/QsEACACIABBIHIi' +
    'AWoiDyABIANq/QAEACAP/QAEAP1R/QsEACACIABBMHIiAGoiASAAIANq/QAEACAB/QAEAP1R/QsE' +
    'ACAQQQRqIhBBwABHDQALCxYAIAAgASACIAMQAiAAIAIgAiADEAILewIBfwF+IAIhCSABNQIAIQog' +
    'BCAFcgRAIAEoAgQgA3AhCQsgACAJNgIAIAAgB0EBayAFIAQbIAhsIAZBAWtBAEF/IAYbIAIgCUYb' +
    'aiIBIAVBAWogCGxBACAEG2ogAa0gCiAKfkIgiH5CIIinQX9zaiAHIAhscDYCBCAACwQAIwALBgAg' +
    'ACQACxAAIwAgAGtBcHEiACQAIAALBQBBgAgL';
// dist/no-simd.wasm — argon2id@1.0.1
const NO_SIMD_WASM_B64 = 'AGFzbQEAAAABPwhgBH9/f38AYAABf2AAAGADf39/AGARf39/f39/f39/f39/f39/f38AYAl/f39/' +
    'f39/f38Bf2ABfwBgAX8BfwITAQNlbnYGbWVtb3J5AgGQCICABAMLCgIDBAAABQEGBwEEBQFwAQIC' +
    'BgkBfwFBkIjAAgsHfQoDeG9yAAEBRwADAkcyAAQFZ2V0TFoABRlfX2luZGlyZWN0X2Z1bmN0aW9u' +
    'X3RhYmxlAQALX2luaXRpYWxpemUAABBfX2Vycm5vX2xvY2F0aW9uAAkJc3RhY2tTYXZlAAYMc3Rh' +
    'Y2tSZXN0b3JlAAcKc3RhY2tBbGxvYwAICQcBAEEBCwEACssaCgMAAQtQAQJ/A0AgACAEQQN0IgNq' +
    'IAIgA2opAwAgASADaikDAIU3AwAgACADQQhyIgNqIAIgA2opAwAgASADaikDAIU3AwAgBEECaiIE' +
    'QYABRw0ACwveDwICfgF/IAAgAUEDdGoiEyATKQMAIhEgACAFQQN0aiIBKQMAIhJ8IBFCAYZC/v//' +
    '/x+DIBJC/////w+DfnwiETcDACAAIA1BA3RqIgUgESAFKQMAhUIgiSIRNwMAIAAgCUEDdGoiCSAR' +
    'IAkpAwAiEnwgEUL/////D4MgEkIBhkL+////H4N+fCIRNwMAIAEgESABKQMAhUIoiSIRNwMAIBMg' +
    'ESATKQMAIhJ8IBFC/////w+DIBJCAYZC/v///x+DfnwiETcDACAFIBEgBSkDAIVCMIkiETcDACAJ' +
    'IBEgCSkDACISfCARQv////8PgyASQgGGQv7///8fg358IhE3AwAgASARIAEpAwCFQgGJNwMAIAAg' +
    'AkEDdGoiDSANKQMAIhEgACAGQQN0aiICKQMAIhJ8IBFCAYZC/v///x+DIBJC/////w+DfnwiETcD' +
    'ACAAIA5BA3RqIgYgESAGKQMAhUIgiSIRNwMAIAAgCkEDdGoiCiARIAopAwAiEnwgEUL/////D4Mg' +
    'EkIBhkL+////H4N+fCIRNwMAIAIgESACKQMAhUIoiSIRNwMAIA0gESANKQMAIhJ8IBFC/////w+D' +
    'IBJCAYZC/v///x+DfnwiETcDACAGIBEgBikDAIVCMIkiETcDACAKIBEgCikDACISfCARQv////8P' +
    'gyASQgGGQv7///8fg358IhE3AwAgAiARIAIpAwCFQgGJNwMAIAAgA0EDdGoiDiAOKQMAIhEgACAH' +
    'QQN0aiIDKQMAIhJ8IBFCAYZC/v///x+DIBJC/////w+DfnwiETcDACAAIA9BA3RqIgcgESAHKQMA' +
    'hUIgiSIRNwMAIAAgC0EDdGoiCyARIAspAwAiEnwgEUL/////D4MgEkIBhkL+////H4N+fCIRNwMA' +
    'IAMgESADKQMAhUIoiSIRNwMAIA4gESAOKQMAIhJ8IBFC/////w+DIBJCAYZC/v///x+DfnwiETcD' +
    'ACAHIBEgBykDAIVCMIkiETcDACALIBEgCykDACISfCARQv////8PgyASQgGGQv7///8fg358IhE3' +
    'AwAgAyARIAMpAwCFQgGJNwMAIAAgBEEDdGoiDyAPKQMAIhEgACAIQQN0aiIEKQMAIhJ8IBFCAYZC' +
    '/v///x+DIBJC/////w+DfnwiETcDACAAIBBBA3RqIgggESAIKQMAhUIgiSIRNwMAIAAgDEEDdGoi' +
    'ACARIAApAwAiEnwgEUL/////D4MgEkIBhkL+////H4N+fCIRNwMAIAQgESAEKQMAhUIoiSIRNwMA' +
    'IA8gESAPKQMAIhJ8IBFC/////w+DIBJCAYZC/v///x+DfnwiETcDACAIIBEgCCkDAIVCMIkiETcD' +
    'ACAAIBEgACkDACISfCARQv////8PgyASQgGGQv7///8fg358IhE3AwAgBCARIAQpAwCFQgGJNwMA' +
    'IBMgEykDACIRIAIpAwAiEnwgEUIBhkL+////H4MgEkL/////D4N+fCIRNwMAIAggESAIKQMAhUIg' +
    'iSIRNwMAIAsgESALKQMAIhJ8IBFC/////w+DIBJCAYZC/v///x+DfnwiETcDACACIBEgAikDAIVC' +
    'KIkiETcDACATIBEgEykDACISfCARQv////8PgyASQgGGQv7///8fg358IhE3AwAgCCARIAgpAwCF' +
    'QjCJIhE3AwAgCyARIAspAwAiEnwgEUL/////D4MgEkIBhkL+////H4N+fCIRNwMAIAIgESACKQMA' +
    'hUIBiTcDACANIA0pAwAiESADKQMAIhJ8IBFCAYZC/v///x+DIBJC/////w+DfnwiETcDACAFIBEg' +
    'BSkDAIVCIIkiETcDACAAIBEgACkDACISfCARQv////8PgyASQgGGQv7///8fg358IhE3AwAgAyAR' +
    'IAMpAwCFQiiJIhE3AwAgDSARIA0pAwAiEnwgEUL/////D4MgEkIBhkL+////H4N+fCIRNwMAIAUg' +
    'ESAFKQMAhUIwiSIRNwMAIAAgESAAKQMAIhJ8IBFC/////w+DIBJCAYZC/v///x+DfnwiETcDACAD' +
    'IBEgAykDAIVCAYk3AwAgDiAOKQMAIhEgBCkDACISfCARQgGGQv7///8fgyASQv////8Pg358IhE3' +
    'AwAgBiARIAYpAwCFQiCJIhE3AwAgCSARIAkpAwAiEnwgEUL/////D4MgEkIBhkL+////H4N+fCIR' +
    'NwMAIAQgESAEKQMAhUIoiSIRNwMAIA4gESAOKQMAIhJ8IBFC/////w+DIBJCAYZC/v///x+Dfnwi' +
    'ETcDACAGIBEgBikDAIVCMIkiETcDACAJIBEgCSkDACISfCARQv////8PgyASQgGGQv7///8fg358' +
    'IhE3AwAgBCARIAQpAwCFQgGJNwMAIA8gDykDACIRIAEpAwAiEnwgEUIBhkL+////H4MgEkL/////' +
    'D4N+fCIRNwMAIAcgESAHKQMAhUIgiSIRNwMAIAogESAKKQMAIhJ8IBFC/////w+DIBJCAYZC/v//' +
    '/x+DfnwiETcDACABIBEgASkDAIVCKIkiETcDACAPIBEgDykDACISfCARQv////8PgyASQgGGQv7/' +
    '//8fg358IhE3AwAgByARIAcpAwCFQjCJIhE3AwAgCiARIAopAwAiEnwgEUL/////D4MgEkIBhkL+' +
    '////H4N+fCIRNwMAIAEgESABKQMAhUIBiTcDAAvdCAEPfwNAIAIgBUEDdCIGaiABIAZqKQMAIAAg' +
    'BmopAwCFNwMAIAIgBkEIciIGaiABIAZqKQMAIAAgBmopAwCFNwMAIAVBAmoiBUGAAUcNAAsDQCAD' +
    'IARBA3QiAGogACACaikDADcDACADIARBAXIiAEEDdCIBaiABIAJqKQMANwMAIAMgBEECciIBQQN0' +
    'IgVqIAIgBWopAwA3AwAgAyAEQQNyIgVBA3QiBmogAiAGaikDADcDACADIARBBHIiBkEDdCIHaiAC' +
    'IAdqKQMANwMAIAMgBEEFciIHQQN0IghqIAIgCGopAwA3AwAgAyAEQQZyIghBA3QiCWogAiAJaikD' +
    'ADcDACADIARBB3IiCUEDdCIKaiACIApqKQMANwMAIAMgBEEIciIKQQN0IgtqIAIgC2opAwA3AwAg' +
    'AyAEQQlyIgtBA3QiDGogAiAMaikDADcDACADIARBCnIiDEEDdCINaiACIA1qKQMANwMAIAMgBEEL' +
    'ciINQQN0Ig5qIAIgDmopAwA3AwAgAyAEQQxyIg5BA3QiD2ogAiAPaikDADcDACADIARBDXIiD0ED' +
    'dCIQaiACIBBqKQMANwMAIAMgBEEOciIQQQN0IhFqIAIgEWopAwA3AwAgAyAEQQ9yIhFBA3QiEmog' +
    'AiASaikDADcDACADIARB//8DcSAAQf//A3EgAUH//wNxIAVB//8DcSAGQf//A3EgB0H//wNxIAhB' +
    '//8DcSAJQf//A3EgCkH//wNxIAtB//8DcSAMQf//A3EgDUH//wNxIA5B//8DcSAPQf//A3EgEEH/' +
    '/wNxIBFB//8DcRACIARB8ABJIQAgBEEQaiEEIAANAAtBACEBIANBAEEBQRBBEUEgQSFBMEExQcAA' +
    'QcEAQdAAQdEAQeAAQeEAQfAAQfEAEAIgA0ECQQNBEkETQSJBI0EyQTNBwgBBwwBB0gBB0wBB4gBB' +
    '4wBB8gBB8wAQAiADQQRBBUEUQRVBJEElQTRBNUHEAEHFAEHUAEHVAEHkAEHlAEH0AEH1ABACIANB' +
    'BkEHQRZBF0EmQSdBNkE3QcYAQccAQdYAQdcAQeYAQecAQfYAQfcAEAIgA0EIQQlBGEEZQShBKUE4' +
    'QTlByABByQBB2ABB2QBB6ABB6QBB+ABB+QAQAiADQQpBC0EaQRtBKkErQTpBO0HKAEHLAEHaAEHb' +
    'AEHqAEHrAEH6AEH7ABACIANBDEENQRxBHUEsQS1BPEE9QcwAQc0AQdwAQd0AQewAQe0AQfwAQf0A' +
    'EAIgA0EOQQ9BHkEfQS5BL0E+QT9BzgBBzwBB3gBB3wBB7gBB7wBB/gBB/wAQAgNAIAIgAUEDdCIA' +
    'aiIEIAAgA2opAwAgBCkDAIU3AwAgAiAAQQhyIgRqIgUgAyAEaikDACAFKQMAhTcDACACIABBEHIi' +
    'BGoiBSADIARqKQMAIAUpAwCFNwMAIAIgAEEYciIAaiIEIAAgA2opAwAgBCkDAIU3AwAgAUEEaiIB' +
    'QYABRw0ACwsWACAAIAEgAiADEAMgACACIAIgAxADC3sCAX8BfiACIQkgATUCACEKIAQgBXIEQCAB' +
    'KAIEIANwIQkLIAAgCTYCACAAIAdBAWsgBSAEGyAIbCAGQQFrQQBBfyAGGyACIAlGG2oiASAFQQFq' +
    'IAhsQQAgBBtqIAGtIAogCn5CIIh+QiCIp0F/c2ogByAIbHA2AgQgAAsEACMACwYAIAAkAAsQACMA' +
    'IABrQXBxIgAkACAACwUAQYAICw==';
// Decode base64 to Uint8Array. Works in Node.js, Bun, and browsers (atob is global in all).
function b64toBytes(b64) {
    const binary = atob(b64.replace(/\s/g, ''));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}
// ---------------------------------------------------------------------------
// WASM loader — singleton, initialised on first hash() call
// ---------------------------------------------------------------------------
// Singleton: WASM initialisation is expensive (~50 ms); cache the hasher.
let _hasher;
async function getHasher() {
    if (_hasher)
        return _hasher;
    _hasher = await setupWasm((importObject) => WebAssembly.instantiate(b64toBytes(SIMD_WASM_B64), importObject), (importObject) => WebAssembly.instantiate(b64toBytes(NO_SIMD_WASM_B64), importObject));
    return _hasher;
}
// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------
/**
 * OWASP 2023 minimum recommendation — suitable for most interactive logins.
 *
 * 19 MiB RAM, 2 passes, 1 thread. Typically 50–200 ms on modern server
 * hardware. Use this for login/registration flows where response latency
 * matters.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
export const ARGON2ID_INTERACTIVE = {
    memoryCost: 19456, // 19 MiB — OWASP Password Storage Cheat Sheet 2023 minimum
    timeCost: 2, // 2 passes over memory
    parallelism: 1, // 1 thread
    saltLength: 32, // 256-bit random salt
    hashLength: 32, // 256-bit output
};
/**
 * OWASP 2023 high-security profile — for sensitive credentials where slower
 * is acceptable.
 *
 * 64 MiB RAM, 3 passes, 4 threads. Expect 200 ms–1 s on server hardware.
 * Use for high-value accounts, passphrase-protected secrets, or key escrow.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
export const ARGON2ID_SENSITIVE = {
    memoryCost: 65536, // 64 MiB — OWASP Password Storage Cheat Sheet 2023 high-security
    timeCost: 3, // 3 passes over memory
    parallelism: 4, // 4 threads
    saltLength: 32, // 256-bit random salt
    hashLength: 32, // 256-bit output
};
/**
 * Key derivation preset — INTERACTIVE parameters optimised for deriving
 * Serpent encryption keys from passphrases.
 *
 * Always outputs 32 bytes (256-bit), directly usable as a Serpent-256 key.
 * Store the returned salt alongside the ciphertext — it is required to
 * re-derive the same key for decryption.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
export const ARGON2ID_DERIVE = {
    ...ARGON2ID_INTERACTIVE,
    hashLength: 32, // always 256-bit for key derivation
};
// ---------------------------------------------------------------------------
// Parameter validation
// ---------------------------------------------------------------------------
function validateParams(p) {
    if (p.memoryCost < 8)
        throw new Error(`Argon2id: memoryCost must be >= 8 KiB (got ${p.memoryCost})`);
    if (p.timeCost < 1)
        throw new Error(`Argon2id: timeCost must be >= 1 (got ${p.timeCost})`);
    if (p.parallelism < 1)
        throw new Error(`Argon2id: parallelism must be >= 1 (got ${p.parallelism})`);
    if (p.hashLength < 4)
        throw new Error(`Argon2id: hashLength must be >= 4 bytes (got ${p.hashLength})`);
    if (p.saltLength < 8)
        throw new Error(`Argon2id: saltLength must be >= 8 bytes (got ${p.saltLength})`);
}
// ---------------------------------------------------------------------------
// Class
// ---------------------------------------------------------------------------
/**
 * Argon2id — memory-hardened password hashing and key derivation.
 *
 * Argon2id is the winner of the Password Hashing Competition (2015) and is
 * standardised in RFC 9106 (2021). It is the recommended replacement for
 * the deprecated {@link PBKDF2}.
 *
 * Unlike PBKDF2, which is purely CPU-bound, Argon2id forces each password
 * guess to allocate and fill a large RAM buffer. This makes brute-force
 * attacks with GPUs or ASICs orders of magnitude more expensive than
 * CPU-only KDFs.
 *
 * Argon2id combines Argon2d (data-dependent memory access, GPU-resistant)
 * with Argon2i (data-independent memory access, side-channel-resistant),
 * making it the correct choice for both password storage and key derivation.
 *
 * @example Password hashing and verification
 * ```typescript
 * const argon2 = new Argon2id();
 * const { hash, salt, params } = await argon2.hash('correct horse battery staple');
 * // store hash + salt + params ...
 * const ok = await argon2.verify('correct horse battery staple', hash, salt, params);
 * ```
 *
 * @example Key derivation for Serpent encryption
 * ```typescript
 * const { key, salt } = await new Argon2id().deriveKey('my passphrase');
 * // store salt alongside ciphertext for decryption
 * const cipher = new Serpent_CBC_PKCS7();
 * const ciphertext = cipher.encrypt(key, plaintext, iv);
 * ```
 */
export class Argon2id {
    /**
   * Hash a password or derive a key from a passphrase.
   *
   * Generates a random salt via `crypto.getRandomValues` if none is provided.
   * The global `crypto` object is available in Node.js 19+, Bun, and all
   * modern browsers.
   *
   * **Security:** always store the returned `salt` and `params` alongside the
   * `hash`. All three are required for later verification or re-derivation.
   * Losing the salt makes the hash permanently unverifiable.
   *
   * @param password - plaintext password or passphrase (string or Uint8Array)
   * @param salt     - optional salt; randomly generated if omitted
   * @param params   - Argon2id parameters (default: ARGON2ID_INTERACTIVE)
   * @returns hash, the salt used, and the parameters used
   */
    async hash(password, salt, params = ARGON2ID_INTERACTIVE) {
        validateParams(params);
        const passwordBytes = typeof password === 'string'
            ? new TextEncoder().encode(password)
            : password;
        const saltBytes = salt ??
            (() => {
                const s = new Uint8Array(params.saltLength);
                crypto.getRandomValues(s);
                return s;
            })();
        const hasher = await getHasher();
        const hash = hasher({
            password: passwordBytes,
            salt: saltBytes,
            passes: params.timeCost,
            memorySize: params.memoryCost,
            parallelism: params.parallelism,
            tagLength: params.hashLength,
        });
        return { hash, salt: saltBytes, params };
    }
    /**
   * Verify a password against a previously computed hash.
   *
   * Recomputes the hash with the provided salt and params, then compares
   * the result using `constantTimeEqual` — a constant-time XOR-accumulate
   * comparison that always visits every byte regardless of content. This
   * prevents timing oracle attacks that could distinguish correct from
   * incorrect bytes.
   *
   * **Never** use `===`, `Buffer.equals()`, or `Array.every()` to compare
   * Argon2id hashes — they are not constant-time.
   *
   * @param password - plaintext password to verify
   * @param hash     - previously computed hash (from {@link Argon2idResult.hash})
   * @param salt     - salt used when the hash was computed
   * @param params   - parameters used when the hash was computed
   * @returns true if password matches, false otherwise
   */
    async verify(password, hash, salt, params = ARGON2ID_INTERACTIVE) {
        const result = await this.hash(password, salt, params);
        return constantTimeEqual(result.hash, hash);
    }
    /**
   * Derive a fixed-length encryption key from a passphrase.
   *
   * Convenience wrapper around {@link hash} using {@link ARGON2ID_DERIVE}
   * parameters. The returned key is directly usable as a Serpent-256 key.
   *
   * **Security:** store the returned `salt` alongside the ciphertext — it
   * is required to re-derive the same key for decryption. The salt is not
   * secret but must be unique per encryption.
   *
   * @param passphrase - source passphrase (string or Uint8Array)
   * @param salt       - optional salt; randomly generated if omitted
   * @param keyLength  - output key length in bytes: 16, 24, or 32 (default: 32)
   * @returns { key, salt } — always store the salt alongside the ciphertext
   */
    async deriveKey(passphrase, salt, keyLength = 32) {
        const derivedParams = {
            ...ARGON2ID_DERIVE,
            hashLength: keyLength,
        };
        const result = await this.hash(passphrase, salt, derivedParams);
        return { key: result.hash, salt: result.salt };
    }
}
