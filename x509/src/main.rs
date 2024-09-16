mod asn1;

use polyfill::*;
use vstd::prelude::*;

use der::Encode;

use asn1::*;
use asn1::vest::*;

verus! {
    #[verifier::external_body]
    fn hexdump(data: &[u8]) {
        for chunk in data.chunks(16) {
            for byte in chunk {
                print!("{:02x} ", byte);
            }
            println!();
        }
    }

    fn test_x509() -> Result<(), ()> {
        // -----BEGIN CERTIFICATE-----
        // MIIFWTCCA0GgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJOTzEd
        // MBsGA1UECgwUQnV5cGFzcyBBUy05ODMxNjMzMjcxIDAeBgNVBAMMF0J1eXBhc3Mg
        // Q2xhc3MgMyBSb290IENBMB4XDTEwMTAyNjA4Mjg1OFoXDTQwMTAyNjA4Mjg1OFow
        // TjELMAkGA1UEBhMCTk8xHTAbBgNVBAoMFEJ1eXBhc3MgQVMtOTgzMTYzMzI3MSAw
        // HgYDVQQDDBdCdXlwYXNzIENsYXNzIDMgUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEB
        // BQADggIPADCCAgoCggIBAKXaCpUWUOOV8l6ddjEGMnqb8RB2uACatVI2zSRHsJ8Y
        // ZLya9vrVediQYkwiL944PdbgqOkcLNt4EemOaFEVcsfzM4fkoF0LXOBXByow9c3E
        // N3coTRiR5r/VUv1xLXA+58bEiuPwKAv0dpihi4dVsjoT/Lc+JzeOIuOoTyrvYLs9
        // tznDDgFHmV0ST9tD+leh7fmdvhFHJlsTmKtdFoqwNxxXnUX/iJY2v7vKB3tvh2PX
        // 0DJq1l1sDPGzbjniazEuOQAnFN44wOwZZoYS6J1yFhNkUsepNxz9gjDthBgd9K5c
        // /3ATAOux9TN6S9ZV+AWNS2mw9bMoNlwUxFFzTWsL8TQH2xc519woe2v1n/MuwU8X
        // KhDzzMro6/1rqy6any2CbgTUUgGTLT2G/H783+9CHaZr77kgxve9oKeV/afmiSTY
        // zIw0bOIjL9kSGiG5VZFvC5F5GQytQIgLcOJ60g7YaEi7ghM5EFjp2CoHxhLbWNvS
        // O1UQRwUVZ2J+GGOmRj8JDlQyXr8NYnon74Do29lLBlo3WiXQCBJ31G8JUJc9yB3D
        // 34xFMFbG02SrZvPAXpacw8Tvw3xrizp5f7NJzz3iiZ+gMEuFuZyUJHmPfWupRWgP
        // K9Dx2hzLabjKSWJtyNBjYt1gD1iqj6G8BaVmos8bdrKEZLFMOVLAMLrwjEsCsLa3
        // AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFEe4zf/lb+74suwv
        // Tg75JbCOPGvDMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAACAj
        // QTUEkMJAYmDv4jVM1z+s4jSQuKFvdvoWFqRINyzpkMLyPPgKn9iB5btb2iUspKdV
        // cSQy9sgL8rxq+JOssgfCX5/bzMiKqr5qb+FJEMwx14C7u8jYog5kV+qi9cKpMRXS
        // IGrs/CIBKM+GuIAeqcwRpTzyFrNHnfzSgCHEy9BHcEGhyoMZCCxt8l13nIoUE9Q2
        // HJLw5QY33KbmkJs4j1xrG0aGQ0JfPgEHU1RdZX33inOhmlRaHylDFCfChQ+1iHsa
        // O5S3HWCntZznKWlXWpuTekMwGwPXYshApqr8ZORK15FTAaggiG6cX0S5y2CBNOxv
        // 033aSF/rtJC8LakcC6wc1aJoIIAE1vyxjy+7SjENSoYc6+I2KSb12tjE8nVhz36u
        // dmNKekBlk4f4HoCMhuWG1o8O/FMsYOgWYRqiPkN7zTlgVGr18okmAWiDSKIz6MkE
        // kbIRNBE+6tBDGR8Dk5AM/1E9V/RBbuHLoL7ryWPNbczk+DaqaJ3tvV2XcEQNtg41
        // 3OEMXbugUZTLfhbrES+jkkXITHHZvMmZUldGL1DPvTVp9D0VzgalLA8+9oG6lLvD
        // u79leNKGef9JOxqDDPDeeOzI8k1MGt6CKfjBWtrt7uYnXuhF0J0cUahoq0Tj0Itq
        // 4/g7u9xN12TyUb7mqqta6THuBrxzvxNiCp/HuZc=
        // -----END CERTIFICATE-----
        let cert: Vec<u8> = vec![0x30, 0x82, 0x05, 0x59, 0x30, 0x82, 0x03, 0x41, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x4e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14, 0x42, 0x75, 0x79, 0x70, 0x61, 0x73, 0x73, 0x20, 0x41, 0x53, 0x2d, 0x39, 0x38, 0x33, 0x31, 0x36, 0x33, 0x33, 0x32, 0x37, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x42, 0x75, 0x79, 0x70, 0x61, 0x73, 0x73, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x33, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x30, 0x31, 0x30, 0x32, 0x36, 0x30, 0x38, 0x32, 0x38, 0x35, 0x38, 0x5a, 0x17, 0x0d, 0x34, 0x30, 0x31, 0x30, 0x32, 0x36, 0x30, 0x38, 0x32, 0x38, 0x35, 0x38, 0x5a, 0x30, 0x4e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14, 0x42, 0x75, 0x79, 0x70, 0x61, 0x73, 0x73, 0x20, 0x41, 0x53, 0x2d, 0x39, 0x38, 0x33, 0x31, 0x36, 0x33, 0x33, 0x32, 0x37, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x42, 0x75, 0x79, 0x70, 0x61, 0x73, 0x73, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x33, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xa5, 0xda, 0x0a, 0x95, 0x16, 0x50, 0xe3, 0x95, 0xf2, 0x5e, 0x9d, 0x76, 0x31, 0x06, 0x32, 0x7a, 0x9b, 0xf1, 0x10, 0x76, 0xb8, 0x00, 0x9a, 0xb5, 0x52, 0x36, 0xcd, 0x24, 0x47, 0xb0, 0x9f, 0x18, 0x64, 0xbc, 0x9a, 0xf6, 0xfa, 0xd5, 0x79, 0xd8, 0x90, 0x62, 0x4c, 0x22, 0x2f, 0xde, 0x38, 0x3d, 0xd6, 0xe0, 0xa8, 0xe9, 0x1c, 0x2c, 0xdb, 0x78, 0x11, 0xe9, 0x8e, 0x68, 0x51, 0x15, 0x72, 0xc7, 0xf3, 0x33, 0x87, 0xe4, 0xa0, 0x5d, 0x0b, 0x5c, 0xe0, 0x57, 0x07, 0x2a, 0x30, 0xf5, 0xcd, 0xc4, 0x37, 0x77, 0x28, 0x4d, 0x18, 0x91, 0xe6, 0xbf, 0xd5, 0x52, 0xfd, 0x71, 0x2d, 0x70, 0x3e, 0xe7, 0xc6, 0xc4, 0x8a, 0xe3, 0xf0, 0x28, 0x0b, 0xf4, 0x76, 0x98, 0xa1, 0x8b, 0x87, 0x55, 0xb2, 0x3a, 0x13, 0xfc, 0xb7, 0x3e, 0x27, 0x37, 0x8e, 0x22, 0xe3, 0xa8, 0x4f, 0x2a, 0xef, 0x60, 0xbb, 0x3d, 0xb7, 0x39, 0xc3, 0x0e, 0x01, 0x47, 0x99, 0x5d, 0x12, 0x4f, 0xdb, 0x43, 0xfa, 0x57, 0xa1, 0xed, 0xf9, 0x9d, 0xbe, 0x11, 0x47, 0x26, 0x5b, 0x13, 0x98, 0xab, 0x5d, 0x16, 0x8a, 0xb0, 0x37, 0x1c, 0x57, 0x9d, 0x45, 0xff, 0x88, 0x96, 0x36, 0xbf, 0xbb, 0xca, 0x07, 0x7b, 0x6f, 0x87, 0x63, 0xd7, 0xd0, 0x32, 0x6a, 0xd6, 0x5d, 0x6c, 0x0c, 0xf1, 0xb3, 0x6e, 0x39, 0xe2, 0x6b, 0x31, 0x2e, 0x39, 0x00, 0x27, 0x14, 0xde, 0x38, 0xc0, 0xec, 0x19, 0x66, 0x86, 0x12, 0xe8, 0x9d, 0x72, 0x16, 0x13, 0x64, 0x52, 0xc7, 0xa9, 0x37, 0x1c, 0xfd, 0x82, 0x30, 0xed, 0x84, 0x18, 0x1d, 0xf4, 0xae, 0x5c, 0xff, 0x70, 0x13, 0x00, 0xeb, 0xb1, 0xf5, 0x33, 0x7a, 0x4b, 0xd6, 0x55, 0xf8, 0x05, 0x8d, 0x4b, 0x69, 0xb0, 0xf5, 0xb3, 0x28, 0x36, 0x5c, 0x14, 0xc4, 0x51, 0x73, 0x4d, 0x6b, 0x0b, 0xf1, 0x34, 0x07, 0xdb, 0x17, 0x39, 0xd7, 0xdc, 0x28, 0x7b, 0x6b, 0xf5, 0x9f, 0xf3, 0x2e, 0xc1, 0x4f, 0x17, 0x2a, 0x10, 0xf3, 0xcc, 0xca, 0xe8, 0xeb, 0xfd, 0x6b, 0xab, 0x2e, 0x9a, 0x9f, 0x2d, 0x82, 0x6e, 0x04, 0xd4, 0x52, 0x01, 0x93, 0x2d, 0x3d, 0x86, 0xfc, 0x7e, 0xfc, 0xdf, 0xef, 0x42, 0x1d, 0xa6, 0x6b, 0xef, 0xb9, 0x20, 0xc6, 0xf7, 0xbd, 0xa0, 0xa7, 0x95, 0xfd, 0xa7, 0xe6, 0x89, 0x24, 0xd8, 0xcc, 0x8c, 0x34, 0x6c, 0xe2, 0x23, 0x2f, 0xd9, 0x12, 0x1a, 0x21, 0xb9, 0x55, 0x91, 0x6f, 0x0b, 0x91, 0x79, 0x19, 0x0c, 0xad, 0x40, 0x88, 0x0b, 0x70, 0xe2, 0x7a, 0xd2, 0x0e, 0xd8, 0x68, 0x48, 0xbb, 0x82, 0x13, 0x39, 0x10, 0x58, 0xe9, 0xd8, 0x2a, 0x07, 0xc6, 0x12, 0xdb, 0x58, 0xdb, 0xd2, 0x3b, 0x55, 0x10, 0x47, 0x05, 0x15, 0x67, 0x62, 0x7e, 0x18, 0x63, 0xa6, 0x46, 0x3f, 0x09, 0x0e, 0x54, 0x32, 0x5e, 0xbf, 0x0d, 0x62, 0x7a, 0x27, 0xef, 0x80, 0xe8, 0xdb, 0xd9, 0x4b, 0x06, 0x5a, 0x37, 0x5a, 0x25, 0xd0, 0x08, 0x12, 0x77, 0xd4, 0x6f, 0x09, 0x50, 0x97, 0x3d, 0xc8, 0x1d, 0xc3, 0xdf, 0x8c, 0x45, 0x30, 0x56, 0xc6, 0xd3, 0x64, 0xab, 0x66, 0xf3, 0xc0, 0x5e, 0x96, 0x9c, 0xc3, 0xc4, 0xef, 0xc3, 0x7c, 0x6b, 0x8b, 0x3a, 0x79, 0x7f, 0xb3, 0x49, 0xcf, 0x3d, 0xe2, 0x89, 0x9f, 0xa0, 0x30, 0x4b, 0x85, 0xb9, 0x9c, 0x94, 0x24, 0x79, 0x8f, 0x7d, 0x6b, 0xa9, 0x45, 0x68, 0x0f, 0x2b, 0xd0, 0xf1, 0xda, 0x1c, 0xcb, 0x69, 0xb8, 0xca, 0x49, 0x62, 0x6d, 0xc8, 0xd0, 0x63, 0x62, 0xdd, 0x60, 0x0f, 0x58, 0xaa, 0x8f, 0xa1, 0xbc, 0x05, 0xa5, 0x66, 0xa2, 0xcf, 0x1b, 0x76, 0xb2, 0x84, 0x64, 0xb1, 0x4c, 0x39, 0x52, 0xc0, 0x30, 0xba, 0xf0, 0x8c, 0x4b, 0x02, 0xb0, 0xb6, 0xb7, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x47, 0xb8, 0xcd, 0xff, 0xe5, 0x6f, 0xee, 0xf8, 0xb2, 0xec, 0x2f, 0x4e, 0x0e, 0xf9, 0x25, 0xb0, 0x8e, 0x3c, 0x6b, 0xc3, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x00, 0x20, 0x23, 0x41, 0x35, 0x04, 0x90, 0xc2, 0x40, 0x62, 0x60, 0xef, 0xe2, 0x35, 0x4c, 0xd7, 0x3f, 0xac, 0xe2, 0x34, 0x90, 0xb8, 0xa1, 0x6f, 0x76, 0xfa, 0x16, 0x16, 0xa4, 0x48, 0x37, 0x2c, 0xe9, 0x90, 0xc2, 0xf2, 0x3c, 0xf8, 0x0a, 0x9f, 0xd8, 0x81, 0xe5, 0xbb, 0x5b, 0xda, 0x25, 0x2c, 0xa4, 0xa7, 0x55, 0x71, 0x24, 0x32, 0xf6, 0xc8, 0x0b, 0xf2, 0xbc, 0x6a, 0xf8, 0x93, 0xac, 0xb2, 0x07, 0xc2, 0x5f, 0x9f, 0xdb, 0xcc, 0xc8, 0x8a, 0xaa, 0xbe, 0x6a, 0x6f, 0xe1, 0x49, 0x10, 0xcc, 0x31, 0xd7, 0x80, 0xbb, 0xbb, 0xc8, 0xd8, 0xa2, 0x0e, 0x64, 0x57, 0xea, 0xa2, 0xf5, 0xc2, 0xa9, 0x31, 0x15, 0xd2, 0x20, 0x6a, 0xec, 0xfc, 0x22, 0x01, 0x28, 0xcf, 0x86, 0xb8, 0x80, 0x1e, 0xa9, 0xcc, 0x11, 0xa5, 0x3c, 0xf2, 0x16, 0xb3, 0x47, 0x9d, 0xfc, 0xd2, 0x80, 0x21, 0xc4, 0xcb, 0xd0, 0x47, 0x70, 0x41, 0xa1, 0xca, 0x83, 0x19, 0x08, 0x2c, 0x6d, 0xf2, 0x5d, 0x77, 0x9c, 0x8a, 0x14, 0x13, 0xd4, 0x36, 0x1c, 0x92, 0xf0, 0xe5, 0x06, 0x37, 0xdc, 0xa6, 0xe6, 0x90, 0x9b, 0x38, 0x8f, 0x5c, 0x6b, 0x1b, 0x46, 0x86, 0x43, 0x42, 0x5f, 0x3e, 0x01, 0x07, 0x53, 0x54, 0x5d, 0x65, 0x7d, 0xf7, 0x8a, 0x73, 0xa1, 0x9a, 0x54, 0x5a, 0x1f, 0x29, 0x43, 0x14, 0x27, 0xc2, 0x85, 0x0f, 0xb5, 0x88, 0x7b, 0x1a, 0x3b, 0x94, 0xb7, 0x1d, 0x60, 0xa7, 0xb5, 0x9c, 0xe7, 0x29, 0x69, 0x57, 0x5a, 0x9b, 0x93, 0x7a, 0x43, 0x30, 0x1b, 0x03, 0xd7, 0x62, 0xc8, 0x40, 0xa6, 0xaa, 0xfc, 0x64, 0xe4, 0x4a, 0xd7, 0x91, 0x53, 0x01, 0xa8, 0x20, 0x88, 0x6e, 0x9c, 0x5f, 0x44, 0xb9, 0xcb, 0x60, 0x81, 0x34, 0xec, 0x6f, 0xd3, 0x7d, 0xda, 0x48, 0x5f, 0xeb, 0xb4, 0x90, 0xbc, 0x2d, 0xa9, 0x1c, 0x0b, 0xac, 0x1c, 0xd5, 0xa2, 0x68, 0x20, 0x80, 0x04, 0xd6, 0xfc, 0xb1, 0x8f, 0x2f, 0xbb, 0x4a, 0x31, 0x0d, 0x4a, 0x86, 0x1c, 0xeb, 0xe2, 0x36, 0x29, 0x26, 0xf5, 0xda, 0xd8, 0xc4, 0xf2, 0x75, 0x61, 0xcf, 0x7e, 0xae, 0x76, 0x63, 0x4a, 0x7a, 0x40, 0x65, 0x93, 0x87, 0xf8, 0x1e, 0x80, 0x8c, 0x86, 0xe5, 0x86, 0xd6, 0x8f, 0x0e, 0xfc, 0x53, 0x2c, 0x60, 0xe8, 0x16, 0x61, 0x1a, 0xa2, 0x3e, 0x43, 0x7b, 0xcd, 0x39, 0x60, 0x54, 0x6a, 0xf5, 0xf2, 0x89, 0x26, 0x01, 0x68, 0x83, 0x48, 0xa2, 0x33, 0xe8, 0xc9, 0x04, 0x91, 0xb2, 0x11, 0x34, 0x11, 0x3e, 0xea, 0xd0, 0x43, 0x19, 0x1f, 0x03, 0x93, 0x90, 0x0c, 0xff, 0x51, 0x3d, 0x57, 0xf4, 0x41, 0x6e, 0xe1, 0xcb, 0xa0, 0xbe, 0xeb, 0xc9, 0x63, 0xcd, 0x6d, 0xcc, 0xe4, 0xf8, 0x36, 0xaa, 0x68, 0x9d, 0xed, 0xbd, 0x5d, 0x97, 0x70, 0x44, 0x0d, 0xb6, 0x0e, 0x35, 0xdc, 0xe1, 0x0c, 0x5d, 0xbb, 0xa0, 0x51, 0x94, 0xcb, 0x7e, 0x16, 0xeb, 0x11, 0x2f, 0xa3, 0x92, 0x45, 0xc8, 0x4c, 0x71, 0xd9, 0xbc, 0xc9, 0x99, 0x52, 0x57, 0x46, 0x2f, 0x50, 0xcf, 0xbd, 0x35, 0x69, 0xf4, 0x3d, 0x15, 0xce, 0x06, 0xa5, 0x2c, 0x0f, 0x3e, 0xf6, 0x81, 0xba, 0x94, 0xbb, 0xc3, 0xbb, 0xbf, 0x65, 0x78, 0xd2, 0x86, 0x79, 0xff, 0x49, 0x3b, 0x1a, 0x83, 0x0c, 0xf0, 0xde, 0x78, 0xec, 0xc8, 0xf2, 0x4d, 0x4c, 0x1a, 0xde, 0x82, 0x29, 0xf8, 0xc1, 0x5a, 0xda, 0xed, 0xee, 0xe6, 0x27, 0x5e, 0xe8, 0x45, 0xd0, 0x9d, 0x1c, 0x51, 0xa8, 0x68, 0xab, 0x44, 0xe3, 0xd0, 0x8b, 0x6a, 0xe3, 0xf8, 0x3b, 0xbb, 0xdc, 0x4d, 0xd7, 0x64, 0xf2, 0x51, 0xbe, 0xe6, 0xaa, 0xab, 0x5a, 0xe9, 0x31, 0xee, 0x06, 0xbc, 0x73, 0xbf, 0x13, 0x62, 0x0a, 0x9f, 0xc7, 0xb9, 0x97];

        // -----BEGIN CERTIFICATE-----
        // MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
        // CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
        // MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
        // MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
        // Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
        // A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
        // 27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
        // Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
        // TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
        // qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
        // szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
        // Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
        // MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
        // wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
        // aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
        // VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
        // AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
        // FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
        // C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
        // QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
        // h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
        // 7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
        // ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
        // MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
        // Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
        // 6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
        // 0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
        // 2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
        // bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
        // -----END CERTIFICATE-----
        let cert: Vec<u8> = vec![0x30, 0x82, 0x05, 0x57, 0x30, 0x82, 0x03, 0x3f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0d, 0x02, 0x03, 0xe5, 0x93, 0x6f, 0x31, 0xb0, 0x13, 0x49, 0x88, 0x6b, 0xa2, 0x17, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00, 0x30, 0x47, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x19, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0b, 0x47, 0x54, 0x53, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x52, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x36, 0x32, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x36, 0x32, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x47, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x19, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0b, 0x47, 0x54, 0x53, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x52, 0x31, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xb6, 0x11, 0x02, 0x8b, 0x1e, 0xe3, 0xa1, 0x77, 0x9b, 0x3b, 0xdc, 0xbf, 0x94, 0x3e, 0xb7, 0x95, 0xa7, 0x40, 0x3c, 0xa1, 0xfd, 0x82, 0xf9, 0x7d, 0x32, 0x06, 0x82, 0x71, 0xf6, 0xf6, 0x8c, 0x7f, 0xfb, 0xe8, 0xdb, 0xbc, 0x6a, 0x2e, 0x97, 0x97, 0xa3, 0x8c, 0x4b, 0xf9, 0x2b, 0xf6, 0xb1, 0xf9, 0xce, 0x84, 0x1d, 0xb1, 0xf9, 0xc5, 0x97, 0xde, 0xef, 0xb9, 0xf2, 0xa3, 0xe9, 0xbc, 0x12, 0x89, 0x5e, 0xa7, 0xaa, 0x52, 0xab, 0xf8, 0x23, 0x27, 0xcb, 0xa4, 0xb1, 0x9c, 0x63, 0xdb, 0xd7, 0x99, 0x7e, 0xf0, 0x0a, 0x5e, 0xeb, 0x68, 0xa6, 0xf4, 0xc6, 0x5a, 0x47, 0x0d, 0x4d, 0x10, 0x33, 0xe3, 0x4e, 0xb1, 0x13, 0xa3, 0xc8, 0x18, 0x6c, 0x4b, 0xec, 0xfc, 0x09, 0x90, 0xdf, 0x9d, 0x64, 0x29, 0x25, 0x23, 0x07, 0xa1, 0xb4, 0xd2, 0x3d, 0x2e, 0x60, 0xe0, 0xcf, 0xd2, 0x09, 0x87, 0xbb, 0xcd, 0x48, 0xf0, 0x4d, 0xc2, 0xc2, 0x7a, 0x88, 0x8a, 0xbb, 0xba, 0xcf, 0x59, 0x19, 0xd6, 0xaf, 0x8f, 0xb0, 0x07, 0xb0, 0x9e, 0x31, 0xf1, 0x82, 0xc1, 0xc0, 0xdf, 0x2e, 0xa6, 0x6d, 0x6c, 0x19, 0x0e, 0xb5, 0xd8, 0x7e, 0x26, 0x1a, 0x45, 0x03, 0x3d, 0xb0, 0x79, 0xa4, 0x94, 0x28, 0xad, 0x0f, 0x7f, 0x26, 0xe5, 0xa8, 0x08, 0xfe, 0x96, 0xe8, 0x3c, 0x68, 0x94, 0x53, 0xee, 0x83, 0x3a, 0x88, 0x2b, 0x15, 0x96, 0x09, 0xb2, 0xe0, 0x7a, 0x8c, 0x2e, 0x75, 0xd6, 0x9c, 0xeb, 0xa7, 0x56, 0x64, 0x8f, 0x96, 0x4f, 0x68, 0xae, 0x3d, 0x97, 0xc2, 0x84, 0x8f, 0xc0, 0xbc, 0x40, 0xc0, 0x0b, 0x5c, 0xbd, 0xf6, 0x87, 0xb3, 0x35, 0x6c, 0xac, 0x18, 0x50, 0x7f, 0x84, 0xe0, 0x4c, 0xcd, 0x92, 0xd3, 0x20, 0xe9, 0x33, 0xbc, 0x52, 0x99, 0xaf, 0x32, 0xb5, 0x29, 0xb3, 0x25, 0x2a, 0xb4, 0x48, 0xf9, 0x72, 0xe1, 0xca, 0x64, 0xf7, 0xe6, 0x82, 0x10, 0x8d, 0xe8, 0x9d, 0xc2, 0x8a, 0x88, 0xfa, 0x38, 0x66, 0x8a, 0xfc, 0x63, 0xf9, 0x01, 0xf9, 0x78, 0xfd, 0x7b, 0x5c, 0x77, 0xfa, 0x76, 0x87, 0xfa, 0xec, 0xdf, 0xb1, 0x0e, 0x79, 0x95, 0x57, 0xb4, 0xbd, 0x26, 0xef, 0xd6, 0x01, 0xd1, 0xeb, 0x16, 0x0a, 0xbb, 0x8e, 0x0b, 0xb5, 0xc5, 0xc5, 0x8a, 0x55, 0xab, 0xd3, 0xac, 0xea, 0x91, 0x4b, 0x29, 0xcc, 0x19, 0xa4, 0x32, 0x25, 0x4e, 0x2a, 0xf1, 0x65, 0x44, 0xd0, 0x02, 0xce, 0xaa, 0xce, 0x49, 0xb4, 0xea, 0x9f, 0x7c, 0x83, 0xb0, 0x40, 0x7b, 0xe7, 0x43, 0xab, 0xa7, 0x6c, 0xa3, 0x8f, 0x7d, 0x89, 0x81, 0xfa, 0x4c, 0xa5, 0xff, 0xd5, 0x8e, 0xc3, 0xce, 0x4b, 0xe0, 0xb5, 0xd8, 0xb3, 0x8e, 0x45, 0xcf, 0x76, 0xc0, 0xed, 0x40, 0x2b, 0xfd, 0x53, 0x0f, 0xb0, 0xa7, 0xd5, 0x3b, 0x0d, 0xb1, 0x8a, 0xa2, 0x03, 0xde, 0x31, 0xad, 0xcc, 0x77, 0xea, 0x6f, 0x7b, 0x3e, 0xd6, 0xdf, 0x91, 0x22, 0x12, 0xe6, 0xbe, 0xfa, 0xd8, 0x32, 0xfc, 0x10, 0x63, 0x14, 0x51, 0x72, 0xde, 0x5d, 0xd6, 0x16, 0x93, 0xbd, 0x29, 0x68, 0x33, 0xef, 0x3a, 0x66, 0xec, 0x07, 0x8a, 0x26, 0xdf, 0x13, 0xd7, 0x57, 0x65, 0x78, 0x27, 0xde, 0x5e, 0x49, 0x14, 0x00, 0xa2, 0x00, 0x7f, 0x9a, 0xa8, 0x21, 0xb6, 0xa9, 0xb1, 0x95, 0xb0, 0xa5, 0xb9, 0x0d, 0x16, 0x11, 0xda, 0xc7, 0x6c, 0x48, 0x3c, 0x40, 0xe0, 0x7e, 0x0d, 0x5a, 0xcd, 0x56, 0x3c, 0xd1, 0x97, 0x05, 0xb9, 0xcb, 0x4b, 0xed, 0x39, 0x4b, 0x9c, 0xc4, 0x3f, 0xd2, 0x55, 0x13, 0x6e, 0x24, 0xb0, 0xd6, 0x71, 0xfa, 0xf4, 0xc1, 0xba, 0xcc, 0xed, 0x1b, 0xf5, 0xfe, 0x81, 0x41, 0xd8, 0x00, 0x98, 0x3d, 0x3a, 0xc8, 0xae, 0x7a, 0x98, 0x37, 0x18, 0x05, 0x95, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xe4, 0xaf, 0x2b, 0x26, 0x71, 0x1a, 0x2b, 0x48, 0x27, 0x85, 0x2f, 0x52, 0x66, 0x2c, 0xef, 0xf0, 0x89, 0x13, 0x71, 0x3e, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x9f, 0xaa, 0x42, 0x26, 0xdb, 0x0b, 0x9b, 0xbe, 0xff, 0x1e, 0x96, 0x92, 0x2e, 0x3e, 0xa2, 0x65, 0x4a, 0x6a, 0x98, 0xba, 0x22, 0xcb, 0x7d, 0xc1, 0x3a, 0xd8, 0x82, 0x0a, 0x06, 0xc6, 0xf6, 0xa5, 0xde, 0xc0, 0x4e, 0x87, 0x66, 0x79, 0xa1, 0xf9, 0xa6, 0x58, 0x9c, 0xaa, 0xf9, 0xb5, 0xe6, 0x60, 0xe7, 0xe0, 0xe8, 0xb1, 0x1e, 0x42, 0x41, 0x33, 0x0b, 0x37, 0x3d, 0xce, 0x89, 0x70, 0x15, 0xca, 0xb5, 0x24, 0xa8, 0xcf, 0x6b, 0xb5, 0xd2, 0x40, 0x21, 0x98, 0xcf, 0x22, 0x34, 0xcf, 0x3b, 0xc5, 0x22, 0x84, 0xe0, 0xc5, 0x0e, 0x8a, 0x7c, 0x5d, 0x88, 0xe4, 0x35, 0x24, 0xce, 0x9b, 0x3e, 0x1a, 0x54, 0x1e, 0x6e, 0xdb, 0xb2, 0x87, 0xa7, 0xfc, 0xf3, 0xfa, 0x81, 0x55, 0x14, 0x62, 0x0a, 0x59, 0xa9, 0x22, 0x05, 0x31, 0x3e, 0x82, 0xd6, 0xee, 0xdb, 0x57, 0x34, 0xbc, 0x33, 0x95, 0xd3, 0x17, 0x1b, 0xe8, 0x27, 0xa2, 0x8b, 0x7b, 0x4e, 0x26, 0x1a, 0x7a, 0x5a, 0x64, 0xb6, 0xd1, 0xac, 0x37, 0xf1, 0xfd, 0xa0, 0xf3, 0x38, 0xec, 0x72, 0xf0, 0x11, 0x75, 0x9d, 0xcb, 0x34, 0x52, 0x8d, 0xe6, 0x76, 0x6b, 0x17, 0xc6, 0xdf, 0x86, 0xab, 0x27, 0x8e, 0x49, 0x2b, 0x75, 0x66, 0x81, 0x10, 0x21, 0xa6, 0xea, 0x3e, 0xf4, 0xae, 0x25, 0xff, 0x7c, 0x15, 0xde, 0xce, 0x8c, 0x25, 0x3f, 0xca, 0x62, 0x70, 0x0a, 0xf7, 0x2f, 0x09, 0x66, 0x07, 0xc8, 0x3f, 0x1c, 0xfc, 0xf0, 0xdb, 0x45, 0x30, 0xdf, 0x62, 0x88, 0xc1, 0xb5, 0x0f, 0x9d, 0xc3, 0x9f, 0x4a, 0xde, 0x59, 0x59, 0x47, 0xc5, 0x87, 0x22, 0x36, 0xe6, 0x82, 0xa7, 0xed, 0x0a, 0xb9, 0xe2, 0x07, 0xa0, 0x8d, 0x7b, 0x7a, 0x4a, 0x3c, 0x71, 0xd2, 0xe2, 0x03, 0xa1, 0x1f, 0x32, 0x07, 0xdd, 0x1b, 0xe4, 0x42, 0xce, 0x0c, 0x00, 0x45, 0x61, 0x80, 0xb5, 0x0b, 0x20, 0x59, 0x29, 0x78, 0xbd, 0xf9, 0x55, 0xcb, 0x63, 0xc5, 0x3c, 0x4c, 0xf4, 0xb6, 0xff, 0xdb, 0x6a, 0x5f, 0x31, 0x6b, 0x99, 0x9e, 0x2c, 0xc1, 0x6b, 0x50, 0xa4, 0xd7, 0xe6, 0x18, 0x14, 0xbd, 0x85, 0x3f, 0x67, 0xab, 0x46, 0x9f, 0xa0, 0xff, 0x42, 0xa7, 0x3a, 0x7f, 0x5c, 0xcb, 0x5d, 0xb0, 0x70, 0x1d, 0x2b, 0x34, 0xf5, 0xd4, 0x76, 0x09, 0x0c, 0xeb, 0x78, 0x4c, 0x59, 0x05, 0xf3, 0x33, 0x42, 0xc3, 0x61, 0x15, 0x10, 0x1b, 0x77, 0x4d, 0xce, 0x22, 0x8c, 0xd4, 0x85, 0xf2, 0x45, 0x7d, 0xb7, 0x53, 0xea, 0xef, 0x40, 0x5a, 0x94, 0x0a, 0x5c, 0x20, 0x5f, 0x4e, 0x40, 0x5d, 0x62, 0x22, 0x76, 0xdf, 0xff, 0xce, 0x61, 0xbd, 0x8c, 0x23, 0x78, 0xd2, 0x37, 0x02, 0xe0, 0x8e, 0xde, 0xd1, 0x11, 0x37, 0x89, 0xf6, 0xbf, 0xed, 0x49, 0x07, 0x62, 0xae, 0x92, 0xec, 0x40, 0x1a, 0xaf, 0x14, 0x09, 0xd9, 0xd0, 0x4e, 0xb2, 0xa2, 0xf7, 0xbe, 0xee, 0xee, 0xd8, 0xff, 0xdc, 0x1a, 0x2d, 0xde, 0xb8, 0x36, 0x71, 0xe2, 0xfc, 0x79, 0xb7, 0x94, 0x25, 0xd1, 0x48, 0x73, 0x5b, 0xa1, 0x35, 0xe7, 0xb3, 0x99, 0x67, 0x75, 0xc1, 0x19, 0x3a, 0x2b, 0x47, 0x4e, 0xd3, 0x42, 0x8e, 0xfd, 0x31, 0xc8, 0x16, 0x66, 0xda, 0xd2, 0x0c, 0x3c, 0xdb, 0xb3, 0x8e, 0xc9, 0xa1, 0x0d, 0x80, 0x0f, 0x7b, 0x16, 0x77, 0x14, 0xbf, 0xff, 0xdb, 0x09, 0x94, 0xb2, 0x93, 0xbc, 0x20, 0x58, 0x15, 0xe9, 0xdb, 0x71, 0x43, 0xf3, 0xde, 0x10, 0xc3, 0x00, 0xdc, 0xa8, 0x2a, 0x95, 0xb6, 0xc2, 0xd6, 0x3f, 0x90, 0x6b, 0x76, 0xdb, 0x6c, 0xfe, 0x8c, 0xbc, 0xf2, 0x70, 0x35, 0x0c, 0xdc, 0x99, 0x19, 0x35, 0xdc, 0xd7, 0xc8, 0x46, 0x63, 0xd5, 0x36, 0x71, 0xae, 0x57, 0xfb, 0xb7, 0x82, 0x6d, 0xdc];

        // We don't support SEQUENCE yet, so just read the inner data as an octet string
        let (len, content) = ASN1(ImplicitTag(TagValue {
            class: TagClass::Universal,
            form: TagForm::Constructed,
            num: 0x10,
        }, OctetString)).parse(cert.as_slice())?;

        // Peel off another layer of SEQUENCE (tbsCertificate)
        let (len, content) = ASN1(ImplicitTag(TagValue {
            class: TagClass::Universal,
            form: TagForm::Constructed,
            num: 0x10,
        }, OctetString)).parse(content)?;

        // Parse the first two field (with the first version being an optional field)
        let (len, res) = OrdChoice::new(
            // Version
            (
                ASN1(ExplicitTag(TagValue {
                    class: TagClass::ContextSpecific,
                    form: TagForm::Constructed,
                    num: 0,
                }, ASN1(Integer))),
                ASN1(BigInt),
            ),

            // Serial number
            ASN1(BigInt),
        ).parse(content)?;

        println_join!("parsed: ", format_dbg(res));

        let string_seq = RepeatResult(vec![ "hello", "world" ]);
        let mut buf = vec![ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
        let len = ASN1(SequenceOf(ASN1(UTF8String))).serialize(string_seq, &mut buf, 0)?;
        buf.truncate(len);

        println_join!("serialized:");
        hexdump(buf.as_slice());

        let attribute: Vec<u8> = vec![0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53];

        let x509_attribute_type_and_value = ASN1(ExplicitTag(TagValue {
            class: TagClass::Universal,
            form: TagForm::Constructed,
            num: 0x10,
        }, (ASN1(ObjectIdentifier), Tail)));

        println_join!("parsed: ", format_dbg(x509_attribute_type_and_value.parse(attribute.as_slice())?));

        // let x509_name = ASN1(SequenceOf(
        //     ASN1(SequenceOf(ASN1(

        // )))))

        Ok(())
    }
}

fn test_var_int() {
    assert!(VarUInt(0).parse(&[ 1, 2, 3 ]).unwrap() == (0, 0));
    assert!(VarUInt(8).parse(&[ 0xff, 0x8f, 0x28, 0, 0, 0, 0, 0 ]).unwrap() == (8, 0xff8f_2800_0000_0000));
    assert!(VarInt(0).parse(&[ 0x7f ]).unwrap() == (0, 0));
    assert!(VarInt(1).parse(&[ 0xff ]).unwrap() == (1, -1));
    assert!(VarInt(2).parse(&[ 0x7f, 0xff ]).unwrap() == (2, 0x7fff));
    assert!(VarInt(2).parse(&[ 0x80, 0x00 ]).unwrap() == (2, -32768));

    let mut data = vec![0; 8];
    assert!(VarUInt(0).serialize(0, &mut data, 0).unwrap() == 0);
    assert!(data == [0; 8]);

    let mut data = vec![0; 8];
    assert!(VarUInt(2).serialize(0xbeef, &mut data, 0).unwrap() == 2);
    assert!(data == [ 0xbe, 0xef, 0, 0, 0, 0, 0, 0 ]);

    let mut data = vec![0; 8];
    assert!(VarInt(2).serialize(0x7fff, &mut data, 0).unwrap() == 2);
    assert!(data == [ 0x7f, 0xff, 0, 0, 0, 0, 0, 0 ]);

    let mut data = vec![0; 8];
    assert!(VarInt(2).serialize(-1, &mut data, 0).unwrap() == 2);
    assert!(data == [ 0xff, 0xff, 0, 0, 0, 0, 0, 0 ]);

    let mut data = vec![0; 8];
    assert!(VarInt(0).serialize(0, &mut data, 0).unwrap() == 0);
    assert!(data == [ 0, 0, 0, 0, 0, 0, 0, 0 ]);

    let mut data = vec![0; 8];
    assert!(VarUInt(1).serialize(256, &mut data, 0).is_err());
    assert!(VarInt(1).serialize(-1000, &mut data, 0).is_err());
    assert!(VarInt(1).serialize(0x80, &mut data, 0).is_err());
}

fn test_length() {
    assert!(Length.parse(&[ 0x0 ]).unwrap() == (1, 0));
    assert!(Length.parse(&[ 0x7f ]).unwrap() == (1, 0x7f));
    assert!(Length.parse(&[ 0x80 ]).is_err());
    assert!(Length.parse(&[ 0x81, 0x80 ]).unwrap() == (2, 0x80));
    assert!(Length.parse(&[ 0x81, 0x7f ]).is_err());
    assert!(Length.parse(&[ 0x82, 0x00, 0xff ]).is_err());
    assert!(Length.parse(&[ 0x82, 0x0f, 0xff ]).unwrap() == (3, 0x0fff));
}

fn test_asn1_int() {
    assert!(Integer.parse(&[ 0x01, 0x00 ]).unwrap() == (2, 0));
    assert!(Integer.parse(&[ 0x00 ]).is_err());
    assert!(Integer.parse(&[ 0x01, 0xff ]).unwrap() == (2, -1));
    assert!(Integer.parse(&[ 0x81, 0x01, 0xff ]).is_err());
    assert!(Integer.parse(&[ 0x02, 0x00, 0xff ]).unwrap() == (3, 0xff));
    assert!(Integer.parse(&[ 0x02, 0x00, 0x7f ]).is_err()); // violation of minimal encoding
}

fn serialize_int(v: IntegerValue) -> Result<Vec<u8>, ()> {
    let mut data = vec![0; 16];
    let len = ASN1(Integer).serialize(v, &mut data, 0)?;
    data.truncate(len);
    Ok(data)
}

/// Compare results of serialize to a common ASN.1 DER library
fn diff_test_int_serialize() {
    let diff = |i| {
        let res1 = serialize_int(i);
        let res2 = i.to_der();

        // println!("Testing {}", i);

        match (&res1, &res2) {
            (Ok(v1), Ok(v2)) => assert!(v1 == v2, "Mismatch when encoding {}: {:?} {:?}", i, v1, v2),
            (Err(_), Err(_)) => {},
            _ => panic!("Mismatch when encoding {}: {:?} {:?}", i, &res1, &res2),
        }
    };

    diff(0);
    diff(i64::MAX);
    diff(i64::MIN);

    for i in 0..65535i64 {
        diff(i);
    }

    for i in -65535i64..0 {
        diff(i);
    }
}

fn serialize_octet_string(v: &[u8]) -> Result<Vec<u8>, ()> {
    let mut data = vec![0; v.len() + 10];
    data[0] = 0x04; // Prepend the tag byte
    let len = OctetString.serialize(v, &mut data, 1)?;
    data.truncate(len + 1);
    Ok(data)
}

fn diff_test_octet_string_serialize() {
    let diff = |bytes: &[u8]| {
        let res1 = serialize_octet_string(bytes);
        let res2 = der::asn1::OctetString::new(bytes).unwrap().to_der();

        // println!("Testing {:?}: {:?} {:?}", bytes, res1, res2);

        match (&res1, &res2) {
            (Ok(v1), Ok(v2)) => assert!(v1 == v2, "Mismatch when encoding {:?}: {:?} {:?}", bytes, v1, v2),
            (Err(_), Err(_)) => {},
            _ => panic!("Mismatch when encoding {:?}: {:?} {:?}", bytes, &res1, &res2),
        }
    };

    diff(&[]);
    diff(&[ 0 ]);
    diff(&[ 0; 256 ]);
    diff(&[ 0; 257 ]);
    diff(&[ 0; 65536 ]);
}

fn serialize_utf8_string(v: &str) -> Result<Vec<u8>, ()> {
    let mut data = vec![0; v.len() + 10];
    data[0] = 0x0c; // Prepend the tag byte
    let len = UTF8String.serialize(v, &mut data, 1)?;
    data.truncate(len + 1);
    Ok(data)
}

fn diff_test_utf8_string_serialize() {
    let diff = |s: &str| {
        let res1 = serialize_utf8_string(s);
        let res2 = s.to_string().to_der();

        match (&res1, &res2) {
            (Ok(v1), Ok(v2)) => assert!(v1 == v2, "Mismatch when encoding {:?}: {:?} {:?}", s, v1, v2),
            (Err(_), Err(_)) => {},
            _ => panic!("Mismatch when encoding {:?}: {:?} {:?}", s, &res1, &res2),
        }
    };

    diff("");
    diff("asdsad");
    diff("黑风雷");
    diff("👨‍👩‍👧‍👦");
    diff("黑风雷".repeat(256).as_str());
}

fn serialize_bit_string(v: BitStringValue) -> Result<Vec<u8>, ()> {
    let mut data = vec![0; v.bit_string().len() + 10];
    data[0] = 0x03; // Prepend the tag byte
    let len = BitString.serialize(v, &mut data, 1)?;
    data.truncate(len + 1);
    Ok(data)
}

fn diff_test_bit_string_serialize() {
    // The first byte of raw should denote the number of trailing zeros
    let diff = |raw: &[u8]| {
        let res1 = serialize_bit_string(BitStringValue::new_raw(raw).unwrap());
        let res2 = der::asn1::BitString::new(raw[0], &raw[1..]).unwrap().to_der();

        // println!("Testing {:?}: {:?} {:?}", raw, res1, res2);

        match (&res1, &res2) {
            (Ok(v1), Ok(v2)) => assert!(v1 == v2, "Mismatch when encoding {:?}: {:?} {:?}", raw, res1, res2),
            (Err(_), Err(_)) => {},
            _ => panic!("Mismatch when encoding {:?}: {:?} {:?}", raw, res1, res2),
        }
    };

    diff(&[0]);
    diff(&[5, 0b11100000]);
    diff(&[4, 0b11100000]);
}

fn serialize_ia5_string(v: &str) -> Result<Vec<u8>, ()> {
    let mut data = vec![0; v.len() + 10];
    data[0] = 0x16; // Prepend the tag byte
    let len = IA5String.serialize(IA5StringValue::new(v.as_bytes()).unwrap(), &mut data, 1)?;
    data.truncate(len + 1);
    Ok(data)
}

fn diff_test_ia5_string_serialize() {
    let diff = |s: &str| {
        let res1 = serialize_ia5_string(s);
        let res2 = der::asn1::Ia5StringRef::new(s).unwrap().to_der();

        // println!("Testing {:?}: {:?} {:?}", s, res1, res2);

        match (&res1, &res2) {
            (Ok(v1), Ok(v2)) => assert!(v1 == v2, "Mismatch when encoding {:?}: {:?} {:?}", s, v1, v2),
            (Err(_), Err(_)) => {},
            _ => panic!("Mismatch when encoding {:?}: {:?} {:?}", s, &res1, &res2),
        }
    };

    diff("");
    diff("\x7f");
    diff("asdsad");
    diff("aaaaaa");
    diff("aaaaa".repeat(100).as_str());
}

/// Wrap a base 128 uint in an object identifier for testing
fn serialize_base_128_uint(v: UInt) -> Result<Vec<u8>, ()> {
    let mut data = vec![0; 3 + 10];
    data[0] = 0x06;
    data[2] = 0x2a;
    let len = Base128UInt.serialize(v, &mut data, 3)?;
    data.truncate(len + 3);
    data[1] = (len + 1) as u8;
    Ok(data)
}

fn diff_test_base_128_uint_serialize() {
    let diff = |v: UInt| {
        let res1 = serialize_base_128_uint(v);
        let res2 = &der::asn1::ObjectIdentifier::new_unwrap(format!("1.2.{}", v).as_str()).to_der();

        // println!("Testing {:?}: {:?} {:?}", v, res1, res2);

        match (&res1, &res2) {
            (Ok(v1), Ok(v2)) => assert!(v1 == v2, "Mismatch when encoding {:?}: {:?} {:?}", v, v1, v2),
            (Err(_), Err(_)) => {},
            _ => panic!("Mismatch when encoding {:?}: {:?} {:?}", v, &res1, &res2),
        }
    };

    for i in 0..16383 {
        // TODO: this seems to a bug in the der crate
        if i == 128 {
            continue;
        }

        diff(i);
    }
}

fn serialize_oid(v: Vec<UInt>) -> Result<Vec<u8>, ()> {
    let mut data = vec![0; 1 + 4 + v.len() * 8];
    data[0] = 0x06;
    let len = ObjectIdentifier.serialize(v, &mut data, 1)?;
    data.truncate(len + 1);
    Ok(data)
}

fn diff_test_oid_serialize() {
    let diff = |v: Vec<UInt>| {
        let res1 = serialize_oid(v.clone());
        let res2 = &der::asn1::ObjectIdentifier::new_unwrap(
            v.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(".").as_str()
        ).to_der();

        // println!("Testing {:?}: {:?} {:?}", v, res1, res2);

        match (&res1, &res2) {
            (Ok(v1), Ok(v2)) => assert!(v1 == v2, "Mismatch when encoding {:?}: {:?} {:?}", v, v1, v2),
            (Err(_), Err(_)) => {},
            _ => panic!("Mismatch when encoding {:?}: {:?} {:?}", v, &res1, &res2),
        }
    };

    diff(vec![1, 2, 3]);
    diff(vec![1, 2, 123214]);
    diff(vec![1, 2, 123214, 1231, 4534, 231]);
    diff(vec![2, 10, 123214, 1231, 4534, 231]);
    diff(vec![2, 39, 123214, 1231, 4534, 231]);
}

pub fn main() {
    test_var_int();
    test_length();
    test_asn1_int();
    diff_test_int_serialize();
    diff_test_octet_string_serialize();
    diff_test_utf8_string_serialize();
    diff_test_bit_string_serialize();
    diff_test_ia5_string_serialize();
    diff_test_base_128_uint_serialize();
    diff_test_oid_serialize();

    println!("{:?}", test_x509());

    // hexdump(&(vec!["hello".to_string(), "world".to_string()]).to_der().unwrap());

    // Large serial numbers
    // ASN1(Integer).parse(&[0x02, 0x0D, 0x02, 0x03, 0xE5, 0x93, 0x6F, 0x31, 0xB0, 0x13, 0x49, 0x88, 0x6B, 0xA2, 0x17]).unwrap();

    // hexdump(content);

    // println!("parsed: {:?}", res);

    // let first_two = OrdChoice(
    //     // Version
    //     ASN1(ExplicitTag(TagValue {
    //         class: TagClass::ContextSpecific,
    //         form: TagForm::Primitive,
    //         num: 0,
    //     }, Integer)),

    //     // Serial number
    //     ASN1(Integer),
    // );

    // first_two.parse(&cert).unwrap();

    // let mut data = vec![0; 32];

    // let len = ASN1(ImplicitTag(
    //     TagValue {
    //         class: TagClass::ContextSpecific,
    //         form: TagForm::Constructed,
    //         num: 0x04,
    //     },
    //     ExplicitTag(TagValue {
    //         class: TagClass::ContextSpecific,
    //         form: TagForm::Constructed,
    //         num: 0x03,
    //     }, Integer),
    // )).serialize(1023, &mut data, 0).unwrap();

    // data.truncate(len);
    // hexdump(data.as_slice());


    // let c = asn1::repeat::Repeat(Base128UInt);

    // let mut data = vec![0; 64];
    // let len = c.serialize(asn1::repeat::RepeatResult(vec![ 1, 2, 12321 ]), &mut data, 0).unwrap();
    // let (_, parsed) = c.parse(&data[..len]).unwrap();

    // hexdump(data.as_slice());
    // println!("parsed: {:?}", parsed);

    // https://github.com/RustCrypto/formats/issues/1520
    // hexdump(&der::asn1::ObjectIdentifier::new_unwrap("1.2.128").to_der().unwrap());
    // println!("decoded: {:?}", der::asn1::ObjectIdentifier::from_der(&der::asn1::ObjectIdentifier::new_unwrap("1.2.128").to_der().unwrap()));
    // println!("decoded: {:?}", der::asn1::ObjectIdentifier::from_der(&der::asn1::ObjectIdentifier::new_unwrap("1.2.16388").to_der().unwrap()));
    // println!("decoded: {:?}", der::asn1::ObjectIdentifier::from_der(&der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549").to_der().unwrap()));
    // hexdump(&der::asn1::ObjectIdentifier::new_unwrap("1.2.0").to_der().unwrap());
}
