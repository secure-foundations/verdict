// Wrappers for hash functions in libcrux

use vstd::prelude::*;

use verdict_polyfill::*;
use libcrux::digest;

verus! {

pub uninterp spec fn spec_sha224_digest(data: Seq<u8>) -> Seq<u8>;
pub uninterp spec fn spec_sha256_digest(data: Seq<u8>) -> Seq<u8>;
pub uninterp spec fn spec_sha384_digest(data: Seq<u8>) -> Seq<u8>;
pub uninterp spec fn spec_sha512_digest(data: Seq<u8>) -> Seq<u8>;

#[verifier::external_body]
#[inline(always)]
pub fn sha224_digest(data: &[u8]) -> (res: [u8; 28])
    ensures res@ == spec_sha224_digest(data@)
{
    digest::sha2_224(data)
}

#[verifier::external_body]
#[inline(always)]
pub fn sha256_digest(data: &[u8]) -> (res: [u8; 32])
    ensures res@ == spec_sha256_digest(data@)
{
    digest::sha2_256(data)
}

#[verifier::external_body]
#[inline(always)]
pub fn sha384_digest(data: &[u8]) -> (res: [u8; 48])
    ensures res@ == spec_sha384_digest(data@)
{
    digest::sha2_384(data)
}

#[verifier::external_body]
#[inline(always)]
pub fn sha512_digest(data: &[u8]) -> (res: [u8; 64])
    ensures res@ == spec_sha512_digest(data@)
{
    digest::sha2_512(data)
}

const HEX_UPPER: [char; 16] = [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' ];

/// Convert any sequence of bytes to its upper-case hex encoding
pub closed spec fn spec_to_hex_upper(data: Seq<u8>) -> Seq<char>
    decreases data.len()
{
    if data.len() == 0 {
        seq![]
    } else {
        seq![
            HEX_UPPER@[(data.first() >> 4) as int],
            HEX_UPPER@[(data.first() & 0x0f) as int],
        ] + spec_to_hex_upper(data.drop_first())
    }
}

/// Convert a sequence of data to a hex string in upper case
/// e.g. [ 0xbe, 0xef ] -> "BEEF"
pub fn to_hex_upper(data: &[u8]) -> (res: String)
    ensures res@ == spec_to_hex_upper(data@)
{
    let data_len = data.len();
    let mut res = if data.len() <= usize::MAX / 2 { string_new_with_cap(data.len() * 2) }
        else { string_new() };

    assert(data@.skip(0) == data@);

    for i in 0..data_len
        invariant
            data_len == data@.len(),
            spec_to_hex_upper(data@) =~=
                res@ + spec_to_hex_upper(data@.skip(i as int)),
            res@.len() == i * 2,
    {
        let byte = data[i];
        assert(0 <= (byte >> 4) < 16 && 0 <= (byte & 0x0f) < 16) by (bit_vector);

        string_push(&mut res, HEX_UPPER[(byte >> 4) as usize]);
        string_push(&mut res, HEX_UPPER[(byte & 0x0f) as usize]);

        assert(data@.skip(i as int).drop_first() == data@.skip(i + 1));
    }

    res
}

}
