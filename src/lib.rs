//! Convert DER-encoded X.509 certificates into [`TrustAnchor`]s at compile time.
//!
//! ```
//! use const_trust_anchor::{TrustAnchor, anchor_from_trusted_cert};
//!
//! const ANCHOR: TrustAnchor<'static> =
//!     anchor_from_trusted_cert(include_bytes!("../tests/data/name_constraints.der"));
//!
//! assert!(ANCHOR.name_constraints.is_some());
//! ```
#![no_std]
use core::fmt;

pub use rustls_pki_types::{Der, TrustAnchor};

/// The reason a certificate could not be converted into a [`TrustAnchor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ends in the middle of a TLV.
    TooShort,
    /// The TLV length is indefinite or longer than 4 bytes.
    UnsupportedLength,
    /// The TLV length is not in the shortest form, which DER requires.
    NonMinimalLength,
    /// The outer `Certificate` is malformed or followed by trailing data.
    BadCertificate,
    /// The `TBSCertificate` is malformed.
    BadTbsCertificate,
    /// The certificate is not X.509 v3.
    UnsupportedVersion,
    /// The `serialNumber` is malformed.
    BadSerialNumber,
    /// The `signature` `AlgorithmIdentifier` is malformed.
    BadSignatureAlgorithm,
    /// The `issuer` is malformed.
    BadIssuer,
    /// The `validity` is malformed.
    BadValidity,
    /// The `subject` is malformed.
    BadSubject,
    /// The `subjectPublicKeyInfo` is malformed.
    BadSubjectPublicKeyInfo,
    /// The `extensions` are malformed.
    BadExtensions,
    /// The name constraints extension is malformed or appears more than once.
    BadNameConstraints,
}

impl Error {
    /// A static description of the error, usable in a const context.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TooShort => "length too short",
            Self::UnsupportedLength => "unsupported length",
            Self::NonMinimalLength => "non-minimal length",
            Self::BadCertificate => "invalid Certificate",
            Self::BadTbsCertificate => "invalid TBSCertificate",
            Self::UnsupportedVersion => "unsupported version",
            Self::BadSerialNumber => "invalid CertificateSerialNumber",
            Self::BadSignatureAlgorithm => "invalid AlgorithmIdentifier",
            Self::BadIssuer => "invalid Issuer",
            Self::BadValidity => "invalid Validity",
            Self::BadSubject => "invalid Subject",
            Self::BadSubjectPublicKeyInfo => "invalid SubjectPublicKeyInfo",
            Self::BadExtensions => "invalid Extensions",
            Self::BadNameConstraints => "invalid NameConstraints",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::error::Error for Error {}

// `?` for const fn
macro_rules! tri {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Err(e),
        }
    };
}

// (tag, value)
type Tlv<'a> = (u8, &'a [u8]);

// parse the DER encoded TLV
// input is a slice of bytes, includes the DER encoded TLV
// output is (remaining bytes, (tag, value))
const fn read_tlv(der: &[u8]) -> Result<(&[u8], Tlv<'_>), Error> {
    let [tag, first_len_byte, rem @ ..] = der else {
        return Err(Error::TooShort);
    };

    let (len, rem) = if *first_len_byte & 0x80 == 0 {
        (*first_len_byte as usize, rem)
    } else {
        let Some((len_bytes, rem)) = rem.split_at_checked((*first_len_byte & 0x7f) as usize) else {
            return Err(Error::TooShort);
        };

        // 4 bytes is enough for any certificate
        let len = match len_bytes {
            [a @ (0x80..)] => u32::from_be_bytes([0, 0, 0, *a]),
            [a @ (1..), b] => u32::from_be_bytes([0, 0, *a, *b]),
            [a @ (1..), b, c] => u32::from_be_bytes([0, *a, *b, *c]),
            [a @ (1..), b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]),
            // fits in the short form, or has leading zeros
            [_] | [0, ..] => return Err(Error::NonMinimalLength),
            // also rejects the indefinite length, which DER forbids
            _ => return Err(Error::UnsupportedLength),
        };
        (len as usize, rem)
    };

    let Some((value, rem)) = rem.split_at_checked(len) else {
        return Err(Error::TooShort);
    };

    Ok((rem, (*tag, value)))
}

// find the NameConstraints extension
// input is the remaining bytes of TBSCertificate after SubjectPublicKeyInfo
// output is the content of the NameConstraints SEQUENCE, same as webpki
const fn find_name_constraints(tbs_rem: &[u8]) -> Result<Option<&[u8]>, Error> {
    // extensions are optional
    if tbs_rem.is_empty() {
        return Ok(None);
    }

    let (&[], (0xa3, extensions)) = tri!(read_tlv(tbs_rem)) else {
        return Err(Error::BadExtensions);
    };
    let (&[], (0x30, mut extensions)) = tri!(read_tlv(extensions)) else {
        return Err(Error::BadExtensions);
    };

    let mut name_constraints = None;

    while !extensions.is_empty() {
        let (rem, (0x30, extension)) = tri!(read_tlv(extensions)) else {
            return Err(Error::BadExtensions);
        };
        extensions = rem;

        let (rem, (0x06, oid)) = tri!(read_tlv(extension)) else {
            return Err(Error::BadExtensions);
        };

        // skip critical, DER omits it when FALSE (DEFAULT), so only TRUE is allowed
        let rem = match rem {
            [0x01, 0x01, 0xff, rem @ ..] => rem,
            [0x01, ..] => return Err(Error::BadExtensions),
            _ => rem,
        };

        let (&[], (0x04, value)) = tri!(read_tlv(rem)) else {
            return Err(Error::BadExtensions);
        };

        // id-ce-nameConstraints 2.5.29.30
        let [0x55, 0x1d, 0x1e] = oid else {
            continue;
        };

        if name_constraints.is_some() {
            return Err(Error::BadNameConstraints);
        }

        let (&[], (0x30, value)) = tri!(read_tlv(value)) else {
            return Err(Error::BadNameConstraints);
        };
        name_constraints = Some(value);
    }

    Ok(name_constraints)
}

// (subject, subject public key info, name constraints)
//
// parsing only passes slices around, because `Der` has a destructor when
// `rustls-pki-types/alloc` is enabled, and destructors cannot run in a const fn
type Parts<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>);

const fn parse(cert: &[u8]) -> Result<Parts<'_>, Error> {
    // parse Certificate
    let (&[], (0x30, cert)) = tri!(read_tlv(cert)) else {
        return Err(Error::BadCertificate);
    };

    // parse TBSCertificate
    let (_, (0x30, tbs_cert)) = tri!(read_tlv(cert)) else {
        return Err(Error::BadTbsCertificate);
    };

    // check version is v3
    let (rem, (0xa0, [0x02, 0x01, 0x02])) = tri!(read_tlv(tbs_cert)) else {
        return Err(Error::UnsupportedVersion);
    };

    // skip serial number
    let (rem, (0x02, _)) = tri!(read_tlv(rem)) else {
        return Err(Error::BadSerialNumber);
    };

    // skip signature
    let (rem, (0x30, _)) = tri!(read_tlv(rem)) else {
        return Err(Error::BadSignatureAlgorithm);
    };

    // skip issuer
    let (rem, (0x30, _)) = tri!(read_tlv(rem)) else {
        return Err(Error::BadIssuer);
    };

    // skip validity
    let (rem, (0x30, _)) = tri!(read_tlv(rem)) else {
        return Err(Error::BadValidity);
    };

    // extract subject
    let (rem, (0x30, subject)) = tri!(read_tlv(rem)) else {
        return Err(Error::BadSubject);
    };

    // extract subject public key info
    let (rem, (0x30, spki)) = tri!(read_tlv(rem)) else {
        return Err(Error::BadSubjectPublicKeyInfo);
    };

    // extract name constraints from extensions
    let name_constraints = tri!(find_name_constraints(rem));

    Ok((subject, spki, name_constraints))
}

const fn to_anchor((subject, spki, name_constraints): Parts<'_>) -> TrustAnchor<'_> {
    TrustAnchor {
        subject: Der::from_slice(subject),
        subject_public_key_info: Der::from_slice(spki),
        name_constraints: match name_constraints {
            Some(nc) => Some(Der::from_slice(nc)),
            None => None,
        },
    }
}

/// Parse a DER-encoded X.509 v3 certificate into the [`TrustAnchor`].
///
/// It is very similar to the
/// [`webpki::anchor_from_trusted_cert`](https://docs.rs/rustls-webpki/latest/webpki/fn.anchor_from_trusted_cert.html),
/// but strictly follows DER, so some non-DER certificates accepted by webpki are rejected.
/// Be aware that this function is not fully validating the certificate.
/// Only call it when you trust the input certificate.
///
/// # Errors
///
/// Returns an [`Error`] describing the first malformed field.
pub const fn try_anchor_from_trusted_cert(cert: &[u8]) -> Result<TrustAnchor<'_>, Error> {
    match parse(cert) {
        Ok(parts) => Ok(to_anchor(parts)),
        Err(e) => Err(e),
    }
}

/// Parse a DER-encoded X.509 v3 certificate into the [`TrustAnchor`].
///
/// The panicking version of [`try_anchor_from_trusted_cert`],
/// supposed to be used in a const context, not the runtime.
/// Be aware that this function is not fully validating the certificate.
/// Only call it when you trust the input certificate.
///
/// # Panics
///
/// Panics if the certificate is malformed or not v3,
/// which becomes a compile error in a const context.
#[must_use]
pub const fn anchor_from_trusted_cert(cert: &[u8]) -> TrustAnchor<'_> {
    match parse(cert) {
        Ok(parts) => to_anchor(parts),
        Err(e) => panic!("{}", e.as_str()),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use rustls_pki_types::CertificateDer;
    use webpki_root_certs::TLS_SERVER_ROOT_CERTS;
    use webpki_roots::TLS_SERVER_ROOTS;

    use super::*;

    const NAME_CONSTRAINTS_CERT: &[u8] = include_bytes!("../tests/data/name_constraints.der");
    const NON_CRITICAL_NAME_CONSTRAINTS_CERT: &[u8] =
        include_bytes!("../tests/data/name_constraints_non_critical.der");
    const TEST_CERTS: [&[u8]; 2] = [NAME_CONSTRAINTS_CERT, NON_CRITICAL_NAME_CONSTRAINTS_CERT];

    fn assert_same_as_webpki(cert: &[u8]) {
        let der = CertificateDer::from(cert);
        let expected = webpki::anchor_from_trusted_cert(&der).unwrap();

        assert_eq!(anchor_from_trusted_cert(cert), expected);
    }

    #[test]
    fn test_anchors_from_webpki_roots() {
        assert_eq!(TLS_SERVER_ROOT_CERTS.len(), TLS_SERVER_ROOTS.len());

        for (cert, ta) in TLS_SERVER_ROOT_CERTS.iter().zip(TLS_SERVER_ROOTS) {
            let my_anchor = anchor_from_trusted_cert(cert);

            // webpki-roots adds name constraints from Mozilla's metadata,
            // which are not in the certificate itself
            assert_eq!(my_anchor.subject, ta.subject);
            assert_eq!(
                my_anchor.subject_public_key_info,
                ta.subject_public_key_info
            );
        }
    }

    #[test]
    fn test_anchors_same_as_webpki() {
        for cert in TLS_SERVER_ROOT_CERTS {
            assert_same_as_webpki(cert);
        }
        for cert in TEST_CERTS {
            assert_same_as_webpki(cert);
        }
    }

    #[test]
    fn test_name_constraints() {
        const CRITICAL: TrustAnchor<'static> = anchor_from_trusted_cert(NAME_CONSTRAINTS_CERT);
        const NON_CRITICAL: TrustAnchor<'static> =
            anchor_from_trusted_cert(NON_CRITICAL_NAME_CONSTRAINTS_CERT);

        assert!(CRITICAL.name_constraints.is_some());
        assert!(NON_CRITICAL.name_constraints.is_some());
    }

    #[test]
    fn test_critical() {
        // id-ce-basicConstraints with critical TRUE in the test certificate
        let pattern = [0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff];
        let pos = NAME_CONSTRAINTS_CERT
            .windows(pattern.len())
            .position(|w| w == pattern)
            .unwrap();
        let value = pos + pattern.len() - 1;

        // DER forbids encoding the DEFAULT FALSE
        let mut cert = NAME_CONSTRAINTS_CERT.to_vec();
        cert[value] = 0x00;
        assert_eq!(
            try_anchor_from_trusted_cert(&cert),
            Err(Error::BadExtensions)
        );

        // BER TRUE
        cert[value] = 0x01;
        assert_eq!(
            try_anchor_from_trusted_cert(&cert),
            Err(Error::BadExtensions)
        );
    }

    #[test]
    fn test_length() {
        // short form
        assert_eq!(
            read_tlv(&[0x04, 0x01, 0xaa]),
            Ok((&[][..], (0x04, &[0xaa][..])))
        );
        // long form
        let mut der = [0; 3 + 0x80];
        der[..3].copy_from_slice(&[0x04, 0x81, 0x80]);
        assert_eq!(read_tlv(&der), Ok((&[][..], (0x04, &der[3..]))));

        // fits in the short form
        assert_eq!(
            read_tlv(&[0x04, 0x81, 0x01, 0xaa]),
            Err(Error::NonMinimalLength)
        );
        // leading zeros
        assert_eq!(
            read_tlv(&[0x04, 0x82, 0x00, 0x01, 0xaa]),
            Err(Error::NonMinimalLength)
        );
        // indefinite length
        assert_eq!(read_tlv(&[0x30, 0x80, 0, 0]), Err(Error::UnsupportedLength));
        // 5 bytes length
        assert_eq!(
            read_tlv(&[0x30, 0x85, 1, 0, 0, 0, 0]),
            Err(Error::UnsupportedLength)
        );
        // truncated
        assert_eq!(read_tlv(&[0x30]), Err(Error::TooShort));
        assert_eq!(read_tlv(&[0x30, 0x82, 0x01]), Err(Error::TooShort));
        assert_eq!(read_tlv(&[0x30, 0x02, 0x00]), Err(Error::TooShort));
    }

    #[test]
    fn test_malformed_input() {
        let certs = TLS_SERVER_ROOT_CERTS.iter().map(AsRef::as_ref);

        for cert in certs.chain(TEST_CERTS) {
            for len in 0..cert.len() {
                assert!(try_anchor_from_trusted_cert(&cert[..len]).is_err());
            }

            let trailing = [cert, &[0]].concat();
            assert_eq!(
                try_anchor_from_trusted_cert(&trailing),
                Err(Error::BadCertificate)
            );
        }
    }

    #[test]
    #[should_panic(expected = "unsupported version")]
    fn test_panic_on_malformed_input() {
        // a SEQUENCE in a SEQUENCE without the version
        let _ = anchor_from_trusted_cert(&[0x30, 0x04, 0x30, 0x02, 0x02, 0x00]);
    }
}
