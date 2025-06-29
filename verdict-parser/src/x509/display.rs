// Impl of Display for some of the X.509 types

use super::*;
use std::fmt::{self, Display};

impl<'a> Display for DirectoryStringValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DirectoryStringValue::PrintableString(s) => write!(f, "{}", s),
            DirectoryStringValue::UTF8String(s) => write!(f, "{}", s),
            DirectoryStringValue::IA5String(s) => write!(f, "{}", s),
            DirectoryStringValue::TeletexString(..) => write!(f, "<TeletexString>"),
            DirectoryStringValue::UniversalString(..) => write!(f, "<UniversalString>"),
            DirectoryStringValue::BMPString(..) => write!(f, "<BMPString>"),
            DirectoryStringValue::Unreachable => write!(f, "<Unreachable>"),
        }
    }
}

impl<'a> Display for AttributeTypeAndValueValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.typ.polyfill_eq(&oid!(COMMON_NAME)) {
            write!(f, "CN={}", self.value)
        } else if self.typ.polyfill_eq(&oid!(COUNTRY_NAME)) {
            write!(f, "C={}", self.value)
        } else if self.typ.polyfill_eq(&oid!(LOCALITY_NAME)) {
            write!(f, "L={}", self.value)
        } else if self.typ.polyfill_eq(&oid!(STATE_NAME)) {
            write!(f, "ST={}", self.value)
        } else if self.typ.polyfill_eq(&oid!(ORGANIZATION_NAME)) {
            write!(f, "O={}", self.value)
        } else if self.typ.polyfill_eq(&oid!(ORGANIZATIONAL_UNIT)) {
            write!(f, "OU={}", self.value)
        } else if self.typ.polyfill_eq(&oid!(STREET_ADDRESS)) {
            write!(f, "STREET={}", self.value)
        } else if self.typ.polyfill_eq(&oid!(SERIAL_NUMBER)) {
            write!(f, "SERIALNUMBER={}", self.value)
        } else if self.typ.polyfill_eq(&oid!(EMAIL_ADDRESS)) {
            write!(f, "EMAILADDRESS={}", self.value)
        } else {
            write!(f, "{:?}={}", self.typ, self.value)
        }
    }
}

impl<'a> Display for RDNValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, attr) in self.0.iter().enumerate() {
            if i == 0 {
                write!(f, "{}", attr)?;
            } else {
                write!(f, " {}", attr)?;
            }
        }
        Ok(())
    }
}

impl<'a> Display for NameValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, rdn) in self.0.iter().enumerate() {
            if i == 0 {
                write!(f, "{}", rdn)?;
            } else {
                write!(f, ", {}", rdn)?;
            }
        }
        Ok(())
    }
}
