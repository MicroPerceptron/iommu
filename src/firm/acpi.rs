//! Minimal bridge from upstream ACPI tables to IOMMU vendor payload parsers.
//!
//! ACPI discovery, mapping, checksums, and the standard SDT header model belong
//! to the upstream `acpi` crate. This module only provides an internal bounded
//! byte reader for IOMMU-specific table payloads that the upstream crate does
//! not currently model, such as DMAR and IVRS bodies.

use core::{fmt, mem::size_of, ptr};

use acpi::sdt::Signature;
use acpi::{Handler, PhysicalMapping, sdt::SdtHeader};

const SDT_HEADER_LEN: usize = size_of::<SdtHeader>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiTableBytesError {
    Truncated { needed: usize, available: usize },
    LengthExceedsBuffer { declared: usize, available: usize },
    WrongSignature { expected: Signature, found: [u8; 4] },
    Malformed(&'static str),
}

impl fmt::Display for AcpiTableBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, available } => {
                write!(
                    f,
                    "ACPI table needs {needed} bytes, only {available} available"
                )
            }
            Self::LengthExceedsBuffer {
                declared,
                available,
            } => write!(
                f,
                "ACPI table declares {declared} bytes, only {available} available"
            ),
            Self::WrongSignature { expected, found } => {
                write!(f, "wrong ACPI signature: expected {expected}, found ")?;
                write_signature(f, *found)
            }
            Self::Malformed(message) => f.write_str(message),
        }
    }
}

fn write_signature(f: &mut fmt::Formatter<'_>, signature: [u8; 4]) -> fmt::Result {
    for byte in signature {
        f.write_str(core::str::from_utf8(&[byte]).unwrap_or("?"))?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct SdtBytes<'a> {
    bytes: &'a [u8],
}

#[allow(dead_code)]
impl<'a> SdtBytes<'a> {
    pub(crate) fn new(bytes: &'a [u8], signature: Signature) -> Result<Self, AcpiTableBytesError> {
        if bytes.len() < SDT_HEADER_LEN {
            return Err(AcpiTableBytesError::Truncated {
                needed: SDT_HEADER_LEN,
                available: bytes.len(),
            });
        }

        let header = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<SdtHeader>()) };
        if header.signature != signature {
            return Err(AcpiTableBytesError::WrongSignature {
                expected: signature,
                found: [bytes[0], bytes[1], bytes[2], bytes[3]],
            });
        }

        let declared = header.length() as usize;
        if declared < SDT_HEADER_LEN {
            return Err(AcpiTableBytesError::Malformed(
                "ACPI table length is shorter than the SDT header",
            ));
        }
        if declared > bytes.len() {
            return Err(AcpiTableBytesError::LengthExceedsBuffer {
                declared,
                available: bytes.len(),
            });
        }

        Ok(Self {
            bytes: &bytes[..declared],
        })
    }

    pub(crate) fn from_mapping<H, T>(
        mapping: &'a PhysicalMapping<H, T>,
        signature: Signature,
    ) -> Result<Self, AcpiTableBytesError>
    where
        H: Handler,
    {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                mapping.virtual_start.cast::<u8>().as_ptr(),
                mapping.region_length,
            )
        };
        Self::new(bytes, signature)
    }

    #[inline]
    pub(crate) const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    #[inline]
    pub(crate) const fn len(self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub(crate) fn read_u8(self, offset: usize) -> Result<u8, AcpiTableBytesError> {
        self.bytes
            .get(offset)
            .copied()
            .ok_or(AcpiTableBytesError::Truncated {
                needed: offset.saturating_add(1),
                available: self.bytes.len(),
            })
    }

    #[inline]
    pub(crate) fn read_u16(self, offset: usize) -> Result<u16, AcpiTableBytesError> {
        let bytes = self.read_array::<2>(offset)?;
        Ok(u16::from_le_bytes(bytes))
    }

    #[inline]
    pub(crate) fn read_u32(self, offset: usize) -> Result<u32, AcpiTableBytesError> {
        let bytes = self.read_array::<4>(offset)?;
        Ok(u32::from_le_bytes(bytes))
    }

    #[inline]
    pub(crate) fn read_u64(self, offset: usize) -> Result<u64, AcpiTableBytesError> {
        let bytes = self.read_array::<8>(offset)?;
        Ok(u64::from_le_bytes(bytes))
    }

    #[inline]
    fn read_array<const N: usize>(self, offset: usize) -> Result<[u8; N], AcpiTableBytesError> {
        let end = offset
            .checked_add(N)
            .ok_or(AcpiTableBytesError::Malformed("ACPI read offset overflow"))?;
        let bytes = self
            .bytes
            .get(offset..end)
            .ok_or(AcpiTableBytesError::Truncated {
                needed: end,
                available: self.bytes.len(),
            })?;
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }
}
