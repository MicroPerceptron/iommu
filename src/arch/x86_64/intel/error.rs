//! Intel VT-d-specific failure modes.

use crate::Error;

/// Errors that preserve VT-d-specific context before being collapsed into the
/// crate-wide public error vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VtdError {
    UnsupportedAddressWidth,
    UnsupportedGranule,
    PageSelectiveInvalidationUnavailable,
    InvalidDomainId,
    InvalidSourceId,
}

impl From<VtdError> for Error {
    #[inline]
    fn from(value: VtdError) -> Self {
        match value {
            VtdError::UnsupportedAddressWidth => Self::InvalidWidth,
            VtdError::UnsupportedGranule => Self::InvalidGranule,
            VtdError::PageSelectiveInvalidationUnavailable => Self::FeatureUnavailable,
            VtdError::InvalidDomainId => Self::InvalidAddressSpace,
            VtdError::InvalidSourceId => Self::InvalidClient,
        }
    }
}
