use kore_memory::PagingError;

/// Shared result type for public IOMMU operations.
pub type Result<T = ()> = core::result::Result<T, Error>;

/// Shared public IOMMU failure modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    ControllerUnavailable,
    InvalidController,
    InvalidAddressSpace,
    InvalidClient,
    InvalidBinding,
    InvalidAddress,
    InvalidRange,
    InvalidGranule,
    InvalidWidth,
    AlreadyMapped,
    NotMapped,
    FeatureUnavailable,
    AddressOverflow,
    PageTable(PagingError),
}

impl From<PagingError> for Error {
    #[inline]
    fn from(value: PagingError) -> Self {
        Self::PageTable(value)
    }
}

#[cfg(target_arch = "x86_64")]
impl From<crate::arch::x86_64::intel::dmar::DmarError> for Error {
    #[inline]
    fn from(value: crate::arch::x86_64::intel::dmar::DmarError) -> Self {
        match value {
            crate::arch::x86_64::intel::dmar::DmarError::Acpi(_) => Self::InvalidController,
            crate::arch::x86_64::intel::dmar::DmarError::Mapping(error) => Self::PageTable(error),
            crate::arch::x86_64::intel::dmar::DmarError::BdfRanges(_)
            | crate::arch::x86_64::intel::dmar::DmarError::Malformed(_) => Self::InvalidRange,
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl From<crate::arch::x86_64::amd::ivrs::IvrsError> for Error {
    #[inline]
    fn from(value: crate::arch::x86_64::amd::ivrs::IvrsError) -> Self {
        match value {
            crate::arch::x86_64::amd::ivrs::IvrsError::Acpi(_) => Self::InvalidController,
            crate::arch::x86_64::amd::ivrs::IvrsError::Mapping(error) => Self::PageTable(error),
            crate::arch::x86_64::amd::ivrs::IvrsError::BdfRanges(_)
            | crate::arch::x86_64::amd::ivrs::IvrsError::Malformed(_) => Self::InvalidRange,
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl From<crate::arch::aarch64::iort::IortError> for Error {
    #[inline]
    fn from(value: crate::arch::aarch64::iort::IortError) -> Self {
        match value {
            crate::arch::aarch64::iort::IortError::Acpi(_) => Self::InvalidController,
            crate::arch::aarch64::iort::IortError::Mapping(error) => Self::PageTable(error),
            crate::arch::aarch64::iort::IortError::BdfRanges(_)
            | crate::arch::aarch64::iort::IortError::Malformed(_) => Self::InvalidRange,
        }
    }
}
