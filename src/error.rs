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
    PageTable(kpte::PagingError),
}

impl From<kpte::PagingError> for Error {
    #[inline]
    fn from(value: kpte::PagingError) -> Self {
        Self::PageTable(value)
    }
}
