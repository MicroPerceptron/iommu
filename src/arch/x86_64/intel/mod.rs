mod caps;
pub mod ctrl;
pub mod dmar;
mod error;
mod info;
pub mod paging;

pub use caps::{VTD_MMIO_SIZE, VtdCapability, VtdExtendedCapability};
pub use ctrl::{
    VtdInterruptEntry, VtdQueuedInvalidationDescriptor, VtdQueuedInvalidationQueue,
    VtdRegisterWindow,
};
pub use error::VtdError;
pub use info::{
    VTD_DEFAULT_DOMAIN, VTD_DOMAIN_MASK, VtdDomain, VtdDomainActivation, VtdDomainControls,
    VtdDomainToken, VtdInfo, VtdIoDomain, VtdVersion,
};
pub use paging::{
    VtdSecondLevelAddressWidth, VtdSecondLevelFlags, VtdSecondLevelMeta39, VtdSecondLevelMeta48,
    VtdSecondLevelMeta57, VtdSecondLevelPageTable39, VtdSecondLevelPageTable48,
    VtdSecondLevelPageTable57, VtdSecondLevelPte,
};
