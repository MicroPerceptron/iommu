mod caps;
mod ctrl;
pub mod dmar;
mod error;
mod info;
pub mod paging;

pub use caps::{VTD_MMIO_SIZE, VtdCapability, VtdExtendedCapability};
pub use ctrl::{VtdInterruptEntry, VtdQueuedInvalidationDescriptor};
pub use error::VtdError;
pub use info::{VtdDomain, VtdDomainId, VtdInfo, VtdVersion};
pub use paging::{
    VtdSecondLevelAddressWidth, VtdSecondLevelFlags, VtdSecondLevelMeta39, VtdSecondLevelMeta48,
    VtdSecondLevelMeta57, VtdSecondLevelPageTable39, VtdSecondLevelPageTable48,
    VtdSecondLevelPageTable57, VtdSecondLevelPte,
};
