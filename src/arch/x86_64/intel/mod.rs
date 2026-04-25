pub mod dmar;
pub mod paging;

pub use paging::{
    VtdSecondLevelFlags, VtdSecondLevelMeta39, VtdSecondLevelMeta48, VtdSecondLevelMeta57,
    VtdSecondLevelPageTable39, VtdSecondLevelPageTable48, VtdSecondLevelPageTable57,
    VtdSecondLevelPte,
};
