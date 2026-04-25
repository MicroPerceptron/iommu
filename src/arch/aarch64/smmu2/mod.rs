//! ARM SMMUv2 VMSA page-table aliases.
//!
//! SMMUv2 and SMMUv3 both consume the ARM VMSA long-descriptor table shape for
//! translated IOVA spaces. The generation-specific modules stay separate for
//! context-bank/stream-table work, but the page-table aliases are intentionally
//! shared.

pub use super::smmu3::{
    SmmuVmsaFlags, SmmuVmsaMeta4K48, SmmuVmsaMeta4K52, SmmuVmsaMeta16K48, SmmuVmsaMeta16K52,
    SmmuVmsaMeta64K48, SmmuVmsaMeta64K52, SmmuVmsaPageTable4K48, SmmuVmsaPageTable4K52,
    SmmuVmsaPageTable16K48, SmmuVmsaPageTable16K52, SmmuVmsaPageTable64K48, SmmuVmsaPageTable64K52,
    SmmuVmsaPte4K48, SmmuVmsaPte4K52, SmmuVmsaPte16K48, SmmuVmsaPte16K52, SmmuVmsaPte64K48,
    SmmuVmsaPte64K52,
};
