//! ARM SMMUv3 VMSA page-table aliases.

use crate::{IoviAddr, PageSize, PageTable, PagingMetaData};

pub use kpte::arch::aarch64::{
    A64Flags as SmmuVmsaFlags, A64Pte4K48 as SmmuVmsaPte4K48, A64Pte4K52 as SmmuVmsaPte4K52,
    A64Pte16K48 as SmmuVmsaPte16K48, A64Pte16K52 as SmmuVmsaPte16K52,
    A64Pte64K48 as SmmuVmsaPte64K48, A64Pte64K52 as SmmuVmsaPte64K52,
};

macro_rules! define_smmu_vmsa_meta_4k {
    ($name:ident, $levels:expr, $va_bits:expr, $pa_bits:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl PagingMetaData for $name {
            const LEVELS: usize = $levels;
            const PA_MAX_BITS: usize = $pa_bits;
            const VA_MAX_BITS: usize = $va_bits;

            type VirtAddr = IoviAddr<u64>;

            #[inline]
            fn level_shift(level: u8) -> u32 {
                12 + ((level as u32) - 1) * 9
            }

            #[inline]
            fn level_index_bits(level: u8) -> u32 {
                if Self::LEVELS == 5 && level == 5 {
                    4
                } else {
                    9
                }
            }

            #[inline]
            fn level_supports_leaf(level: u8, size: PageSize) -> bool {
                matches!(
                    (level, size),
                    (1, PageSize::Size4K) | (2, PageSize::Size2M) | (3, PageSize::Size1G)
                )
            }
        }
    };
}

macro_rules! define_smmu_vmsa_meta_16k {
    ($name:ident, $va_bits:expr, $pa_bits:expr, $root_bits:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl PagingMetaData for $name {
            const LEVELS: usize = 4;
            const PA_MAX_BITS: usize = $pa_bits;
            const VA_MAX_BITS: usize = $va_bits;
            const INDEX_BITS: u32 = 11;
            const BASE_PAGE_SIZE: PageSize = PageSize::Size16K;
            const TABLE_FRAME_SIZE: PageSize = PageSize::Size16K;

            type VirtAddr = IoviAddr<u64>;

            #[inline]
            fn level_shift(level: u8) -> u32 {
                14 + ((level as u32) - 1) * 11
            }

            #[inline]
            fn level_index_bits(level: u8) -> u32 {
                if level == 4 { $root_bits } else { 11 }
            }

            #[inline]
            fn level_supports_leaf(level: u8, size: PageSize) -> bool {
                matches!(
                    (level, size),
                    (1, PageSize::Size16K) | (2, PageSize::Size32M) | (3, PageSize::Size64G)
                )
            }
        }
    };
}

macro_rules! define_smmu_vmsa_meta_64k {
    ($name:ident, $va_bits:expr, $pa_bits:expr, $root_bits:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl PagingMetaData for $name {
            const LEVELS: usize = 3;
            const PA_MAX_BITS: usize = $pa_bits;
            const VA_MAX_BITS: usize = $va_bits;
            const INDEX_BITS: u32 = 13;
            const BASE_PAGE_SIZE: PageSize = PageSize::Size64K;
            const TABLE_FRAME_SIZE: PageSize = PageSize::Size64K;

            type VirtAddr = IoviAddr<u64>;

            #[inline]
            fn level_shift(level: u8) -> u32 {
                16 + ((level as u32) - 1) * 13
            }

            #[inline]
            fn level_index_bits(level: u8) -> u32 {
                if level == 3 { $root_bits } else { 13 }
            }

            #[inline]
            fn level_supports_leaf(level: u8, size: PageSize) -> bool {
                matches!(
                    (level, size),
                    (1, PageSize::Size64K) | (2, PageSize::Size512M) | (3, PageSize::Size4T)
                )
            }
        }
    };
}

define_smmu_vmsa_meta_4k!(SmmuVmsaMeta4K48, 4, 48, 48);
define_smmu_vmsa_meta_4k!(SmmuVmsaMeta4K52, 5, 52, 52);
define_smmu_vmsa_meta_16k!(SmmuVmsaMeta16K48, 48, 48, 1);
define_smmu_vmsa_meta_16k!(SmmuVmsaMeta16K52, 52, 52, 5);
define_smmu_vmsa_meta_64k!(SmmuVmsaMeta64K48, 48, 48, 6);
define_smmu_vmsa_meta_64k!(SmmuVmsaMeta64K52, 52, 52, 10);

pub type SmmuVmsaPageTable4K48<Alloc, Tlb> =
    PageTable<SmmuVmsaMeta4K48, SmmuVmsaPte4K48, Alloc, Tlb>;
pub type SmmuVmsaPageTable4K52<Alloc, Tlb> =
    PageTable<SmmuVmsaMeta4K52, SmmuVmsaPte4K52, Alloc, Tlb>;
pub type SmmuVmsaPageTable16K48<Alloc, Tlb> =
    PageTable<SmmuVmsaMeta16K48, SmmuVmsaPte16K48, Alloc, Tlb>;
pub type SmmuVmsaPageTable16K52<Alloc, Tlb> =
    PageTable<SmmuVmsaMeta16K52, SmmuVmsaPte16K52, Alloc, Tlb>;
pub type SmmuVmsaPageTable64K48<Alloc, Tlb> =
    PageTable<SmmuVmsaMeta64K48, SmmuVmsaPte64K48, Alloc, Tlb>;
pub type SmmuVmsaPageTable64K52<Alloc, Tlb> =
    PageTable<SmmuVmsaMeta64K52, SmmuVmsaPte64K52, Alloc, Tlb>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smmu_vmsa_uses_iova_addresses() {
        let iova = IoviAddr::<u64>::from(0x1000);
        assert!(SmmuVmsaMeta4K48::vaddr_is_valid(iova));
    }

    #[test]
    fn root_index_widths_match_granule_and_va_width() {
        assert_eq!(SmmuVmsaMeta16K48::level_index_bits(4), 1);
        assert_eq!(SmmuVmsaMeta16K52::level_index_bits(4), 5);
        assert_eq!(SmmuVmsaMeta64K48::level_index_bits(3), 6);
        assert_eq!(SmmuVmsaMeta64K52::level_index_bits(3), 10);
    }
}
