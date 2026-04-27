//! RISC-V IOMMU page-table aliases.

use kore_memory::{PageSize, PageTableWalker, PagingMetaData};

use crate::IoviAddr;

pub use kore_memory::arch::riscv64::{
    Rv64Flags as RvIommuFlags, Rv64Pte as RvIommuPte, Rv64SvpbmtPte as RvIommuSvpbmtPte,
};

macro_rules! define_rv_iommu_meta {
    ($name:ident, $levels:expr, $va_bits:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl PagingMetaData for $name {
            const LEVELS: usize = $levels;
            const PA_MAX_BITS: usize = 56;
            const VA_MAX_BITS: usize = $va_bits;

            type VirtAddr = IoviAddr<u64>;

            #[inline]
            fn level_shift(level: u8) -> u32 {
                12 + ((level as u32) - 1) * 9
            }

            #[inline]
            fn level_supports_leaf(level: u8, size: PageSize) -> bool {
                matches!(
                    (level, size),
                    (1, PageSize::Size4K)
                        | (2, PageSize::Size2M)
                        | (3, PageSize::Size1G)
                        | (4, PageSize::Size512G)
                ) && (level as usize) <= Self::LEVELS
            }
        }
    };
}

define_rv_iommu_meta!(RvIommuMeta39, 3, 39);
define_rv_iommu_meta!(RvIommuMeta48, 4, 48);
define_rv_iommu_meta!(RvIommuMeta57, 5, 57);

pub type RvIommuPageTable39<Alloc> = PageTableWalker<RvIommuMeta39, RvIommuPte, Alloc>;
pub type RvIommuPageTable48<Alloc> = PageTableWalker<RvIommuMeta48, RvIommuPte, Alloc>;
pub type RvIommuPageTable57<Alloc> = PageTableWalker<RvIommuMeta57, RvIommuPte, Alloc>;

pub type RvIommuSvpbmtPageTable39<Alloc> = PageTableWalker<RvIommuMeta39, RvIommuSvpbmtPte, Alloc>;
pub type RvIommuSvpbmtPageTable48<Alloc> = PageTableWalker<RvIommuMeta48, RvIommuSvpbmtPte, Alloc>;
pub type RvIommuSvpbmtPageTable57<Alloc> = PageTableWalker<RvIommuMeta57, RvIommuSvpbmtPte, Alloc>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn riscv_iommu_uses_iova_addresses() {
        let iova = IoviAddr::<u64>::from(0x1000);
        assert!(RvIommuMeta39::vaddr_is_valid(iova));
    }

    #[test]
    fn sv_widths_match_expected_levels() {
        assert_eq!(RvIommuMeta39::LEVELS, 3);
        assert_eq!(RvIommuMeta48::LEVELS, 4);
        assert_eq!(RvIommuMeta57::LEVELS, 5);
    }
}
