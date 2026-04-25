//! Intel VT-d second-level page-table entries.

use core::fmt;

use memory_addr::PhysAddr;

use crate::{
    AccessFlags, CachePolicy, IoviAddr, MemoryAttributes, PageSize, PageTable, PageTableEntry,
    PageTableEntryKind, PagingMetaData,
};

const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const READ: u64 = 1 << 0;
const WRITE: u64 = 1 << 1;
const SUPER_PAGE: u64 = 1 << 7;
const PRESENT: u64 = READ | WRITE;

/// Intel VT-d second-level PTE flags.
///
/// VT-d second-level leaves encode read/write permission directly. Cache,
/// shareability, coherency, and execute intent remain carried in the flags
/// value for API symmetry, but this descriptor format does not encode them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VtdSecondLevelFlags {
    pub access: AccessFlags,
    pub attrs: MemoryAttributes,
}

impl VtdSecondLevelFlags {
    #[inline]
    pub const fn new(access: AccessFlags) -> Self {
        Self {
            access,
            attrs: MemoryAttributes::writeback(),
        }
    }

    #[inline]
    pub const fn with_cache(mut self, cache: CachePolicy) -> Self {
        self.attrs = self.attrs.with_cache(cache);
        self
    }

    #[inline]
    pub const fn with_attrs(mut self, attrs: MemoryAttributes) -> Self {
        self.attrs = attrs;
        self
    }

    #[inline(always)]
    fn to_leaf_bits(self, size: PageSize) -> u64 {
        let mut bits = 0;
        if self.access.contains(AccessFlags::READ) {
            bits |= READ;
        }
        if self.access.contains(AccessFlags::WRITE) {
            bits |= WRITE;
        }
        if !matches!(size, PageSize::Size4K) {
            bits |= SUPER_PAGE;
        }
        bits
    }

    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        let mut access = AccessFlags::empty();
        if (bits & READ) != 0 {
            access |= AccessFlags::READ;
        }
        if (bits & WRITE) != 0 {
            access |= AccessFlags::WRITE;
        }
        Self {
            access,
            attrs: MemoryAttributes::writeback(),
        }
    }
}

/// Intel VT-d second-level page-table entry.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct VtdSecondLevelPte(u64);

impl fmt::Debug for VtdSecondLevelPte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VtdSecondLevelPte")
            .field(&format_args!("{:#018x}", self.0))
            .finish()
    }
}

impl PageTableEntry for VtdSecondLevelPte {
    type Flags = VtdSecondLevelFlags;

    #[inline]
    fn new_leaf(paddr: PhysAddr, flags: Self::Flags, size: PageSize) -> Self {
        Self(((paddr.as_usize() as u64) & ADDR_MASK) | flags.to_leaf_bits(size))
    }

    #[inline]
    fn new_table(paddr: PhysAddr, _level: u8) -> Self {
        Self(((paddr.as_usize() as u64) & ADDR_MASK) | PRESENT)
    }

    #[inline]
    fn paddr(&self) -> PhysAddr {
        PhysAddr::from_usize((self.0 & ADDR_MASK) as usize)
    }

    #[inline]
    fn flags(&self) -> Self::Flags {
        VtdSecondLevelFlags::from_bits(self.0)
    }

    #[inline]
    fn is_present(&self) -> bool {
        (self.0 & PRESENT) != 0
    }

    #[inline]
    fn entry_kind(&self, level: u8) -> PageTableEntryKind {
        if !self.is_present() {
            PageTableEntryKind::Invalid
        } else if level == 1 || (self.0 & SUPER_PAGE) != 0 {
            PageTableEntryKind::Leaf
        } else {
            PageTableEntryKind::Table
        }
    }

    #[inline]
    fn clear(&mut self) {
        self.0 = 0;
    }

    #[inline]
    fn bits(&self) -> u64 {
        self.0
    }

    #[inline]
    fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
}

macro_rules! define_vtd_meta {
    ($name:ident, $levels:expr, $va_bits:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl PagingMetaData for $name {
            const LEVELS: usize = $levels;
            const PA_MAX_BITS: usize = 52;
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
                    (1, PageSize::Size4K) | (2, PageSize::Size2M) | (3, PageSize::Size1G)
                )
            }
        }
    };
}

define_vtd_meta!(VtdSecondLevelMeta39, 3, 39);
define_vtd_meta!(VtdSecondLevelMeta48, 4, 48);
define_vtd_meta!(VtdSecondLevelMeta57, 5, 57);

pub type VtdSecondLevelPageTable39<Alloc, Tlb> =
    PageTable<VtdSecondLevelMeta39, VtdSecondLevelPte, Alloc, Tlb>;
pub type VtdSecondLevelPageTable48<Alloc, Tlb> =
    PageTable<VtdSecondLevelMeta48, VtdSecondLevelPte, Alloc, Tlb>;
pub type VtdSecondLevelPageTable57<Alloc, Tlb> =
    PageTable<VtdSecondLevelMeta57, VtdSecondLevelPte, Alloc, Tlb>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_2m_sets_super_bit() {
        let flags = VtdSecondLevelFlags::new(AccessFlags::READ | AccessFlags::WRITE);
        let pte =
            VtdSecondLevelPte::new_leaf(PhysAddr::from_usize(0x20_0000), flags, PageSize::Size2M);

        assert_eq!(pte.entry_kind(2), PageTableEntryKind::Leaf);
        assert_eq!(pte.bits() & SUPER_PAGE, SUPER_PAGE);
        assert_eq!(pte.paddr(), PhysAddr::from_usize(0x20_0000));
        assert!(pte.flags().access.contains(AccessFlags::READ));
        assert!(pte.flags().access.contains(AccessFlags::WRITE));
    }

    #[test]
    fn table_entry_is_intermediate() {
        let pte = VtdSecondLevelPte::new_table(PhysAddr::from_usize(0x4000), 4);
        assert_eq!(pte.entry_kind(4), PageTableEntryKind::Table);
        assert_eq!(pte.paddr(), PhysAddr::from_usize(0x4000));
    }
}
