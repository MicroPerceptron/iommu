//! AMD-Vi page-table entries.

use core::fmt;

use memory_addr::PhysAddr;

use crate::{
    AccessFlags, CachePolicy, IoviAddr, MemoryAttributes, PageSize, PageTable, PageTableEntry,
    PageTableEntryKind, PagingMetaData,
};

const PRESENT: u64 = 1 << 0;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const IO_READ: u64 = 1 << 61;
const IO_WRITE: u64 = 1 << 62;
const NEXT_LEVEL_MASK: u64 = 0x7 << 9;
const LARGE_LEAF_LEVEL: u8 = 7;

#[inline]
const fn level_enc(level: u8) -> u64 {
    ((level as u64) << 9) & NEXT_LEVEL_MASK
}

#[inline]
const fn next_level(bits: u64) -> u8 {
    ((bits >> 9) & 0x7) as u8
}

/// AMD-Vi IOPTE flags.
///
/// AMD-Vi v1 page-table leaves encode IO read/write permission in the high
/// bits. Cache and sharing attributes are carried for higher-level policy but
/// are not represented in this descriptor format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AmdViFlags {
    pub access: AccessFlags,
    pub attrs: MemoryAttributes,
}

impl AmdViFlags {
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
        let mut bits = PRESENT;
        if self.access.contains(AccessFlags::READ) {
            bits |= IO_READ;
        }
        if self.access.contains(AccessFlags::WRITE) {
            bits |= IO_WRITE;
        }
        if !matches!(size, PageSize::Size4K) {
            bits |= level_enc(LARGE_LEAF_LEVEL);
        }
        bits
    }

    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        let mut access = AccessFlags::empty();
        if (bits & IO_READ) != 0 {
            access |= AccessFlags::READ;
        }
        if (bits & IO_WRITE) != 0 {
            access |= AccessFlags::WRITE;
        }
        Self {
            access,
            attrs: MemoryAttributes::writeback(),
        }
    }
}

/// AMD-Vi IOMMU page-table entry.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct AmdViPte(u64);

impl fmt::Debug for AmdViPte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AmdViPte")
            .field(&format_args!("{:#018x}", self.0))
            .finish()
    }
}

impl PageTableEntry for AmdViPte {
    type Flags = AmdViFlags;

    #[inline]
    fn new_leaf(paddr: PhysAddr, flags: Self::Flags, size: PageSize) -> Self {
        Self(((paddr.as_usize() as u64) & ADDR_MASK) | flags.to_leaf_bits(size))
    }

    #[inline]
    fn new_table(paddr: PhysAddr, level: u8) -> Self {
        let child_level = level.saturating_sub(1);
        Self(
            ((paddr.as_usize() as u64) & ADDR_MASK)
                | PRESENT
                | IO_READ
                | IO_WRITE
                | level_enc(child_level),
        )
    }

    #[inline]
    fn paddr(&self) -> PhysAddr {
        PhysAddr::from_usize((self.0 & ADDR_MASK) as usize)
    }

    #[inline]
    fn flags(&self) -> Self::Flags {
        AmdViFlags::from_bits(self.0)
    }

    #[inline]
    fn is_present(&self) -> bool {
        (self.0 & PRESENT) != 0
    }

    #[inline]
    fn entry_kind(&self, level: u8) -> PageTableEntryKind {
        if !self.is_present() {
            return PageTableEntryKind::Invalid;
        }

        let next = next_level(self.0);
        if level == 1 {
            PageTableEntryKind::Leaf
        } else if next == level.saturating_sub(1) {
            PageTableEntryKind::Table
        } else if next == 0 || next == LARGE_LEAF_LEVEL {
            PageTableEntryKind::Leaf
        } else {
            PageTableEntryKind::Invalid
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

macro_rules! define_amd_vi_meta {
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

define_amd_vi_meta!(AmdViMeta39, 3, 39);
define_amd_vi_meta!(AmdViMeta48, 4, 48);
define_amd_vi_meta!(AmdViMeta57, 5, 57);

pub type AmdViPageTable39<Alloc> = PageTable<AmdViMeta39, AmdViPte, Alloc>;
pub type AmdViPageTable48<Alloc> = PageTable<AmdViMeta48, AmdViPte, Alloc>;
pub type AmdViPageTable57<Alloc> = PageTable<AmdViMeta57, AmdViPte, Alloc>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_entry_encodes_child_level() {
        let pte = AmdViPte::new_table(PhysAddr::from_usize(0x8000), 4);
        assert_eq!(next_level(pte.bits()), 3);
        assert_eq!(pte.entry_kind(4), PageTableEntryKind::Table);
        assert_eq!(pte.paddr(), PhysAddr::from_usize(0x8000));
    }

    #[test]
    fn large_leaf_uses_large_level_marker() {
        let flags = AmdViFlags::new(AccessFlags::READ | AccessFlags::WRITE);
        let pte = AmdViPte::new_leaf(PhysAddr::from_usize(0x4000_0000), flags, PageSize::Size1G);

        assert_eq!(next_level(pte.bits()), LARGE_LEAF_LEVEL);
        assert_eq!(pte.entry_kind(3), PageTableEntryKind::Leaf);
        assert!(pte.flags().access.contains(AccessFlags::READ));
        assert!(pte.flags().access.contains(AccessFlags::WRITE));
    }
}
