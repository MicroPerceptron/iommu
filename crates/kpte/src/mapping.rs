use memory_addr::{AddrRange, MemoryAddr, PhysAddr, PhysAddrRange};

use crate::{PageSize, PageTableEntry, PagingResult};

/// A resolved leaf mapping.
///
/// `range` is the exact virtual/IOVA range covered by the leaf; its
/// length determines the leaf size. `paddr` is the aligned physical base
/// the leaf points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping<Entry, V>
where
    Entry: PageTableEntry,
    V: MemoryAddr,
{
    pub range: AddrRange<V>,
    pub paddr: PhysAddr,
    pub flags: Entry::Flags,
}

impl<Entry, V> Mapping<Entry, V>
where
    Entry: PageTableEntry,
    V: MemoryAddr,
{
    #[inline]
    pub const fn new(range: AddrRange<V>, paddr: PhysAddr, flags: Entry::Flags) -> Self {
        Self {
            range,
            paddr,
            flags,
        }
    }

    #[inline]
    pub fn size(&self) -> Option<PageSize> {
        PageSize::from_bytes(self.range.size())
    }
}

/// Physical backing shape supplied to [`PageTable::map`](crate::PageTable::map).
///
/// `Contiguous` carries one physical extent. `Scattered` carries ordered
/// physical extents that back one virtually-contiguous range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapBacking<'a> {
    Contiguous(PhysAddrRange),
    Scattered(&'a [PhysAddrRange]),
}

impl<'a> MapBacking<'a> {
    #[inline]
    pub const fn contiguous(range: PhysAddrRange) -> Self {
        Self::Contiguous(range)
    }

    #[inline]
    pub fn contiguous_from_start_size(start: PhysAddr, size: usize) -> Self {
        Self::Contiguous(PhysAddrRange::from_start_size(start, size))
    }

    #[inline]
    pub const fn scattered(ranges: &'a [PhysAddrRange]) -> Self {
        Self::Scattered(ranges)
    }
}

impl<'a> From<PhysAddrRange> for MapBacking<'a> {
    #[inline]
    fn from(range: PhysAddrRange) -> Self {
        Self::Contiguous(range)
    }
}

/// Converts ergonomic backing expressions into a [`MapBacking`].
///
/// A bare [`PhysAddr`] is interpreted as one contiguous range with the
/// same byte length as the virtual range being mapped.
pub trait IntoMapBacking<'a> {
    fn into_map_backing(self, virtual_size: usize) -> PagingResult<MapBacking<'a>>;
}

impl<'a> IntoMapBacking<'a> for MapBacking<'a> {
    #[inline]
    fn into_map_backing(self, _virtual_size: usize) -> PagingResult<MapBacking<'a>> {
        Ok(self)
    }
}

impl<'a> IntoMapBacking<'a> for PhysAddr {
    #[inline]
    fn into_map_backing(self, virtual_size: usize) -> PagingResult<MapBacking<'a>> {
        Ok(MapBacking::contiguous_from_start_size(self, virtual_size))
    }
}

impl<'a> IntoMapBacking<'a> for PhysAddrRange {
    #[inline]
    fn into_map_backing(self, _virtual_size: usize) -> PagingResult<MapBacking<'a>> {
        Ok(MapBacking::Contiguous(self))
    }
}

impl<'a> IntoMapBacking<'a> for &'a [PhysAddrRange] {
    #[inline]
    fn into_map_backing(self, _virtual_size: usize) -> PagingResult<MapBacking<'a>> {
        Ok(MapBacking::Scattered(self))
    }
}

impl<'a, const N: usize> IntoMapBacking<'a> for &'a [PhysAddrRange; N] {
    #[inline]
    fn into_map_backing(self, _virtual_size: usize) -> PagingResult<MapBacking<'a>> {
        Ok(MapBacking::Scattered(&self[..]))
    }
}

impl<'a, const N: usize> IntoMapBacking<'a> for &'a heapless::Vec<PhysAddrRange, N> {
    #[inline]
    fn into_map_backing(self, _virtual_size: usize) -> PagingResult<MapBacking<'a>> {
        Ok(MapBacking::Scattered(self.as_slice()))
    }
}

/// Physical contiguity contract for a mapping request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum MappingContiguity {
    /// Backing must be one contiguous physical range. The walker may use
    /// the largest legal leaf size at each aligned span.
    #[default]
    Contiguous,
    /// Backing may be multiple physical ranges. Every mapped leaf uses
    /// this granule exactly.
    Scattered(PageSize),
}

/// Mapping-level flags: hardware leaf flags plus backing-shape policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MappingFlags<F> {
    leaf: F,
    contiguity: MappingContiguity,
}

impl<F> MappingFlags<F> {
    #[inline]
    pub const fn new(leaf: F) -> Self {
        Self {
            leaf,
            contiguity: MappingContiguity::Contiguous,
        }
    }

    #[inline]
    pub const fn contiguous(leaf: F) -> Self {
        Self::new(leaf)
    }

    #[inline]
    pub const fn scattered(leaf: F, granule: PageSize) -> Self {
        Self {
            leaf,
            contiguity: MappingContiguity::Scattered(granule),
        }
    }

    #[inline]
    pub const fn with_contiguity(mut self, contiguity: MappingContiguity) -> Self {
        self.contiguity = contiguity;
        self
    }

    #[inline]
    pub const fn leaf(&self) -> F
    where
        F: Copy,
    {
        self.leaf
    }

    #[inline]
    pub const fn contiguity(&self) -> MappingContiguity {
        self.contiguity
    }
}

impl<F> From<F> for MappingFlags<F> {
    #[inline]
    fn from(leaf: F) -> Self {
        Self::new(leaf)
    }
}
