use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign};

use kore_memory::{AccessFlags, MemoryAttributes};

/// Target-neutral DMA access permissions.
///
/// This intentionally aliases the permission substrate used by `kore_memory`
/// page-table entries so CPU and IOMMU mappings share the same mechanical
/// access vocabulary.
pub type DmaAccess = AccessFlags;

/// Effective attributes for one DMA-visible mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DmaAttrs {
    access: DmaAccess,
    memory: MemoryAttributes,
}

impl DmaAttrs {
    #[inline]
    pub const fn new(access: DmaAccess, memory: MemoryAttributes) -> Self {
        Self { access, memory }
    }

    #[inline]
    pub const fn access(self) -> DmaAccess {
        self.access
    }

    #[inline]
    pub const fn memory(self) -> MemoryAttributes {
        self.memory
    }
}

/// Translation-stage summary for one IOMMU address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TranslationStage {
    Stage1,
    Stage2,
    Nested,
}

/// Client-local binding slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum BindingSelector {
    #[default]
    Default,
    AddrSpace(u32),
    Substream(u32),
}

impl BindingSelector {
    #[inline]
    pub const fn from_addr_space(id: u32) -> Self {
        Self::AddrSpace(id)
    }

    #[inline]
    pub const fn from_substream(id: u32) -> Self {
        Self::Substream(id)
    }
}

/// Translation target bound to one client selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingTarget<Domain> {
    Abort,
    PassThrough,
    Domain(Domain),
}

/// One client binding request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding<Client, Domain> {
    client: Client,
    selector: BindingSelector,
    target: BindingTarget<Domain>,
}

impl<Client, Domain> Binding<Client, Domain> {
    #[inline]
    pub const fn new(
        client: Client,
        selector: BindingSelector,
        target: BindingTarget<Domain>,
    ) -> Self {
        Self {
            client,
            selector,
            target,
        }
    }

    #[inline]
    pub fn client(self) -> Client
    where
        Client: Copy,
    {
        self.client
    }

    #[inline]
    pub fn selector(self) -> BindingSelector {
        self.selector
    }

    #[inline]
    pub fn target(self) -> BindingTarget<Domain>
    where
        Domain: Copy,
    {
        self.target
    }
}

/// Coarse feature flags common to modern DMA-remapping units.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CapabilityFlags(u64);

impl CapabilityFlags {
    pub const TRANSLATION: Self = Self(1 << 0);
    pub const PASID: Self = Self(1 << 1);
    pub const ATS: Self = Self(1 << 2);
    pub const DEVICE_TLB: Self = Self(1 << 3);
    pub const INTERRUPT_REMAPPING: Self = Self(1 << 4);
    pub const NESTED_TRANSLATION: Self = Self(1 << 5);
    pub const PAGE_REQUESTS: Self = Self(1 << 6);
    pub const DIRTY_TRACKING: Self = Self(1 << 7);

    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for CapabilityFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CapabilityFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for CapabilityFlags {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for CapabilityFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
