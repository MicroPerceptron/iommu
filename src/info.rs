use memory_addr::PhysAddrRange;

use crate::{CapabilityFlags, MmioAddrRange, TranslationStage};

/// IOMMU implementation family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ControllerKind {
    IntelVtd,
    AmdVi,
    ArmSmmuV2,
    ArmSmmuV3,
    RiscvIommu,
    Unknown(u16),
}

/// Immutable descriptor for one discovered IOMMU unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IommuInfo {
    kind: ControllerKind,
    segment: Option<u16>,
    mmio: MmioAddrRange,
    caps: CapabilityFlags,
    stage: TranslationStage,
}

impl IommuInfo {
    #[inline]
    pub const fn new(
        kind: ControllerKind,
        segment: Option<u16>,
        mmio: MmioAddrRange,
        caps: CapabilityFlags,
        stage: TranslationStage,
    ) -> Self {
        Self {
            kind,
            segment,
            mmio,
            caps,
            stage,
        }
    }

    #[inline]
    pub const fn kind(self) -> ControllerKind {
        self.kind
    }

    #[inline]
    pub const fn segment(self) -> Option<u16> {
        self.segment
    }

    #[inline]
    pub const fn mmio(self) -> MmioAddrRange {
        self.mmio
    }

    #[inline]
    pub const fn caps(self) -> CapabilityFlags {
        self.caps
    }

    #[inline]
    pub const fn stage(self) -> TranslationStage {
        self.stage
    }
}

/// Firmware-declared DMA reservation that the OS must preserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservedRegion<Client> {
    range: PhysAddrRange,
    client: Option<Client>,
}

impl<Client> ReservedRegion<Client> {
    #[inline]
    pub const fn new(range: PhysAddrRange, client: Option<Client>) -> Self {
        Self { range, client }
    }

    #[inline]
    pub fn range(self) -> PhysAddrRange {
        self.range
    }

    #[inline]
    pub fn client(self) -> Option<Client>
    where
        Client: Copy,
    {
        self.client
    }
}
