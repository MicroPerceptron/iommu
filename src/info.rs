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

/// Caller-supplied IOMMU address-space identifier.
///
/// The crate treats domain allocation as host policy: kernels already have
/// ASID/VMID/capability allocation machinery, and IOMMU drivers only need a
/// compact typed value to program into hardware-specific tables. `MASK`
/// describes the low bits that belong to the architectural identifier; any
/// remaining high bits can carry a host-side generation tag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct IoDomain<const MASK: u32 = 0x0000_ffff>(u32);

impl<const MASK: u32> IoDomain<MASK> {
    const ID_BITS: u32 = MASK.count_ones();
    const GENERATION_MASK: u32 = if Self::ID_BITS >= u32::BITS {
        0
    } else {
        u32::MAX >> Self::ID_BITS
    };

    #[inline]
    pub const fn new(id: u32, generation: u32) -> Option<Self> {
        if (id & !MASK) == 0 {
            Some(Self::from_parts_trusted(id, generation))
        } else {
            None
        }
    }

    #[inline]
    pub const fn from_asid(asid: u32) -> Option<Self> {
        Self::new(asid, 0)
    }

    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn capacity() -> u32 {
        if Self::ID_BITS >= u32::BITS {
            u32::MAX
        } else {
            1 << Self::ID_BITS
        }
    }

    #[inline]
    pub const fn id(self) -> u32 {
        self.0 & MASK
    }

    #[inline]
    pub const fn generation(self) -> u32 {
        if Self::ID_BITS >= u32::BITS {
            0
        } else {
            self.0 >> Self::ID_BITS
        }
    }

    #[inline]
    pub(crate) const fn from_parts_trusted(id: u32, generation: u32) -> Self {
        let gen_bits = if Self::ID_BITS >= u32::BITS {
            0
        } else {
            (generation & Self::GENERATION_MASK) << Self::ID_BITS
        };
        Self((id & MASK) | gen_bits)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_domain_keeps_asid_and_generation_separate() {
        let domain = IoDomain::<0x0000_ffff>::new(0x1234, 0xabcd).unwrap();

        assert_eq!(domain.id(), 0x1234);
        assert_eq!(domain.generation(), 0xabcd);
        assert_eq!(domain.bits(), 0xabcd_1234);
        assert_eq!(IoDomain::<0x0000_ffff>::capacity(), 0x1_0000);
    }

    #[test]
    fn io_domain_rejects_ids_outside_mask() {
        assert!(IoDomain::<0x0000_ffff>::from_asid(0xffff).is_some());
        assert!(IoDomain::<0x0000_ffff>::from_asid(0x1_0000).is_none());
    }
}
