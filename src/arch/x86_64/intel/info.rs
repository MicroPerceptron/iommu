//! Intel VT-d controller and domain descriptors.

use kore_memory::PageSize;
use memory_addr::PhysAddr;

use crate::{ControllerKind, IoDomain, IommuInfo, MmioAddrRange, TranslationStage};

use super::{
    caps::{VtdCapability, VtdExtendedCapability},
    paging::VtdSecondLevelAddressWidth,
};

pub const VTD_DOMAIN_MASK: u32 = 0x0000_ffff;
pub type VtdIoDomain = IoDomain<VTD_DOMAIN_MASK>;
/// Conventional non-zero domain id for simple second-level setups.
pub const VTD_DEFAULT_DOMAIN: VtdIoDomain = VtdIoDomain::from_parts_trusted(1, 0);

/// VT-d version register split into major/minor nibbles.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VtdVersion(u32);

impl VtdVersion {
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn major(self) -> u8 {
        ((self.0 >> 4) & 0x0f) as u8
    }

    #[inline]
    pub const fn minor(self) -> u8 {
        (self.0 & 0x0f) as u8
    }
}

/// One concrete VT-d translation domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtdDomain {
    id: VtdIoDomain,
    root: PhysAddr,
    width: VtdSecondLevelAddressWidth,
    stage: TranslationStage,
}

impl VtdDomain {
    #[inline]
    pub const fn new(
        id: VtdIoDomain,
        root: PhysAddr,
        width: VtdSecondLevelAddressWidth,
        stage: TranslationStage,
    ) -> Self {
        Self {
            id,
            root,
            width,
            stage,
        }
    }

    #[inline]
    pub const fn id(self) -> VtdIoDomain {
        self.id
    }

    #[inline]
    pub const fn root(self) -> PhysAddr {
        self.root
    }

    #[inline]
    pub const fn width(self) -> VtdSecondLevelAddressWidth {
        self.width
    }

    #[inline]
    pub const fn stage(self) -> TranslationStage {
        self.stage
    }
}

/// Immutable information discovered for one Intel VT-d remapping unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtdInfo {
    base: IommuInfo,
    version: VtdVersion,
    host_address_width: Option<u8>,
    cap: VtdCapability,
    ecap: VtdExtendedCapability,
    explicit_device_scopes: bool,
}

impl VtdInfo {
    #[inline]
    pub const fn new(
        base: IommuInfo,
        version: VtdVersion,
        host_address_width: Option<u8>,
        cap: VtdCapability,
        ecap: VtdExtendedCapability,
        explicit_device_scopes: bool,
    ) -> Self {
        Self {
            base,
            version,
            host_address_width,
            cap,
            ecap,
            explicit_device_scopes,
        }
    }

    #[inline]
    pub fn from_registers(
        segment: Option<u16>,
        mmio: MmioAddrRange,
        version: u32,
        host_address_width: Option<u8>,
        cap: u64,
        ecap: u64,
        explicit_device_scopes: bool,
    ) -> Self {
        let cap = VtdCapability::from_bits(cap);
        let ecap = VtdExtendedCapability::from_bits(ecap);
        let base = IommuInfo::new(
            ControllerKind::IntelVtd,
            segment,
            mmio,
            ecap.capability_flags(),
            TranslationStage::Stage2,
        );

        Self::new(
            base,
            VtdVersion::from_bits(version),
            host_address_width,
            cap,
            ecap,
            explicit_device_scopes,
        )
    }

    #[inline]
    pub const fn base(self) -> IommuInfo {
        self.base
    }

    #[inline]
    pub const fn version(self) -> VtdVersion {
        self.version
    }

    #[inline]
    pub const fn host_address_width(self) -> Option<u8> {
        self.host_address_width
    }

    #[inline]
    pub const fn cap(self) -> VtdCapability {
        self.cap
    }

    #[inline]
    pub const fn ecap(self) -> VtdExtendedCapability {
        self.ecap
    }

    #[inline]
    pub const fn explicit_device_scopes(self) -> bool {
        self.explicit_device_scopes
    }

    #[inline]
    pub const fn best_second_level_width(self) -> Option<VtdSecondLevelAddressWidth> {
        self.cap.best_address_width()
    }

    #[inline]
    pub const fn supports_leaf_size(self, size: PageSize) -> bool {
        self.cap.supports_leaf_size(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_splits_major_and_minor() {
        let version = VtdVersion::from_bits(0x23);
        assert_eq!(version.major(), 2);
        assert_eq!(version.minor(), 3);
    }

    #[test]
    fn vtd_domain_is_the_common_domain_value() {
        let domain = VtdIoDomain::new(0x1234, 7).unwrap();

        assert_eq!(domain.id(), 0x1234);
        assert_eq!(domain.generation(), 7);
        assert_eq!(VTD_DEFAULT_DOMAIN.id(), 1);
    }
}
