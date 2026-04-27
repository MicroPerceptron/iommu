//! Intel VT-d controller and domain descriptors.

use kore_memory::{AddrSpaceActivation, AddrSpaceToken, PageSize, PagingError, PagingResult};
use memory_addr::{MemoryAddr, PhysAddr};

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

    #[inline]
    pub const fn controls(self) -> VtdDomainControls {
        VtdDomainControls::new(self.id, self.width)
    }
}

impl From<VtdDomainToken> for VtdDomain {
    #[inline]
    fn from(value: VtdDomainToken) -> Self {
        value.domain()
    }
}

/// VT-d second-level address-space installation controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VtdDomainControls {
    id: VtdIoDomain,
    width: VtdSecondLevelAddressWidth,
}

impl VtdDomainControls {
    #[inline]
    pub const fn new(id: VtdIoDomain, width: VtdSecondLevelAddressWidth) -> Self {
        Self { id, width }
    }

    #[inline]
    pub const fn id(self) -> VtdIoDomain {
        self.id
    }

    #[inline]
    pub const fn width(self) -> VtdSecondLevelAddressWidth {
        self.width
    }

    #[inline]
    pub const fn stage(self) -> TranslationStage {
        TranslationStage::Stage2
    }
}

/// Installed VT-d second-level address-space token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtdDomainToken {
    root: PhysAddr,
    controls: VtdDomainControls,
}

impl VtdDomainToken {
    #[inline]
    pub const fn new(root: PhysAddr, controls: VtdDomainControls) -> Self {
        Self { root, controls }
    }

    #[inline]
    pub const fn controls(self) -> VtdDomainControls {
        self.controls
    }

    #[inline]
    pub const fn id(self) -> VtdIoDomain {
        self.controls.id()
    }

    #[inline]
    pub const fn width(self) -> VtdSecondLevelAddressWidth {
        self.controls.width()
    }

    #[inline]
    pub const fn stage(self) -> TranslationStage {
        self.controls.stage()
    }

    #[inline]
    pub const fn domain(self) -> VtdDomain {
        VtdDomain::new(self.id(), self.root, self.width(), self.stage())
    }
}

impl AddrSpaceToken for VtdDomainToken {
    #[inline]
    fn root(self) -> PhysAddr {
        self.root
    }
}

/// Stateless VT-d domain installer for `PageTable::install_with`.
///
/// This encodes the second-level page-table root into a domain token. Hardware
/// activation is controller-specific because VT-d still has to publish that
/// token through root/context tables for concrete requesters.
#[derive(Clone, Copy, Debug, Default)]
pub struct VtdDomainActivation;

impl AddrSpaceActivation for VtdDomainActivation {
    type Token = VtdDomainToken;
    type Controls = VtdDomainControls;

    #[inline]
    fn install(&self, root: PhysAddr, controls: Self::Controls) -> PagingResult<Self::Token> {
        if !root.is_aligned(PageSize::Size4K.bytes()) {
            return Err(PagingError::NotAligned);
        }
        Ok(VtdDomainToken::new(root, controls))
    }

    #[inline]
    unsafe fn activate(&self, _token: Self::Token) -> PagingResult {
        Err(PagingError::InvalidMappingShape)
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

    #[test]
    fn domain_activation_installs_second_level_root_token() {
        let activation = VtdDomainActivation;
        let controls =
            VtdDomainControls::new(VTD_DEFAULT_DOMAIN, VtdSecondLevelAddressWidth::Bits48);
        let token = activation
            .install(PhysAddr::from(0x4000usize), controls)
            .unwrap();
        let domain = token.domain();

        assert_eq!(token.root(), PhysAddr::from(0x4000usize));
        assert_eq!(token.controls(), controls);
        assert_eq!(domain.id(), VTD_DEFAULT_DOMAIN);
        assert_eq!(domain.root(), PhysAddr::from(0x4000usize));
        assert_eq!(domain.width(), VtdSecondLevelAddressWidth::Bits48);
        assert_eq!(domain.stage(), TranslationStage::Stage2);
    }

    #[test]
    fn domain_activation_rejects_unaligned_roots() {
        let activation = VtdDomainActivation;
        let controls =
            VtdDomainControls::new(VTD_DEFAULT_DOMAIN, VtdSecondLevelAddressWidth::Bits39);

        assert_eq!(
            activation.install(PhysAddr::from(0x1234usize), controls),
            Err(PagingError::NotAligned)
        );
    }

    #[test]
    fn stateless_domain_activation_does_not_publish_to_hardware() {
        let activation = VtdDomainActivation;
        let controls =
            VtdDomainControls::new(VTD_DEFAULT_DOMAIN, VtdSecondLevelAddressWidth::Bits39);
        let token = activation
            .install(PhysAddr::from(0x4000usize), controls)
            .unwrap();

        assert_eq!(
            unsafe { activation.activate(token) },
            Err(PagingError::InvalidMappingShape)
        );
    }
}
