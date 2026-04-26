//! Intel VT-d capability register decoding.

use crate::{CapabilityFlags, PageSize};

use super::paging::VtdSecondLevelAddressWidth;

/// Size of one VT-d remapping-unit MMIO register frame.
pub const VTD_MMIO_SIZE: usize = 0x1000;

const CAP_MGAW_SHIFT: u64 = 16;
const CAP_MGAW_MASK: u64 = 0x3f;
const CAP_SAGAW_SHIFT: u64 = 8;
const CAP_SAGAW_MASK: u64 = 0x1f;
const CAP_ZLR: u64 = 1 << 22;
const CAP_FRO_SHIFT: u64 = 24;
const CAP_FRO_MASK: u64 = 0x03ff;
const CAP_SLLPS_SHIFT: u64 = 34;
const CAP_SLLPS_MASK: u64 = 0x0f;
const CAP_PSI: u64 = 1 << 39;
const CAP_NFR_SHIFT: u64 = 40;
const CAP_NFR_MASK: u64 = 0xff;
const CAP_MAMV_SHIFT: u64 = 48;
const CAP_MAMV_MASK: u64 = 0x3f;
const CAP_DWD: u64 = 1 << 54;
const CAP_DRD: u64 = 1 << 55;
const CAP_FL1GP: u64 = 1 << 56;
const CAP_PI: u64 = 1 << 59;
const CAP_FL5LP: u64 = 1 << 60;

const ECAP_C: u64 = 1 << 0;
const ECAP_QI: u64 = 1 << 1;
const ECAP_DT: u64 = 1 << 2;
const ECAP_IR: u64 = 1 << 3;
const ECAP_EIM: u64 = 1 << 4;
const ECAP_PT: u64 = 1 << 6;
const ECAP_SC: u64 = 1 << 7;
const ECAP_IRO_SHIFT: u64 = 8;
const ECAP_IRO_MASK: u64 = 0x3ff;
const ECAP_MHMV_SHIFT: u64 = 20;
const ECAP_MHMV_MASK: u64 = 0x0f;
const ECAP_MTS: u64 = 1 << 25;
const ECAP_NEST: u64 = 1 << 26;
const ECAP_PRS: u64 = 1 << 29;
const ECAP_ERS: u64 = 1 << 30;
const ECAP_SRS: u64 = 1 << 31;
const ECAP_NWFS: u64 = 1 << 33;
const ECAP_EAFS: u64 = 1 << 34;
const ECAP_PSS_SHIFT: u64 = 35;
const ECAP_PSS_MASK: u64 = 0x1f;
const ECAP_PASID: u64 = 1 << 40;
const ECAP_DIT: u64 = 1 << 41;
const ECAP_PDS: u64 = 1 << 42;
const ECAP_SMTS: u64 = 1 << 43;
const ECAP_SLADS: u64 = 1 << 45;
const ECAP_SLTS: u64 = 1 << 46;
const ECAP_FLTS: u64 = 1 << 47;

/// Raw VT-d Capability register.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VtdCapability(u64);

impl VtdCapability {
    #[inline]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn max_guest_address_width(self) -> u8 {
        (((self.0 >> CAP_MGAW_SHIFT) & CAP_MGAW_MASK) as u8).saturating_add(1)
    }

    #[inline]
    pub const fn supported_agaw_mask(self) -> u8 {
        ((self.0 >> CAP_SAGAW_SHIFT) & CAP_SAGAW_MASK) as u8
    }

    #[inline]
    pub const fn supports_address_width(self, width: VtdSecondLevelAddressWidth) -> bool {
        (self.supported_agaw_mask() & width.sagaw_bit()) != 0
    }

    #[inline]
    pub const fn best_address_width(self) -> Option<VtdSecondLevelAddressWidth> {
        if self.supports_address_width(VtdSecondLevelAddressWidth::Bits57) {
            Some(VtdSecondLevelAddressWidth::Bits57)
        } else if self.supports_address_width(VtdSecondLevelAddressWidth::Bits48) {
            Some(VtdSecondLevelAddressWidth::Bits48)
        } else if self.supports_address_width(VtdSecondLevelAddressWidth::Bits39) {
            Some(VtdSecondLevelAddressWidth::Bits39)
        } else {
            None
        }
    }

    #[inline]
    pub const fn fault_record_register_offset(self) -> u64 {
        ((self.0 >> CAP_FRO_SHIFT) & CAP_FRO_MASK) * 16
    }

    #[inline]
    pub const fn fault_record_count(self) -> u16 {
        (((self.0 >> CAP_NFR_SHIFT) & CAP_NFR_MASK) as u16).saturating_add(1)
    }

    #[inline]
    pub const fn superpage_mask(self) -> u8 {
        ((self.0 >> CAP_SLLPS_SHIFT) & CAP_SLLPS_MASK) as u8
    }

    #[inline]
    pub const fn supports_leaf_size(self, size: PageSize) -> bool {
        match size {
            PageSize::Size4K => true,
            PageSize::Size2M => (self.superpage_mask() & 0b0001) != 0,
            PageSize::Size1G => (self.superpage_mask() & 0b0010) != 0,
            _ => false,
        }
    }

    #[inline]
    pub const fn page_selective_invalidation(self) -> bool {
        (self.0 & CAP_PSI) != 0
    }

    #[inline]
    pub const fn max_address_mask_value(self) -> u8 {
        ((self.0 >> CAP_MAMV_SHIFT) & CAP_MAMV_MASK) as u8
    }

    #[inline]
    pub const fn page_selective_address_mask(self, size: PageSize) -> Option<u8> {
        let required = match size {
            PageSize::Size4K => 0,
            PageSize::Size2M => 9,
            PageSize::Size1G => 18,
            _ => return None,
        };

        if self.page_selective_invalidation() && self.max_address_mask_value() >= required {
            Some(required)
        } else {
            None
        }
    }

    #[inline]
    pub const fn write_draining(self) -> bool {
        (self.0 & CAP_DWD) != 0
    }

    #[inline]
    pub const fn read_draining(self) -> bool {
        (self.0 & CAP_DRD) != 0
    }

    #[inline]
    pub const fn first_level_1g_page(self) -> bool {
        (self.0 & CAP_FL1GP) != 0
    }

    #[inline]
    pub const fn posted_interrupts(self) -> bool {
        (self.0 & CAP_PI) != 0
    }

    #[inline]
    pub const fn first_level_5_level_paging(self) -> bool {
        (self.0 & CAP_FL5LP) != 0
    }

    #[inline]
    pub const fn zero_length_read(self) -> bool {
        (self.0 & CAP_ZLR) != 0
    }
}

impl From<u64> for VtdCapability {
    #[inline]
    fn from(value: u64) -> Self {
        Self::from_bits(value)
    }
}

impl From<VtdCapability> for u64 {
    #[inline]
    fn from(value: VtdCapability) -> Self {
        value.bits()
    }
}

/// Raw VT-d Extended Capability register.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VtdExtendedCapability(u64);

impl VtdExtendedCapability {
    #[inline]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn coherent_page_walks(self) -> bool {
        (self.0 & ECAP_C) != 0
    }

    #[inline]
    pub const fn queued_invalidation(self) -> bool {
        (self.0 & ECAP_QI) != 0
    }

    #[inline]
    pub const fn device_tlb(self) -> bool {
        (self.0 & ECAP_DT) != 0
    }

    #[inline]
    pub const fn interrupt_remapping(self) -> bool {
        (self.0 & ECAP_IR) != 0
    }

    #[inline]
    pub const fn extended_interrupt_mode(self) -> bool {
        (self.0 & ECAP_EIM) != 0
    }

    #[inline]
    pub const fn pass_through(self) -> bool {
        (self.0 & ECAP_PT) != 0
    }

    #[inline]
    pub const fn snoop_control(self) -> bool {
        (self.0 & ECAP_SC) != 0
    }

    #[inline]
    pub const fn iotlb_register_offset(self) -> u64 {
        ((self.0 >> ECAP_IRO_SHIFT) & ECAP_IRO_MASK) * 16
    }

    #[inline]
    pub const fn max_handle_mask_value(self) -> u8 {
        ((self.0 >> ECAP_MHMV_SHIFT) & ECAP_MHMV_MASK) as u8
    }

    #[inline]
    pub const fn memory_type_support(self) -> bool {
        (self.0 & ECAP_MTS) != 0
    }

    #[inline]
    pub const fn nested_translation(self) -> bool {
        (self.0 & ECAP_NEST) != 0
    }

    #[inline]
    pub const fn page_requests(self) -> bool {
        (self.0 & ECAP_PRS) != 0
    }

    #[inline]
    pub const fn execute_requests(self) -> bool {
        (self.0 & ECAP_ERS) != 0
    }

    #[inline]
    pub const fn supervisor_requests(self) -> bool {
        (self.0 & ECAP_SRS) != 0
    }

    #[inline]
    pub const fn no_write_flag(self) -> bool {
        (self.0 & ECAP_NWFS) != 0
    }

    #[inline]
    pub const fn extended_accessed_flag(self) -> bool {
        (self.0 & ECAP_EAFS) != 0
    }

    #[inline]
    pub const fn pasid(self) -> bool {
        (self.0 & ECAP_PASID) != 0
    }

    #[inline]
    pub const fn pasid_bits(self) -> u8 {
        (((self.0 >> ECAP_PSS_SHIFT) & ECAP_PSS_MASK) as u8).saturating_add(1)
    }

    #[inline]
    pub const fn device_tlb_invalidation_throttle(self) -> bool {
        (self.0 & ECAP_DIT) != 0
    }

    #[inline]
    pub const fn page_request_draining(self) -> bool {
        (self.0 & ECAP_PDS) != 0
    }

    #[inline]
    pub const fn scalable_mode(self) -> bool {
        (self.0 & ECAP_SMTS) != 0
    }

    #[inline]
    pub const fn second_level_accessed_dirty(self) -> bool {
        (self.0 & ECAP_SLADS) != 0
    }

    #[inline]
    pub const fn second_level_translation(self) -> bool {
        (self.0 & ECAP_SLTS) != 0
    }

    #[inline]
    pub const fn first_level_translation(self) -> bool {
        (self.0 & ECAP_FLTS) != 0
    }

    #[inline]
    pub fn capability_flags(self) -> CapabilityFlags {
        let mut flags = CapabilityFlags::TRANSLATION;

        if self.pasid() {
            flags |= CapabilityFlags::PASID;
        }
        if self.device_tlb() {
            flags |= CapabilityFlags::DEVICE_TLB;
        }
        if self.interrupt_remapping() {
            flags |= CapabilityFlags::INTERRUPT_REMAPPING;
        }
        if self.nested_translation() {
            flags |= CapabilityFlags::NESTED_TRANSLATION;
        }
        if self.page_requests() {
            flags |= CapabilityFlags::PAGE_REQUESTS;
        }
        if self.second_level_accessed_dirty() {
            flags |= CapabilityFlags::DIRTY_TRACKING;
        }

        flags
    }
}

impl From<u64> for VtdExtendedCapability {
    #[inline]
    fn from(value: u64) -> Self {
        Self::from_bits(value)
    }
}

impl From<VtdExtendedCapability> for u64 {
    #[inline]
    fn from(value: VtdExtendedCapability) -> Self {
        value.bits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_decodes_address_widths_and_superpages() {
        let cap = VtdCapability::from_bits(
            (0b111_u64 << CAP_SAGAW_SHIFT)
                | (47_u64 << CAP_MGAW_SHIFT)
                | (0b0011_u64 << CAP_SLLPS_SHIFT),
        );

        assert_eq!(cap.max_guest_address_width(), 48);
        assert!(cap.supports_address_width(VtdSecondLevelAddressWidth::Bits39));
        assert!(cap.supports_address_width(VtdSecondLevelAddressWidth::Bits48));
        assert!(!cap.supports_address_width(VtdSecondLevelAddressWidth::Bits57));
        assert_eq!(
            cap.best_address_width(),
            Some(VtdSecondLevelAddressWidth::Bits48)
        );
        assert!(cap.supports_leaf_size(PageSize::Size2M));
        assert!(cap.supports_leaf_size(PageSize::Size1G));
    }

    #[test]
    fn ecap_lifts_common_flags() {
        let ecap = VtdExtendedCapability::from_bits(ECAP_QI | ECAP_DT | ECAP_IR | ECAP_PASID);
        let flags = ecap.capability_flags();

        assert!(ecap.queued_invalidation());
        assert!(flags.contains(CapabilityFlags::TRANSLATION));
        assert!(flags.contains(CapabilityFlags::PASID));
        assert!(flags.contains(CapabilityFlags::DEVICE_TLB));
        assert!(flags.contains(CapabilityFlags::INTERRUPT_REMAPPING));
    }
}
