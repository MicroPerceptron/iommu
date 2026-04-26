//! Intel VT-d controller-side descriptor helpers.

use crate::{IoviAddr, PageSize, PciDevice, Result};

use super::{caps::VtdCapability, error::VtdError, info::VtdDomainId};

const QI_CC_TYPE: u64 = 0x1;
const QI_IOTLB_TYPE: u64 = 0x2;
const QI_IEC_TYPE: u64 = 0x4;

const QI_CC_GLOBAL: u64 = 1 << 4;
const QI_CC_DEVICE: u64 = 3 << 4;
const QI_CC_SID_SHIFT: u64 = 32;

const QI_IOTLB_GLOBAL: u64 = 1 << 4;
const QI_IOTLB_DOMAIN: u64 = 2 << 4;
const QI_IOTLB_PAGE: u64 = 3 << 4;
const QI_IOTLB_DW: u64 = 1 << 6;
const QI_IOTLB_DR: u64 = 1 << 7;
const QI_IOTLB_DID_SHIFT: u64 = 16;

const QI_IEC_SELECTIVE: u64 = 1 << 4;
const QI_IEC_IDX_SHIFT: u64 = 32;

const PAGE_ADDR_MASK: u64 = !0xfff_u64;
const IVA_AM_MASK: u64 = 0x3f;

/// Raw queued-invalidation descriptor, ready to be written to a VT-d QI ring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VtdQueuedInvalidationDescriptor {
    low: u64,
    high: u64,
}

impl VtdQueuedInvalidationDescriptor {
    #[inline]
    pub const fn from_words(low: u64, high: u64) -> Self {
        Self { low, high }
    }

    #[inline]
    pub const fn low(self) -> u64 {
        self.low
    }

    #[inline]
    pub const fn high(self) -> u64 {
        self.high
    }

    #[inline]
    pub const fn context_global() -> Self {
        Self::from_words(QI_CC_TYPE | QI_CC_GLOBAL, 0)
    }

    #[inline]
    pub const fn context_device(client: PciDevice) -> Self {
        Self::from_words(
            QI_CC_TYPE | QI_CC_DEVICE | ((client.bdf().as_u16() as u64) << QI_CC_SID_SHIFT),
            0,
        )
    }

    #[inline]
    pub const fn iotlb_global(cap: VtdCapability) -> Self {
        Self::from_words(QI_IOTLB_TYPE | QI_IOTLB_GLOBAL | iotlb_drain_bits(cap), 0)
    }

    #[inline]
    pub const fn iotlb_domain(domain: VtdDomainId, cap: VtdCapability) -> Self {
        Self::from_words(
            QI_IOTLB_TYPE
                | QI_IOTLB_DOMAIN
                | iotlb_drain_bits(cap)
                | ((domain.as_u16() as u64) << QI_IOTLB_DID_SHIFT),
            0,
        )
    }

    #[inline]
    pub fn iotlb_page(
        domain: VtdDomainId,
        iova: IoviAddr<u64>,
        granule: PageSize,
        cap: VtdCapability,
    ) -> Result<Self> {
        let address_mask = cap
            .page_selective_address_mask(granule)
            .ok_or(VtdError::PageSelectiveInvalidationUnavailable)?;

        Ok(Self::from_words(
            QI_IOTLB_TYPE
                | QI_IOTLB_PAGE
                | iotlb_drain_bits(cap)
                | ((domain.as_u16() as u64) << QI_IOTLB_DID_SHIFT),
            ((iova.as_usize() as u64) & PAGE_ADDR_MASK)
                | u64::from(address_mask & IVA_AM_MASK as u8),
        ))
    }

    #[inline]
    pub const fn interrupt_entry_cache(entry: VtdInterruptEntry) -> Self {
        Self::from_words(
            QI_IEC_TYPE | QI_IEC_SELECTIVE | ((entry.as_u16() as u64) << QI_IEC_IDX_SHIFT),
            0,
        )
    }
}

/// Interrupt-remapping table entry index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VtdInterruptEntry(u16);

impl VtdInterruptEntry {
    #[inline]
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

#[inline]
const fn iotlb_drain_bits(cap: VtdCapability) -> u64 {
    let mut bits = 0;
    if cap.read_draining() {
        bits |= QI_IOTLB_DR;
    }
    if cap.write_draining() {
        bits |= QI_IOTLB_DW;
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP_PSI: u64 = 1 << 39;
    const CAP_MAMV_SHIFT: u64 = 48;

    #[test]
    fn context_device_uses_pci_source_id() {
        let client = PciDevice::new(0, 0x2a, 5, 3).unwrap();
        let desc = VtdQueuedInvalidationDescriptor::context_device(client);

        assert_eq!(desc.low() >> QI_CC_SID_SHIFT, 0x2a2b);
    }

    #[test]
    fn page_iotlb_descriptor_encodes_address_mask() {
        let cap = VtdCapability::from_bits(CAP_PSI | (18_u64 << CAP_MAMV_SHIFT));
        let desc = VtdQueuedInvalidationDescriptor::iotlb_page(
            VtdDomainId::new(7),
            IoviAddr::<u64>::from(0x4000_1234),
            PageSize::Size1G,
            cap,
        )
        .unwrap();

        assert_eq!((desc.low() >> QI_IOTLB_DID_SHIFT) & 0xffff, 7);
        assert_eq!(desc.high() & PAGE_ADDR_MASK, 0x4000_1000);
        assert_eq!(desc.high() & IVA_AM_MASK, 18);
    }
}
