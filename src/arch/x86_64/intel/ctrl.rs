//! Intel VT-d controller-side descriptor helpers.

use kore_memory::{Mapping, PageSize, PageTableEntry};
use memory_addr::{PhysAddrRange, VirtAddr};

use crate::{CommandQueue, IoviAddr, MmioAddrRange, MmioRange, PciDevice, Result};

use super::{
    caps::{VtdCapability, VtdExtendedCapability},
    error::VtdError,
    info::{VtdIoDomain, VtdVersion},
};

pub type VtdQueuedInvalidationQueue<const N: usize> = CommandQueue<N>;

pub const REG_VERSION: usize = 0x00;
pub const REG_CAP: usize = 0x08;
pub const REG_ECAP: usize = 0x10;
pub const REG_GCMD: usize = 0x18;
pub const REG_GSTS: usize = 0x1c;
pub const REG_RTADDR: usize = 0x20;
pub const REG_CCMD: usize = 0x28;
pub const REG_FSTS: usize = 0x34;
pub const REG_FECTL: usize = 0x38;
pub const REG_FEDATA: usize = 0x3c;
pub const REG_FEADDR: usize = 0x40;
pub const REG_FEUADDR: usize = 0x44;
pub const REG_IQH: usize = 0x80;
pub const REG_IQT: usize = 0x88;
pub const REG_IQA: usize = 0x90;
pub const REG_IRTA: usize = 0xb8;

pub const GCMD_TE: u32 = 1 << 31;
pub const GCMD_SRTP: u32 = 1 << 30;
pub const GCMD_QIE: u32 = 1 << 26;
pub const GCMD_IRE: u32 = 1 << 25;
pub const GCMD_SIRTP: u32 = 1 << 24;

pub const GSTS_TES: u32 = 1 << 31;
pub const GSTS_RTPS: u32 = 1 << 30;
pub const GSTS_QIES: u32 = 1 << 26;
pub const GSTS_IRES: u32 = 1 << 25;
pub const GSTS_IRTPS: u32 = 1 << 24;

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

/// Mapped VT-d register window.
///
/// The caller owns how the MMIO page is mapped. Once handed to this wrapper,
/// register access goes through the volatile helpers already provided by
/// `kore_memory::Mapping`, keeping VT-d code out of the raw pointer business.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtdRegisterWindow<Entry>
where
    Entry: PageTableEntry,
{
    mapping: Mapping<Entry, VirtAddr>,
}

impl<Entry> VtdRegisterWindow<Entry>
where
    Entry: PageTableEntry,
{
    #[inline]
    pub const fn new(mapping: Mapping<Entry, VirtAddr>) -> Self {
        Self { mapping }
    }

    #[inline]
    pub const fn mapping(&self) -> &Mapping<Entry, VirtAddr> {
        &self.mapping
    }

    #[inline]
    pub const fn mapping_mut(&mut self) -> &mut Mapping<Entry, VirtAddr> {
        &mut self.mapping
    }

    #[inline]
    pub fn mmio_range(&self) -> MmioAddrRange {
        <MmioAddrRange as MmioRange<usize>>::from_phys_range(PhysAddrRange::from_start_size(
            self.mapping.paddr,
            self.mapping.range.size(),
        ))
    }

    #[inline]
    pub fn read32(&self, offset: usize) -> Result<u32> {
        self.mapping.read_vo32(offset).map_err(Into::into)
    }

    #[inline]
    pub fn write32(&mut self, offset: usize, value: u32) -> Result {
        self.mapping.write_vo32(offset, value).map_err(Into::into)
    }

    #[inline]
    pub fn modify32(&mut self, offset: usize, f: impl FnOnce(u32) -> u32) -> Result<u32> {
        self.mapping.modify_vo32(offset, f).map_err(Into::into)
    }

    #[inline]
    pub fn read64(&self, offset: usize) -> Result<u64> {
        self.mapping.read_vo64(offset).map_err(Into::into)
    }

    #[inline]
    pub fn write64(&mut self, offset: usize, value: u64) -> Result {
        self.mapping.write_vo64(offset, value).map_err(Into::into)
    }

    #[inline]
    pub fn modify64(&mut self, offset: usize, f: impl FnOnce(u64) -> u64) -> Result<u64> {
        self.mapping.modify_vo64(offset, f).map_err(Into::into)
    }

    #[inline]
    pub fn version(&self) -> Result<VtdVersion> {
        self.read32(REG_VERSION).map(VtdVersion::from_bits)
    }

    #[inline]
    pub fn capability(&self) -> Result<VtdCapability> {
        self.read64(REG_CAP).map(VtdCapability::from_bits)
    }

    #[inline]
    pub fn extended_capability(&self) -> Result<VtdExtendedCapability> {
        self.read64(REG_ECAP).map(VtdExtendedCapability::from_bits)
    }

    #[inline]
    pub fn global_status(&self) -> Result<u32> {
        self.read32(REG_GSTS)
    }

    #[inline]
    pub fn global_command(&mut self, command: u32) -> Result {
        self.write32(REG_GCMD, command)
    }
}

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
    pub fn submit_to<const N: usize, RH, WT, CE>(
        self,
        queue: &VtdQueuedInvalidationQueue<N>,
        read_head: RH,
        write_tail: WT,
        check_error: CE,
    ) -> Result
    where
        RH: Fn() -> usize,
        WT: Fn(usize),
        CE: Fn() -> Result,
    {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.low.to_le_bytes());
        bytes[8..].copy_from_slice(&self.high.to_le_bytes());
        queue.submit(bytes, read_head, write_tail, check_error)
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
    pub const fn iotlb_domain(domain: VtdIoDomain, cap: VtdCapability) -> Self {
        Self::from_words(
            QI_IOTLB_TYPE
                | QI_IOTLB_DOMAIN
                | iotlb_drain_bits(cap)
                | ((domain.id() as u64) << QI_IOTLB_DID_SHIFT),
            0,
        )
    }

    #[inline]
    pub fn iotlb_page(
        domain: VtdIoDomain,
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
                | ((domain.id() as u64) << QI_IOTLB_DID_SHIFT),
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
    use memory_addr::{PhysAddr, PhysAddrRange, VirtAddr, VirtAddrRange};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::vec;

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
            VtdIoDomain::from_asid(7).unwrap(),
            IoviAddr::<u64>::from(0x4000_1234),
            PageSize::Size1G,
            cap,
        )
        .unwrap();

        assert_eq!((desc.low() >> QI_IOTLB_DID_SHIFT) & 0xffff, 7);
        assert_eq!(desc.high() & PAGE_ADDR_MASK, 0x4000_1000);
        assert_eq!(desc.high() & IVA_AM_MASK, 18);
    }

    #[test]
    fn queued_invalidation_descriptor_submits_to_command_queue() {
        const ENTRIES: usize = 4;
        const ENTRY_BYTES: usize = 16;

        let buffer = vec![0u8; ENTRIES * ENTRY_BYTES];
        let phys = PhysAddrRange::from_start_size(
            PhysAddr::from_usize(buffer.as_ptr() as usize),
            buffer.len(),
        );
        let virt = VirtAddrRange::from_start_size(
            VirtAddr::from_usize(buffer.as_ptr() as usize),
            buffer.len(),
        );
        let backing =
            unsafe { crate::CommandQueueBacking::new(phys, virt, ENTRIES, ENTRY_BYTES) }.unwrap();
        let mut queue: VtdQueuedInvalidationQueue<ENTRIES> = VtdQueuedInvalidationQueue::new();
        queue.init(backing).unwrap();

        let head = AtomicUsize::new(0);
        let desc = VtdQueuedInvalidationDescriptor::context_global();
        desc.submit_to(
            &queue,
            || head.load(Ordering::Acquire),
            |tail| head.store(tail, Ordering::Release),
            || Ok(()),
        )
        .unwrap();

        let low = u64::from_ne_bytes(buffer[0..8].try_into().unwrap());
        let high = u64::from_ne_bytes(buffer[8..16].try_into().unwrap());
        assert_eq!(low, desc.low());
        assert_eq!(high, desc.high());
    }
}
