//! Intel VT-d controller-side descriptor helpers.
//!
//! VT-d has two related but distinct table families:
//!
//! - second-level DMA translation tables, implemented in `paging.rs` through
//!   `kore_memory::PageTableEntry`
//! - requester-routing and controller tables, implemented here as fixed-width
//!   hardware descriptors
//!
//! Root entries, context entries, queued-invalidation descriptors, and
//! interrupt-remapping entries are not page-table entries: they publish or
//! synchronize translation domains, but they do not describe IOVA leaves.

use core::hint::spin_loop;

use kore_memory::{Mapping, PageSize, PageTableEntry};
use memory_addr::{MemoryAddr, PhysAddr, PhysAddrRange, VirtAddr, VirtAddrRange};
use x86_64::instructions::interrupts::without_interrupts;

use crate::{
    Binding, BindingSelector, BindingTarget, CommandQueue, DescriptorTableBacking, Error,
    InterruptRoute, IoviAddr, MmioAddrRange, MmioRange, MsiMessage, PciDevice, Result,
};

use super::{
    caps::{VtdCapability, VtdExtendedCapability},
    error::VtdError,
    info::{VtdDomain, VtdIoDomain, VtdVersion},
};
use crate::arch::x86_64::{
    X86InterruptVector, X86MsiDelivery, X86MsiDeliveryMode, X86MsiDestination, X86MsiTriggerMode,
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

const IRTA_SIZE_MASK: u64 = 0xf;
const IRTA_EIME: u64 = 1 << 11;
const IRTE_PRESENT: u64 = 1 << 0;
const IRTE_DESTINATION_MODE_LOGICAL: u64 = 1 << 2;
const IRTE_REDIRECTION_HINT: u64 = 1 << 3;
const IRTE_TRIGGER_MODE_LEVEL: u64 = 1 << 4;
const IRTE_DELIVERY_MODE_SHIFT: u64 = 5;
const IRTE_VECTOR_SHIFT: u64 = 16;
const IRTE_DESTINATION_SHIFT: u64 = 32;
const IRTE_SOURCE_ID_SHIFT: u64 = 0;
const IRTE_SOURCE_ID_QUALIFIER_SHIFT: u64 = 16;
const IRTE_SOURCE_VALIDATION_TYPE_SHIFT: u64 = 18;
const IRTE_SOURCE_VALIDATION_VERIFY_SOURCE_ID: u64 = 1;
const IRTE_SOURCE_QUALIFIER_ALL_BITS: u64 = 0;
const REMAPPED_MSI_INDEX_HIGH_BIT: u64 = 1 << 2;
const REMAPPED_MSI_SUBHANDLE_VALID: u64 = 1 << 3;
const REMAPPED_MSI_INTERRUPT_FORMAT: u64 = 1 << 4;
const REMAPPED_MSI_INDEX_SHIFT: u64 = 5;
const REMAPPED_MSI_INDEX_LOW_MASK: u16 = 0x7fff;
const INTERRUPT_REMAP_ENTRY_BYTES: usize = 16;
const INTERRUPT_REMAP_MIN_ENTRIES: usize = 2;
const INTERRUPT_REMAP_MAX_ENTRIES: usize = 1 << 16;
const ROOT_ENTRY_BYTES: usize = 16;
const ROOT_ENTRY_COUNT: usize = 256;
const CONTEXT_ENTRY_BYTES: usize = 16;
const CONTEXT_ENTRY_COUNT: usize = 256;
const ROOT_ENTRY_PRESENT: u64 = 1 << 0;
const CONTEXT_PRESENT: u64 = 1 << 0;
const CONTEXT_TRANSLATION_TYPE_SHIFT: u64 = 2;
const CONTEXT_TRANSLATION_TYPE_MULTI_LEVEL: u64 = 0;
const CONTEXT_TRANSLATION_TYPE_PASS_THROUGH: u64 = 2;
const CONTEXT_ADDRESS_WIDTH_MASK: u64 = 0x7;
const CONTEXT_DOMAIN_ID_SHIFT: u64 = 8;

const PAGE_ADDR_MASK: u64 = !0xfff_u64;
const TABLE_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const IVA_AM_MASK: u64 = 0x3f;
const FECTL_INTERRUPT_MASK: u32 = 1 << 31;
const REGISTER_TRANSITION_POLL_LIMIT: usize = 1_000_000;

/// Caller-provided backing for the VT-d requester root-entry table.
///
/// A legacy root table is one 4 KiB page containing 256 128-bit entries, one
/// per PCI bus number in the remapping unit's segment. Each entry points to a
/// context table; it is not the root page of a DMA translation address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtdRootTableBacking {
    backing: DescriptorTableBacking<ROOT_ENTRY_BYTES>,
}

impl VtdRootTableBacking {
    /// # Safety
    ///
    /// `virt` must be a live writable mapping of `phys` for one root-entry
    /// table page, and the memory must remain owned by the VT-d unit while
    /// requester lookup can consult it.
    #[inline]
    pub unsafe fn new(phys: PhysAddrRange, virt: VirtAddrRange) -> Result<Self> {
        let backing = unsafe {
            DescriptorTableBacking::new_aligned(
                phys,
                virt,
                ROOT_ENTRY_COUNT,
                PageSize::Size4K.bytes(),
            )?
        };
        Ok(Self { backing })
    }

    #[inline]
    pub const fn backing(self) -> DescriptorTableBacking<ROOT_ENTRY_BYTES> {
        self.backing
    }

    #[inline]
    pub const fn phys(self) -> PhysAddrRange {
        self.backing.phys()
    }

    #[inline]
    pub const fn virt(self) -> VirtAddrRange {
        self.backing.virt()
    }

    #[inline]
    pub const fn entry_count(self) -> usize {
        ROOT_ENTRY_COUNT
    }

    #[inline]
    pub const fn entry_bytes(self) -> usize {
        ROOT_ENTRY_BYTES
    }

    #[inline]
    pub const fn bus_entry_index(bus: u8) -> usize {
        bus as usize
    }

    #[inline]
    fn entry_vaddr(self, bus: u8) -> Result<VirtAddr> {
        self.backing.entry_vaddr(Self::bus_entry_index(bus))
    }
}

/// Caller-provided backing for one VT-d context-entry table.
///
/// A context table is one 4 KiB page containing 256 128-bit entries, one per
/// device/function slot under a single PCI bus. Context entries select the
/// translation target for a PCI requester; they are not IOVA page-table leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtdContextTableBacking {
    backing: DescriptorTableBacking<CONTEXT_ENTRY_BYTES>,
}

impl VtdContextTableBacking {
    /// # Safety
    ///
    /// `virt` must be a live writable mapping of `phys` for one context-entry
    /// table page, and the memory must remain owned by the VT-d unit while
    /// requester lookup can consult it.
    #[inline]
    pub unsafe fn new(phys: PhysAddrRange, virt: VirtAddrRange) -> Result<Self> {
        let backing = unsafe {
            DescriptorTableBacking::new_aligned(
                phys,
                virt,
                CONTEXT_ENTRY_COUNT,
                PageSize::Size4K.bytes(),
            )?
        };
        Ok(Self { backing })
    }

    #[inline]
    pub const fn backing(self) -> DescriptorTableBacking<CONTEXT_ENTRY_BYTES> {
        self.backing
    }

    #[inline]
    pub const fn phys(self) -> PhysAddrRange {
        self.backing.phys()
    }

    #[inline]
    pub const fn virt(self) -> VirtAddrRange {
        self.backing.virt()
    }

    #[inline]
    pub const fn entry_count(self) -> usize {
        CONTEXT_ENTRY_COUNT
    }

    #[inline]
    pub const fn entry_bytes(self) -> usize {
        CONTEXT_ENTRY_BYTES
    }

    #[inline]
    pub const fn client_entry_index(client: PciDevice) -> usize {
        vtd_context_entry_index(client) as usize
    }

    #[inline]
    fn entry_vaddr(self, index: u8) -> Result<VirtAddr> {
        self.backing.entry_vaddr(index as usize)
    }

    #[inline]
    fn client_entry_vaddr(self, client: PciDevice) -> Result<VirtAddr> {
        self.entry_vaddr(vtd_context_entry_index(client))
    }
}

/// VT-d root-entry descriptor for routing a PCI bus to a context table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct VtdRootEntry {
    low: u64,
    high: u64,
}

impl VtdRootEntry {
    #[inline]
    pub const fn from_words(low: u64, high: u64) -> Self {
        Self { low, high }
    }

    #[inline]
    pub const fn disabled() -> Self {
        Self::from_words(0, 0)
    }

    #[inline]
    pub fn from_context_table(table: VtdContextTableBacking) -> Result<Self> {
        let root = table.phys().start;
        if !root.is_aligned(PageSize::Size4K.bytes()) {
            return Err(Error::InvalidAddress);
        }
        Ok(Self::from_words(
            ((root.as_usize() as u64) & TABLE_ADDR_MASK) | ROOT_ENTRY_PRESENT,
            0,
        ))
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
    pub const fn present(self) -> bool {
        (self.low & ROOT_ENTRY_PRESENT) != 0
    }

    #[inline]
    pub fn context_table_root(self) -> Option<PhysAddr> {
        self.present()
            .then(|| PhysAddr::from_usize((self.low & TABLE_ADDR_MASK) as usize))
    }
}

/// VT-d legacy context-entry descriptor for routing one requester.
///
/// A context entry either aborts the requester, lets it pass through when
/// hardware supports that mode, or points at a second-level DMA translation
/// root represented by [`VtdDomain`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct VtdContextEntry {
    low: u64,
    high: u64,
}

impl VtdContextEntry {
    #[inline]
    pub const fn from_words(low: u64, high: u64) -> Self {
        Self { low, high }
    }

    #[inline]
    pub const fn disabled() -> Self {
        Self::from_words(0, 0)
    }

    #[inline]
    pub fn from_domain(domain: VtdDomain) -> Result<Self> {
        let root = domain.root();
        if !root.is_aligned(PageSize::Size4K.bytes()) {
            return Err(Error::InvalidAddress);
        }

        Ok(Self::from_words(
            ((root.as_usize() as u64) & TABLE_ADDR_MASK)
                | CONTEXT_PRESENT
                | (CONTEXT_TRANSLATION_TYPE_MULTI_LEVEL << CONTEXT_TRANSLATION_TYPE_SHIFT),
            vtd_agaw_bits(domain.width()) | ((domain.id().id() as u64) << CONTEXT_DOMAIN_ID_SHIFT),
        ))
    }

    #[inline]
    pub const fn pass_through() -> Self {
        Self::from_words(
            CONTEXT_PRESENT
                | (CONTEXT_TRANSLATION_TYPE_PASS_THROUGH << CONTEXT_TRANSLATION_TYPE_SHIFT),
            0,
        )
    }

    #[inline]
    pub fn from_binding(
        binding: Binding<PciDevice, VtdDomain>,
        cap: VtdExtendedCapability,
    ) -> Result<Self> {
        if binding.selector() != BindingSelector::Default {
            return Err(Error::FeatureUnavailable);
        }

        match binding.target() {
            BindingTarget::Abort => Ok(Self::disabled()),
            BindingTarget::PassThrough => {
                if cap.pass_through() {
                    Ok(Self::pass_through())
                } else {
                    Err(Error::FeatureUnavailable)
                }
            }
            BindingTarget::Domain(domain) => Self::from_domain(domain),
        }
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
    pub const fn present(self) -> bool {
        (self.low & CONTEXT_PRESENT) != 0
    }

    #[inline]
    pub const fn translation_type(self) -> u8 {
        ((self.low >> CONTEXT_TRANSLATION_TYPE_SHIFT) & 0x7) as u8
    }

    #[inline]
    pub const fn domain_id(self) -> u16 {
        ((self.high >> CONTEXT_DOMAIN_ID_SHIFT) & 0xffff) as u16
    }

    #[inline]
    pub const fn address_width_bits(self) -> u8 {
        match (self.high & CONTEXT_ADDRESS_WIDTH_MASK) as u8 {
            1 => 39,
            2 => 48,
            3 => 57,
            _ => 30,
        }
    }

    #[inline]
    pub fn page_table_root(self) -> Option<PhysAddr> {
        (self.present() && self.translation_type() == CONTEXT_TRANSLATION_TYPE_MULTI_LEVEL as u8)
            .then(|| PhysAddr::from_usize((self.low & TABLE_ADDR_MASK) as usize))
    }
}

/// Caller-provided backing for a VT-d interrupt-remapping table.
///
/// The backing must contain `entry_count` contiguous 128-bit IRTE slots and
/// must remain writable while interrupt remapping can consult it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtdInterruptRemapTableBacking {
    backing: DescriptorTableBacking<INTERRUPT_REMAP_ENTRY_BYTES>,
}

impl VtdInterruptRemapTableBacking {
    /// # Safety
    ///
    /// `virt` must be a live writable mapping of `phys` for at least
    /// `entry_count * 16` bytes, and the table memory must stay owned by the
    /// VT-d unit while interrupt remapping is enabled.
    #[inline]
    pub unsafe fn new(
        phys: PhysAddrRange,
        virt: VirtAddrRange,
        entry_count: usize,
    ) -> Result<Self> {
        if !(INTERRUPT_REMAP_MIN_ENTRIES..=INTERRUPT_REMAP_MAX_ENTRIES).contains(&entry_count)
            || !entry_count.is_power_of_two()
        {
            return Err(Error::InvalidRange);
        }
        let backing = unsafe {
            DescriptorTableBacking::new_aligned(phys, virt, entry_count, PageSize::Size4K.bytes())?
        };

        Ok(Self { backing })
    }

    #[inline]
    pub const fn backing(self) -> DescriptorTableBacking<INTERRUPT_REMAP_ENTRY_BYTES> {
        self.backing
    }

    #[inline]
    pub const fn phys(self) -> PhysAddrRange {
        self.backing.phys()
    }

    #[inline]
    pub const fn virt(self) -> VirtAddrRange {
        self.backing.virt()
    }

    #[inline]
    pub const fn entry_count(self) -> usize {
        self.backing.entry_count()
    }

    #[inline]
    pub const fn entry_bytes(self) -> usize {
        self.backing.entry_bytes()
    }

    #[inline]
    pub fn byte_len(self) -> usize {
        self.backing.byte_len()
    }

    #[inline]
    fn irta_size(self) -> u64 {
        u64::from(self.entry_count().trailing_zeros() - 1) & IRTA_SIZE_MASK
    }

    #[inline]
    fn entry_vaddr(self, entry: VtdInterruptEntry) -> Result<VirtAddr> {
        let index = usize::from(entry.as_u16());
        self.backing.entry_vaddr(index)
    }
}

/// VT-d remapped MSI/MSI-X message produced for a device-side MSI source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VtdRemappedMsi {
    entry: VtdInterruptEntry,
    subhandle: u16,
    message: MsiMessage,
}

impl VtdRemappedMsi {
    #[inline]
    pub const fn new(entry: VtdInterruptEntry, subhandle: u16) -> Self {
        Self {
            entry,
            subhandle,
            message: remapped_msi_message(entry, subhandle),
        }
    }

    #[inline]
    pub const fn entry(self) -> VtdInterruptEntry {
        self.entry
    }

    #[inline]
    pub const fn subhandle(self) -> u16 {
        self.subhandle
    }

    #[inline]
    pub const fn message(self) -> MsiMessage {
        self.message
    }
}

impl From<VtdRemappedMsi> for MsiMessage {
    #[inline]
    fn from(value: VtdRemappedMsi) -> Self {
        value.message()
    }
}

/// VT-d interrupt-remapping delivery target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VtdInterruptRemapTarget {
    destination: u32,
    vector: X86InterruptVector,
    delivery_mode: X86MsiDeliveryMode,
    trigger_mode: X86MsiTriggerMode,
    destination_mode_logical: bool,
    redirection_hint: bool,
}

impl VtdInterruptRemapTarget {
    #[inline]
    pub const fn new(
        destination: u32,
        vector: X86InterruptVector,
        delivery_mode: X86MsiDeliveryMode,
    ) -> Self {
        Self {
            destination,
            vector,
            delivery_mode,
            trigger_mode: X86MsiTriggerMode::Edge,
            destination_mode_logical: false,
            redirection_hint: false,
        }
    }

    #[inline]
    pub const fn from_x86_delivery(delivery: X86MsiDelivery) -> Self {
        Self {
            destination: delivery.destination().id() as u32,
            vector: delivery.vector(),
            delivery_mode: delivery.delivery_mode(),
            trigger_mode: delivery.trigger_mode(),
            destination_mode_logical: delivery.destination().is_logical(),
            redirection_hint: delivery.redirection_hint(),
        }
    }

    #[inline]
    pub const fn with_trigger_mode(mut self, trigger_mode: X86MsiTriggerMode) -> Self {
        self.trigger_mode = trigger_mode;
        self
    }

    #[inline]
    pub const fn with_logical_destination_mode(mut self, enabled: bool) -> Self {
        self.destination_mode_logical = enabled;
        self
    }

    #[inline]
    pub const fn with_redirection_hint(mut self, enabled: bool) -> Self {
        self.redirection_hint = enabled;
        self
    }

    #[inline]
    pub const fn destination(self) -> u32 {
        self.destination
    }

    #[inline]
    pub const fn vector(self) -> X86InterruptVector {
        self.vector
    }

    #[inline]
    pub const fn delivery_mode(self) -> X86MsiDeliveryMode {
        self.delivery_mode
    }

    #[inline]
    pub const fn trigger_mode(self) -> X86MsiTriggerMode {
        self.trigger_mode
    }

    #[inline]
    pub const fn destination_mode_logical(self) -> bool {
        self.destination_mode_logical
    }

    #[inline]
    pub const fn redirection_hint(self) -> bool {
        self.redirection_hint
    }
}

/// Raw VT-d interrupt-remapping table entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct VtdInterruptRemapEntry {
    low: u64,
    high: u64,
}

impl VtdInterruptRemapEntry {
    #[inline]
    pub const fn from_words(low: u64, high: u64) -> Self {
        Self { low, high }
    }

    #[inline]
    pub const fn disabled() -> Self {
        Self::from_words(0, 0)
    }

    #[inline]
    pub const fn from_target(source: PciDevice, target: VtdInterruptRemapTarget) -> Self {
        let mut low = IRTE_PRESENT
            | ((target.delivery_mode() as u64) << IRTE_DELIVERY_MODE_SHIFT)
            | ((target.vector().get() as u64) << IRTE_VECTOR_SHIFT)
            | ((target.destination() as u64) << IRTE_DESTINATION_SHIFT);
        if target.destination_mode_logical() {
            low |= IRTE_DESTINATION_MODE_LOGICAL;
        }
        if target.redirection_hint() {
            low |= IRTE_REDIRECTION_HINT;
        }
        if matches!(target.trigger_mode(), X86MsiTriggerMode::Level) {
            low |= IRTE_TRIGGER_MODE_LEVEL;
        }

        Self::from_words(low, source_validation_high(source.bdf().as_u16()))
    }

    #[inline]
    pub const fn from_x86_delivery(source: PciDevice, delivery: X86MsiDelivery) -> Self {
        Self::from_target(source, VtdInterruptRemapTarget::from_x86_delivery(delivery))
    }

    #[inline]
    pub const fn fixed(
        source: PciDevice,
        destination: X86MsiDestination,
        vector: u8,
    ) -> Result<Self> {
        let Ok(vector) = crate::arch::x86_64::X86InterruptVector::new(vector) else {
            return Err(Error::InvalidRange);
        };
        Ok(Self::from_target(
            source,
            VtdInterruptRemapTarget::from_x86_delivery(X86MsiDelivery::new(
                destination,
                vector,
                X86MsiDeliveryMode::Fixed,
            )),
        ))
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
    pub const fn present(self) -> bool {
        (self.low & IRTE_PRESENT) != 0
    }
}

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

    #[inline]
    pub fn fault_status(&self) -> Result<u32> {
        self.read32(REG_FSTS)
    }

    #[inline]
    pub fn invalidate_queue_head(&self) -> Result<usize> {
        self.read64(REG_IQH).map(|head| head as usize)
    }

    #[inline]
    pub fn invalidate_queue_tail(&self) -> Result<usize> {
        self.read64(REG_IQT).map(|tail| tail as usize)
    }

    #[inline]
    pub fn write_invalidate_queue_tail(&mut self, tail: usize) -> Result {
        self.write64(REG_IQT, tail as u64)
    }

    #[inline]
    fn poll_transition() {
        spin_loop();
    }

    pub fn wait_global_status(&self, mask: u32, expected: u32) -> Result {
        for _ in 0..REGISTER_TRANSITION_POLL_LIMIT {
            if (self.global_status()? & mask) == (expected & mask) {
                return Ok(());
            }
            Self::poll_transition();
        }

        Err(VtdError::RegisterTransitionTimeout.into())
    }

    pub fn set_root_entry_table(&mut self, root: PhysAddr) -> Result {
        if !root.is_aligned(PageSize::Size4K.bytes()) {
            return Err(VtdError::UnsupportedGranule.into());
        }

        without_interrupts(|| {
            self.write64(REG_RTADDR, root.as_usize() as u64)?;
            let status = self.global_status()?;
            self.global_command(status | GCMD_SRTP)
        })?;
        self.wait_global_status(GSTS_RTPS, GSTS_RTPS)
    }

    #[inline]
    pub fn set_root_table(&mut self, table: VtdRootTableBacking) -> Result {
        self.set_root_entry_table(table.phys().start)
    }

    #[inline]
    pub fn write_root_entry(
        &mut self,
        table: VtdRootTableBacking,
        bus: u8,
        entry: VtdRootEntry,
    ) -> Result {
        write_root_entry(table, bus, entry)
    }

    #[inline]
    pub fn read_root_entry(&self, table: VtdRootTableBacking, bus: u8) -> Result<VtdRootEntry> {
        read_root_entry(table, bus)
    }

    #[inline]
    pub fn clear_root_entry(&mut self, table: VtdRootTableBacking, bus: u8) -> Result {
        self.write_root_entry(table, bus, VtdRootEntry::disabled())
    }

    #[inline]
    pub fn write_context_entry(
        &mut self,
        table: VtdContextTableBacking,
        client: PciDevice,
        entry: VtdContextEntry,
    ) -> Result {
        write_context_entry(table, client, entry)
    }

    #[inline]
    pub fn read_context_entry(
        &self,
        table: VtdContextTableBacking,
        client: PciDevice,
    ) -> Result<VtdContextEntry> {
        read_context_entry(table, client)
    }

    #[inline]
    pub fn clear_context_entry(
        &mut self,
        table: VtdContextTableBacking,
        client: PciDevice,
    ) -> Result {
        self.write_context_entry(table, client, VtdContextEntry::disabled())
    }

    #[inline]
    pub fn write_binding_context(
        &mut self,
        table: VtdContextTableBacking,
        binding: Binding<PciDevice, VtdDomain>,
    ) -> Result {
        self.write_context_entry(
            table,
            binding.client(),
            VtdContextEntry::from_binding(binding, self.extended_capability()?)?,
        )
    }

    pub fn set_translation_enabled(&mut self, enabled: bool) -> Result {
        let status_bit = if enabled { GSTS_TES } else { 0 };

        without_interrupts(|| {
            let status = self.global_status()?;
            let command = if enabled {
                status | GCMD_TE
            } else {
                status & !GCMD_TE
            };
            self.global_command(command)
        })?;
        self.wait_global_status(GSTS_TES, status_bit)
    }

    #[inline]
    pub fn enable_translation(&mut self) -> Result {
        self.set_translation_enabled(true)
    }

    #[inline]
    pub fn disable_translation(&mut self) -> Result {
        self.set_translation_enabled(false)
    }

    pub fn set_queued_invalidation_enabled(&mut self, enabled: bool) -> Result {
        let status_bit = if enabled { GSTS_QIES } else { 0 };

        without_interrupts(|| {
            let status = self.global_status()?;
            let command = if enabled {
                status | GCMD_QIE
            } else {
                status & !GCMD_QIE
            };
            self.global_command(command)
        })?;
        self.wait_global_status(GSTS_QIES, status_bit)
    }

    #[inline]
    pub fn enable_queued_invalidation(&mut self) -> Result {
        self.set_queued_invalidation_enabled(true)
    }

    #[inline]
    pub fn disable_queued_invalidation(&mut self) -> Result {
        self.set_queued_invalidation_enabled(false)
    }

    pub fn set_interrupt_remapping_enabled(&mut self, enabled: bool) -> Result {
        let status_bit = if enabled { GSTS_IRES } else { 0 };

        without_interrupts(|| {
            let status = self.global_status()?;
            let command = if enabled {
                status | GCMD_IRE
            } else {
                status & !GCMD_IRE
            };
            self.global_command(command)
        })?;
        self.wait_global_status(GSTS_IRES, status_bit)
    }

    #[inline]
    pub fn enable_interrupt_remapping(&mut self) -> Result {
        self.set_interrupt_remapping_enabled(true)
    }

    #[inline]
    pub fn disable_interrupt_remapping(&mut self) -> Result {
        self.set_interrupt_remapping_enabled(false)
    }

    pub fn set_interrupt_remap_table(
        &mut self,
        table: VtdInterruptRemapTableBacking,
        extended_interrupt_mode: bool,
    ) -> Result {
        let mut value = (table.phys().start.as_usize() as u64 & PAGE_ADDR_MASK) | table.irta_size();
        if extended_interrupt_mode {
            value |= IRTA_EIME;
        }

        without_interrupts(|| {
            self.write64(REG_IRTA, value)?;
            let status = self.global_status()?;
            self.global_command(status | GCMD_SIRTP)
        })?;
        self.wait_global_status(GSTS_IRTPS, GSTS_IRTPS)
    }

    #[inline]
    pub fn write_interrupt_remap_entry(
        &mut self,
        table: VtdInterruptRemapTableBacking,
        entry: VtdInterruptEntry,
        remap: VtdInterruptRemapEntry,
    ) -> Result {
        write_interrupt_remap_entry(table, entry, remap)
    }

    #[inline]
    pub fn clear_interrupt_remap_entry(
        &mut self,
        table: VtdInterruptRemapTableBacking,
        entry: VtdInterruptEntry,
    ) -> Result {
        self.write_interrupt_remap_entry(table, entry, VtdInterruptRemapEntry::disabled())
    }

    pub fn compose_interrupt_remap<const N: usize>(
        &mut self,
        table: VtdInterruptRemapTableBacking,
        queue: &VtdQueuedInvalidationQueue<N>,
        entry: VtdInterruptEntry,
        subhandle: u16,
        remap: VtdInterruptRemapEntry,
    ) -> Result<VtdRemappedMsi> {
        self.write_interrupt_remap_entry(table, entry, remap)?;
        self.submit_queued_invalidation(
            queue,
            VtdQueuedInvalidationDescriptor::interrupt_entry_cache(entry),
        )?;
        Ok(VtdRemappedMsi::new(entry, subhandle))
    }

    pub fn configure_fault_event(&mut self, route: InterruptRoute) -> Result {
        without_interrupts(|| match route {
            InterruptRoute::Disabled => self.write32(REG_FECTL, FECTL_INTERRUPT_MASK),
            InterruptRoute::Msi(message) => {
                self.write32(REG_FEDATA, message.data())?;
                self.write32(REG_FEADDR, message.address() as u32)?;
                self.write32(REG_FEUADDR, (message.address() >> 32) as u32)?;
                self.write32(REG_FECTL, 0)
            }
        })
    }

    #[inline]
    pub fn fault_event_message(&self) -> Result<MsiMessage> {
        let data = self.read32(REG_FEDATA)?;
        let low = self.read32(REG_FEADDR)? as u64;
        let high = self.read32(REG_FEUADDR)? as u64;
        Ok(MsiMessage::new(low | (high << 32), data))
    }

    #[inline]
    pub fn fault_event_route(&self) -> Result<InterruptRoute> {
        if (self.read32(REG_FECTL)? & FECTL_INTERRUPT_MASK) != 0 {
            Ok(InterruptRoute::Disabled)
        } else {
            self.fault_event_message().map(InterruptRoute::Msi)
        }
    }

    pub fn submit_queued_invalidation<const N: usize>(
        &mut self,
        queue: &VtdQueuedInvalidationQueue<N>,
        descriptor: VtdQueuedInvalidationDescriptor,
    ) -> Result {
        let mut tail_result = Ok(());
        let this = self as *mut Self;
        descriptor.submit_to(
            queue,
            || unsafe { (&*this).invalidate_queue_head() },
            |tail| unsafe { tail_result = (&mut *this).write_invalidate_queue_tail(tail) },
            || unsafe { (&*this).fault_status().map(|_| ()) },
        )?;
        tail_result
    }

    #[inline]
    pub fn invalidate_context_global<const N: usize>(
        &mut self,
        queue: &VtdQueuedInvalidationQueue<N>,
    ) -> Result {
        self.submit_queued_invalidation(queue, VtdQueuedInvalidationDescriptor::context_global())
    }

    #[inline]
    pub fn invalidate_context_device<const N: usize>(
        &mut self,
        queue: &VtdQueuedInvalidationQueue<N>,
        client: PciDevice,
    ) -> Result {
        self.submit_queued_invalidation(
            queue,
            VtdQueuedInvalidationDescriptor::context_device(client),
        )
    }

    #[inline]
    pub fn invalidate_iotlb_global<const N: usize>(
        &mut self,
        queue: &VtdQueuedInvalidationQueue<N>,
        cap: VtdCapability,
    ) -> Result {
        self.submit_queued_invalidation(queue, VtdQueuedInvalidationDescriptor::iotlb_global(cap))
    }

    #[inline]
    pub fn invalidate_iotlb_domain<const N: usize>(
        &mut self,
        queue: &VtdQueuedInvalidationQueue<N>,
        domain: VtdIoDomain,
        cap: VtdCapability,
    ) -> Result {
        self.submit_queued_invalidation(
            queue,
            VtdQueuedInvalidationDescriptor::iotlb_domain(domain, cap),
        )
    }

    pub fn invalidate_iotlb_page<const N: usize>(
        &mut self,
        queue: &VtdQueuedInvalidationQueue<N>,
        domain: VtdIoDomain,
        iova: IoviAddr<u64>,
        granule: PageSize,
        cap: VtdCapability,
    ) -> Result {
        let descriptor = VtdQueuedInvalidationDescriptor::iotlb_page(domain, iova, granule, cap)?;
        self.submit_queued_invalidation(queue, descriptor)
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
        RH: FnMut() -> Result<usize>,
        WT: FnMut(usize),
        CE: FnMut() -> Result,
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

    #[inline]
    pub const fn remapped_msi(self, subhandle: u16) -> VtdRemappedMsi {
        VtdRemappedMsi::new(self, subhandle)
    }
}

#[inline]
const fn source_validation_high(source_id: u16) -> u64 {
    ((source_id as u64) << IRTE_SOURCE_ID_SHIFT)
        | (IRTE_SOURCE_QUALIFIER_ALL_BITS << IRTE_SOURCE_ID_QUALIFIER_SHIFT)
        | (IRTE_SOURCE_VALIDATION_VERIFY_SOURCE_ID << IRTE_SOURCE_VALIDATION_TYPE_SHIFT)
}

#[inline]
const fn remapped_msi_message(entry: VtdInterruptEntry, subhandle: u16) -> MsiMessage {
    let raw = entry.as_u16();
    let address = 0xfee0_0000u64
        | REMAPPED_MSI_SUBHANDLE_VALID
        | REMAPPED_MSI_INTERRUPT_FORMAT
        | (((raw as u64 >> 15) & 0x1) * REMAPPED_MSI_INDEX_HIGH_BIT)
        | (((raw & REMAPPED_MSI_INDEX_LOW_MASK) as u64) << REMAPPED_MSI_INDEX_SHIFT);
    MsiMessage::new(address, subhandle as u32)
}

#[inline]
const fn vtd_agaw_bits(width: super::paging::VtdSecondLevelAddressWidth) -> u64 {
    match width {
        super::paging::VtdSecondLevelAddressWidth::Bits39 => 1,
        super::paging::VtdSecondLevelAddressWidth::Bits48 => 2,
        super::paging::VtdSecondLevelAddressWidth::Bits57 => 3,
    }
}

#[inline]
const fn vtd_context_entry_index(client: PciDevice) -> u8 {
    (client.device() << 3) | client.function()
}

#[inline]
fn write_128(vaddr: VirtAddr, low: u64, high: u64) {
    unsafe {
        let ptr = vaddr.as_mut_ptr_of::<u64>();
        ptr.write_volatile(low.to_le());
        ptr.add(1).write_volatile(high.to_le());
    }
}

#[inline]
fn read_128(vaddr: VirtAddr) -> (u64, u64) {
    unsafe {
        let ptr = vaddr.as_ptr_of::<u64>();
        (
            u64::from_le(ptr.read_volatile()),
            u64::from_le(ptr.add(1).read_volatile()),
        )
    }
}

#[inline]
fn write_root_entry(table: VtdRootTableBacking, bus: u8, entry: VtdRootEntry) -> Result {
    let vaddr = table.entry_vaddr(bus)?;
    write_128(vaddr, entry.low(), entry.high());
    Ok(())
}

#[inline]
fn read_root_entry(table: VtdRootTableBacking, bus: u8) -> Result<VtdRootEntry> {
    let vaddr = table.entry_vaddr(bus)?;
    let (low, high) = read_128(vaddr);
    Ok(VtdRootEntry::from_words(low, high))
}

#[inline]
fn write_context_entry(
    table: VtdContextTableBacking,
    client: PciDevice,
    entry: VtdContextEntry,
) -> Result {
    let vaddr = table.client_entry_vaddr(client)?;
    write_128(vaddr, entry.low(), entry.high());
    Ok(())
}

#[inline]
fn read_context_entry(table: VtdContextTableBacking, client: PciDevice) -> Result<VtdContextEntry> {
    let vaddr = table.client_entry_vaddr(client)?;
    let (low, high) = read_128(vaddr);
    Ok(VtdContextEntry::from_words(low, high))
}

#[inline]
fn write_interrupt_remap_entry(
    table: VtdInterruptRemapTableBacking,
    entry: VtdInterruptEntry,
    remap: VtdInterruptRemapEntry,
) -> Result {
    let vaddr = table.entry_vaddr(entry)?;
    write_128(vaddr, remap.low(), remap.high());
    Ok(())
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
    const ECAP_PT: u64 = 1 << 6;

    fn table_range(buffer: &mut [u8], phys_base: usize) -> (PhysAddrRange, VirtAddrRange) {
        (
            PhysAddrRange::from_start_size(PhysAddr::from_usize(phys_base), buffer.len()),
            VirtAddrRange::from_start_size(
                VirtAddr::from_usize(buffer.as_mut_ptr() as usize),
                buffer.len(),
            ),
        )
    }

    #[test]
    fn root_entry_points_at_context_table() {
        let mut root_page = vec![0u8; PageSize::Size4K.bytes()];
        let mut context_page = vec![0u8; PageSize::Size4K.bytes()];
        let (root_phys, root_virt) = table_range(&mut root_page, 0x4000);
        let (context_phys, context_virt) = table_range(&mut context_page, 0x8000);
        let root_table = unsafe { VtdRootTableBacking::new(root_phys, root_virt) }.unwrap();
        let context_table =
            unsafe { VtdContextTableBacking::new(context_phys, context_virt) }.unwrap();
        let entry = VtdRootEntry::from_context_table(context_table).unwrap();

        write_root_entry(root_table, 0x2a, entry).unwrap();

        let read = read_root_entry(root_table, 0x2a).unwrap();
        assert!(read.present());
        assert_eq!(read.context_table_root(), Some(context_phys.start));
    }

    #[test]
    fn context_entry_encodes_domain_root_width_and_id() {
        let domain = VtdDomain::new(
            VtdIoDomain::from_asid(0x1234).unwrap(),
            PhysAddr::from_usize(0x20_0000),
            super::super::paging::VtdSecondLevelAddressWidth::Bits48,
            crate::TranslationStage::Stage2,
        );
        let entry = VtdContextEntry::from_domain(domain).unwrap();

        assert!(entry.present());
        assert_eq!(
            entry.translation_type(),
            CONTEXT_TRANSLATION_TYPE_MULTI_LEVEL as u8
        );
        assert_eq!(entry.page_table_root(), Some(domain.root()));
        assert_eq!(entry.domain_id(), 0x1234);
        assert_eq!(entry.address_width_bits(), 48);
    }

    #[test]
    fn context_table_writes_device_function_slot() {
        let mut context_page = vec![0u8; PageSize::Size4K.bytes()];
        let (context_phys, context_virt) = table_range(&mut context_page, 0x8000);
        let context_table =
            unsafe { VtdContextTableBacking::new(context_phys, context_virt) }.unwrap();
        let client = PciDevice::new(0, 4, 5, 3).unwrap();
        let entry = VtdContextEntry::pass_through();

        write_context_entry(context_table, client, entry).unwrap();

        assert_eq!(VtdContextTableBacking::client_entry_index(client), 0x2b);
        assert_eq!(read_context_entry(context_table, client).unwrap(), entry);
    }

    #[test]
    fn binding_context_rejects_non_default_selector_for_legacy_contexts() {
        let client = PciDevice::new(0, 0, 1, 0).unwrap();
        let binding = Binding::new(
            client,
            BindingSelector::from_substream(7),
            BindingTarget::<VtdDomain>::Abort,
        );

        assert_eq!(
            VtdContextEntry::from_binding(binding, VtdExtendedCapability::from_bits(ECAP_PT)),
            Err(Error::FeatureUnavailable)
        );
    }

    #[test]
    fn binding_context_checks_pass_through_capability() {
        let client = PciDevice::new(0, 0, 1, 0).unwrap();
        let binding = Binding::new(client, BindingSelector::Default, BindingTarget::PassThrough);

        assert_eq!(
            VtdContextEntry::from_binding(binding, VtdExtendedCapability::from_bits(0)),
            Err(Error::FeatureUnavailable)
        );

        let entry =
            VtdContextEntry::from_binding(binding, VtdExtendedCapability::from_bits(ECAP_PT))
                .unwrap();
        assert!(entry.present());
        assert_eq!(
            entry.translation_type(),
            CONTEXT_TRANSLATION_TYPE_PASS_THROUGH as u8
        );
    }

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
    fn interrupt_remap_entry_encodes_x86_delivery_and_source() {
        let source = PciDevice::new(0, 0x2a, 5, 3).unwrap();
        let delivery = X86MsiDelivery::fixed(
            X86MsiDestination::Physical(0x42),
            crate::arch::x86_64::X86InterruptVector::new(0x45).unwrap(),
        );
        let entry = VtdInterruptRemapEntry::from_x86_delivery(source, delivery);

        assert!(entry.present());
        assert_eq!((entry.low() >> IRTE_VECTOR_SHIFT) & 0xff, 0x45);
        assert_eq!((entry.low() >> IRTE_DESTINATION_SHIFT) & 0xffff_ffff, 0x42);
        assert_eq!(entry.low() & IRTE_DESTINATION_MODE_LOGICAL, 0);
        assert_eq!(entry.low() & IRTE_TRIGGER_MODE_LEVEL, 0);
        assert_eq!(entry.high() & 0xffff, u64::from(source.bdf().as_u16()));
        assert_eq!(
            (entry.high() >> IRTE_SOURCE_VALIDATION_TYPE_SHIFT) & 0x3,
            IRTE_SOURCE_VALIDATION_VERIFY_SOURCE_ID
        );
    }

    #[test]
    fn interrupt_remap_entry_keeps_delivery_mode_bits() {
        let source = PciDevice::new(0, 0, 1, 0).unwrap();
        let delivery = X86MsiDelivery::new(
            X86MsiDestination::Logical(0x03),
            crate::arch::x86_64::X86InterruptVector::new(0x80).unwrap(),
            X86MsiDeliveryMode::LowestPriority,
        )
        .with_trigger_mode(X86MsiTriggerMode::Level)
        .with_redirection_hint(true);
        let entry = VtdInterruptRemapEntry::from_x86_delivery(source, delivery);

        assert_ne!(entry.low() & IRTE_DESTINATION_MODE_LOGICAL, 0);
        assert_ne!(entry.low() & IRTE_REDIRECTION_HINT, 0);
        assert_ne!(entry.low() & IRTE_TRIGGER_MODE_LEVEL, 0);
        assert_eq!((entry.low() >> IRTE_DELIVERY_MODE_SHIFT) & 0x7, 1);
    }

    #[test]
    fn interrupt_remap_target_preserves_extended_destination_id() {
        let source = PciDevice::new(0, 0, 2, 0).unwrap();
        let target = VtdInterruptRemapTarget::new(
            0x1234_5678,
            crate::arch::x86_64::X86InterruptVector::new(0x90).unwrap(),
            X86MsiDeliveryMode::Fixed,
        );
        let entry = VtdInterruptRemapEntry::from_target(source, target);

        assert_eq!(
            (entry.low() >> IRTE_DESTINATION_SHIFT) & 0xffff_ffff,
            0x1234_5678
        );
    }

    #[test]
    fn remapped_msi_message_encodes_index_and_subhandle() {
        let message = VtdInterruptEntry::new(0x1234).remapped_msi(7);

        assert_eq!(message.message().address(), 0xfee2_4698);
        assert_eq!(message.message().data(), 7);
    }

    #[test]
    fn interrupt_remap_table_writes_128_bit_entry() {
        let mut buffer = vec![0u128; 2];
        let phys = PhysAddrRange::from_start_size(PhysAddr::from_usize(0x4000), 32);
        let virt =
            VirtAddrRange::from_start_size(VirtAddr::from_usize(buffer.as_mut_ptr() as usize), 32);
        let table = unsafe { VtdInterruptRemapTableBacking::new(phys, virt, 2) }.unwrap();
        let remap =
            VtdInterruptRemapEntry::from_words(0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00);

        write_interrupt_remap_entry(table, VtdInterruptEntry::new(1), remap).unwrap();

        let words = unsafe { core::slice::from_raw_parts(buffer.as_ptr() as *const u64, 4) };
        assert_eq!(words[2], remap.low());
        assert_eq!(words[3], remap.high());
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
            || Ok(head.load(Ordering::Acquire)),
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
