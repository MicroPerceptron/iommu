use core::{
    fmt::Debug,
    hint::spin_loop,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
};

use kore_memory::{PageSize, PageTable, TlbInvalidation};
use memory_addr::{MemoryAddr, PhysAddrRange, VirtAddr, VirtAddrRange};

use crate::{Binding, BindingSelector, Error, IoviAddr, Result, TranslationStage};

const COMMAND_QUEUE_POLL_LIMIT: usize = 1_000_000;
const QUEUE_SLOT_EMPTY: u8 = 0;
const QUEUE_SLOT_WRITING: u8 = 1;
const QUEUE_SLOT_READY: u8 = 2;
const QUEUE_SLOT_PUBLISHED: u8 = 3;

/// Target-neutral MSI/MSI-X style interrupt message.
///
/// The host interrupt subsystem owns vector allocation and PCI capability
/// programming. IOMMU controllers consume this value for controller-owned
/// paths such as fault-event delivery or interrupt-remapping entries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct InterruptMessage {
    addr: u64,
    data: u32,
}

impl InterruptMessage {
    #[inline]
    pub const fn new(addr: u64, data: u32) -> Self {
        Self { addr, data }
    }

    #[inline]
    pub const fn addr(self) -> u64 {
        self.addr
    }

    #[inline]
    pub const fn data(self) -> u32 {
        self.data
    }
}

/// Controller fault-event delivery configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultEventConfig {
    message: InterruptMessage,
    enabled: bool,
}

impl FaultEventConfig {
    #[inline]
    pub const fn new(message: InterruptMessage, enabled: bool) -> Self {
        Self { message, enabled }
    }

    #[inline]
    pub const fn message(self) -> InterruptMessage {
        self.message
    }

    #[inline]
    pub const fn enabled(self) -> bool {
        self.enabled
    }
}

/// Caller-provided backing for one hardware command queue.
///
/// The backing must be physically contiguous and mapped writable at `virt`.
/// Construction is unsafe because the crate cannot prove that the virtual
/// range is live, writable, and aliases the supplied physical range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandQueueBacking {
    phys: PhysAddrRange,
    virt: VirtAddrRange,
    entry_count: usize,
    entry_bytes: usize,
}

impl CommandQueueBacking {
    /// # Safety
    ///
    /// `virt` must be a live writable mapping of `phys` for at least
    /// `entry_count * entry_bytes` bytes, and the memory must remain owned by
    /// the queue while hardware can read commands from it.
    #[inline]
    pub unsafe fn new(
        phys: PhysAddrRange,
        virt: VirtAddrRange,
        entry_count: usize,
        entry_bytes: usize,
    ) -> Result<Self> {
        if entry_count == 0 || !entry_count.is_power_of_two() {
            return Err(Error::InvalidRange);
        }
        if entry_bytes == 0 || !entry_bytes.is_power_of_two() || entry_bytes < 8 {
            return Err(Error::InvalidGranule);
        }
        let size = entry_count
            .checked_mul(entry_bytes)
            .ok_or(Error::AddressOverflow)?;
        if phys.size() < size || virt.size() < size {
            return Err(Error::InvalidRange);
        }
        if phys.start.as_usize() % entry_bytes != 0 || virt.start.as_usize() % entry_bytes != 0 {
            return Err(Error::InvalidAddress);
        }

        Ok(Self {
            phys,
            virt,
            entry_count,
            entry_bytes,
        })
    }

    #[inline]
    pub const fn phys(self) -> PhysAddrRange {
        self.phys
    }

    #[inline]
    pub const fn virt(self) -> VirtAddrRange {
        self.virt
    }

    #[inline]
    pub const fn entry_count(self) -> usize {
        self.entry_count
    }

    #[inline]
    pub const fn entry_bytes(self) -> usize {
        self.entry_bytes
    }

    #[inline]
    pub fn byte_len(self) -> usize {
        self.entry_count * self.entry_bytes
    }

    #[inline]
    fn entry_vaddr(self, slot: usize) -> Result<VirtAddr> {
        let offset = slot
            .checked_mul(self.entry_bytes)
            .ok_or(Error::AddressOverflow)?;
        self.virt
            .start
            .checked_add(offset)
            .ok_or(Error::AddressOverflow)
    }
}

/// Lock-free hardware command queue.
///
/// This manages the shared ring mechanics used by VT-d queued invalidation
/// and AMD-Vi command buffers. Descriptor width, descriptor encoding, register
/// programming, and error checks stay in the concrete controller. `N` is only
/// the software slot-state capacity; the active hardware queue depth still
/// comes from [`CommandQueueBacking::entry_count`].
#[derive(Debug)]
pub struct CommandQueue<const N: usize> {
    backing: Option<CommandQueueBacking>,
    claim: AtomicUsize,
    committed: AtomicUsize,
    retired: AtomicUsize,
    slot_state: [AtomicU8; N],
}

impl<const N: usize> CommandQueue<N> {
    #[inline]
    pub const fn new() -> Self {
        Self {
            backing: None,
            claim: AtomicUsize::new(0),
            committed: AtomicUsize::new(0),
            retired: AtomicUsize::new(0),
            slot_state: [const { AtomicU8::new(QUEUE_SLOT_EMPTY) }; N],
        }
    }

    #[inline]
    pub fn init(&mut self, backing: CommandQueueBacking) -> Result {
        if N == 0 || backing.entry_count() > N {
            return Err(Error::InvalidRange);
        }
        self.backing = Some(backing);
        self.claim.store(0, Ordering::Release);
        self.committed.store(0, Ordering::Release);
        self.retired.store(0, Ordering::Release);
        for slot in &self.slot_state[..backing.entry_count()] {
            slot.store(QUEUE_SLOT_EMPTY, Ordering::Release);
        }
        Ok(())
    }

    #[inline]
    pub fn backing(&self) -> Option<CommandQueueBacking> {
        self.backing
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.backing.is_some()
    }

    #[inline]
    pub fn submit<const W: usize, RH, WT, CE>(
        &self,
        bytes: [u8; W],
        read_head: RH,
        mut write_tail: WT,
        mut check_error: CE,
    ) -> Result
    where
        RH: FnMut() -> Result<usize>,
        WT: FnMut(usize),
        CE: FnMut() -> Result,
    {
        let backing = self.backing.ok_or(Error::ControllerUnavailable)?;
        if W == 0 || !W.is_power_of_two() || W > backing.entry_bytes() {
            return Err(Error::InvalidGranule);
        }
        let ticket = self.claim.fetch_add(1, Ordering::AcqRel);
        self.wait_for_capacity(ticket, backing.entry_count())?;

        let slot = ticket & (backing.entry_count() - 1);
        self.wait_for_empty(slot)?;
        self.slot_state[slot].store(QUEUE_SLOT_WRITING, Ordering::Release);
        self.write_slot(backing, slot, &bytes)?;
        self.slot_state[slot].store(QUEUE_SLOT_READY, Ordering::Release);

        self.wait_to_publish(ticket)?;
        let tail = ((slot + 1) & (backing.entry_count() - 1)) * backing.entry_bytes();
        write_tail(tail);
        self.slot_state[slot].store(QUEUE_SLOT_PUBLISHED, Ordering::Release);
        self.committed.store(ticket + 1, Ordering::Release);

        self.wait_for_consumed(slot, backing.entry_bytes(), read_head)?;
        check_error()?;
        self.slot_state[slot].store(QUEUE_SLOT_EMPTY, Ordering::Release);
        self.advance_retired(ticket + 1);
        Ok(())
    }

    #[inline]
    fn wait_for_capacity(&self, ticket: usize, entry_count: usize) -> Result {
        for _ in 0..COMMAND_QUEUE_POLL_LIMIT {
            let retired = self.retired.load(Ordering::Acquire);
            if ticket.wrapping_sub(retired) < entry_count {
                return Ok(());
            }
            spin_loop();
        }
        Err(Error::ControllerUnavailable)
    }

    #[inline]
    fn wait_for_empty(&self, slot: usize) -> Result {
        for _ in 0..COMMAND_QUEUE_POLL_LIMIT {
            if self.slot_state[slot].load(Ordering::Acquire) == QUEUE_SLOT_EMPTY {
                return Ok(());
            }
            spin_loop();
        }
        Err(Error::ControllerUnavailable)
    }

    #[inline]
    fn wait_to_publish(&self, ticket: usize) -> Result {
        for _ in 0..COMMAND_QUEUE_POLL_LIMIT {
            if self.committed.load(Ordering::Acquire) == ticket {
                return Ok(());
            }
            spin_loop();
        }
        Err(Error::ControllerUnavailable)
    }

    #[inline]
    fn wait_for_consumed<RH>(&self, slot: usize, entry_bytes: usize, mut read_head: RH) -> Result
    where
        RH: FnMut() -> Result<usize>,
    {
        for _ in 0..COMMAND_QUEUE_POLL_LIMIT {
            let head_slot = read_head()? / entry_bytes;
            if head_slot != slot {
                return Ok(());
            }
            spin_loop();
        }
        Err(Error::ControllerUnavailable)
    }

    #[inline]
    fn advance_retired(&self, next: usize) {
        let mut current = self.retired.load(Ordering::Acquire);
        while current < next {
            match self.retired.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    #[inline]
    fn write_slot<const W: usize>(
        &self,
        backing: CommandQueueBacking,
        slot: usize,
        bytes: &[u8; W],
    ) -> Result {
        let vaddr = backing.entry_vaddr(slot)?;
        unsafe {
            let base = vaddr.as_mut_ptr_of::<u8>();
            for offset in 0..backing.entry_bytes() {
                let value = bytes.get(offset).copied().unwrap_or(0);
                base.add(offset).write_volatile(value);
            }
        }
        Ok(())
    }
}

impl<const MAX_ENTRIES: usize> Default for CommandQueue<MAX_ENTRIES> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// IOTLB invalidation contract.
///
/// The supertrait is the CPU-side `kore_memory` invalidation hook. Device-facing
/// implementations can therefore be passed directly into a `kore_memory` map/unmap
/// call while also carrying IOTLB and device-TLB invalidation primitives for
/// the controller's post-write hardware synchronization.
pub trait IoTlbInvalidation<V: MemoryAddr = IoviAddr>: TlbInvalidation<V> {
    type Client: Copy + Debug + Eq;

    fn flush_iotlb(&self, iova: V);
    fn flush_iotlb_all(&self);

    fn flush_iotlb_range(&self, start: V, page_size: PageSize, count_pages: usize) {
        let stride = page_size.bytes();
        let mut base: usize = start.into();
        for _ in 0..count_pages {
            self.flush_iotlb(<V as From<usize>>::from(base));
            base = base.saturating_add(stride);
        }
    }

    fn flush_device_tlb(&self, client: Self::Client, iova: V);
    fn flush_device_tlb_all(&self, client: Self::Client);

    fn flush_device_tlb_range(
        &self,
        client: Self::Client,
        start: V,
        page_size: PageSize,
        count_pages: usize,
    ) {
        let stride = page_size.bytes();
        let mut base: usize = start.into();
        for _ in 0..count_pages {
            self.flush_device_tlb(client, <V as From<usize>>::from(base));
            base = base.saturating_add(stride);
        }
    }

    fn prefer_full_iotlb_flush(&self, pending_count: usize) -> bool {
        self.prefer_full_flush(pending_count)
    }
}

/// Unit requester identity for APIs that need a client type but ignore it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoClient;

/// No-op IOTLB invalidator for host tests and pre-hardware table construction.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoIoTlbFlush<Client = NoClient>(core::marker::PhantomData<fn() -> Client>);

impl<Client> NoIoTlbFlush<Client> {
    #[inline]
    pub const fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<V, Client> TlbInvalidation<V> for NoIoTlbFlush<Client>
where
    V: MemoryAddr,
    Client: Copy + Debug + Eq + 'static,
{
    #[inline(always)]
    fn flush_tlb_local(&self, _vaddr: V) {}

    #[inline(always)]
    fn flush_tlb_all_local(&self) {}

    #[inline(always)]
    fn flush_tlb_range_local(&self, _start: V, _page_size: PageSize, _count_pages: usize) {}

    #[inline(always)]
    fn prefer_full_flush(&self, _pending_count: usize) -> bool {
        false
    }
}

impl<V, Client> IoTlbInvalidation<V> for NoIoTlbFlush<Client>
where
    V: MemoryAddr,
    Client: Copy + Debug + Eq + 'static,
{
    type Client = Client;

    #[inline(always)]
    fn flush_iotlb(&self, _iova: V) {}

    #[inline(always)]
    fn flush_iotlb_all(&self) {}

    #[inline(always)]
    fn flush_iotlb_range(&self, _start: V, _page_size: PageSize, _count_pages: usize) {}

    #[inline(always)]
    fn flush_device_tlb(&self, _client: Client, _iova: V) {}

    #[inline(always)]
    fn flush_device_tlb_all(&self, _client: Client) {}

    #[inline(always)]
    fn flush_device_tlb_range(
        &self,
        _client: Client,
        _start: V,
        _page_size: PageSize,
        _count_pages: usize,
    ) {
    }

    #[inline(always)]
    fn prefer_full_iotlb_flush(&self, _pending_count: usize) -> bool {
        false
    }
}

/// Explicit invalidation request against one controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidate<Client, V = IoviAddr> {
    Global,
    AddressSpace,
    Leaf {
        iova: V,
        granule: PageSize,
    },
    Device {
        client: Client,
    },
    DeviceLeaf {
        client: Client,
        iova: V,
        granule: PageSize,
    },
}

/// Effective invalidate scope completed by hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidateScope {
    Global,
    Domain,
    Leaf,
    Device,
    DeviceLeaf,
}

/// Result summary for one invalidate request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidateOutcome {
    scope: InvalidateScope,
    queued: bool,
}

impl InvalidateOutcome {
    #[inline]
    pub const fn new(scope: InvalidateScope, queued: bool) -> Self {
        Self { scope, queued }
    }

    #[inline]
    pub const fn scope(self) -> InvalidateScope {
        self.scope
    }

    #[inline]
    pub const fn queued(self) -> bool {
        self.queued
    }
}

/// Live IOMMU controller contract.
///
/// A controller is also a typed IOVA page table. Implementations can expose
/// a concrete inner `kore_memory::PageTableWalker` and get most of the mapping
/// surface mechanically through the [`PageTable`] trait, while this trait
/// adds the controller-specific attachment, invalidation, and fault paths.
pub trait Controller<V: MemoryAddr = IoviAddr>: PageTable<V> {
    type Info;
    type Client: Copy + Debug + Eq;
    type Domain: Copy + Debug + Eq;
    type Invalidator: IoTlbInvalidation<V, Client = Self::Client>;
    type Fault;

    fn info(&self) -> &Self::Info;
    fn domain(&self) -> Self::Domain;
    fn stage(&self) -> TranslationStage;
    fn enable(&mut self) -> Result;
    fn bind(&mut self, binding: Binding<Self::Client, Self::Domain>) -> Result;
    fn unbind(&mut self, client: Self::Client, selector: BindingSelector) -> Result;
    fn invalidator(&self) -> &Self::Invalidator;
    fn invalidate(&mut self, request: Invalidate<Self::Client, V>) -> Result<InvalidateOutcome>;
    fn configure_fault_event(&mut self, config: FaultEventConfig) -> Result;
    fn poll_fault(&mut self) -> Result<Option<Self::Fault>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory_addr::{PhysAddr, VirtAddr};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        vec,
    };

    const ENTRIES: usize = 8;
    const ENTRY_BYTES: usize = 16;

    fn test_queue() -> (CommandQueue<ENTRIES>, std::vec::Vec<u8>, AtomicUsize) {
        let buffer = vec![0u8; ENTRIES * ENTRY_BYTES];
        let phys = PhysAddrRange::from_start_size(
            PhysAddr::from_usize(buffer.as_ptr() as usize),
            buffer.len(),
        );
        let virt = VirtAddrRange::from_start_size(
            VirtAddr::from_usize(buffer.as_ptr() as usize),
            buffer.len(),
        );
        let backing = unsafe { CommandQueueBacking::new(phys, virt, ENTRIES, ENTRY_BYTES) }
            .expect("valid queue backing");
        let mut queue = CommandQueue::new();
        queue.init(backing).expect("queue init");
        (queue, buffer, AtomicUsize::new(0))
    }

    fn read_slot(buffer: &[u8], slot: usize) -> (u64, u64) {
        let offset = slot * ENTRY_BYTES;
        let low = u64::from_ne_bytes(buffer[offset..offset + 8].try_into().unwrap());
        let high = u64::from_ne_bytes(buffer[offset + 8..offset + 16].try_into().unwrap());
        (low, high)
    }

    #[test]
    fn command_queue_backing_rejects_non_power_of_two_entries() {
        let buffer = vec![0u8; ENTRIES * ENTRY_BYTES];
        let phys = PhysAddrRange::from_start_size(
            PhysAddr::from_usize(buffer.as_ptr() as usize),
            buffer.len(),
        );
        let virt = VirtAddrRange::from_start_size(
            VirtAddr::from_usize(buffer.as_ptr() as usize),
            buffer.len(),
        );

        let result = unsafe { CommandQueueBacking::new(phys, virt, 7, ENTRY_BYTES) };
        assert_eq!(result, Err(Error::InvalidRange));
    }

    #[test]
    fn command_queue_submit_writes_entry_and_advances_tail() {
        let (queue, buffer, head) = test_queue();
        let tail = AtomicUsize::new(0);
        let low = 0xaaaa_bbbb_cccc_ddddu64;
        let high = 0x1111_2222_3333_4444u64;
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&low.to_ne_bytes());
        bytes[8..].copy_from_slice(&high.to_ne_bytes());

        queue
            .submit(
                bytes,
                || Ok(head.load(Ordering::Acquire)),
                |new_tail| {
                    tail.store(new_tail, Ordering::Release);
                    head.store(new_tail, Ordering::Release);
                },
                || Ok(()),
            )
            .unwrap();

        assert_eq!(tail.load(Ordering::Acquire), ENTRY_BYTES);
        assert_eq!(read_slot(&buffer, 0), (low, high));
    }

    #[test]
    fn command_queue_sequential_submits_wrap_slots() {
        let (queue, buffer, head) = test_queue();

        for i in 0..(ENTRIES * 2) {
            let marker = i as u64;
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&marker.to_ne_bytes());
            bytes[8..].copy_from_slice(&(!marker).to_ne_bytes());
            queue
                .submit(
                    bytes,
                    || Ok(head.load(Ordering::Acquire)),
                    |new_tail| head.store(new_tail, Ordering::Release),
                    || Ok(()),
                )
                .unwrap();

            assert_eq!(read_slot(&buffer, i % ENTRIES), (marker, !marker));
        }
    }
}
