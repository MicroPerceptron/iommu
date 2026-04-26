use core::{fmt::Debug, marker::PhantomData};

use kpte::{PageTable, TlbInvalidation};
use memory_addr::MemoryAddr;

use crate::{Binding, BindingSelector, Error, IoviAddr, PageSize, Result, TranslationStage};

/// DMA/IOMMU invalidation contract.
///
/// The supertrait is the CPU-side `kpte` invalidation hook. Device-facing
/// implementations can therefore be passed directly into a `kpte` map/unmap
/// call while also carrying IOTLB and device-TLB invalidation primitives for
/// the controller's post-write hardware synchronization.
pub trait DmaTlbInvalidation<V: MemoryAddr = IoviAddr>: TlbInvalidation<V> {
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

/// No-op DMA invalidator for host tests and pre-hardware table construction.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDmaFlush<Client = ()>(PhantomData<fn() -> Client>);

impl<Client> NoDmaFlush<Client> {
    #[inline]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<V, Client> TlbInvalidation<V> for NoDmaFlush<Client>
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

impl<V, Client> DmaTlbInvalidation<V> for NoDmaFlush<Client>
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
    AddrSpace,
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
/// a concrete inner `kpte::PageTableWalker` and get most of the mapping
/// surface mechanically through the [`PageTable`] trait, while this trait
/// adds the controller-specific attachment, invalidation, and fault paths.
pub trait Controller<V: MemoryAddr = IoviAddr>: PageTable<V> {
    type Info;
    type Client: Copy + Debug + Eq;
    type AddrSpace: Copy + Debug + Eq;
    type Invalidator: DmaTlbInvalidation<V, Client = Self::Client>;
    type Fault;

    fn info(&self) -> &Self::Info;
    fn aspace(&self) -> Self::AddrSpace;
    fn stage(&self) -> TranslationStage;
    fn enable(&mut self) -> Result;
    fn bind(&mut self, binding: Binding<Self::Client, Self::AddrSpace>) -> Result;
    fn unbind(&mut self, client: Self::Client, selector: BindingSelector) -> Result;
    fn invalidator(&self) -> &Self::Invalidator;
    fn invalidate(&mut self, request: Invalidate<Self::Client, V>) -> Result<InvalidateOutcome>;
    fn poll_fault(&mut self) -> Result<Option<Self::Fault>> {
        Err(Error::FeatureUnavailable)
    }
}
