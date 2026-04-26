#![cfg_attr(not(test), no_std)]

mod addr;
mod caps;
mod ctrl;
mod devs;
mod error;
mod firm;
mod info;

pub mod arch;

pub use addr::{
    IoPort, IoPortRange, Iovi32Addr, Iovi32AddrRange, IoviAddr, IoviAddrRange, Mmio32Addr,
    Mmio32AddrRange, MmioAddr, MmioAddrRange, MmioRange, Unsigned,
};
pub use caps::{
    Binding, BindingSelector, BindingTarget, CapabilityFlags, DmaAccess, DmaAttrs, TranslationStage,
};
pub use ctrl::{
    CommandQueue, CommandQueueBacking, Controller, FaultEventConfig, InterruptMessage, Invalidate,
    InvalidateOutcome, InvalidateScope, IoTlbInvalidation, NoIoTlbFlush,
};
pub use error::{Error, Result};
pub use firm::pcie::{Bdf, BdfRange, BdfRangeSet, PciDevice};
pub use info::{ControllerKind, IoDomain, IommuInfo, ReservedRegion};
pub use kpte::{
    AccessFlags, CachePolicy, Coherency, FrameAllocator, IntoMapBacking, MapBacking, Mapping,
    MappingContiguity, MappingFlags, MemoryAttributes, NoFlush, PageSize, PageTable,
    PageTableEntry, PageTableEntryKind, PageTableWalker, PagingError, PagingMetaData, PagingResult,
    Shareability, TlbInvalidation,
};
