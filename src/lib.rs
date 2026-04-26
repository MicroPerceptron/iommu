#![cfg_attr(not(test), no_std)]

mod addr;
mod arch;
mod caps;
mod ctrl;
mod devs;
mod error;
mod firm;
mod info;

pub use addr::{
    IoPort, IoPortRange, Iovi32Addr, Iovi32AddrRange, IoviAddr, IoviAddrRange, Mmio32Addr,
    Mmio32AddrRange, MmioAddr, MmioAddrRange, MmioRange, Unsigned,
};
pub use caps::{
    Binding, BindingSelector, BindingTarget, CapabilityFlags, DmaAccess, DmaAttrs, TranslationStage,
};
pub use ctrl::{
    Controller, DmaTlbInvalidation, Invalidate, InvalidateOutcome, InvalidateScope, NoDmaFlush,
};
pub use error::{Error, Result};
pub use firm::pcie::{Bdf, BdfRange, BdfRangeSet, PciDevice};
pub use info::{ControllerKind, ReservedRegion, UnitInfo};
pub use kpte::{
    AccessFlags, CachePolicy, Coherency, FrameAllocator, IntoMapBacking, MapBacking, Mapping,
    MappingContiguity, MappingFlags, MemoryAttributes, NoFlush, PageSize, PageTable,
    PageTableEntry, PageTableEntryKind, PageTableWalker, PagingError, PagingMetaData, PagingResult,
    Shareability, TlbInvalidation,
};
