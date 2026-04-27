#![cfg_attr(not(test), no_std)]

mod addr;
mod caps;
mod ctrl;
mod error;
mod firm;
mod info;

pub mod arch;

#[allow(deprecated)]
pub use addr::{
    IoPort, IoPortRange, Iovi32Addr, Iovi32AddrRange, IoviAddr, IoviAddrRange, Mmio32Addr,
    Mmio32AddrRange, MmioAddr, MmioAddrRange, MmioRange, Unsigned,
};
pub use caps::{
    Binding, BindingSelector, BindingTarget, CapabilityFlags, DmaAccess, DmaAttrs, TranslationStage,
};
pub use ctrl::{
    CommandQueue, CommandQueueBacking, Controller, FaultEventConfig, InterruptMessage, Invalidate,
    InvalidateOutcome, InvalidateScope, IoTlbInvalidation, NoClient, NoIoTlbFlush,
};
pub use error::{Error, Result};
pub use firm::pcie::{Bdf, BdfRange, BdfRangeSet, PciDevice};
pub use info::{ControllerKind, IoDomain, IommuInfo, ReservedRegion};
