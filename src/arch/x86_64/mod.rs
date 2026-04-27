pub mod amd;
pub mod intel;
mod interrupt;

pub use interrupt::{
    X86InterruptVector, X86MsiDelivery, X86MsiDeliveryMode, X86MsiDestination, X86MsiLevel,
    X86MsiTriggerMode,
};
