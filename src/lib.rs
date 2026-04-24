#![no_std]

#[cfg(test)]
extern crate std;

mod addr;
mod arch;
mod error;

pub use addr::{
    Iovi32Addr, Iovi32AddrRange, IoviAddr, IoviAddrRange, Mmio32Addr, Mmio32AddrRange, MmioAddr,
    MmioAddrRange,
};
