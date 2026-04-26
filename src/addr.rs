use core::{fmt, marker::PhantomData, mem::size_of};

use memory_addr::{AddrRange, MemoryAddr, PhysAddr, PhysAddrRange};

/// Unsigned integer types that can be used as the underlying representation
/// for MMIO and IOVA addresses.
pub trait Unsigned: Copy + Ord + Sized {
    const MAX: usize;

    fn checked_add(self, offset: usize) -> Option<Self>;
}

impl Unsigned for u32 {
    const MAX: usize = u32::MAX as usize;

    #[inline]
    fn checked_add(self, offset: usize) -> Option<Self> {
        self.checked_add(offset as u32)
    }
}

impl Unsigned for u64 {
    const MAX: usize = u64::MAX as usize;

    #[inline]
    fn checked_add(self, offset: usize) -> Option<Self> {
        self.checked_add(offset as u64)
    }
}

impl Unsigned for usize {
    const MAX: usize = usize::MAX;

    #[inline]
    fn checked_add(self, offset: usize) -> Option<Self> {
        self.checked_add(offset)
    }
}

#[repr(C)]
union Cast<T: Copy, U: Copy> {
    from: T,
    to: U,
}

/// Convert from an unsigned integer type to usize for address manipulation.
#[inline(always)]
const fn into_usize<T: Unsigned>(value: T) -> usize {
    if size_of::<T>() == 4 {
        // Safe for u32 -> usize (zero-extended)
        let c = Cast::<T, u32> { from: value };
        unsafe { c.to as usize }
    } else {
        // Safe for u64/usize -> usize
        let c = Cast::<T, usize> { from: value };
        unsafe { c.to }
    }
}

/// Convert from usize to an unsigned integer type for address storage.
#[inline(always)]
const fn from_usize<T: Unsigned>(value: usize) -> T {
    assert!(value <= T::MAX);
    if size_of::<T>() == 4 {
        // Safe for usize -> u32 (truncated)
        let c = Cast::<usize, T> { from: value };
        unsafe { c.to }
    } else {
        // Safe for usize -> u64/usize
        let c = Cast::<usize, T> { from: value };
        unsafe { c.to }
    }
}

/// MMIO address-space marker.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum MmioSpace {}

/// I/O virtual address-space marker.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum IoviSpace {}

#[repr(transparent)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IoAddr<T: Unsigned, Space>(T, PhantomData<fn() -> Space>);

impl<T: Unsigned, Space> Into<usize> for IoAddr<T, Space> {
    #[inline]
    fn into(self) -> usize {
        into_usize(self.0)
    }
}

impl<T: Unsigned, Space> From<usize> for IoAddr<T, Space> {
    #[inline]
    fn from(value: usize) -> Self {
        Self(from_usize(value), PhantomData)
    }
}

impl<T: Unsigned, Space> IoAddr<T, Space> {
    #[inline]
    pub fn as_usize(&self) -> usize {
        into_usize(self.0)
    }

    #[inline]
    pub fn from_usize(addr: usize) -> Self {
        Self(from_usize(addr), PhantomData)
    }

    #[inline]
    pub fn checked_mul(&self, factor: usize) -> Option<Self> {
        let current: usize = self.as_usize();
        current.checked_mul(factor).map(Self::from_usize)
    }
}

impl<T: Unsigned> IoAddr<T, MmioSpace> {
    #[inline]
    pub const fn from_phys(addr: PhysAddr) -> Self {
        Self(from_usize(addr.as_usize()), PhantomData)
    }

    #[inline]
    pub const fn as_phys(self) -> PhysAddr {
        PhysAddr::from_usize(into_usize(self.0))
    }
}

impl<T: Unsigned, Space> fmt::Debug for IoAddr<T, Space> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IoAddr({:#x})", self.as_usize())
    }
}

impl<T: Unsigned, Space> fmt::Display for IoAddr<T, Space> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.as_usize())
    }
}

impl<T: Unsigned, Space> fmt::LowerHex for IoAddr<T, Space> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.as_usize(), f)
    }
}

impl<T: Unsigned, Space> fmt::UpperHex for IoAddr<T, Space> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.as_usize(), f)
    }
}

/// Memory-mapped I/O address.
pub type MmioAddr<T = usize> = IoAddr<T, MmioSpace>;

/// I/O virtual address.
pub type IoviAddr<T = usize> = IoAddr<T, IoviSpace>;

/// Range of MMIO addresses. `end` is exclusive, matching the convention used
/// by [`AddrRange`].
pub type MmioAddrRange<T = usize> = AddrRange<IoAddr<T, MmioSpace>>;

/// Range of I/O virtual addresses. `end` is exclusive, matching the convention
/// used by [`AddrRange`].
pub type IoviAddrRange<T = usize> = AddrRange<IoAddr<T, IoviSpace>>;

pub type Mmio32Addr = MmioAddr<u32>;
pub type Iovi32Addr = IoviAddr<u32>;
pub type Mmio32AddrRange = MmioAddrRange<u32>;
pub type Iovi32AddrRange = IoviAddrRange<u32>;

/// Extension methods for MMIO address ranges, providing convenient methods for
/// constructing and accessing registers at fixed offsets from a base address.
/// These methods return `Option` to reflect the possibility of out-of-bounds
/// accesses when the offset is too large for the range.
pub trait MmioRange<T: Unsigned>: Sized {
    fn from_start_size(start: MmioAddr<T>, size: usize) -> Option<Self>;
    fn from_phys_range(range: PhysAddrRange) -> Self;
    fn from_phys_start_size(start: PhysAddr, size: usize) -> Option<Self>;
    fn to_phys_range(self) -> PhysAddrRange;
    fn as_phys_range(self) -> PhysAddrRange {
        self.to_phys_range()
    }
    fn reg<const W: usize>(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg8(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg16(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg32(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg64(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg16_aligned(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg32_aligned(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg64_aligned(self, offset: usize) -> Option<MmioAddr<T>>;
}

impl<T: Unsigned> MmioRange<T> for MmioAddrRange<T> {
    #[inline]
    fn from_start_size(start: MmioAddr<T>, size: usize) -> Option<Self> {
        Self::try_from_start_size(start, size)
    }

    #[inline]
    fn from_phys_range(range: PhysAddrRange) -> Self {
        Self {
            start: MmioAddr::from_phys(range.start),
            end: MmioAddr::from_phys(range.end),
        }
    }

    #[inline]
    fn from_phys_start_size(start: PhysAddr, size: usize) -> Option<Self> {
        <Self as MmioRange<T>>::from_start_size(MmioAddr::from_phys(start), size)
    }

    #[inline]
    fn to_phys_range(self) -> PhysAddrRange {
        PhysAddrRange {
            start: self.start.as_phys(),
            end: self.end.as_phys(),
        }
    }

    #[inline]
    fn reg<const W: usize>(self, offset: usize) -> Option<MmioAddr<T>> {
        let addr = self.start.checked_add(offset)?;
        let end = addr.checked_add(W)?;
        if end > self.end { None } else { Some(addr) }
    }

    #[inline]
    fn reg8(self, offset: usize) -> Option<MmioAddr<T>> {
        self.reg::<1>(offset)
    }

    #[inline]
    fn reg16(self, offset: usize) -> Option<MmioAddr<T>> {
        self.reg::<2>(offset)
    }

    #[inline]
    fn reg32(self, offset: usize) -> Option<MmioAddr<T>> {
        self.reg::<4>(offset)
    }

    #[inline]
    fn reg64(self, offset: usize) -> Option<MmioAddr<T>> {
        self.reg::<8>(offset)
    }

    #[inline]
    fn reg16_aligned(self, offset: usize) -> Option<MmioAddr<T>> {
        let addr = self.reg16(offset)?;
        addr.is_aligned(2usize).then_some(addr)
    }

    #[inline]
    fn reg32_aligned(self, offset: usize) -> Option<MmioAddr<T>> {
        let addr = self.reg32(offset)?;
        addr.is_aligned(4usize).then_some(addr)
    }

    #[inline]
    fn reg64_aligned(self, offset: usize) -> Option<MmioAddr<T>> {
        let addr = self.reg64(offset)?;
        addr.is_aligned(8usize).then_some(addr)
    }
}

/// Port I/O address. x86 legacy, occasionally still in use for
/// firmware-era devices (COM serial, CF8/CFC configuration access,
/// PIT/PIC registers) on platforms that haven't migrated to MMIO.
///
/// Deliberately **not** built on [`def_usize_addr`]: the port I/O
/// address space is genuinely 16-bit (the `in`/`out` instructions
/// encode the port in `dx`, so `0x10000` is not representable at the
/// ISA level). Widening to `usize` would silently admit invalid ports.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(transparent)]
#[cfg_attr(
    not(target_arch = "x86_64"),
    deprecated(
        note = "Io ports are only meaningful on x86_64 targets, but they're being used on a different architecture"
    )
)]
pub struct IoPort(u16);

impl From<u16> for IoPort {
    #[inline]
    fn from(port: u16) -> Self {
        Self(port)
    }
}

impl From<IoPort> for u16 {
    #[inline]
    fn from(port: IoPort) -> Self {
        port.0
    }
}

impl IoPort {
    #[inline]
    pub const fn new(port: u16) -> Self {
        Self(port)
    }

    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    #[inline]
    pub fn checked_add(self, offset: u16) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    #[inline]
    pub fn checked_sub(self, offset: u16) -> Option<Self> {
        self.0.checked_sub(offset).map(Self)
    }

    #[inline]
    pub fn checked_mul(self, factor: u16) -> Option<Self> {
        self.0.checked_mul(factor).map(Self)
    }

    #[inline]
    pub fn checked_div(self, divisor: u16) -> Option<Self> {
        self.0.checked_div(divisor).map(Self)
    }
}

impl fmt::Debug for IoPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PORT:{:#06x}", self.0)
    }
}

impl fmt::Display for IoPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}", self.0)
    }
}

impl fmt::LowerHex for IoPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for IoPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

/// Range of port I/O addresses. `end` is exclusive, matching the
/// convention used by [`AddrRange`] for MMIO / IOVA.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(
    not(target_arch = "x86_64"),
    deprecated(
        note = "Io ports are only meaningful on x86_64 targets, but they're being used on a different architecture"
    )
)]
pub struct IoPortRange {
    start: IoPort,
    end: IoPort,
}

impl IoPortRange {
    #[inline]
    pub const fn new(start: IoPort, end: IoPort) -> Self {
        Self { start, end }
    }

    /// Build from a base and byte-count. Returns `None` when the range
    /// would overflow the 16-bit port I/O space.
    #[inline]
    pub fn from_start_size(start: IoPort, size: u16) -> Option<Self> {
        let end = start.checked_add(size)?;
        Some(Self { start, end })
    }

    #[inline]
    pub const fn start(self) -> IoPort {
        self.start
    }

    #[inline]
    pub const fn end(self) -> IoPort {
        self.end
    }

    /// Number of ports covered by the range, `end - start`.
    #[inline]
    pub const fn size(self) -> u16 {
        self.end.0 - self.start.0
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.start.0 >= self.end.0
    }

    /// Whether `port` falls inside the range, using the same
    /// `[start, end)` semantics as [`AddrRange::contains`].
    #[inline]
    pub const fn contains(self, port: IoPort) -> bool {
        self.start.0 <= port.0 && port.0 < self.end.0
    }
}

impl fmt::Debug for IoPortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PORT[{:#06x}..{:#06x}]", self.start.0, self.end.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_mmio_round_trips<T: Unsigned>(samples: &[usize]) {
        for &value in samples {
            let addr = MmioAddr::<T>::from(value);
            let round_trip: usize = addr.into();
            assert_eq!(round_trip, value);

            let phys = PhysAddr::from_usize(value);
            let addr = MmioAddr::<T>::from_phys(phys);
            assert_eq!(addr.as_phys().as_usize(), value);
        }
    }

    fn assert_iovi_round_trips<T: Unsigned>(samples: &[usize]) {
        for &value in samples {
            let addr = IoviAddr::<T>::from(value);
            let round_trip: usize = addr.into();
            assert_eq!(round_trip, value);
        }
    }

    fn mmio_value<T: Unsigned>(addr: MmioAddr<T>) -> usize {
        addr.into()
    }

    #[test]
    fn mmio_addr_u32_round_trips_representable_values() {
        assert_mmio_round_trips::<u32>(&[0, 1, 0x1000, 0xffff, u32::MAX as usize]);
    }

    #[test]
    fn mmio_addr_u64_round_trips_representable_values() {
        assert_mmio_round_trips::<u64>(&[0, 1, 0x1000, 0xffff_ffff, usize::MAX]);
    }

    #[test]
    fn iovi_addr_u32_round_trips_representable_values() {
        assert_iovi_round_trips::<u32>(&[0, 1, 0x1000, 0xffff, u32::MAX as usize]);
    }

    #[test]
    fn iovi_addr_u64_round_trips_representable_values() {
        assert_iovi_round_trips::<u64>(&[0, 1, 0x1000, 0xffff_ffff, usize::MAX]);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    #[should_panic]
    fn mmio_addr_u32_rejects_out_of_range_values() {
        let _ = MmioAddr::<u32>::from(u32::MAX as usize + 1);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    #[should_panic]
    fn mmio_addr_u32_checked_add_and_mul_reject_overflows() {
        let addr = MmioAddr::<u32>::from(0x1000);
        assert_eq!(addr.checked_add(0x1000).unwrap().as_usize(), 0x2000usize);
        assert!(addr.checked_add(u32::MAX as usize).is_none());
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    #[should_panic]
    fn iovi_addr_u32_rejects_out_of_range_values() {
        let _ = IoviAddr::<u32>::from(u32::MAX as usize + 1);
    }

    #[test]
    fn mmio_range_register_helpers_respect_bounds_and_alignment() {
        let range = MmioAddrRange::<u32>::new(MmioAddr::from(0x1000), MmioAddr::from(0x1040));

        assert_eq!(mmio_value(range.reg8(0).unwrap()), 0x1000);
        assert_eq!(mmio_value(range.reg16(0x10).unwrap()), 0x1010);
        assert_eq!(mmio_value(range.reg32(0x20).unwrap()), 0x1020);
        assert_eq!(mmio_value(range.reg64(0x38).unwrap()), 0x1038);
        assert!(range.reg64(0x39).is_none());
        assert_eq!(
            range.to_phys_range(),
            PhysAddrRange::from_start_size(PhysAddr::from_usize(0x1000), 0x40)
        );

        assert_eq!(mmio_value(range.reg32_aligned(0x20).unwrap()), 0x1020);
        assert!(range.reg32_aligned(0x22).is_none());
    }
}
