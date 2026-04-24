use core::fmt;

use memory_addr::{AddrRange, MemoryAddr, PhysAddr, PhysAddrRange};

/// Unsigned integer types that can be used as the underlying representation
/// for MMIO and IOVA addresses.
pub trait Unsigned: Copy + Ord + Sized {
    const MAX: usize;
}

impl Unsigned for u32 {
    const MAX: usize = u32::MAX as usize;
}

impl Unsigned for u64 {
    const MAX: usize = u64::MAX as usize;
}

impl Unsigned for usize {
    const MAX: usize = usize::MAX;
}

#[repr(C)]
union Cast<T: Copy, U: Copy> {
    from: T,
    to: U,
}

/// Common supertrait for MMIO and IOVA addresses, which share the same address
/// space and access semantics. This allows us to provide shared helper methods
/// for both types without code duplication.
#[inline(always)]
const fn into_usize<T: Unsigned>(value: T) -> usize {
    if core::mem::size_of::<T>() == 4 {
        // Safe for u32 -> usize (zero-extended)
        let c = Cast::<T, u32> { from: value };
        unsafe { c.to as usize }
    } else {
        // Safe for u64/usize -> usize
        let c = Cast::<T, usize> { from: value };
        unsafe { c.to }
    }
}

/// Common supertrait for MMIO and IOVA addresses, which share the same address
/// space and access semantics. This allows us to provide shared helper methods
/// for both types without code duplication.
#[inline(always)]
const fn from_usize<T: Unsigned>(value: usize) -> T {
    assert!(value <= T::MAX);
    if core::mem::size_of::<T>() == 4 {
        // Safe for usize -> u32 (truncated)
        let c = Cast::<usize, T> { from: value };
        unsafe { c.to }
    } else {
        // Safe for usize -> u64/usize
        let c = Cast::<usize, T> { from: value };
        unsafe { c.to }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct IoAddr<T: Unsigned>(T);

impl<T: Unsigned> Into<usize> for IoAddr<T> {
    #[inline]
    fn into(self) -> usize {
        into_usize(self.0)
    }
}

impl<T: Unsigned> From<usize> for IoAddr<T> {
    #[inline]
    fn from(value: usize) -> Self {
        Self(from_usize(value))
    }
}

impl<T: Unsigned> IoAddr<T>
where
    Self: MemoryAddr,
{
    #[inline]
    pub const fn from_phys(addr: PhysAddr) -> Self {
        Self(from_usize(addr.as_usize()))
    }

    #[inline]
    pub const fn as_phys(self) -> PhysAddr {
        PhysAddr::from_usize(into_usize(self.0))
    }
}

/// Memory-mapped I/O address. Used for MMIO and IOVA, which share the same
/// address space and access semantics.
pub type MmioAddr<T = usize> = IoAddr<T>;

/// I/O virtual address. Used for MMIO and IOVA, which share the same address
/// space and access semantics.
pub type IoviAddr<T = usize> = IoAddr<T>;

/// Range of MMIO or IOVA addresses. `end` is exclusive, matching the
/// convention used by [`AddrRange`] for MMIO / IOVA.
pub type MmioAddrRange<T = usize> = AddrRange<IoAddr<T>>;

/// Range of I/O virtual addresses. `end` is exclusive, matching the
/// convention used by [`AddrRange`] for MMIO / IOVA.
pub type IoviAddrRange<T = usize> = AddrRange<IoAddr<T>>;

pub type Mmio32Addr = MmioAddr<u32>;
pub type Iovi32Addr = IoviAddr<u32>;
pub type Mmio32AddrRange = MmioAddrRange<u32>;
pub type Iovi32AddrRange = IoviAddrRange<u32>;

/// Extension methods for MMIO / IOVA address ranges, providing convenient
/// methods for constructing and accessing registers at fixed offsets from a
/// base address. These methods return `Option` to reflect the possibility of
/// out-of-bounds accesses when the offset is too large for the range.
pub trait MmioAddrRangeExt<T: Unsigned> {
    fn from_phys_range(range: PhysAddrRange) -> Self;
    fn as_phys_range(self) -> PhysAddrRange;
    fn reg<const W: usize>(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg8(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg16(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg32(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg64(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg16_aligned(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg32_aligned(self, offset: usize) -> Option<MmioAddr<T>>;
    fn reg64_aligned(self, offset: usize) -> Option<MmioAddr<T>>;
}

impl<T: Unsigned> MmioAddrRangeExt<T> for MmioAddrRange<T> {
    #[inline]
    fn from_phys_range(range: PhysAddrRange) -> Self {
        Self {
            start: MmioAddr::from_phys(range.start),
            end: MmioAddr::from_phys(range.end),
        }
    }

    #[inline]
    fn as_phys_range(self) -> PhysAddrRange {
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

    fn assert_mmio_round_trips<T: Unsigned>(samples: &[usize])
    where
        MmioAddr<T>: MemoryAddr,
    {
        for &value in samples {
            let addr = MmioAddr::<T>::from(value);
            let round_trip: usize = addr.into();
            assert_eq!(round_trip, value);

            let phys = PhysAddr::from_usize(value);
            let addr = MmioAddr::<T>::from_phys(phys);
            assert_eq!(addr.as_phys().as_usize(), value);
        }
    }

    fn assert_iovi_round_trips<T: Unsigned>(samples: &[usize])
    where
        IoviAddr<T>: MemoryAddr,
    {
        for &value in samples {
            let addr = IoviAddr::<T>::from(value);
            let round_trip: usize = addr.into();
            assert_eq!(round_trip, value);

            let phys = PhysAddr::from_usize(value);
            let addr = IoviAddr::<T>::from_phys(phys);
            assert_eq!(addr.as_phys().as_usize(), value);
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

        assert_eq!(mmio_value(range.reg32_aligned(0x20).unwrap()), 0x1020);
        assert!(range.reg32_aligned(0x22).is_none());
    }
}
