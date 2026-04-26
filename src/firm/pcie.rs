use core::fmt;

use acpi::PciAddress;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Bdf(u16);

impl Bdf {
    #[inline]
    pub const fn new(bus: u8, device: u8, function: u8) -> Result<Self, PciDeviceError> {
        if device >= 32 {
            return Err(PciDeviceError::DeviceOutOfRange);
        }
        if function >= 8 {
            return Err(PciDeviceError::FunctionOutOfRange);
        }

        Ok(Self(
            ((bus as u16) << 8) | ((device as u16) << 3) | (function as u16),
        ))
    }

    #[inline]
    pub const fn from_bus_device_function(
        bus: u8,
        device: u8,
        function: u8,
    ) -> Result<Self, PciDeviceError> {
        Self::new(bus, device, function)
    }

    #[inline]
    pub const fn from_u16(bdf: u16) -> Self {
        Self(bdf)
    }

    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0 as u32
    }

    #[inline]
    pub const fn bus(self) -> u8 {
        (self.0 >> 8) as u8
    }

    #[inline]
    pub const fn device(self) -> u8 {
        ((self.0 >> 3) & 0x1f) as u8
    }

    #[inline]
    pub const fn function(self) -> u8 {
        (self.0 & 0x07) as u8
    }

    #[inline]
    pub const fn checked_add(self, n: u16) -> Option<Self> {
        match self.0.checked_add(n) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    #[inline]
    pub const fn offset_from(self, base: Bdf) -> Option<u16> {
        self.0.checked_sub(base.0)
    }
}

impl From<u16> for Bdf {
    #[inline]
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

impl From<Bdf> for u16 {
    #[inline]
    fn from(value: Bdf) -> Self {
        value.as_u16()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciDeviceError {
    DeviceOutOfRange,
    FunctionOutOfRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PciDevice(u32);

impl PciDevice {
    #[inline]
    pub const fn new(
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Result<Self, PciDeviceError> {
        Ok(Self::from_segment_bdf(
            segment,
            match Bdf::new(bus, device, function) {
                Ok(bdf) => bdf,
                Err(error) => return Err(error),
            },
        ))
    }

    #[inline]
    pub const fn from_segment_bdf(segment: u16, bdf: Bdf) -> Self {
        Self(((segment as u32) << 16) | (bdf.as_u16() as u32))
    }

    #[inline]
    pub fn from_address(address: PciAddress) -> Result<Self, PciDeviceError> {
        Self::new(
            address.segment(),
            address.bus(),
            address.device(),
            address.function(),
        )
    }

    #[inline]
    pub fn as_addr(self) -> PciAddress {
        PciAddress::new(self.segment(), self.bus(), self.device(), self.function())
    }

    #[inline]
    pub const fn from_u32(packed: u32) -> Self {
        Self(packed)
    }

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn bdf(self) -> Bdf {
        Bdf::from_u16((self.0 & 0xffff) as u16)
    }

    #[inline]
    pub const fn segment(self) -> u16 {
        (self.0 >> 16) as u16
    }

    #[inline]
    pub const fn bus(self) -> u8 {
        ((self.0 >> 8) & 0xff) as u8
    }

    #[inline]
    pub const fn device(self) -> u8 {
        ((self.0 >> 3) & 0x1f) as u8
    }

    #[inline]
    pub const fn function(self) -> u8 {
        (self.0 & 0x07) as u8
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BdfRange {
    start: Bdf,
    end_exclusive: u32,
}

impl BdfRange {
    pub const EMPTY: Self = Self {
        start: Bdf::from_u16(0),
        end_exclusive: 0,
    };

    #[inline]
    pub const fn single(bdf: Bdf) -> Self {
        Self {
            start: bdf,
            end_exclusive: bdf.as_u32() + 1,
        }
    }

    #[inline]
    pub const fn inclusive(start: Bdf, end: Bdf) -> Result<Self, BdfRangeError> {
        if end.as_u16() < start.as_u16() {
            return Err(BdfRangeError::Reversed);
        }

        Ok(Self {
            start,
            end_exclusive: end.as_u32() + 1,
        })
    }

    #[inline]
    pub const fn start(self) -> Bdf {
        self.start
    }

    #[inline]
    pub const fn end_inclusive(self) -> Option<Bdf> {
        if self.is_empty() {
            return None;
        }

        Some(Bdf::from_u16((self.end_exclusive - 1) as u16))
    }

    #[inline]
    pub const fn len(self) -> u32 {
        self.end_exclusive - self.start.as_u32()
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.end_exclusive == self.start.as_u32()
    }

    #[inline]
    pub const fn contains(self, bdf: Bdf) -> bool {
        let raw = bdf.as_u32();
        self.start.as_u32() <= raw && raw < self.end_exclusive
    }

    #[inline]
    const fn from_bounds(start: u32, end_exclusive: u32) -> Result<Self, BdfRangeError> {
        if start > u16::MAX as u32 || end_exclusive > (u16::MAX as u32) + 1 {
            return Err(BdfRangeError::OutOfRange);
        }
        if end_exclusive < start {
            return Err(BdfRangeError::Reversed);
        }

        Ok(Self {
            start: Bdf::from_u16(start as u16),
            end_exclusive,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BdfRangeSet<const N: usize> {
    windows: [BdfRange; N],
    count: usize,
}

impl<const N: usize> BdfRangeSet<N> {
    #[inline]
    pub const fn empty() -> Self {
        Self {
            windows: [BdfRange::EMPTY; N],
            count: 0,
        }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    pub fn as_slice(&self) -> &[BdfRange] {
        &self.windows[..self.count]
    }

    #[inline]
    pub fn insert_single<E>(&mut self, bdf: Bdf) -> Result<(), E>
    where
        E: From<BdfRangeSetError>,
    {
        self.insert(BdfRange::single(bdf))
    }

    pub fn insert<E>(&mut self, range: BdfRange) -> Result<(), E>
    where
        E: From<BdfRangeSetError>,
    {
        if range.is_empty() {
            return Ok(());
        }

        let mut index = 0usize;
        while index < self.count {
            let current = self.windows[index];
            let current_end = current.end_exclusive;
            let range_end = range.end_exclusive;
            let range_start = range.start.as_u32();
            let current_start = current.start.as_u32();

            if range_start >= current_start && range_end <= current_end {
                return Ok(());
            }
            if range_start <= current_end && range_end >= current_start {
                let merged_start = current_start.min(range_start);
                let merged_end = current_end.max(range_end);
                self.windows[index] = BdfRange::from_bounds(merged_start, merged_end)
                    .map_err(BdfRangeSetError::from)
                    .map_err(E::from)?;
                self.merge_around::<E>(index)?;
                return Ok(());
            }
            if range_start < current_start {
                return self.insert_at(index, range);
            }
            index += 1;
        }

        self.insert_at(self.count, range)
    }

    fn insert_at<E>(&mut self, index: usize, range: BdfRange) -> Result<(), E>
    where
        E: From<BdfRangeSetError>,
    {
        if self.count == N {
            return Err(E::from(BdfRangeSetError::Full));
        }

        let mut cursor = self.count;
        while cursor > index {
            self.windows[cursor] = self.windows[cursor - 1];
            cursor -= 1;
        }
        self.windows[index] = range;
        self.count += 1;
        self.merge_around::<E>(index)
    }

    fn merge_around<E>(&mut self, mut index: usize) -> Result<(), E>
    where
        E: From<BdfRangeSetError>,
    {
        while index > 0 {
            if !self.merge_pair::<E>(index - 1, index)? {
                break;
            }
            index -= 1;
        }

        while index + 1 < self.count {
            if !self.merge_pair::<E>(index, index + 1)? {
                break;
            }
        }

        Ok(())
    }

    fn merge_pair<E>(&mut self, left: usize, right: usize) -> Result<bool, E>
    where
        E: From<BdfRangeSetError>,
    {
        let left_range = self.windows[left];
        let right_range = self.windows[right];
        let left_end = left_range.end_exclusive;
        if right_range.start.as_u32() > left_end {
            return Ok(false);
        }

        let right_end = right_range.end_exclusive;
        let merged_end = left_end.max(right_end);
        self.windows[left] = BdfRange::from_bounds(left_range.start.as_u32(), merged_end)
            .map_err(BdfRangeSetError::from)
            .map_err(E::from)?;
        self.remove(right);
        Ok(true)
    }

    fn remove(&mut self, index: usize) {
        let mut cursor = index;
        while cursor + 1 < self.count {
            self.windows[cursor] = self.windows[cursor + 1];
            cursor += 1;
        }
        self.count -= 1;
        self.windows[self.count] = BdfRange::EMPTY;
    }
}

impl<const N: usize> Default for BdfRangeSet<N> {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BdfRangeSetError {
    Full,
    Overflow,
    InvalidRange(BdfRangeError),
}

impl From<BdfRangeError> for BdfRangeSetError {
    #[inline]
    fn from(value: BdfRangeError) -> Self {
        Self::InvalidRange(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BdfRangeError {
    Reversed,
    OutOfRange,
}

impl fmt::Display for BdfRangeSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("too many BDF ranges"),
            Self::Overflow => f.write_str("BDF range overflow"),
            Self::InvalidRange(error) => write!(f, "{error}"),
        }
    }
}

impl fmt::Display for BdfRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reversed => f.write_str("BDF range end is before start"),
            Self::OutOfRange => f.write_str("BDF range bound is outside the PCI requester space"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Bdf, BdfRange, BdfRangeSet};

    #[test]
    fn bdf_encodes_requester_id() {
        let requester = Bdf::from_bus_device_function(0x2a, 5, 3).unwrap();
        assert_eq!(requester.as_u32(), (0x2a_u32 << 8) | (5_u32 << 3) | 3);
        assert_eq!(requester.bus(), 0x2a);
        assert_eq!(requester.device(), 5);
        assert_eq!(requester.function(), 3);
    }

    #[test]
    fn bdf_range_set_sorts_and_merges_adjacent_ranges() {
        let mut ranges = BdfRangeSet::<4>::empty();
        ranges
            .insert::<super::BdfRangeSetError>(
                BdfRange::inclusive(Bdf::from_u16(12), Bdf::from_u16(13)).unwrap(),
            )
            .unwrap();
        ranges
            .insert::<super::BdfRangeSetError>(
                BdfRange::inclusive(Bdf::from_u16(10), Bdf::from_u16(11)).unwrap(),
            )
            .unwrap();
        ranges
            .insert_single::<super::BdfRangeSetError>(Bdf::from_u16(14))
            .unwrap();
        ranges
            .insert::<super::BdfRangeSetError>(BdfRange::single(Bdf::from_u16(20)))
            .unwrap();

        assert_eq!(
            ranges.as_slice(),
            &[
                BdfRange::inclusive(Bdf::from_u16(10), Bdf::from_u16(14)).unwrap(),
                BdfRange::single(Bdf::from_u16(20))
            ]
        );
    }
}
