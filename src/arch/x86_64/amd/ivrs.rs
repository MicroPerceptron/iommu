//! AMD-Vi IVRS firmware table parsing.

use core::fmt;

use acpi::{
    AcpiTable, Handler, PhysicalMapping,
    sdt::{SdtHeader, Signature},
};
use memory_addr::{PhysAddr, PhysAddrRange};

use crate::firm::{
    acpi::{AcpiTableBytesError, SdtBytes},
    pcie::{Bdf, BdfRange, BdfRangeSet, BdfRangeSetError, PciDevice},
};
use crate::{MmioAddr, MmioAddrRange, MmioRange};

const IVRS_IVINFO_OFFSET: usize = 36;
const IVRS_BLOCKS_OFFSET: usize = 48;

const IVHD_TYPE_10H: u8 = 0x10;
const IVHD_TYPE_11H: u8 = 0x11;
const IVHD_TYPE_40H: u8 = 0x40;

const IVMD_TYPE_ALL: u8 = 0x20;
const IVMD_TYPE_SPECIFIED: u8 = 0x21;
const IVMD_TYPE_RANGE: u8 = 0x22;

const IVHD_FLAGS_OFFSET: usize = 1;
const IVHD_LENGTH_OFFSET: usize = 2;
const IVHD_DEVICE_ID_OFFSET: usize = 4;
const IVHD_CAP_OFFSET: usize = 6;
const IVHD_BASE_ADDR_OFFSET: usize = 8;
const IVHD_SEGMENT_OFFSET: usize = 16;
const IVHD_INFO_OFFSET: usize = 18;
const IVHD_10H_FEATURE_OFFSET: usize = 20;
const IVHD_10H_DEVICE_ENTRIES_OFFSET: usize = 24;
const IVHD_11H_EFR_OFFSET: usize = 24;
const IVHD_11H_DEVICE_ENTRIES_OFFSET: usize = 40;
const IVHD_10H_MIN_LENGTH: usize = 24;
const IVHD_11H_MIN_LENGTH: usize = 40;

const IVMD_MIN_LENGTH: usize = 24;
const IVMD_FLAGS_OFFSET: usize = 1;
const IVMD_DEVICE_ID_OFFSET: usize = 4;
const IVMD_AUX_OFFSET: usize = 6;
const IVMD_START_ADDR_OFFSET: usize = 8;
const IVMD_MEM_LENGTH_OFFSET: usize = 16;

const DEVENTRY_PAD: u8 = 0x00;
const DEVENTRY_ALL: u8 = 0x01;
const DEVENTRY_SELECT: u8 = 0x02;
const DEVENTRY_RANGE_START: u8 = 0x03;
const DEVENTRY_RANGE_END: u8 = 0x04;
const DEVENTRY_ALIAS_SELECT: u8 = 0x42;
const DEVENTRY_ALIAS_RANGE_START: u8 = 0x43;
const DEVENTRY_SPECIAL: u8 = 0x48;

const IVHD_FLAG_IOTLB_SUP: u8 = 1 << 4;
const IVHD_FLAG_COHERENT: u8 = 1 << 5;
const IVHD_FLAG_PREFSUP: u8 = 1 << 6;
const IVHD_FLAG_PPRSUP: u8 = 1 << 7;
const AMD_VI_REGISTER_WINDOW_SIZE: usize = 0x4000;

pub const IVRS_REQUESTER_WINDOW_CAPACITY: usize = 16;

pub type IvrsBdfRangeSet = BdfRangeSet<IVRS_REQUESTER_WINDOW_CAPACITY>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IvrsError {
    Table(AcpiTableBytesError),
    BdfRanges(BdfRangeSetError),
    Malformed(&'static str),
}

impl From<AcpiTableBytesError> for IvrsError {
    #[inline]
    fn from(value: AcpiTableBytesError) -> Self {
        Self::Table(value)
    }
}

impl From<BdfRangeSetError> for IvrsError {
    #[inline]
    fn from(value: BdfRangeSetError) -> Self {
        Self::BdfRanges(value)
    }
}

impl fmt::Display for IvrsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Table(error) => write!(f, "{error}"),
            Self::BdfRanges(error) => write!(f, "{error}"),
            Self::Malformed(message) => f.write_str(message),
        }
    }
}

fn mmio_register_window(
    base: u64,
    size: usize,
    addr_error: &'static str,
    range_error: &'static str,
) -> Result<MmioAddrRange, IvrsError> {
    let base = usize::try_from(base).map_err(|_| IvrsError::Malformed(addr_error))?;
    <MmioAddrRange as MmioRange<usize>>::from_start_size(MmioAddr::from(base), size)
        .ok_or(IvrsError::Malformed(range_error))
}

fn phys_range_from_start_size(
    start: u64,
    size: u64,
    addr_error: &'static str,
    range_error: &'static str,
) -> Result<PhysAddrRange, IvrsError> {
    let start = usize::try_from(start).map_err(|_| IvrsError::Malformed(addr_error))?;
    let size = usize::try_from(size).map_err(|_| IvrsError::Malformed(addr_error))?;
    if size == 0 {
        return Err(IvrsError::Malformed(range_error));
    }
    PhysAddrRange::try_from_start_size(PhysAddr::from_usize(start), size)
        .ok_or(IvrsError::Malformed(range_error))
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct IvrsAcpiTable {
    pub header: SdtHeader,
}

unsafe impl AcpiTable for IvrsAcpiTable {
    const SIGNATURE: Signature = Signature::IVRS;

    #[inline]
    fn header(&self) -> &SdtHeader {
        &self.header
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IvrsTable<'a> {
    sdt: SdtBytes<'a>,
}

impl<'a> IvrsTable<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, IvrsError> {
        let sdt = SdtBytes::new(bytes, IvrsAcpiTable::SIGNATURE)?;
        if sdt.len() < IVRS_BLOCKS_OFFSET {
            return Err(IvrsError::Malformed("IVRS table shorter than fixed header"));
        }
        Ok(Self { sdt })
    }

    pub fn from_acpi_mapping<H>(
        mapping: &'a PhysicalMapping<H, IvrsAcpiTable>,
    ) -> Result<Self, IvrsError>
    where
        H: Handler,
    {
        let sdt = SdtBytes::from_mapping(mapping, IvrsAcpiTable::SIGNATURE)?;
        if sdt.len() < IVRS_BLOCKS_OFFSET {
            return Err(IvrsError::Malformed("IVRS table shorter than fixed header"));
        }
        Ok(Self { sdt })
    }

    #[inline]
    pub const fn bytes(self) -> &'a [u8] {
        self.sdt.bytes()
    }

    #[inline]
    pub fn ivinfo(self) -> Result<u32, IvrsError> {
        Ok(self.sdt.read_u32(IVRS_IVINFO_OFFSET)?)
    }

    #[inline]
    pub fn blocks(self) -> IvrsBlocks<'a> {
        IvrsBlocks {
            table: self,
            offset: IVRS_BLOCKS_OFFSET,
        }
    }

    pub fn for_each_ivhd<F>(self, mut f: F) -> Result<(), IvrsError>
    where
        F: FnMut(u32, Ivhd) -> Result<(), IvrsError>,
    {
        let ivinfo = self.ivinfo()?;
        self.for_each_block(|block| {
            if let IvrsBlock::Ivhd(unit) = block {
                f(ivinfo, unit)?;
            }
            Ok(())
        })
    }

    pub fn for_each_ivmd<F>(self, mut f: F) -> Result<(), IvrsError>
    where
        F: FnMut(Ivmd) -> Result<(), IvrsError>,
    {
        self.for_each_block(|block| {
            if let IvrsBlock::Ivmd(memory) = block {
                f(memory)?;
            }
            Ok(())
        })
    }

    pub fn ivhd_bdf_ranges(
        self,
        registers: MmioAddrRange,
    ) -> Result<Option<IvrsBdfRangeSet>, IvrsError> {
        let mut found_unit = false;
        let mut ranges = IvrsBdfRangeSet::empty();
        let mut saw_all = false;

        self.for_each_block(|block| {
            let IvrsBlock::Ivhd(unit) = block else {
                return Ok(());
            };
            if unit.registers != registers {
                return Ok(());
            }

            found_unit = true;
            if unit.include_all {
                saw_all = true;
                return Ok(());
            }

            self.walk_device_entries(
                unit.block_offset,
                device_entries_offset(unit.block_type),
                unit.length,
                |entry| match entry {
                    IvhdDeviceEntry::All => {
                        saw_all = true;
                        Ok(())
                    }
                    IvhdDeviceEntry::Select(device_id)
                    | IvhdDeviceEntry::AliasSelect(device_id, _)
                    | IvhdDeviceEntry::Special(device_id, _) => {
                        ranges.insert_single::<IvrsError>(device_id)
                    }
                    IvhdDeviceEntry::Range(start, end) => ranges.insert::<IvrsError>(
                        BdfRange::inclusive(start, end).map_err(BdfRangeSetError::from)?,
                    ),
                    IvhdDeviceEntry::Pad => Ok(()),
                },
            )
        })?;

        if !found_unit || saw_all || ranges.is_empty() {
            return Ok(None);
        }
        Ok(Some(ranges))
    }

    fn for_each_block<F>(self, mut f: F) -> Result<(), IvrsError>
    where
        F: FnMut(IvrsBlock) -> Result<(), IvrsError>,
    {
        for block in self.blocks() {
            f(block?)?;
        }
        Ok(())
    }

    fn parse_block(self, offset: usize, length: usize, kind: u8) -> Result<IvrsBlock, IvrsError> {
        match kind {
            IVHD_TYPE_10H | IVHD_TYPE_11H | IVHD_TYPE_40H => {
                Ok(IvrsBlock::Ivhd(self.parse_ivhd(offset, length, kind)?))
            }
            IVMD_TYPE_ALL | IVMD_TYPE_SPECIFIED | IVMD_TYPE_RANGE => {
                Ok(IvrsBlock::Ivmd(self.parse_ivmd(offset, length, kind)?))
            }
            other => Ok(IvrsBlock::Unknown(IvrsUnknown {
                kind: other,
                offset,
                length,
            })),
        }
    }

    fn parse_ivhd(self, offset: usize, length: usize, block_type: u8) -> Result<Ivhd, IvrsError> {
        let min_length = match block_type {
            IVHD_TYPE_10H => IVHD_10H_MIN_LENGTH,
            IVHD_TYPE_11H | IVHD_TYPE_40H => IVHD_11H_MIN_LENGTH,
            _ => return Err(IvrsError::Malformed("unsupported IVHD block type")),
        };
        if length < min_length {
            return Err(IvrsError::Malformed(
                "IVHD block shorter than minimum for its type",
            ));
        }

        let mut include_all = false;
        let mut has_device_scopes = false;
        let entries_offset = device_entries_offset(block_type);
        if length > entries_offset {
            self.walk_device_entries(offset, entries_offset, length, |entry| {
                match entry {
                    IvhdDeviceEntry::All => include_all = true,
                    IvhdDeviceEntry::Select(_)
                    | IvhdDeviceEntry::Range(_, _)
                    | IvhdDeviceEntry::AliasSelect(_, _)
                    | IvhdDeviceEntry::Special(_, _) => has_device_scopes = true,
                    IvhdDeviceEntry::Pad => {}
                }
                Ok(())
            })?;
        }

        Ok(Ivhd {
            block_type,
            flags: self.sdt.read_u8(offset + IVHD_FLAGS_OFFSET)?,
            capability_offset: self.sdt.read_u16(offset + IVHD_CAP_OFFSET)?,
            registers: mmio_register_window(
                self.sdt.read_u64(offset + IVHD_BASE_ADDR_OFFSET)?,
                AMD_VI_REGISTER_WINDOW_SIZE,
                "IVHD base address cannot fit in usize",
                "IVHD register window overflows",
            )?,
            device: PciDevice::from_segment_bdf(
                self.sdt.read_u16(offset + IVHD_SEGMENT_OFFSET)?,
                Bdf::from_u16(self.sdt.read_u16(offset + IVHD_DEVICE_ID_OFFSET)?),
            ),
            iommu_info: self.sdt.read_u16(offset + IVHD_INFO_OFFSET)?,
            feature_info: if block_type == IVHD_TYPE_10H {
                Some(self.sdt.read_u32(offset + IVHD_10H_FEATURE_OFFSET)?)
            } else {
                None
            },
            efr: if matches!(block_type, IVHD_TYPE_11H | IVHD_TYPE_40H) {
                Some(self.sdt.read_u64(offset + IVHD_11H_EFR_OFFSET)?)
            } else {
                None
            },
            include_all,
            has_device_scopes,
            block_offset: offset,
            length,
        })
    }

    fn parse_ivmd(self, offset: usize, length: usize, block_type: u8) -> Result<Ivmd, IvrsError> {
        if length < IVMD_MIN_LENGTH {
            return Err(IvrsError::Malformed("IVMD block too short"));
        }
        Ok(Ivmd {
            ivmd_type: block_type,
            flags: self.sdt.read_u8(offset + IVMD_FLAGS_OFFSET)?,
            device_id: Bdf::from_u16(self.sdt.read_u16(offset + IVMD_DEVICE_ID_OFFSET)?),
            aux_device_id: Bdf::from_u16(self.sdt.read_u16(offset + IVMD_AUX_OFFSET)?),
            memory: phys_range_from_start_size(
                self.sdt.read_u64(offset + IVMD_START_ADDR_OFFSET)?,
                self.sdt.read_u64(offset + IVMD_MEM_LENGTH_OFFSET)?,
                "IVMD memory address cannot fit in usize",
                "IVMD memory range overflows",
            )?,
        })
    }

    fn walk_device_entries<F>(
        self,
        block_offset: usize,
        entries_offset: usize,
        block_length: usize,
        mut f: F,
    ) -> Result<(), IvrsError>
    where
        F: FnMut(IvhdDeviceEntry) -> Result<(), IvrsError>,
    {
        let mut offset = entries_offset;
        let mut pending_range_start = None;

        while offset < block_length {
            let entry_offset = block_offset + offset;
            let entry_type = self.sdt.read_u8(entry_offset)?;
            let entry_size = match entry_type {
                0x00..=0x04 => 4usize,
                0x42 | 0x43 | 0x46 | 0x47 | 0x48 => 8usize,
                0xf0.. => break,
                _ => 4usize,
            };

            if offset + entry_size > block_length {
                return Err(IvrsError::Malformed("IVHD device entry extends past block"));
            }

            let device_id = Bdf::from_u16(self.sdt.read_u16(entry_offset + 2)?);
            match entry_type {
                DEVENTRY_PAD => f(IvhdDeviceEntry::Pad)?,
                DEVENTRY_ALL => f(IvhdDeviceEntry::All)?,
                DEVENTRY_SELECT => f(IvhdDeviceEntry::Select(device_id))?,
                DEVENTRY_RANGE_START | DEVENTRY_ALIAS_RANGE_START => {
                    pending_range_start = Some(device_id);
                }
                DEVENTRY_RANGE_END => {
                    if let Some(start) = pending_range_start.take() {
                        if device_id < start {
                            return Err(IvrsError::Malformed("IVHD device range is reversed"));
                        }
                        f(IvhdDeviceEntry::Range(start, device_id))?;
                    }
                }
                DEVENTRY_ALIAS_SELECT => f(IvhdDeviceEntry::AliasSelect(
                    device_id,
                    Bdf::from_u16(self.sdt.read_u16(entry_offset + 6)?),
                ))?,
                DEVENTRY_SPECIAL => f(IvhdDeviceEntry::Special(
                    Bdf::from_u16(self.sdt.read_u16(entry_offset + 6)?),
                    self.sdt.read_u8(entry_offset + 1)?,
                ))?,
                _ => {}
            }

            offset += entry_size;
        }

        Ok(())
    }
}

pub struct IvrsBlocks<'a> {
    table: IvrsTable<'a>,
    offset: usize,
}

impl Iterator for IvrsBlocks<'_> {
    type Item = Result<IvrsBlock, IvrsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.table.sdt.len() {
            return None;
        }
        if self.offset + 4 > self.table.sdt.len() {
            self.offset = self.table.sdt.len();
            return Some(Err(IvrsError::Malformed(
                "IVRS block truncated before header",
            )));
        }

        let offset = self.offset;
        let kind = match self.table.sdt.read_u8(offset) {
            Ok(kind) => kind,
            Err(error) => return Some(Err(error.into())),
        };
        let length = match self.table.sdt.read_u16(offset + IVHD_LENGTH_OFFSET) {
            Ok(length) => usize::from(length),
            Err(error) => return Some(Err(error.into())),
        };
        if length < 4 {
            self.offset = self.table.sdt.len();
            return Some(Err(IvrsError::Malformed(
                "IVRS block length smaller than header",
            )));
        }
        if offset + length > self.table.sdt.len() {
            self.offset = self.table.sdt.len();
            return Some(Err(IvrsError::Malformed(
                "IVRS block extends past table length",
            )));
        }

        self.offset += length;
        Some(self.table.parse_block(offset, length, kind))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IvrsBlock {
    Ivhd(Ivhd),
    Ivmd(Ivmd),
    Unknown(IvrsUnknown),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IvrsUnknown {
    pub kind: u8,
    pub offset: usize,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ivhd {
    pub block_type: u8,
    pub flags: u8,
    pub registers: MmioAddrRange,
    pub device: PciDevice,
    pub capability_offset: u16,
    pub iommu_info: u16,
    pub feature_info: Option<u32>,
    pub efr: Option<u64>,
    pub include_all: bool,
    pub has_device_scopes: bool,
    block_offset: usize,
    length: usize,
}

impl Ivhd {
    #[inline]
    pub const fn segment(self) -> u16 {
        self.device.segment()
    }

    #[inline]
    pub const fn bdf(self) -> Bdf {
        self.device.bdf()
    }

    #[inline]
    pub const fn iotlb_support(self) -> bool {
        (self.flags & IVHD_FLAG_IOTLB_SUP) != 0
    }

    #[inline]
    pub const fn coherent(self) -> bool {
        (self.flags & IVHD_FLAG_COHERENT) != 0
    }

    #[inline]
    pub const fn prefsup(self) -> bool {
        (self.flags & IVHD_FLAG_PREFSUP) != 0
    }

    #[inline]
    pub const fn pprsup(self) -> bool {
        (self.flags & IVHD_FLAG_PPRSUP) != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ivmd {
    pub ivmd_type: u8,
    pub flags: u8,
    pub device_id: Bdf,
    pub aux_device_id: Bdf,
    pub memory: PhysAddrRange,
}

impl Ivmd {
    #[inline]
    pub const fn is_all_devices(self) -> bool {
        self.ivmd_type == IVMD_TYPE_ALL
    }

    #[inline]
    pub const fn is_specified(self) -> bool {
        self.ivmd_type == IVMD_TYPE_SPECIFIED
    }

    #[inline]
    pub const fn is_range(self) -> bool {
        self.ivmd_type == IVMD_TYPE_RANGE
    }

    #[inline]
    pub const fn start_address(self) -> PhysAddr {
        self.memory.start
    }

    #[inline]
    pub fn limit_address(self) -> PhysAddr {
        PhysAddr::from_usize(self.memory.end.as_usize() - 1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IvhdDeviceEntry {
    Pad,
    All,
    Select(Bdf),
    Range(Bdf, Bdf),
    AliasSelect(Bdf, Bdf),
    Special(Bdf, u8),
}

#[inline]
const fn device_entries_offset(block_type: u8) -> usize {
    match block_type {
        IVHD_TYPE_11H | IVHD_TYPE_40H => IVHD_11H_DEVICE_ENTRIES_OFFSET,
        _ => IVHD_10H_DEVICE_ENTRIES_OFFSET,
    }
}

pub use crate::firm::pcie::BdfRange as IvrsBdfRange;

#[cfg(test)]
mod tests {
    use super::{IvrsBdfRange, IvrsBlock, IvrsTable};
    use crate::firm::pcie::Bdf;
    use crate::{MmioAddr, MmioAddrRange, MmioRange};
    use acpi::sdt::Signature;
    use memory_addr::{PhysAddr, PhysAddrRange};

    fn registers(base: usize) -> MmioAddrRange {
        <MmioAddrRange as MmioRange<usize>>::from_start_size(
            MmioAddr::from(base),
            super::AMD_VI_REGISTER_WINDOW_SIZE,
        )
        .unwrap()
    }

    fn write_sdt_header(bytes: &mut [u8], signature: Signature, length: usize) {
        bytes[0..4].copy_from_slice(signature.as_str().as_bytes());
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes[8] = 1;
    }

    #[test]
    fn parses_ivhd_and_bdf_ranges() {
        let mut ivrs = [0u8; 80];
        write_sdt_header(&mut ivrs, Signature::IVRS, 80);
        ivrs[36..40].copy_from_slice(&0x1234u32.to_le_bytes());

        ivrs[48] = 0x10;
        ivrs[49] = 1 << 5;
        ivrs[50..52].copy_from_slice(&32u16.to_le_bytes());
        ivrs[52..54].copy_from_slice(&0x0100u16.to_le_bytes());
        ivrs[54..56].copy_from_slice(&0x40u16.to_le_bytes());
        ivrs[56..64].copy_from_slice(&(0xfed8_0000u64).to_le_bytes());
        ivrs[64..66].copy_from_slice(&2u16.to_le_bytes());
        ivrs[66..68].copy_from_slice(&0x55u16.to_le_bytes());
        ivrs[68..72].copy_from_slice(&0xa5a5u32.to_le_bytes());

        ivrs[72] = 0x02;
        ivrs[74..76].copy_from_slice(&0x210u16.to_le_bytes());
        ivrs[76] = 0x02;
        ivrs[78..80].copy_from_slice(&0x211u16.to_le_bytes());

        let table = IvrsTable::parse(&ivrs).unwrap();
        assert_eq!(table.ivinfo().unwrap(), 0x1234);

        let blocks: heapless::Vec<_, 2> = table.blocks().collect::<Result<_, _>>().unwrap();
        assert!(
            matches!(blocks.as_slice(), [IvrsBlock::Ivhd(unit)] if unit.segment() == 2 && unit.coherent())
        );

        let windows = table
            .ivhd_bdf_ranges(registers(0xfed8_0000))
            .unwrap()
            .unwrap();
        assert_eq!(
            windows.as_slice(),
            &[IvrsBdfRange::inclusive(Bdf::from_u16(0x210), Bdf::from_u16(0x211)).unwrap()]
        );
    }

    #[test]
    fn parses_ivmd_reserved_memory() {
        let mut ivrs = [0u8; 72];
        write_sdt_header(&mut ivrs, Signature::IVRS, 72);
        ivrs[48] = 0x21;
        ivrs[50..52].copy_from_slice(&24u16.to_le_bytes());
        ivrs[52..54].copy_from_slice(&0x320u16.to_le_bytes());
        ivrs[56..64].copy_from_slice(&(0x2000_0000u64).to_le_bytes());
        ivrs[64..72].copy_from_slice(&(0x2000u64).to_le_bytes());

        let table = IvrsTable::parse(&ivrs).unwrap();
        let blocks: heapless::Vec<_, 2> = table.blocks().collect::<Result<_, _>>().unwrap();
        let IvrsBlock::Ivmd(memory) = blocks[0] else {
            panic!("expected IVMD");
        };

        assert!(memory.is_specified());
        assert_eq!(memory.device_id, Bdf::from_u16(0x320));
        assert_eq!(
            memory.memory,
            PhysAddrRange::from_start_size(PhysAddr::from_usize(0x2000_0000), 0x2000)
        );
        assert_eq!(memory.limit_address(), PhysAddr::from_usize(0x2000_1fff));
    }
}
