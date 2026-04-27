//! AMD-Vi IVRS firmware table parsing.

use core::{fmt, mem::size_of};

use acpi::{
    AcpiError, AcpiTable,
    sdt::{SdtHeader, Signature},
};
use kore_memory::{Mapping, PageTableEntry, PagingError};
use memory_addr::{MemoryAddr, PhysAddr, PhysAddrRange, VirtAddr};

use crate::firm::pcie::{Bdf, BdfRange, BdfRangeSet, BdfRangeSetError, PciDevice};
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
const DEVENTRY_EXTENDED_SELECT: u8 = 0x46;
const DEVENTRY_EXTENDED_RANGE_START: u8 = 0x47;
const DEVENTRY_SPECIAL: u8 = 0x48;
const DEVENTRY_ACPI_NAMED: u8 = 0xf0;
const DEVENTRY_ACPI_NAMED_MIN_LENGTH: usize = 22;

const IVHD_FLAG_IOTLB_SUP: u8 = 1 << 4;
const IVHD_FLAG_COHERENT: u8 = 1 << 5;
const IVHD_FLAG_PREFSUP: u8 = 1 << 6;
const IVHD_FLAG_PPRSUP: u8 = 1 << 7;
const AMD_VI_REGISTER_WINDOW_SIZE: usize = 0x4000;

pub const IVRS_REQUESTER_WINDOW_CAPACITY: usize = 16;

pub type IvrsBdfRangeSet = BdfRangeSet<IVRS_REQUESTER_WINDOW_CAPACITY>;

#[derive(Clone, Debug)]
pub enum IvrsError {
    Acpi(AcpiError),
    BdfRanges(BdfRangeSetError),
    Mapping(PagingError),
    Malformed(&'static str),
}

impl From<AcpiError> for IvrsError {
    #[inline]
    fn from(value: AcpiError) -> Self {
        Self::Acpi(value)
    }
}

impl From<BdfRangeSetError> for IvrsError {
    #[inline]
    fn from(value: BdfRangeSetError) -> Self {
        Self::BdfRanges(value)
    }
}

impl From<PagingError> for IvrsError {
    #[inline]
    fn from(value: PagingError) -> Self {
        Self::Mapping(value)
    }
}

impl fmt::Display for IvrsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acpi(error) => write!(f, "{error:?}"),
            Self::BdfRanges(error) => write!(f, "{error}"),
            Self::Mapping(error) => write!(f, "{error:?}"),
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

fn table_bytes<'a, T: AcpiTable>(
    bytes: &'a [u8],
    short_header: &'static str,
    short_table: &'static str,
) -> Result<&'a [u8], IvrsError> {
    if bytes.len() < size_of::<SdtHeader>() {
        return Err(IvrsError::Malformed(short_header));
    }

    let header = unsafe { &*bytes.as_ptr().cast::<SdtHeader>() };
    if header.signature != T::SIGNATURE {
        return Err(IvrsError::Acpi(AcpiError::SdtInvalidSignature(
            T::SIGNATURE,
        )));
    }

    let length = header.length() as usize;
    if length < size_of::<SdtHeader>() || length > bytes.len() {
        return Err(IvrsError::Malformed(short_table));
    }

    unsafe { header.validate(T::SIGNATURE)? };
    Ok(&bytes[..length])
}

unsafe fn from_mapping<Entry, P>(mapping: &Mapping<Entry, VirtAddr, P>) -> Result<&[u8], IvrsError>
where
    Entry: PageTableEntry,
    P: MemoryAddr,
{
    let len = mapping.range.size();
    let ptr = mapping.as_ptr_of::<u8>(0)?;
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
    message: &'static str,
) -> Result<[u8; N], IvrsError> {
    let end = offset
        .checked_add(N)
        .ok_or(IvrsError::Malformed("IVRS read offset overflow"))?;
    let bytes = bytes
        .get(offset..end)
        .ok_or(IvrsError::Malformed(message))?;
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[inline]
fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, IvrsError> {
    bytes
        .get(offset)
        .copied()
        .ok_or(IvrsError::Malformed("IVRS table read is out of bounds"))
}

#[inline]
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, IvrsError> {
    Ok(u16::from_le_bytes(read_array(
        bytes,
        offset,
        "IVRS table read is out of bounds",
    )?))
}

#[inline]
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, IvrsError> {
    Ok(u32::from_le_bytes(read_array(
        bytes,
        offset,
        "IVRS table read is out of bounds",
    )?))
}

#[inline]
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, IvrsError> {
    Ok(u64::from_le_bytes(read_array(
        bytes,
        offset,
        "IVRS table read is out of bounds",
    )?))
}

#[derive(Clone, Copy, Debug)]
pub struct IvrsTable<'a> {
    sdt: &'a [u8],
}

impl<'a> IvrsTable<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, IvrsError> {
        let sdt = table_bytes::<IvrsAcpiTable>(
            bytes,
            "IVRS table shorter than SDT header",
            "IVRS table length is invalid",
        )?;
        if sdt.len() < IVRS_BLOCKS_OFFSET {
            return Err(IvrsError::Malformed("IVRS table shorter than fixed header"));
        }
        Ok(Self { sdt })
    }

    /// Parse an IVRS table from an already-readable `kore_memory` mapping.
    ///
    /// # Safety
    ///
    /// `mapping` must remain live and readable for the returned table's
    /// lifetime, and its virtual range must cover the complete ACPI table.
    pub unsafe fn from_mapping<Entry, P>(
        mapping: &'a Mapping<Entry, VirtAddr, P>,
    ) -> Result<Self, IvrsError>
    where
        Entry: PageTableEntry,
        P: MemoryAddr,
    {
        let bytes = unsafe { from_mapping(mapping)? };
        Self::parse(bytes)
    }

    #[inline]
    pub const fn bytes(self) -> &'a [u8] {
        self.sdt
    }

    #[inline]
    pub fn ivinfo(self) -> Result<u32, IvrsError> {
        read_u32(self.sdt, IVRS_IVINFO_OFFSET)
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
                    IvhdDeviceEntry::All { .. } => {
                        saw_all = true;
                        Ok(())
                    }
                    IvhdDeviceEntry::Select { device_id, .. }
                    | IvhdDeviceEntry::AliasSelect { device_id, .. }
                    | IvhdDeviceEntry::ExtendedSelect { device_id, .. }
                    | IvhdDeviceEntry::Special { device_id, .. }
                    | IvhdDeviceEntry::AcpiNamed { device_id, .. } => {
                        ranges.insert_single::<IvrsError>(device_id)
                    }
                    IvhdDeviceEntry::Range { start, end, .. }
                    | IvhdDeviceEntry::AliasRange { start, end, .. }
                    | IvhdDeviceEntry::ExtendedRange { start, end, .. } => ranges
                        .insert::<IvrsError>(
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
                    IvhdDeviceEntry::All { .. } => include_all = true,
                    IvhdDeviceEntry::Select { .. }
                    | IvhdDeviceEntry::Range { .. }
                    | IvhdDeviceEntry::AliasSelect { .. }
                    | IvhdDeviceEntry::AliasRange { .. }
                    | IvhdDeviceEntry::ExtendedSelect { .. }
                    | IvhdDeviceEntry::ExtendedRange { .. }
                    | IvhdDeviceEntry::Special { .. }
                    | IvhdDeviceEntry::AcpiNamed { .. } => has_device_scopes = true,
                    IvhdDeviceEntry::Pad => {}
                }
                Ok(())
            })?;
        }

        Ok(Ivhd {
            block_type,
            flags: read_u8(self.sdt, offset + IVHD_FLAGS_OFFSET)?,
            capability_offset: read_u16(self.sdt, offset + IVHD_CAP_OFFSET)?,
            registers: mmio_register_window(
                read_u64(self.sdt, offset + IVHD_BASE_ADDR_OFFSET)?,
                AMD_VI_REGISTER_WINDOW_SIZE,
                "IVHD base address cannot fit in usize",
                "IVHD register window overflows",
            )?,
            device: PciDevice::from_segment_bdf(
                read_u16(self.sdt, offset + IVHD_SEGMENT_OFFSET)?,
                Bdf::from_u16(read_u16(self.sdt, offset + IVHD_DEVICE_ID_OFFSET)?),
            ),
            iommu_info: read_u16(self.sdt, offset + IVHD_INFO_OFFSET)?,
            feature_info: if block_type == IVHD_TYPE_10H {
                Some(read_u32(self.sdt, offset + IVHD_10H_FEATURE_OFFSET)?)
            } else {
                None
            },
            efr: if matches!(block_type, IVHD_TYPE_11H | IVHD_TYPE_40H) {
                Some(read_u64(self.sdt, offset + IVHD_11H_EFR_OFFSET)?)
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
            flags: read_u8(self.sdt, offset + IVMD_FLAGS_OFFSET)?,
            device_id: Bdf::from_u16(read_u16(self.sdt, offset + IVMD_DEVICE_ID_OFFSET)?),
            aux_device_id: Bdf::from_u16(read_u16(self.sdt, offset + IVMD_AUX_OFFSET)?),
            memory: phys_range_from_start_size(
                read_u64(self.sdt, offset + IVMD_START_ADDR_OFFSET)?,
                read_u64(self.sdt, offset + IVMD_MEM_LENGTH_OFFSET)?,
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
        F: FnMut(IvhdDeviceEntry<'a>) -> Result<(), IvrsError>,
    {
        let mut offset = entries_offset;
        let mut pending_range_start = None;

        while offset < block_length {
            let entry_offset = block_offset + offset;
            let entry_type = read_u8(self.sdt, entry_offset)?;
            let entry_size = match entry_type {
                0x00..=0x04 => 4usize,
                0x42 | 0x43 | 0x46 | 0x47 | 0x48 => 8usize,
                DEVENTRY_ACPI_NAMED => {
                    if offset + DEVENTRY_ACPI_NAMED_MIN_LENGTH > block_length {
                        return Err(IvrsError::Malformed(
                            "IVHD ACPI named device entry truncated before UID length",
                        ));
                    }
                    DEVENTRY_ACPI_NAMED_MIN_LENGTH
                        + usize::from(read_u8(self.sdt, entry_offset + 21)?)
                }
                0xf1.. => break,
                _ => 4usize,
            };

            if offset + entry_size > block_length {
                return Err(IvrsError::Malformed("IVHD device entry extends past block"));
            }

            let (device_id, data_setting) = if entry_type == DEVENTRY_ACPI_NAMED {
                (
                    Bdf::from_u16(read_u16(self.sdt, entry_offset + 1)?),
                    read_u8(self.sdt, entry_offset + 3)?,
                )
            } else {
                (
                    Bdf::from_u16(read_u16(self.sdt, entry_offset + 2)?),
                    read_u8(self.sdt, entry_offset + 1)?,
                )
            };
            match entry_type {
                DEVENTRY_PAD => f(IvhdDeviceEntry::Pad)?,
                DEVENTRY_ALL => f(IvhdDeviceEntry::All { data_setting })?,
                DEVENTRY_SELECT => f(IvhdDeviceEntry::Select {
                    device_id,
                    data_setting,
                })?,
                DEVENTRY_RANGE_START => {
                    pending_range_start = Some(PendingIvhdRange {
                        start: device_id,
                        kind: PendingIvhdRangeKind::Plain,
                        data_setting,
                    });
                }
                DEVENTRY_ALIAS_RANGE_START => {
                    pending_range_start = Some(PendingIvhdRange {
                        start: device_id,
                        kind: PendingIvhdRangeKind::Alias {
                            source: Bdf::from_u16(read_u16(self.sdt, entry_offset + 6)?),
                        },
                        data_setting,
                    });
                }
                DEVENTRY_EXTENDED_RANGE_START => {
                    pending_range_start = Some(PendingIvhdRange {
                        start: device_id,
                        kind: PendingIvhdRangeKind::Extended {
                            extended_data_setting: read_u32(self.sdt, entry_offset + 4)?,
                        },
                        data_setting,
                    });
                }
                DEVENTRY_RANGE_END => {
                    if let Some(start) = pending_range_start.take() {
                        if device_id < start.start {
                            return Err(IvrsError::Malformed("IVHD device range is reversed"));
                        }
                        match start.kind {
                            PendingIvhdRangeKind::Plain => f(IvhdDeviceEntry::Range {
                                start: start.start,
                                end: device_id,
                                data_setting: start.data_setting,
                            })?,
                            PendingIvhdRangeKind::Alias { source } => {
                                f(IvhdDeviceEntry::AliasRange {
                                    start: start.start,
                                    end: device_id,
                                    source,
                                    data_setting: start.data_setting,
                                })?
                            }
                            PendingIvhdRangeKind::Extended {
                                extended_data_setting,
                            } => f(IvhdDeviceEntry::ExtendedRange {
                                start: start.start,
                                end: device_id,
                                data_setting: start.data_setting,
                                extended_data_setting,
                            })?,
                        }
                    }
                }
                DEVENTRY_ALIAS_SELECT => f(IvhdDeviceEntry::AliasSelect {
                    device_id,
                    source: Bdf::from_u16(read_u16(self.sdt, entry_offset + 6)?),
                    data_setting,
                })?,
                DEVENTRY_EXTENDED_SELECT => f(IvhdDeviceEntry::ExtendedSelect {
                    device_id,
                    data_setting,
                    extended_data_setting: read_u32(self.sdt, entry_offset + 4)?,
                })?,
                DEVENTRY_SPECIAL => f(IvhdDeviceEntry::Special {
                    device_id: Bdf::from_u16(read_u16(self.sdt, entry_offset + 6)?),
                    variety: data_setting,
                })?,
                DEVENTRY_ACPI_NAMED => f(IvhdDeviceEntry::AcpiNamed {
                    device_id,
                    data_setting,
                    hardware_id: read_u64(self.sdt, entry_offset + 4)?,
                    compatible_id: read_u64(self.sdt, entry_offset + 12)?,
                    uid_format: read_u8(self.sdt, entry_offset + 20)?,
                    uid: &self.sdt
                        [entry_offset + DEVENTRY_ACPI_NAMED_MIN_LENGTH..entry_offset + entry_size],
                })?,
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
        let kind = match read_u8(self.table.sdt, offset) {
            Ok(kind) => kind,
            Err(error) => return Some(Err(error.into())),
        };
        let length = match read_u16(self.table.sdt, offset + IVHD_LENGTH_OFFSET) {
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
struct PendingIvhdRange {
    start: Bdf,
    kind: PendingIvhdRangeKind,
    data_setting: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingIvhdRangeKind {
    Plain,
    Alias { source: Bdf },
    Extended { extended_data_setting: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IvhdDeviceEntry<'a> {
    Pad,
    All {
        data_setting: u8,
    },
    Select {
        device_id: Bdf,
        data_setting: u8,
    },
    Range {
        start: Bdf,
        end: Bdf,
        data_setting: u8,
    },
    AliasSelect {
        device_id: Bdf,
        source: Bdf,
        data_setting: u8,
    },
    AliasRange {
        start: Bdf,
        end: Bdf,
        source: Bdf,
        data_setting: u8,
    },
    ExtendedSelect {
        device_id: Bdf,
        data_setting: u8,
        extended_data_setting: u32,
    },
    ExtendedRange {
        start: Bdf,
        end: Bdf,
        data_setting: u8,
        extended_data_setting: u32,
    },
    Special {
        device_id: Bdf,
        variety: u8,
    },
    AcpiNamed {
        device_id: Bdf,
        data_setting: u8,
        hardware_id: u64,
        compatible_id: u64,
        uid_format: u8,
        uid: &'a [u8],
    },
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
    use super::{IvhdDeviceEntry, IvrsBdfRange, IvrsBlock, IvrsTable};
    use crate::firm::pcie::Bdf;
    use crate::{MmioAddr, MmioAddrRange, MmioRange};
    use acpi::sdt::Signature;
    use kore_memory::{Mapping, PageSize, PageTableEntry, PageTableEntryKind};
    use memory_addr::{PhysAddr, PhysAddrRange, VirtAddr, VirtAddrRange};

    #[derive(Clone, Copy, Debug)]
    struct TestEntry;

    impl PageTableEntry for TestEntry {
        type Flags = ();

        fn new_leaf(_paddr: PhysAddr, _flags: Self::Flags, _size: PageSize) -> Self {
            Self
        }

        fn new_table(_paddr: PhysAddr, _level: u8) -> Self {
            Self
        }

        fn paddr(&self) -> PhysAddr {
            PhysAddr::from_usize(0)
        }

        fn flags(&self) -> Self::Flags {}

        fn is_present(&self) -> bool {
            true
        }

        fn entry_kind(&self, _level: u8) -> PageTableEntryKind {
            PageTableEntryKind::Leaf
        }

        fn clear(&mut self) {}

        fn bits(&self) -> u64 {
            0
        }

        fn from_bits(_bits: u64) -> Self {
            Self
        }
    }

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

    fn finish_sdt_checksum(bytes: &mut [u8]) {
        bytes[9] = 0;
        bytes[9] = 0u8.wrapping_sub(
            bytes
                .iter()
                .fold(0, |sum: u8, byte| sum.wrapping_add(*byte)),
        );
    }

    fn table_mapping(bytes: &[u8]) -> Mapping<TestEntry, VirtAddr> {
        let start = VirtAddr::from_usize(bytes.as_ptr() as usize);
        Mapping::new(
            VirtAddrRange::from_start_size(start, bytes.len()),
            PhysAddr::from_usize(0),
            (),
        )
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

        finish_sdt_checksum(&mut ivrs);

        let mapping = table_mapping(&ivrs);
        let table = unsafe { IvrsTable::from_mapping(&mapping) }.unwrap();
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

        finish_sdt_checksum(&mut ivrs);

        let mapping = table_mapping(&ivrs);
        let table = unsafe { IvrsTable::from_mapping(&mapping) }.unwrap();
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

    #[test]
    fn parses_extended_and_acpi_named_ivhd_entries() {
        let mut ivrs = [0u8; 122];
        write_sdt_header(&mut ivrs, Signature::IVRS, 122);

        ivrs[48] = 0x11;
        ivrs[49] = 1 << 5;
        ivrs[50..52].copy_from_slice(&74u16.to_le_bytes());
        ivrs[52..54].copy_from_slice(&0x0100u16.to_le_bytes());
        ivrs[54..56].copy_from_slice(&0x40u16.to_le_bytes());
        ivrs[56..64].copy_from_slice(&(0xfed8_0000u64).to_le_bytes());
        ivrs[64..66].copy_from_slice(&2u16.to_le_bytes());
        ivrs[66..68].copy_from_slice(&0x55u16.to_le_bytes());
        ivrs[72..80].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());

        ivrs[88] = 0x46;
        ivrs[89] = 0xaa;
        ivrs[90..92].copy_from_slice(&0x0123u16.to_le_bytes());
        ivrs[92..96].copy_from_slice(&0xdead_beefu32.to_le_bytes());

        ivrs[96] = 0xf0;
        ivrs[97..99].copy_from_slice(&0x00a5u16.to_le_bytes());
        ivrs[99] = 0x40;
        ivrs[100..108].copy_from_slice(b"AMDI0020");
        ivrs[108..116].copy_from_slice(&0u64.to_le_bytes());
        ivrs[116] = 2;
        ivrs[117] = 4;
        ivrs[118..122].copy_from_slice(b"ID01");

        finish_sdt_checksum(&mut ivrs);

        let mapping = table_mapping(&ivrs);
        let table = unsafe { IvrsTable::from_mapping(&mapping) }.unwrap();
        let blocks: heapless::Vec<_, 2> = table.blocks().collect::<Result<_, _>>().unwrap();
        let IvrsBlock::Ivhd(unit) = blocks[0] else {
            panic!("expected IVHD");
        };

        let mut entries = heapless::Vec::<_, 4>::new();
        table
            .walk_device_entries(
                unit.block_offset,
                super::device_entries_offset(unit.block_type),
                unit.length,
                |entry| {
                    entries.push(entry).unwrap();
                    Ok(())
                },
            )
            .unwrap();

        assert!(matches!(entries[0], IvhdDeviceEntry::ExtendedSelect {
                device_id,
                data_setting: 0xaa,
                extended_data_setting: 0xdead_beef,
            } if device_id == Bdf::from_u16(0x0123)));
        assert!(matches!(entries[1], IvhdDeviceEntry::AcpiNamed {
                device_id,
                data_setting: 0x40,
                hardware_id,
                compatible_id: 0,
                uid_format: 2,
                uid,
            } if device_id == Bdf::from_u16(0x00a5)
                && hardware_id == u64::from_le_bytes(*b"AMDI0020")
                && uid == b"ID01"));

        let ranges = table
            .ivhd_bdf_ranges(registers(0xfed8_0000))
            .unwrap()
            .unwrap();
        assert_eq!(
            ranges.as_slice(),
            &[
                IvrsBdfRange::single(Bdf::from_u16(0x00a5)),
                IvrsBdfRange::single(Bdf::from_u16(0x0123)),
            ]
        );
    }
}
