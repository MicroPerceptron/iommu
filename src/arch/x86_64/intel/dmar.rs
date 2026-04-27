//! Intel VT-d DMAR firmware table parsing.

use core::{fmt, mem::size_of};

use acpi::{
    AcpiError, AcpiTable,
    sdt::{SdtHeader, Signature},
};
use kore_memory::{Mapping, PageTableEntry, PagingError};
use memory_addr::{MemoryAddr, PhysAddr, PhysAddrRange, VirtAddr};

use crate::{
    MmioAddr, MmioAddrRange, MmioRange,
    firm::pcie::{Bdf, BdfRange, BdfRangeSet, BdfRangeSetError, PciDevice},
};

const DMAR_HOST_ADDRESS_WIDTH_OFFSET: usize = 36;
const DMAR_FLAGS_OFFSET: usize = 37;
const DMAR_STRUCTURES_OFFSET: usize = 48;

const DMAR_DRHD: u16 = 0;
const DMAR_RMRR: u16 = 1;
const DMAR_ATSR: u16 = 2;
const DMAR_RHSA: u16 = 3;
const DMAR_ANDD: u16 = 4;
const DMAR_SATC: u16 = 5;
const DMAR_SIDP: u16 = 6;

const DRHD_MIN_LENGTH: usize = 16;
const RMRR_MIN_LENGTH: usize = 24;
const ATSR_MIN_LENGTH: usize = 8;
const RHSA_MIN_LENGTH: usize = 20;
const ANDD_MIN_LENGTH: usize = 8;
const SATC_MIN_LENGTH: usize = 8;
const SIDP_MIN_LENGTH: usize = 8;
const DEVICE_SCOPE_HEADER_LENGTH: usize = 6;
const VTD_REGISTER_WINDOW_SIZE: usize = 0x1000;

const DEVICE_SCOPE_ENDPOINT: u8 = 1;
const DEVICE_SCOPE_BRIDGE: u8 = 2;
const DEVICE_SCOPE_IOAPIC: u8 = 3;
const DEVICE_SCOPE_HPET: u8 = 4;
const DEVICE_SCOPE_NAMESPACE_DEVICE: u8 = 5;

pub const DMAR_REQUESTER_WINDOW_CAPACITY: usize = 16;

pub type DmarBdfRangeSet = BdfRangeSet<DMAR_REQUESTER_WINDOW_CAPACITY>;

#[derive(Clone, Debug)]
pub enum DmarError {
    Acpi(AcpiError),
    BdfRanges(BdfRangeSetError),
    Mapping(PagingError),
    Malformed(&'static str),
}

impl From<AcpiError> for DmarError {
    #[inline]
    fn from(value: AcpiError) -> Self {
        Self::Acpi(value)
    }
}

impl From<BdfRangeSetError> for DmarError {
    #[inline]
    fn from(value: BdfRangeSetError) -> Self {
        Self::BdfRanges(value)
    }
}

impl From<PagingError> for DmarError {
    #[inline]
    fn from(value: PagingError) -> Self {
        Self::Mapping(value)
    }
}

impl fmt::Display for DmarError {
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
) -> Result<MmioAddrRange, DmarError> {
    let base = usize::try_from(base).map_err(|_| DmarError::Malformed(addr_error))?;
    <MmioAddrRange as MmioRange<usize>>::from_start_size(MmioAddr::from(base), size)
        .ok_or(DmarError::Malformed(range_error))
}

fn inclusive_phys_range(
    base: u64,
    limit: u64,
    addr_error: &'static str,
    limit_error: &'static str,
) -> Result<PhysAddrRange, DmarError> {
    let base = usize::try_from(base).map_err(|_| DmarError::Malformed(addr_error))?;
    let end = limit
        .checked_add(1)
        .ok_or(DmarError::Malformed(limit_error))?;
    let end = usize::try_from(end).map_err(|_| DmarError::Malformed(addr_error))?;
    Ok(PhysAddrRange::new(
        PhysAddr::from_usize(base),
        PhysAddr::from_usize(end),
    ))
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct DmarAcpiTable {
    pub header: SdtHeader,
}

unsafe impl AcpiTable for DmarAcpiTable {
    const SIGNATURE: Signature = Signature::DMAR;

    #[inline]
    fn header(&self) -> &SdtHeader {
        &self.header
    }
}

fn table_bytes<'a, T: AcpiTable>(
    bytes: &'a [u8],
    short_header: &'static str,
    short_table: &'static str,
) -> Result<&'a [u8], DmarError> {
    if bytes.len() < size_of::<SdtHeader>() {
        return Err(DmarError::Malformed(short_header));
    }

    let header = unsafe { &*bytes.as_ptr().cast::<SdtHeader>() };
    if header.signature != T::SIGNATURE {
        return Err(DmarError::Acpi(AcpiError::SdtInvalidSignature(
            T::SIGNATURE,
        )));
    }

    let length = header.length() as usize;
    if length < size_of::<SdtHeader>() || length > bytes.len() {
        return Err(DmarError::Malformed(short_table));
    }

    unsafe { header.validate(T::SIGNATURE)? };
    Ok(&bytes[..length])
}

unsafe fn from_mapping<Entry, P>(mapping: &Mapping<Entry, VirtAddr, P>) -> Result<&[u8], DmarError>
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
) -> Result<[u8; N], DmarError> {
    let end = offset
        .checked_add(N)
        .ok_or(DmarError::Malformed("DMAR read offset overflow"))?;
    let bytes = bytes
        .get(offset..end)
        .ok_or(DmarError::Malformed(message))?;
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[inline]
fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, DmarError> {
    bytes
        .get(offset)
        .copied()
        .ok_or(DmarError::Malformed("DMAR table read is out of bounds"))
}

#[inline]
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DmarError> {
    Ok(u16::from_le_bytes(read_array(
        bytes,
        offset,
        "DMAR table read is out of bounds",
    )?))
}

#[inline]
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DmarError> {
    Ok(u32::from_le_bytes(read_array(
        bytes,
        offset,
        "DMAR table read is out of bounds",
    )?))
}

#[inline]
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DmarError> {
    Ok(u64::from_le_bytes(read_array(
        bytes,
        offset,
        "DMAR table read is out of bounds",
    )?))
}

#[derive(Clone, Copy, Debug)]
pub struct DmarTable<'a> {
    sdt: &'a [u8],
}

impl<'a> DmarTable<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, DmarError> {
        let sdt = table_bytes::<DmarAcpiTable>(
            bytes,
            "DMAR table shorter than SDT header",
            "DMAR table length is invalid",
        )?;
        if sdt.len() < DMAR_STRUCTURES_OFFSET {
            return Err(DmarError::Malformed("DMAR table shorter than fixed header"));
        }
        Ok(Self { sdt })
    }

    /// Parse a DMAR table from an already-readable `kore_memory` mapping.
    ///
    /// # Safety
    ///
    /// `mapping` must remain live and readable for the returned table's
    /// lifetime, and its virtual range must cover the complete ACPI table.
    pub unsafe fn from_mapping<Entry, P>(
        mapping: &'a Mapping<Entry, VirtAddr, P>,
    ) -> Result<Self, DmarError>
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
    pub fn host_address_width(self) -> Result<u8, DmarError> {
        read_u8(self.sdt, DMAR_HOST_ADDRESS_WIDTH_OFFSET)
    }

    #[inline]
    pub fn flags(self) -> Result<u8, DmarError> {
        read_u8(self.sdt, DMAR_FLAGS_OFFSET)
    }

    #[inline]
    pub fn structures(self) -> DmarStructures<'a> {
        DmarStructures {
            table: self,
            offset: DMAR_STRUCTURES_OFFSET,
        }
    }

    pub fn for_each_drhd<F>(self, mut f: F) -> Result<(), DmarError>
    where
        F: FnMut(u8, DmarDrhd) -> Result<(), DmarError>,
    {
        let host_width = self.host_address_width()?;
        self.for_each_structure(|structure| {
            if let DmarStructure::Drhd(unit) = structure {
                f(host_width, unit)?;
            }
            Ok(())
        })
    }

    pub fn for_each_rmrr<F>(self, mut f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarRmrr) -> Result<(), DmarError>,
    {
        self.for_each_structure(|structure| {
            if let DmarStructure::Rmrr(region) = structure {
                f(region)?;
            }
            Ok(())
        })
    }

    pub fn for_each_atsr<F>(self, mut f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarAtsr) -> Result<(), DmarError>,
    {
        self.for_each_structure(|structure| {
            if let DmarStructure::Atsr(unit) = structure {
                f(unit)?;
            }
            Ok(())
        })
    }

    pub fn for_each_rhsa<F>(self, mut f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarRhsa) -> Result<(), DmarError>,
    {
        self.for_each_structure(|structure| {
            if let DmarStructure::Rhsa(affinity) = structure {
                f(affinity)?;
            }
            Ok(())
        })
    }

    pub fn for_each_andd<F>(self, mut f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarAndd<'a>) -> Result<(), DmarError>,
    {
        self.for_each_structure(|structure| {
            if let DmarStructure::Andd(device) = structure {
                f(device)?;
            }
            Ok(())
        })
    }

    pub fn for_each_satc<F>(self, mut f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarSatc) -> Result<(), DmarError>,
    {
        self.for_each_structure(|structure| {
            if let DmarStructure::Satc(unit) = structure {
                f(unit)?;
            }
            Ok(())
        })
    }

    pub fn for_each_sidp<F>(self, mut f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarSidp) -> Result<(), DmarError>,
    {
        self.for_each_structure(|structure| {
            if let DmarStructure::Sidp(unit) = structure {
                f(unit)?;
            }
            Ok(())
        })
    }

    pub fn has_sidp(self) -> Result<bool, DmarError> {
        let mut found = false;
        self.for_each_sidp(|_| {
            found = true;
            Ok(())
        })?;
        Ok(found)
    }

    pub fn for_each_drhd_device_scope<F>(self, unit: DmarDrhd, f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarDeviceScope<'a>) -> Result<(), DmarError>,
    {
        self.walk_device_scopes(unit.structure_offset, DRHD_MIN_LENGTH, unit.length, f)
    }

    pub fn for_each_rmrr_device_scope<F>(self, region: DmarRmrr, f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarDeviceScope<'a>) -> Result<(), DmarError>,
    {
        self.walk_device_scopes(region.structure_offset, RMRR_MIN_LENGTH, region.length, f)
    }

    pub fn for_each_atsr_device_scope<F>(self, unit: DmarAtsr, f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarDeviceScope<'a>) -> Result<(), DmarError>,
    {
        self.walk_device_scopes(unit.structure_offset, ATSR_MIN_LENGTH, unit.length, f)
    }

    pub fn for_each_satc_device_scope<F>(self, unit: DmarSatc, f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarDeviceScope<'a>) -> Result<(), DmarError>,
    {
        self.walk_device_scopes(unit.structure_offset, SATC_MIN_LENGTH, unit.length, f)
    }

    pub fn for_each_sidp_device_scope<F>(self, unit: DmarSidp, f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarDeviceScope<'a>) -> Result<(), DmarError>,
    {
        self.walk_device_scopes(unit.structure_offset, SIDP_MIN_LENGTH, unit.length, f)
    }

    pub fn drhd_bdf_ranges(
        self,
        registers: MmioAddrRange,
    ) -> Result<Option<DmarBdfRangeSet>, DmarError> {
        let mut found_unit = false;
        let mut ranges = DmarBdfRangeSet::empty();
        let mut unresolved = false;

        self.for_each_structure(|structure| {
            let DmarStructure::Drhd(unit) = structure else {
                return Ok(());
            };
            if unit.registers != registers {
                return Ok(());
            }

            found_unit = true;
            if unit.include_all {
                return Ok(());
            }

            self.walk_device_scopes(
                unit.structure_offset,
                DRHD_MIN_LENGTH,
                unit.length,
                |scope| {
                    if let Some(requester) = scope.requester {
                        ranges.insert::<DmarError>(requester)?;
                    } else {
                        unresolved = true;
                    }
                    Ok(())
                },
            )
        })?;

        if !found_unit || unresolved || ranges.is_empty() {
            return Ok(None);
        }
        Ok(Some(ranges))
    }

    pub fn rmrr_bdf_ranges(
        self,
        segment: u16,
        memory: PhysAddrRange,
    ) -> Result<Option<DmarBdfRangeSet>, DmarError> {
        let mut found_region = false;
        let mut ranges = DmarBdfRangeSet::empty();
        let mut unresolved = false;

        self.for_each_structure(|structure| {
            let DmarStructure::Rmrr(region) = structure else {
                return Ok(());
            };
            if region.segment != segment || region.memory != memory {
                return Ok(());
            }

            found_region = true;
            self.walk_device_scopes(
                region.structure_offset,
                RMRR_MIN_LENGTH,
                region.length,
                |scope| {
                    if let Some(requester) = scope.requester {
                        ranges.insert::<DmarError>(requester)?;
                    } else {
                        unresolved = true;
                    }
                    Ok(())
                },
            )
        })?;

        if !found_region || unresolved || ranges.is_empty() {
            return Ok(None);
        }
        Ok(Some(ranges))
    }

    pub fn drhd_requester_match(
        self,
        registers: MmioAddrRange,
        requester: PciDevice,
    ) -> Result<Option<DmarRequesterMatch>, DmarError> {
        let mut match_result = None;

        self.for_each_structure(|structure| {
            let DmarStructure::Drhd(unit) = structure else {
                return Ok(());
            };
            if unit.registers != registers {
                return Ok(());
            }

            if unit.segment != requester.segment() {
                match_result = Some(DmarRequesterMatch::NotCovered);
                return Ok(());
            }

            if unit.include_all {
                match_result = Some(DmarRequesterMatch::Covered);
                return Ok(());
            }

            let mut exact_match = false;
            let mut unresolved = false;
            self.walk_device_scopes(
                unit.structure_offset,
                DRHD_MIN_LENGTH,
                unit.length,
                |scope| {
                    if let Some(scope_requester) = scope.requester {
                        if scope_requester.contains(requester.bdf()) {
                            exact_match = true;
                        }
                    } else {
                        unresolved = true;
                    }
                    Ok(())
                },
            )?;

            match_result = Some(if exact_match {
                DmarRequesterMatch::Covered
            } else if unresolved {
                DmarRequesterMatch::Unresolved
            } else {
                DmarRequesterMatch::NotCovered
            });

            Ok(())
        })?;

        Ok(match_result)
    }

    pub fn satc_device_ats_required(self, requester: PciDevice) -> Result<bool, DmarError> {
        if self.has_sidp()? {
            return Ok(false);
        }

        let mut required = false;
        self.for_each_structure(|structure| {
            let DmarStructure::Satc(unit) = structure else {
                return Ok(());
            };
            if unit.segment != requester.segment() || !unit.atc_required || !unit.has_device_scopes
            {
                return Ok(());
            }

            self.walk_device_scopes(
                unit.structure_offset,
                SATC_MIN_LENGTH,
                unit.length,
                |scope| {
                    if scope
                        .requester
                        .is_some_and(|scope_requester| scope_requester.contains(requester.bdf()))
                    {
                        required = true;
                    }
                    Ok(())
                },
            )
        })?;
        Ok(required)
    }

    pub fn rhsa_proximity_domain_for_registers(
        self,
        registers: MmioAddrRange,
    ) -> Result<Option<u32>, DmarError> {
        let mut proximity_domain = None;
        self.for_each_rhsa(|rhsa| {
            if rhsa.registers == registers {
                proximity_domain = Some(rhsa.proximity_domain);
            }
            Ok(())
        })?;
        Ok(proximity_domain)
    }

    pub fn andd_name_for_device_number(
        self,
        acpi_device_number: u8,
    ) -> Result<Option<&'a [u8]>, DmarError> {
        let mut object_name = None;
        self.for_each_andd(|andd| {
            if andd.acpi_device_number == acpi_device_number {
                object_name = Some(andd.object_name);
            }
            Ok(())
        })?;
        Ok(object_name)
    }

    fn for_each_structure<F>(self, mut f: F) -> Result<(), DmarError>
    where
        F: FnMut(DmarStructure<'a>) -> Result<(), DmarError>,
    {
        for structure in self.structures() {
            f(structure?)?;
        }
        Ok(())
    }

    fn parse_structure(
        self,
        offset: usize,
        length: usize,
        kind: u16,
    ) -> Result<DmarStructure<'a>, DmarError> {
        match kind {
            DMAR_DRHD => Ok(DmarStructure::Drhd(self.parse_drhd(offset, length)?)),
            DMAR_RMRR => Ok(DmarStructure::Rmrr(self.parse_rmrr(offset, length)?)),
            DMAR_ATSR => Ok(DmarStructure::Atsr(self.parse_atsr(offset, length)?)),
            DMAR_RHSA => Ok(DmarStructure::Rhsa(self.parse_rhsa(offset, length)?)),
            DMAR_ANDD => Ok(DmarStructure::Andd(self.parse_andd(offset, length)?)),
            DMAR_SATC => Ok(DmarStructure::Satc(self.parse_satc(offset, length)?)),
            DMAR_SIDP => Ok(DmarStructure::Sidp(self.parse_sidp(offset, length)?)),
            other => Ok(DmarStructure::Unknown(DmarUnknown {
                kind: other,
                offset,
                length,
            })),
        }
    }

    fn parse_drhd(self, offset: usize, length: usize) -> Result<DmarDrhd, DmarError> {
        if length < DRHD_MIN_LENGTH {
            return Err(DmarError::Malformed(
                "DMAR DRHD structure shorter than minimum",
            ));
        }
        let flags = read_u8(self.sdt, offset + 4)?;
        Ok(DmarDrhd {
            flags,
            segment: read_u16(self.sdt, offset + 6)?,
            registers: mmio_register_window(
                read_u64(self.sdt, offset + 8)?,
                VTD_REGISTER_WINDOW_SIZE,
                "DMAR DRHD register base cannot fit in usize",
                "DMAR DRHD register window overflows",
            )?,
            include_all: (flags & 0x01) != 0,
            has_device_scopes: length > DRHD_MIN_LENGTH,
            structure_offset: offset,
            length,
        })
    }

    fn parse_andd(self, offset: usize, length: usize) -> Result<DmarAndd<'a>, DmarError> {
        if length < ANDD_MIN_LENGTH {
            return Err(DmarError::Malformed(
                "DMAR ANDD structure shorter than minimum",
            ));
        }
        Ok(DmarAndd {
            acpi_device_number: read_u8(self.sdt, offset + 7)?,
            object_name: &self.sdt[offset + ANDD_MIN_LENGTH..offset + length],
        })
    }

    fn parse_rmrr(self, offset: usize, length: usize) -> Result<DmarRmrr, DmarError> {
        if length < RMRR_MIN_LENGTH {
            return Err(DmarError::Malformed(
                "DMAR RMRR structure shorter than minimum",
            ));
        }
        let base = read_u64(self.sdt, offset + 8)?;
        let limit = read_u64(self.sdt, offset + 16)?;
        if limit < base {
            return Err(DmarError::Malformed("DMAR RMRR limit smaller than base"));
        }
        Ok(DmarRmrr {
            segment: read_u16(self.sdt, offset + 6)?,
            memory: inclusive_phys_range(
                base,
                limit,
                "DMAR RMRR address cannot fit in usize",
                "DMAR RMRR inclusive limit overflows",
            )?,
            has_device_scopes: length > RMRR_MIN_LENGTH,
            structure_offset: offset,
            length,
        })
    }

    fn parse_atsr(self, offset: usize, length: usize) -> Result<DmarAtsr, DmarError> {
        if length < ATSR_MIN_LENGTH {
            return Err(DmarError::Malformed(
                "DMAR ATSR structure shorter than minimum",
            ));
        }
        let flags = read_u8(self.sdt, offset + 4)?;
        Ok(DmarAtsr {
            flags,
            segment: read_u16(self.sdt, offset + 6)?,
            include_all: (flags & 0x01) != 0,
            has_device_scopes: length > ATSR_MIN_LENGTH,
            structure_offset: offset,
            length,
        })
    }

    fn parse_rhsa(self, offset: usize, length: usize) -> Result<DmarRhsa, DmarError> {
        if length < RHSA_MIN_LENGTH {
            return Err(DmarError::Malformed(
                "DMAR RHSA structure shorter than minimum",
            ));
        }
        Ok(DmarRhsa {
            registers: mmio_register_window(
                read_u64(self.sdt, offset + 8)?,
                VTD_REGISTER_WINDOW_SIZE,
                "DMAR RHSA register base cannot fit in usize",
                "DMAR RHSA register window overflows",
            )?,
            proximity_domain: read_u32(self.sdt, offset + 16)?,
        })
    }

    fn parse_satc(self, offset: usize, length: usize) -> Result<DmarSatc, DmarError> {
        if length < SATC_MIN_LENGTH {
            return Err(DmarError::Malformed(
                "DMAR SATC structure shorter than minimum",
            ));
        }
        let flags = read_u8(self.sdt, offset + 4)?;
        Ok(DmarSatc {
            flags,
            segment: read_u16(self.sdt, offset + 6)?,
            atc_required: (flags & 0x01) != 0,
            has_device_scopes: length > SATC_MIN_LENGTH,
            structure_offset: offset,
            length,
        })
    }

    fn parse_sidp(self, offset: usize, length: usize) -> Result<DmarSidp, DmarError> {
        if length < SIDP_MIN_LENGTH {
            return Err(DmarError::Malformed(
                "DMAR SIDP structure shorter than minimum",
            ));
        }
        Ok(DmarSidp {
            segment: read_u16(self.sdt, offset + 6)?,
            has_device_scopes: length > SIDP_MIN_LENGTH,
            structure_offset: offset,
            length,
        })
    }

    fn walk_device_scopes<F>(
        self,
        structure_offset: usize,
        scopes_offset: usize,
        structure_length: usize,
        mut f: F,
    ) -> Result<(), DmarError>
    where
        F: FnMut(DmarDeviceScope<'a>) -> Result<(), DmarError>,
    {
        let mut offset = scopes_offset;
        while offset < structure_length {
            if offset + DEVICE_SCOPE_HEADER_LENGTH > structure_length {
                return Err(DmarError::Malformed(
                    "DMAR device scope truncated before fixed header",
                ));
            }

            let scope_offset = structure_offset + offset;
            let scope_length = usize::from(read_u8(self.sdt, scope_offset + 1)?);
            if scope_length < DEVICE_SCOPE_HEADER_LENGTH {
                return Err(DmarError::Malformed(
                    "DMAR device scope shorter than minimum",
                ));
            }
            if offset + scope_length > structure_length {
                return Err(DmarError::Malformed(
                    "DMAR device scope extends past structure",
                ));
            }

            let path_bytes = scope_length - DEVICE_SCOPE_HEADER_LENGTH;
            if (path_bytes & 1) != 0 {
                return Err(DmarError::Malformed(
                    "DMAR device scope path has odd byte length",
                ));
            }

            let start_bus = read_u8(self.sdt, scope_offset + 5)?;
            let path_start = scope_offset + DEVICE_SCOPE_HEADER_LENGTH;
            let path_end = scope_offset + scope_length;
            let path = DmarDeviceScopePath {
                bytes: &self.sdt[path_start..path_end],
            };
            let requester = path.single_requester(start_bus).ok().map(BdfRange::single);

            f(DmarDeviceScope {
                kind: DmarDeviceScopeKind::from_raw(read_u8(self.sdt, scope_offset)?),
                flags: read_u8(self.sdt, scope_offset + 2)?,
                enumeration_id: read_u8(self.sdt, scope_offset + 4)?,
                start_bus,
                path,
                requester,
            })?;

            offset += scope_length;
        }
        Ok(())
    }
}

pub struct DmarStructures<'a> {
    table: DmarTable<'a>,
    offset: usize,
}

impl<'a> Iterator for DmarStructures<'a> {
    type Item = Result<DmarStructure<'a>, DmarError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.table.sdt.len() {
            return None;
        }
        if self.offset + 4 > self.table.sdt.len() {
            self.offset = self.table.sdt.len();
            return Some(Err(DmarError::Malformed(
                "DMAR structure truncated before header",
            )));
        }

        let offset = self.offset;
        let kind = match read_u16(self.table.sdt, offset) {
            Ok(kind) => kind,
            Err(error) => return Some(Err(error.into())),
        };
        let length = match read_u16(self.table.sdt, offset + 2) {
            Ok(length) => usize::from(length),
            Err(error) => return Some(Err(error.into())),
        };
        if length < 4 {
            self.offset = self.table.sdt.len();
            return Some(Err(DmarError::Malformed(
                "DMAR structure length smaller than header",
            )));
        }
        if offset + length > self.table.sdt.len() {
            self.offset = self.table.sdt.len();
            return Some(Err(DmarError::Malformed(
                "DMAR structure extends past table length",
            )));
        }

        self.offset += length;
        Some(self.table.parse_structure(offset, length, kind))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmarStructure<'a> {
    Drhd(DmarDrhd),
    Rmrr(DmarRmrr),
    Atsr(DmarAtsr),
    Rhsa(DmarRhsa),
    Andd(DmarAndd<'a>),
    Satc(DmarSatc),
    Sidp(DmarSidp),
    Unknown(DmarUnknown),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarUnknown {
    pub kind: u16,
    pub offset: usize,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarDrhd {
    pub flags: u8,
    pub segment: u16,
    pub registers: MmioAddrRange,
    pub include_all: bool,
    pub has_device_scopes: bool,
    structure_offset: usize,
    length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarRmrr {
    pub segment: u16,
    pub memory: PhysAddrRange,
    pub has_device_scopes: bool,
    structure_offset: usize,
    length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarAtsr {
    pub flags: u8,
    pub segment: u16,
    pub include_all: bool,
    pub has_device_scopes: bool,
    structure_offset: usize,
    length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarRhsa {
    pub registers: MmioAddrRange,
    pub proximity_domain: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarAndd<'a> {
    pub acpi_device_number: u8,
    pub object_name: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarSatc {
    pub flags: u8,
    pub segment: u16,
    pub atc_required: bool,
    pub has_device_scopes: bool,
    structure_offset: usize,
    length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarSidp {
    pub segment: u16,
    pub has_device_scopes: bool,
    structure_offset: usize,
    length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarDeviceScope<'a> {
    pub kind: DmarDeviceScopeKind,
    pub flags: u8,
    pub enumeration_id: u8,
    pub start_bus: u8,
    pub path: DmarDeviceScopePath<'a>,
    pub requester: Option<BdfRange>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarDeviceScopePath<'a> {
    bytes: &'a [u8],
}

impl<'a> DmarDeviceScopePath<'a> {
    #[inline]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    #[inline]
    pub const fn depth(self) -> usize {
        self.bytes.len() / 2
    }

    #[inline]
    pub fn entry(self, index: usize) -> Option<DmarDeviceScopePathEntry> {
        let offset = index.checked_mul(2)?;
        let device = *self.bytes.get(offset)?;
        let function = *self.bytes.get(offset + 1)?;
        Some(DmarDeviceScopePathEntry { device, function })
    }

    #[inline]
    pub fn last_entry(self) -> Option<DmarDeviceScopePathEntry> {
        self.depth()
            .checked_sub(1)
            .and_then(|index| self.entry(index))
    }

    #[inline]
    pub fn single_requester(self, start_bus: u8) -> Result<Bdf, DmarError> {
        if self.depth() != 1 {
            return Err(DmarError::Malformed(
                "DMAR scope path is not a single requester",
            ));
        }
        let entry = self
            .entry(0)
            .ok_or(DmarError::Malformed("DMAR scope path missing requester"))?;
        Bdf::new(start_bus, entry.device, entry.function)
            .map_err(|_| DmarError::Malformed("DMAR scope requester BDF is invalid"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarDeviceScopePathEntry {
    pub device: u8,
    pub function: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmarDeviceScopeKind {
    Endpoint,
    Bridge,
    IoApic,
    Hpet,
    NamespaceDevice,
    Unknown(u8),
}

impl DmarDeviceScopeKind {
    #[inline]
    const fn from_raw(raw: u8) -> Self {
        match raw {
            DEVICE_SCOPE_ENDPOINT => Self::Endpoint,
            DEVICE_SCOPE_BRIDGE => Self::Bridge,
            DEVICE_SCOPE_IOAPIC => Self::IoApic,
            DEVICE_SCOPE_HPET => Self::Hpet,
            DEVICE_SCOPE_NAMESPACE_DEVICE => Self::NamespaceDevice,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmarRequesterMatch {
    Covered,
    NotCovered,
    Unresolved,
}

pub use crate::firm::pcie::BdfRange as DmarBdfRange;

#[cfg(test)]
mod tests {
    use super::{DmarBdfRange, DmarRequesterMatch, DmarStructure, DmarTable};
    use crate::firm::pcie::{Bdf, PciDevice};
    use crate::{MmioAddr, MmioAddrRange, MmioRange};
    use acpi::sdt::Signature;
    use kore_memory::{Mapping, PageSize, PageTableEntry, PageTableEntryKind};
    use memory_addr::{PhysAddr, VirtAddr, VirtAddrRange};

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
            super::VTD_REGISTER_WINDOW_SIZE,
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
    fn parses_drhd_and_exact_bdf_ranges() {
        let mut dmar = [0u8; 88];
        write_sdt_header(&mut dmar, Signature::DMAR, 88);
        dmar[36] = 47;

        dmar[48..50].copy_from_slice(&0u16.to_le_bytes());
        dmar[50..52].copy_from_slice(&40u16.to_le_bytes());
        dmar[54..56].copy_from_slice(&3u16.to_le_bytes());
        dmar[56..64].copy_from_slice(&(0xfed9_0000u64).to_le_bytes());

        for (offset, function) in [(64, 0u8), (72, 1u8), (80, 2u8)] {
            dmar[offset] = 1;
            dmar[offset + 1] = 8;
            dmar[offset + 5] = 0x2a;
            dmar[offset + 6] = 5;
            dmar[offset + 7] = function;
        }

        finish_sdt_checksum(&mut dmar);

        let mapping = table_mapping(&dmar);
        let table = unsafe { DmarTable::from_mapping(&mapping) }.unwrap();
        assert_eq!(table.host_address_width().unwrap(), 47);

        let units: heapless::Vec<_, 2> = table.structures().collect::<Result<_, _>>().unwrap();
        assert!(matches!(units.as_slice(), [DmarStructure::Drhd(unit)] if unit.segment == 3));

        let windows = table
            .drhd_bdf_ranges(registers(0xfed9_0000))
            .unwrap()
            .unwrap();
        assert_eq!(
            windows.as_slice(),
            &[DmarBdfRange::inclusive(
                Bdf::new(0x2a, 5, 0).unwrap(),
                Bdf::new(0x2a, 5, 2).unwrap()
            )
            .unwrap()]
        );
        assert_eq!(
            table
                .drhd_requester_match(
                    registers(0xfed9_0000),
                    PciDevice::new(3, 0x2a, 5, 1).unwrap()
                )
                .unwrap(),
            Some(DmarRequesterMatch::Covered)
        );
    }

    #[test]
    fn parses_reserved_memory_affinity_and_satc() {
        let mut dmar = [0u8; 100];
        write_sdt_header(&mut dmar, Signature::DMAR, 100);
        dmar[36] = 47;

        dmar[48..50].copy_from_slice(&1u16.to_le_bytes());
        dmar[50..52].copy_from_slice(&24u16.to_le_bytes());
        dmar[54..56].copy_from_slice(&2u16.to_le_bytes());
        dmar[56..64].copy_from_slice(&(0x1000_0000u64).to_le_bytes());
        dmar[64..72].copy_from_slice(&(0x1000_ffffu64).to_le_bytes());

        dmar[72..74].copy_from_slice(&3u16.to_le_bytes());
        dmar[74..76].copy_from_slice(&20u16.to_le_bytes());
        dmar[80..88].copy_from_slice(&(0xfed9_1000u64).to_le_bytes());
        dmar[88..92].copy_from_slice(&9u32.to_le_bytes());

        dmar[92..94].copy_from_slice(&5u16.to_le_bytes());
        dmar[94..96].copy_from_slice(&8u16.to_le_bytes());
        dmar[96] = 1;
        dmar[98..100].copy_from_slice(&2u16.to_le_bytes());

        finish_sdt_checksum(&mut dmar);

        let mapping = table_mapping(&dmar);
        let table = unsafe { DmarTable::from_mapping(&mapping) }.unwrap();
        let mut rmrr = None;
        table
            .for_each_rmrr(|region| {
                rmrr = Some(region);
                Ok(())
            })
            .unwrap();
        assert_eq!(rmrr.unwrap().segment, 2);
        assert_eq!(
            table
                .rhsa_proximity_domain_for_registers(registers(0xfed9_1000))
                .unwrap(),
            Some(9)
        );

        let mut satc = None;
        table
            .for_each_satc(|unit| {
                satc = Some(unit);
                Ok(())
            })
            .unwrap();
        assert!(satc.unwrap().atc_required);
    }

    #[test]
    fn parses_andd_and_preserves_multi_hop_scope_path() {
        let mut dmar = [0u8; 86];
        write_sdt_header(&mut dmar, Signature::DMAR, 86);
        dmar[36] = 47;

        dmar[48..50].copy_from_slice(&0u16.to_le_bytes());
        dmar[50..52].copy_from_slice(&26u16.to_le_bytes());
        dmar[56..64].copy_from_slice(&(0xfed9_0000u64).to_le_bytes());

        dmar[64] = 5;
        dmar[65] = 10;
        dmar[68] = 7;
        dmar[69] = 0x2a;
        dmar[70] = 0x1c;
        dmar[71] = 0;
        dmar[72] = 5;
        dmar[73] = 1;

        dmar[74..76].copy_from_slice(&4u16.to_le_bytes());
        dmar[76..78].copy_from_slice(&12u16.to_le_bytes());
        dmar[81] = 7;
        dmar[82..86].copy_from_slice(b"DEV0");

        finish_sdt_checksum(&mut dmar);

        let mapping = table_mapping(&dmar);
        let table = unsafe { DmarTable::from_mapping(&mapping) }.unwrap();
        let structures: heapless::Vec<_, 2> = table.structures().collect::<Result<_, _>>().unwrap();
        assert!(
            matches!(structures.as_slice(), [DmarStructure::Drhd(_), DmarStructure::Andd(andd)]
                if andd.acpi_device_number == 7 && andd.object_name == b"DEV0")
        );
        assert_eq!(
            table.andd_name_for_device_number(7).unwrap(),
            Some(&b"DEV0"[..])
        );

        let DmarStructure::Drhd(unit) = structures[0] else {
            panic!("expected DRHD");
        };
        let mut scope = None;
        table
            .for_each_drhd_device_scope(unit, |s| {
                scope = Some(s);
                Ok(())
            })
            .unwrap();
        let scope = scope.unwrap();
        assert_eq!(scope.kind, super::DmarDeviceScopeKind::NamespaceDevice);
        assert_eq!(scope.flags, 0);
        assert_eq!(scope.enumeration_id, 7);
        assert_eq!(scope.start_bus, 0x2a);
        assert_eq!(scope.path.depth(), 2);
        assert_eq!(scope.path.entry(0).unwrap().device, 0x1c);
        assert_eq!(scope.path.entry(1).unwrap().function, 1);
        assert_eq!(scope.requester, None);
    }

    #[test]
    fn parses_sidp_and_ignores_satc_policy_when_present() {
        let mut dmar = [0u8; 80];
        write_sdt_header(&mut dmar, Signature::DMAR, 80);
        dmar[36] = 47;

        dmar[48..50].copy_from_slice(&5u16.to_le_bytes());
        dmar[50..52].copy_from_slice(&16u16.to_le_bytes());
        dmar[52] = 1;
        dmar[54..56].copy_from_slice(&2u16.to_le_bytes());
        dmar[56] = 1;
        dmar[57] = 8;
        dmar[61] = 0x2a;
        dmar[62] = 5;
        dmar[63] = 1;

        dmar[64..66].copy_from_slice(&6u16.to_le_bytes());
        dmar[66..68].copy_from_slice(&16u16.to_le_bytes());
        dmar[70..72].copy_from_slice(&2u16.to_le_bytes());
        dmar[72] = 1;
        dmar[73] = 8;
        dmar[74] = 0x81;
        dmar[76] = 3;
        dmar[77] = 0x2a;
        dmar[78] = 5;
        dmar[79] = 1;

        finish_sdt_checksum(&mut dmar);

        let mapping = table_mapping(&dmar);
        let table = unsafe { DmarTable::from_mapping(&mapping) }.unwrap();
        let structures: heapless::Vec<_, 2> = table.structures().collect::<Result<_, _>>().unwrap();
        assert!(
            matches!(structures.as_slice(), [DmarStructure::Satc(satc), DmarStructure::Sidp(sidp)]
                if satc.segment == 2 && sidp.segment == 2 && sidp.has_device_scopes)
        );
        assert!(table.has_sidp().unwrap());
        assert!(
            !table
                .satc_device_ats_required(PciDevice::new(2, 0x2a, 5, 1).unwrap())
                .unwrap()
        );

        let DmarStructure::Sidp(sidp) = structures[1] else {
            panic!("expected SIDP");
        };
        let mut scope = None;
        table
            .for_each_sidp_device_scope(sidp, |s| {
                scope = Some(s);
                Ok(())
            })
            .unwrap();
        let scope = scope.unwrap();
        assert_eq!(scope.kind, super::DmarDeviceScopeKind::Endpoint);
        assert_eq!(scope.flags, 0x81);
        assert_eq!(scope.enumeration_id, 3);
        assert_eq!(
            scope.requester,
            Some(DmarBdfRange::single(Bdf::new(0x2a, 5, 1).unwrap()))
        );
    }
}
