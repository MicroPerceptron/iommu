//! ARM IORT firmware table parsing.

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

const IORT_NODE_COUNT_OFFSET: usize = 36;
const IORT_NODE_OFFSET_OFFSET: usize = 40;
const IORT_TABLE_MIN_LENGTH: usize = 48;

const IORT_NODE_HEADER_LENGTH: usize = 16;
const IORT_ID_MAPPING_LENGTH: usize = 20;

const IORT_NODE_ITS_GROUP: u8 = 0x00;
const IORT_NODE_NAMED_COMPONENT: u8 = 0x01;
const IORT_NODE_ROOT_COMPLEX: u8 = 0x02;
const IORT_NODE_SMMU: u8 = 0x03;
const IORT_NODE_SMMU_V3: u8 = 0x04;
const IORT_NODE_PMCG: u8 = 0x05;
const IORT_NODE_RMR: u8 = 0x06;

const ITS_GROUP_MIN_LENGTH: usize = IORT_NODE_HEADER_LENGTH + 4;
const NAMED_COMPONENT_MIN_LENGTH: usize = IORT_NODE_HEADER_LENGTH + 13;
const ROOT_COMPLEX_MIN_LENGTH: usize = IORT_NODE_HEADER_LENGTH + 19;
const SMMU_MIN_LENGTH: usize = IORT_NODE_HEADER_LENGTH + 44;
const SMMU_V3_MIN_LENGTH: usize = IORT_NODE_HEADER_LENGTH + 52;
const PMCG_MIN_LENGTH: usize = IORT_NODE_HEADER_LENGTH + 24;
const RMR_MIN_LENGTH: usize = IORT_NODE_HEADER_LENGTH + 12;
const RMR_DESCRIPTOR_LENGTH: usize = 20;

pub const IORT_REQUESTER_WINDOW_CAPACITY: usize = 16;

pub type IortBdfRangeSet = BdfRangeSet<IORT_REQUESTER_WINDOW_CAPACITY>;

#[derive(Clone, Debug)]
pub enum IortError {
    Acpi(AcpiError),
    BdfRanges(BdfRangeSetError),
    Mapping(PagingError),
    Malformed(&'static str),
}

impl From<AcpiError> for IortError {
    #[inline]
    fn from(value: AcpiError) -> Self {
        Self::Acpi(value)
    }
}

impl From<BdfRangeSetError> for IortError {
    #[inline]
    fn from(value: BdfRangeSetError) -> Self {
        Self::BdfRanges(value)
    }
}

impl From<PagingError> for IortError {
    #[inline]
    fn from(value: PagingError) -> Self {
        Self::Mapping(value)
    }
}

impl fmt::Display for IortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acpi(error) => write!(f, "{error:?}"),
            Self::BdfRanges(error) => write!(f, "{error}"),
            Self::Mapping(error) => write!(f, "{error:?}"),
            Self::Malformed(message) => f.write_str(message),
        }
    }
}

fn checked_offset(base: usize, offset: usize) -> Result<usize, IortError> {
    base.checked_add(offset)
        .ok_or(IortError::Malformed("IORT offset overflow"))
}

fn mmio_address(base: u64) -> Result<MmioAddr, IortError> {
    let base = usize::try_from(base)
        .map_err(|_| IortError::Malformed("IORT MMIO address cannot fit in usize"))?;
    Ok(MmioAddr::from(base))
}

fn mmio_range_from_start_size(start: u64, size: u64) -> Result<MmioAddrRange, IortError> {
    let start = mmio_address(start)?;
    let size = usize::try_from(size)
        .map_err(|_| IortError::Malformed("IORT MMIO range size cannot fit in usize"))?;
    if size == 0 {
        return Err(IortError::Malformed("IORT MMIO range is empty"));
    }
    <MmioAddrRange as MmioRange<usize>>::from_start_size(start, size)
        .ok_or(IortError::Malformed("IORT MMIO range overflows"))
}

fn phys_range_from_start_size(start: u64, size: u64) -> Result<PhysAddrRange, IortError> {
    let start = usize::try_from(start)
        .map_err(|_| IortError::Malformed("IORT physical address cannot fit in usize"))?;
    let size = usize::try_from(size)
        .map_err(|_| IortError::Malformed("IORT physical range size cannot fit in usize"))?;
    if size == 0 {
        return Err(IortError::Malformed("IORT physical range is empty"));
    }
    PhysAddrRange::try_from_start_size(PhysAddr::from_usize(start), size)
        .ok_or(IortError::Malformed("IORT physical range overflows"))
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct IortAcpiTable {
    pub header: SdtHeader,
}

unsafe impl AcpiTable for IortAcpiTable {
    const SIGNATURE: Signature = Signature::IORT;

    #[inline]
    fn header(&self) -> &SdtHeader {
        &self.header
    }
}

fn table_bytes<'a, T: AcpiTable>(
    bytes: &'a [u8],
    short_header: &'static str,
    short_table: &'static str,
) -> Result<&'a [u8], IortError> {
    if bytes.len() < size_of::<SdtHeader>() {
        return Err(IortError::Malformed(short_header));
    }

    let header = unsafe { &*bytes.as_ptr().cast::<SdtHeader>() };
    if header.signature != T::SIGNATURE {
        return Err(IortError::Acpi(AcpiError::SdtInvalidSignature(
            T::SIGNATURE,
        )));
    }

    let length = header.length() as usize;
    if length < size_of::<SdtHeader>() || length > bytes.len() {
        return Err(IortError::Malformed(short_table));
    }

    unsafe { header.validate(T::SIGNATURE)? };
    Ok(&bytes[..length])
}

unsafe fn from_mapping<Entry, P>(mapping: &Mapping<Entry, VirtAddr, P>) -> Result<&[u8], IortError>
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
) -> Result<[u8; N], IortError> {
    let end = offset
        .checked_add(N)
        .ok_or(IortError::Malformed("IORT read offset overflow"))?;
    let bytes = bytes
        .get(offset..end)
        .ok_or(IortError::Malformed(message))?;
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[inline]
fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, IortError> {
    bytes
        .get(offset)
        .copied()
        .ok_or(IortError::Malformed("IORT table read is out of bounds"))
}

#[inline]
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, IortError> {
    Ok(u16::from_le_bytes(read_array(
        bytes,
        offset,
        "IORT table read is out of bounds",
    )?))
}

#[inline]
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, IortError> {
    Ok(u32::from_le_bytes(read_array(
        bytes,
        offset,
        "IORT table read is out of bounds",
    )?))
}

#[inline]
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, IortError> {
    Ok(u64::from_le_bytes(read_array(
        bytes,
        offset,
        "IORT table read is out of bounds",
    )?))
}

#[derive(Clone, Copy, Debug)]
pub struct IortTable<'a> {
    sdt: &'a [u8],
}

impl<'a> IortTable<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, IortError> {
        let sdt = table_bytes::<IortAcpiTable>(
            bytes,
            "IORT table shorter than SDT header",
            "IORT table length is invalid",
        )?;
        if sdt.len() < IORT_TABLE_MIN_LENGTH {
            return Err(IortError::Malformed("IORT table shorter than fixed header"));
        }
        Ok(Self { sdt })
    }

    /// Parse an IORT table from an already-readable `kore_memory` mapping.
    ///
    /// # Safety
    ///
    /// `mapping` must remain live and readable for the returned table's
    /// lifetime, and its virtual range must cover the complete ACPI table.
    pub unsafe fn from_mapping<Entry, P>(
        mapping: &'a Mapping<Entry, VirtAddr, P>,
    ) -> Result<Self, IortError>
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
    pub fn node_count(self) -> Result<u32, IortError> {
        read_u32(self.sdt, IORT_NODE_COUNT_OFFSET)
    }

    #[inline]
    pub fn node_offset(self) -> Result<u32, IortError> {
        read_u32(self.sdt, IORT_NODE_OFFSET_OFFSET)
    }

    pub fn nodes(self) -> Result<IortNodes<'a>, IortError> {
        let offset = usize::try_from(self.node_offset()?)
            .map_err(|_| IortError::Malformed("IORT node offset cannot fit in usize"))?;
        if offset < IORT_TABLE_MIN_LENGTH || offset > self.sdt.len() {
            return Err(IortError::Malformed("IORT node array offset is invalid"));
        }
        Ok(IortNodes {
            table: self,
            offset,
            remaining: self.node_count()?,
        })
    }

    pub fn node_by_reference(self, reference: u32) -> Result<Option<IortNode<'a>>, IortError> {
        let offset = usize::try_from(reference)
            .map_err(|_| IortError::Malformed("IORT node reference cannot fit in usize"))?;
        if offset < self.node_offset()? as usize || offset >= self.sdt.len() {
            return Ok(None);
        }

        for node in self.nodes()? {
            let node = node?;
            if node.header().offset == offset {
                return Ok(Some(node));
            }
        }
        Ok(None)
    }

    pub fn id_mappings(self, node: IortNode<'a>) -> Result<IortIdMappings<'a>, IortError> {
        self.id_mappings_for_header(node.header())
    }

    pub fn id_mappings_for(self, header: IortNodeHeader) -> Result<IortIdMappings<'a>, IortError> {
        self.id_mappings_for_header(header)
    }

    pub fn its_identifiers(self, group: IortItsGroup) -> Result<IortItsIdentifiers<'a>, IortError> {
        let start = group.header.offset + ITS_GROUP_MIN_LENGTH;
        let bytes = usize::try_from(group.its_count)
            .ok()
            .and_then(|count| count.checked_mul(4))
            .ok_or(IortError::Malformed(
                "IORT ITS identifier array length overflows",
            ))?;
        let end = checked_offset(start, bytes)?;
        if end > group.header.end_offset() {
            return Err(IortError::Malformed(
                "IORT ITS identifier array extends past node",
            ));
        }
        Ok(IortItsIdentifiers {
            table: self,
            offset: start,
            remaining: group.its_count,
        })
    }

    pub fn rmr_descriptors(
        self,
        memory: IortReservedMemory,
    ) -> Result<IortRmrDescriptors<'a>, IortError> {
        let start = checked_offset(memory.header.offset, memory.descriptor_offset as usize)?;
        let bytes = usize::try_from(memory.descriptor_count)
            .ok()
            .and_then(|count| count.checked_mul(RMR_DESCRIPTOR_LENGTH))
            .ok_or(IortError::Malformed(
                "IORT RMR descriptor array length overflows",
            ))?;
        let end = checked_offset(start, bytes)?;
        if (memory.descriptor_offset as usize) < RMR_MIN_LENGTH || end > memory.header.end_offset()
        {
            return Err(IortError::Malformed(
                "IORT RMR descriptor array extends past node",
            ));
        }
        Ok(IortRmrDescriptors {
            table: self,
            offset: start,
            remaining: memory.descriptor_count,
        })
    }

    pub fn smmu_context_interrupts(
        self,
        smmu: IortSmmu,
    ) -> Result<IortSmmuInterrupts<'a>, IortError> {
        self.smmu_interrupts(
            smmu.header,
            smmu.context_interrupt_offset,
            smmu.context_interrupt_count,
        )
    }

    pub fn smmu_pmu_interrupts(self, smmu: IortSmmu) -> Result<IortSmmuInterrupts<'a>, IortError> {
        self.smmu_interrupts(
            smmu.header,
            smmu.pmu_interrupt_offset,
            smmu.pmu_interrupt_count,
        )
    }

    pub fn smmu_global_interrupt(
        self,
        smmu: IortSmmu,
    ) -> Result<Option<IortSmmuGlobalInterrupt>, IortError> {
        if smmu.global_interrupt_offset == 0 {
            return Ok(None);
        }
        let offset = checked_offset(smmu.header.offset, smmu.global_interrupt_offset as usize)?;
        if checked_offset(offset, 16)? > smmu.header.end_offset() {
            return Err(IortError::Malformed(
                "IORT SMMU global interrupt extends past node",
            ));
        }
        Ok(Some(IortSmmuGlobalInterrupt {
            nsg_irpt: read_u32(self.sdt, offset)?,
            nsg_irpt_flags: read_u32(self.sdt, offset + 4)?,
            nsg_cfg_irpt: read_u32(self.sdt, offset + 8)?,
            nsg_cfg_irpt_flags: read_u32(self.sdt, offset + 12)?,
        }))
    }

    pub fn root_complex_for_segment(
        self,
        segment: u16,
    ) -> Result<Option<IortRootComplex>, IortError> {
        let mut found = None;
        self.for_each_root_complex(|root| {
            if root.pci_segment_number == u32::from(segment) {
                found = Some(root);
            }
            Ok(())
        })?;
        Ok(found)
    }

    pub fn root_complex_bdf_ranges(
        self,
        segment: u16,
    ) -> Result<Option<IortBdfRangeSet>, IortError> {
        let Some(root) = self.root_complex_for_segment(segment)? else {
            return Ok(None);
        };

        let mut ranges = IortBdfRangeSet::empty();
        for mapping in self.id_mappings_for(root.header)? {
            if let Some(range) = mapping?.input_bdf_range()? {
                ranges.insert::<IortError>(range)?;
            }
        }
        if ranges.is_empty() {
            return Ok(None);
        }
        Ok(Some(ranges))
    }

    pub fn root_complex_requester_match(
        self,
        requester: PciDevice,
    ) -> Result<Option<IortRequesterMatch>, IortError> {
        let Some(root) = self.root_complex_for_segment(requester.segment())? else {
            return Ok(None);
        };

        let mut covered = false;
        let mut unresolved = false;
        for mapping in self.id_mappings_for(root.header)? {
            let mapping = mapping?;
            match mapping.input_bdf_range()? {
                Some(range) if range.contains(requester.bdf()) => covered = true,
                Some(_) => {}
                None => unresolved = true,
            }
        }

        Ok(Some(if covered {
            IortRequesterMatch::Covered
        } else if unresolved {
            IortRequesterMatch::Unresolved
        } else {
            IortRequesterMatch::NotCovered
        }))
    }

    pub fn map_id_to_kind(
        self,
        node: IortNode<'a>,
        input_id: u32,
        target: IortNodeKind,
    ) -> Result<Option<IortIdTranslation<'a>>, IortError> {
        let mut current = node;
        let mut id = input_id;
        let mut remaining = self.node_count()?;

        while remaining != 0 {
            if current.header().kind == target {
                return Ok(Some(IortIdTranslation { node: current, id }));
            }

            let Some(translation) = self.translate_once(current, id)? else {
                return Ok(None);
            };
            id = translation.id;
            let Some(next) = self.node_by_reference(translation.output_reference)? else {
                return Ok(None);
            };
            current = next;
            remaining -= 1;
        }

        Err(IortError::Malformed(
            "IORT ID mapping graph contains a cycle",
        ))
    }

    pub fn map_pci_requester_to_kind(
        self,
        requester: PciDevice,
        target: IortNodeKind,
    ) -> Result<Option<IortIdTranslation<'a>>, IortError> {
        let Some(root) = self.root_complex_for_segment(requester.segment())? else {
            return Ok(None);
        };
        self.map_id_to_kind(
            IortNode::RootComplex(root),
            requester.bdf().as_u32(),
            target,
        )
    }

    pub fn iommu_for_pci_requester(
        self,
        requester: PciDevice,
    ) -> Result<Option<IortIdTranslation<'a>>, IortError> {
        if let Some(translation) =
            self.map_pci_requester_to_kind(requester, IortNodeKind::SmmuV3)?
        {
            return Ok(Some(translation));
        }
        self.map_pci_requester_to_kind(requester, IortNodeKind::Smmu)
    }

    pub fn rmr_bdf_ranges(
        self,
        memory: PhysAddrRange,
    ) -> Result<Option<IortBdfRangeSet>, IortError> {
        let mut ranges = IortBdfRangeSet::empty();
        let mut found_memory = false;
        let mut unresolved = false;

        self.for_each_reserved_memory(|rmr| {
            let mut rmr_matches = false;
            for descriptor in self.rmr_descriptors(rmr)? {
                if descriptor?.memory == memory {
                    rmr_matches = true;
                    found_memory = true;
                }
            }
            if !rmr_matches {
                return Ok(());
            }

            for mapping in self.id_mappings_for(rmr.header)? {
                match mapping?.input_bdf_range()? {
                    Some(range) => ranges.insert::<IortError>(range)?,
                    None => unresolved = true,
                }
            }
            Ok(())
        })?;

        if !found_memory || unresolved || ranges.is_empty() {
            return Ok(None);
        }
        Ok(Some(ranges))
    }

    pub fn for_each_smmu_v3<F>(self, mut f: F) -> Result<(), IortError>
    where
        F: FnMut(IortSmmuV3) -> Result<(), IortError>,
    {
        self.for_each_node(|node| {
            if let IortNode::SmmuV3(smmu) = node {
                f(smmu)?;
            }
            Ok(())
        })
    }

    pub fn for_each_root_complex<F>(self, mut f: F) -> Result<(), IortError>
    where
        F: FnMut(IortRootComplex) -> Result<(), IortError>,
    {
        self.for_each_node(|node| {
            if let IortNode::RootComplex(root) = node {
                f(root)?;
            }
            Ok(())
        })
    }

    pub fn for_each_reserved_memory<F>(self, mut f: F) -> Result<(), IortError>
    where
        F: FnMut(IortReservedMemory) -> Result<(), IortError>,
    {
        self.for_each_node(|node| {
            if let IortNode::ReservedMemory(memory) = node {
                f(memory)?;
            }
            Ok(())
        })
    }

    fn for_each_node<F>(self, mut f: F) -> Result<(), IortError>
    where
        F: FnMut(IortNode<'a>) -> Result<(), IortError>,
    {
        for node in self.nodes()? {
            f(node?)?;
        }
        Ok(())
    }

    fn translate_once(
        self,
        node: IortNode<'a>,
        input_id: u32,
    ) -> Result<Option<IortSingleStepTranslation>, IortError> {
        let mut fallback = None;
        for mapping in self.id_mappings(node)? {
            let mapping = mapping?;
            let Some(output_id) = mapping.translate_for_node_kind(node.header().kind, input_id)
            else {
                continue;
            };

            let translation = IortSingleStepTranslation {
                id: output_id,
                output_reference: mapping.output_reference,
            };

            if mapping.id_count > 0
                && input_id == mapping.input_base.saturating_add(mapping.id_count)
            {
                fallback = Some(translation);
                continue;
            }

            return Ok(Some(translation));
        }
        Ok(fallback)
    }

    fn parse_node(self, offset: usize) -> Result<IortNode<'a>, IortError> {
        let header = self.parse_node_header(offset)?;
        match header.kind {
            IortNodeKind::ItsGroup => Ok(IortNode::ItsGroup(self.parse_its_group(header)?)),
            IortNodeKind::NamedComponent => Ok(IortNode::NamedComponent(
                self.parse_named_component(header)?,
            )),
            IortNodeKind::RootComplex => {
                Ok(IortNode::RootComplex(self.parse_root_complex(header)?))
            }
            IortNodeKind::Smmu => Ok(IortNode::Smmu(self.parse_smmu(header)?)),
            IortNodeKind::SmmuV3 => Ok(IortNode::SmmuV3(self.parse_smmu_v3(header)?)),
            IortNodeKind::Pmcg => Ok(IortNode::Pmcg(self.parse_pmcg(header)?)),
            IortNodeKind::ReservedMemory => Ok(IortNode::ReservedMemory(
                self.parse_reserved_memory(header)?,
            )),
            IortNodeKind::Unknown(kind) => Ok(IortNode::Unknown(IortUnknownNode { kind, header })),
        }
    }

    fn parse_node_header(self, offset: usize) -> Result<IortNodeHeader, IortError> {
        if checked_offset(offset, IORT_NODE_HEADER_LENGTH)? > self.sdt.len() {
            return Err(IortError::Malformed("IORT node truncated before header"));
        }
        let length = usize::from(read_u16(self.sdt, offset + 1)?);
        if length < IORT_NODE_HEADER_LENGTH {
            return Err(IortError::Malformed("IORT node length smaller than header"));
        }
        if checked_offset(offset, length)? > self.sdt.len() {
            return Err(IortError::Malformed("IORT node extends past table length"));
        }

        Ok(IortNodeHeader {
            kind: IortNodeKind::from_raw(read_u8(self.sdt, offset)?),
            revision: read_u8(self.sdt, offset + 3)?,
            identifier: read_u32(self.sdt, offset + 4)?,
            mapping_count: read_u32(self.sdt, offset + 8)?,
            mapping_offset: read_u32(self.sdt, offset + 12)?,
            offset,
            length,
        })
    }

    fn parse_its_group(self, header: IortNodeHeader) -> Result<IortItsGroup, IortError> {
        if header.length < ITS_GROUP_MIN_LENGTH {
            return Err(IortError::Malformed(
                "IORT ITS group node shorter than minimum",
            ));
        }
        Ok(IortItsGroup {
            its_count: read_u32(self.sdt, header.offset + 16)?,
            header,
        })
    }

    fn parse_named_component(
        self,
        header: IortNodeHeader,
    ) -> Result<IortNamedComponent<'a>, IortError> {
        if header.length < NAMED_COMPONENT_MIN_LENGTH {
            return Err(IortError::Malformed(
                "IORT named component node shorter than minimum",
            ));
        }
        let name_start = header.offset + NAMED_COMPONENT_MIN_LENGTH;
        let name_end = if header.mapping_count == 0 {
            header.end_offset()
        } else {
            checked_offset(header.offset, header.mapping_offset as usize)?
        };
        if name_end < name_start || name_end > header.end_offset() {
            return Err(IortError::Malformed(
                "IORT named component device name bounds are invalid",
            ));
        }

        Ok(IortNamedComponent {
            node_flags: read_u32(self.sdt, header.offset + 16)?,
            memory_properties: self.read_memory_access(header.offset + 20)?,
            memory_address_limit: read_u8(self.sdt, header.offset + 28)?,
            device_name: &self.sdt[name_start..name_end],
            header,
        })
    }

    fn parse_root_complex(self, header: IortNodeHeader) -> Result<IortRootComplex, IortError> {
        if header.length < ROOT_COMPLEX_MIN_LENGTH {
            return Err(IortError::Malformed(
                "IORT root complex node shorter than minimum",
            ));
        }
        Ok(IortRootComplex {
            memory_properties: self.read_memory_access(header.offset + 16)?,
            ats_attribute: read_u32(self.sdt, header.offset + 24)?,
            pci_segment_number: read_u32(self.sdt, header.offset + 28)?,
            memory_address_limit: read_u8(self.sdt, header.offset + 32)?,
            pasid_capabilities: read_u16(self.sdt, header.offset + 33)?,
            header,
        })
    }

    fn parse_smmu(self, header: IortNodeHeader) -> Result<IortSmmu, IortError> {
        if header.length < SMMU_MIN_LENGTH {
            return Err(IortError::Malformed("IORT SMMU node shorter than minimum"));
        }
        Ok(IortSmmu {
            registers: mmio_range_from_start_size(
                read_u64(self.sdt, header.offset + 16)?,
                read_u64(self.sdt, header.offset + 24)?,
            )?,
            model: read_u32(self.sdt, header.offset + 32)?,
            flags: read_u32(self.sdt, header.offset + 36)?,
            global_interrupt_offset: read_u32(self.sdt, header.offset + 40)?,
            context_interrupt_count: read_u32(self.sdt, header.offset + 44)?,
            context_interrupt_offset: read_u32(self.sdt, header.offset + 48)?,
            pmu_interrupt_count: read_u32(self.sdt, header.offset + 52)?,
            pmu_interrupt_offset: read_u32(self.sdt, header.offset + 56)?,
            header,
        })
    }

    fn parse_smmu_v3(self, header: IortNodeHeader) -> Result<IortSmmuV3, IortError> {
        if header.length < SMMU_V3_MIN_LENGTH {
            return Err(IortError::Malformed(
                "IORT SMMUv3 node shorter than minimum",
            ));
        }
        let vatos_address = read_u64(self.sdt, header.offset + 32)?;
        Ok(IortSmmuV3 {
            base_address: mmio_address(read_u64(self.sdt, header.offset + 16)?)?,
            flags: read_u32(self.sdt, header.offset + 24)?,
            vatos_address: if vatos_address == 0 {
                None
            } else {
                Some(mmio_address(vatos_address)?)
            },
            model: read_u32(self.sdt, header.offset + 40)?,
            event_gsiv: read_u32(self.sdt, header.offset + 44)?,
            pri_gsiv: read_u32(self.sdt, header.offset + 48)?,
            gerr_gsiv: read_u32(self.sdt, header.offset + 52)?,
            sync_gsiv: read_u32(self.sdt, header.offset + 56)?,
            pxm: read_u32(self.sdt, header.offset + 60)?,
            id_mapping_index: read_u32(self.sdt, header.offset + 64)?,
            header,
        })
    }

    fn parse_pmcg(self, header: IortNodeHeader) -> Result<IortPmcg, IortError> {
        if header.length < PMCG_MIN_LENGTH {
            return Err(IortError::Malformed("IORT PMCG node shorter than minimum"));
        }
        let page1 = read_u64(self.sdt, header.offset + 32)?;
        Ok(IortPmcg {
            page0_base_address: mmio_address(read_u64(self.sdt, header.offset + 16)?)?,
            overflow_gsiv: read_u32(self.sdt, header.offset + 24)?,
            node_reference: read_u32(self.sdt, header.offset + 28)?,
            page1_base_address: if page1 == 0 {
                None
            } else {
                Some(mmio_address(page1)?)
            },
            header,
        })
    }

    fn parse_reserved_memory(
        self,
        header: IortNodeHeader,
    ) -> Result<IortReservedMemory, IortError> {
        if header.length < RMR_MIN_LENGTH {
            return Err(IortError::Malformed("IORT RMR node shorter than minimum"));
        }
        Ok(IortReservedMemory {
            flags: read_u32(self.sdt, header.offset + 16)?,
            descriptor_count: read_u32(self.sdt, header.offset + 20)?,
            descriptor_offset: read_u32(self.sdt, header.offset + 24)?,
            header,
        })
    }

    fn id_mappings_for_header(
        self,
        header: IortNodeHeader,
    ) -> Result<IortIdMappings<'a>, IortError> {
        if header.mapping_count == 0 {
            return Ok(IortIdMappings {
                table: self,
                offset: header.end_offset(),
                remaining: 0,
            });
        }
        let mapping_offset = header.mapping_offset as usize;
        let start = checked_offset(header.offset, mapping_offset)?;
        let bytes = usize::try_from(header.mapping_count)
            .ok()
            .and_then(|count| count.checked_mul(IORT_ID_MAPPING_LENGTH))
            .ok_or(IortError::Malformed(
                "IORT ID mapping array length overflows",
            ))?;
        let end = checked_offset(start, bytes)?;
        if mapping_offset < IORT_NODE_HEADER_LENGTH || end > header.end_offset() {
            return Err(IortError::Malformed(
                "IORT ID mapping array extends past node",
            ));
        }
        Ok(IortIdMappings {
            table: self,
            offset: start,
            remaining: header.mapping_count,
        })
    }

    fn smmu_interrupts(
        self,
        header: IortNodeHeader,
        offset: u32,
        count: u32,
    ) -> Result<IortSmmuInterrupts<'a>, IortError> {
        if count == 0 {
            return Ok(IortSmmuInterrupts {
                table: self,
                offset: header.end_offset(),
                remaining: 0,
            });
        }
        let start = checked_offset(header.offset, offset as usize)?;
        let bytes = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(8))
            .ok_or(IortError::Malformed(
                "IORT SMMU interrupt array length overflows",
            ))?;
        if (offset as usize) < SMMU_MIN_LENGTH
            || checked_offset(start, bytes)? > header.end_offset()
        {
            return Err(IortError::Malformed(
                "IORT SMMU interrupt array extends past node",
            ));
        }
        Ok(IortSmmuInterrupts {
            table: self,
            offset: start,
            remaining: count,
        })
    }

    fn read_memory_access(self, offset: usize) -> Result<IortMemoryAccess, IortError> {
        Ok(IortMemoryAccess {
            cache_coherency: read_u32(self.sdt, offset)?,
            hints: read_u8(self.sdt, offset + 4)?,
            memory_flags: read_u8(self.sdt, offset + 7)?,
        })
    }
}

pub struct IortNodes<'a> {
    table: IortTable<'a>,
    offset: usize,
    remaining: u32,
}

impl<'a> Iterator for IortNodes<'a> {
    type Item = Result<IortNode<'a>, IortError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.offset >= self.table.sdt.len() {
            self.remaining = 0;
            return Some(Err(IortError::Malformed(
                "IORT node count exceeds table contents",
            )));
        }

        let offset = self.offset;
        let length = match read_u16(self.table.sdt, offset + 1) {
            Ok(length) => usize::from(length),
            Err(error) => {
                self.remaining = 0;
                return Some(Err(error.into()));
            }
        };
        if length < IORT_NODE_HEADER_LENGTH {
            self.remaining = 0;
            return Some(Err(IortError::Malformed(
                "IORT node length smaller than header",
            )));
        }
        let Ok(end) = checked_offset(offset, length) else {
            self.remaining = 0;
            return Some(Err(IortError::Malformed("IORT node offset overflows")));
        };
        if end > self.table.sdt.len() {
            self.remaining = 0;
            return Some(Err(IortError::Malformed(
                "IORT node extends past table length",
            )));
        }

        self.offset += length;
        self.remaining -= 1;
        Some(self.table.parse_node(offset))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IortNode<'a> {
    ItsGroup(IortItsGroup),
    NamedComponent(IortNamedComponent<'a>),
    RootComplex(IortRootComplex),
    Smmu(IortSmmu),
    SmmuV3(IortSmmuV3),
    Pmcg(IortPmcg),
    ReservedMemory(IortReservedMemory),
    Unknown(IortUnknownNode),
}

impl IortNode<'_> {
    #[inline]
    pub const fn header(self) -> IortNodeHeader {
        match self {
            Self::ItsGroup(node) => node.header,
            Self::NamedComponent(node) => node.header,
            Self::RootComplex(node) => node.header,
            Self::Smmu(node) => node.header,
            Self::SmmuV3(node) => node.header,
            Self::Pmcg(node) => node.header,
            Self::ReservedMemory(node) => node.header,
            Self::Unknown(node) => node.header,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortNodeHeader {
    pub kind: IortNodeKind,
    pub revision: u8,
    pub identifier: u32,
    pub mapping_count: u32,
    pub mapping_offset: u32,
    pub offset: usize,
    pub length: usize,
}

impl IortNodeHeader {
    #[inline]
    pub const fn end_offset(self) -> usize {
        self.offset + self.length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IortNodeKind {
    ItsGroup,
    NamedComponent,
    RootComplex,
    Smmu,
    SmmuV3,
    Pmcg,
    ReservedMemory,
    Unknown(u8),
}

impl IortNodeKind {
    #[inline]
    const fn from_raw(raw: u8) -> Self {
        match raw {
            IORT_NODE_ITS_GROUP => Self::ItsGroup,
            IORT_NODE_NAMED_COMPONENT => Self::NamedComponent,
            IORT_NODE_ROOT_COMPLEX => Self::RootComplex,
            IORT_NODE_SMMU => Self::Smmu,
            IORT_NODE_SMMU_V3 => Self::SmmuV3,
            IORT_NODE_PMCG => Self::Pmcg,
            IORT_NODE_RMR => Self::ReservedMemory,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IortRequesterMatch {
    Covered,
    NotCovered,
    Unresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortIdTranslation<'a> {
    pub node: IortNode<'a>,
    pub id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IortSingleStepTranslation {
    id: u32,
    output_reference: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortUnknownNode {
    pub kind: u8,
    pub header: IortNodeHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortMemoryAccess {
    pub cache_coherency: u32,
    pub hints: u8,
    pub memory_flags: u8,
}

impl IortMemoryAccess {
    #[inline]
    pub const fn is_coherent(self) -> bool {
        (self.cache_coherency & 1) != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortIdMapping {
    pub input_base: u32,
    pub id_count: u32,
    pub output_base: u32,
    pub output_reference: u32,
    pub flags: u32,
}

impl IortIdMapping {
    #[inline]
    pub const fn is_single_mapping(self) -> bool {
        (self.flags & 1) != 0
    }

    pub fn input_bdf_range(self) -> Result<Option<BdfRange>, IortError> {
        if self.is_single_mapping() {
            return Ok(BdfRange::inclusive(Bdf::from_u16(0), Bdf::from_u16(u16::MAX)).ok());
        }

        let Some(end) = self.input_base.checked_add(self.id_count) else {
            return Ok(None);
        };
        if self.input_base > u32::from(u16::MAX) || end > u32::from(u16::MAX) {
            return Ok(None);
        }
        BdfRange::inclusive(
            Bdf::from_u16(self.input_base as u16),
            Bdf::from_u16(end as u16),
        )
        .map(Some)
        .map_err(|_| IortError::Malformed("IORT requester ID range is reversed"))
    }

    fn translate_for_node_kind(self, kind: IortNodeKind, input_id: u32) -> Option<u32> {
        if self.is_single_mapping() {
            return kind.single_mapping_allowed().then_some(self.output_base);
        }

        let end = self.input_base.checked_add(self.id_count)?;
        if input_id < self.input_base || input_id > end {
            return None;
        }
        self.output_base
            .checked_add(input_id.checked_sub(self.input_base)?)
    }
}

impl IortNodeKind {
    #[inline]
    const fn single_mapping_allowed(self) -> bool {
        matches!(
            self,
            Self::NamedComponent | Self::RootComplex | Self::SmmuV3 | Self::Pmcg
        )
    }
}

pub struct IortIdMappings<'a> {
    table: IortTable<'a>,
    offset: usize,
    remaining: u32,
}

impl Iterator for IortIdMappings<'_> {
    type Item = Result<IortIdMapping, IortError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let offset = self.offset;
        self.offset += IORT_ID_MAPPING_LENGTH;
        self.remaining -= 1;
        Some(
            (|| -> Result<IortIdMapping, IortError> {
                Ok(IortIdMapping {
                    input_base: read_u32(self.table.sdt, offset)?,
                    id_count: read_u32(self.table.sdt, offset + 4)?,
                    output_base: read_u32(self.table.sdt, offset + 8)?,
                    output_reference: read_u32(self.table.sdt, offset + 12)?,
                    flags: read_u32(self.table.sdt, offset + 16)?,
                })
            })()
            .map_err(IortError::from),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortItsGroup {
    pub its_count: u32,
    pub header: IortNodeHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortItsIdentifier {
    pub identifier: u32,
}

pub struct IortItsIdentifiers<'a> {
    table: IortTable<'a>,
    offset: usize,
    remaining: u32,
}

impl Iterator for IortItsIdentifiers<'_> {
    type Item = Result<IortItsIdentifier, IortError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let offset = self.offset;
        self.offset += 4;
        self.remaining -= 1;
        Some(
            (|| -> Result<IortItsIdentifier, IortError> {
                Ok(IortItsIdentifier {
                    identifier: read_u32(self.table.sdt, offset)?,
                })
            })()
            .map_err(IortError::from),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortNamedComponent<'a> {
    pub node_flags: u32,
    pub memory_properties: IortMemoryAccess,
    pub memory_address_limit: u8,
    pub device_name: &'a [u8],
    pub header: IortNodeHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortRootComplex {
    pub memory_properties: IortMemoryAccess,
    pub ats_attribute: u32,
    pub pci_segment_number: u32,
    pub memory_address_limit: u8,
    pub pasid_capabilities: u16,
    pub header: IortNodeHeader,
}

impl IortRootComplex {
    #[inline]
    pub const fn ats_supported(self) -> bool {
        (self.ats_attribute & 1) != 0
    }

    #[inline]
    pub const fn pri_supported(self) -> bool {
        (self.ats_attribute & (1 << 1)) != 0
    }

    #[inline]
    pub const fn pasid_forward_supported(self) -> bool {
        (self.ats_attribute & (1 << 2)) != 0
    }

    #[inline]
    pub const fn max_pasid_width(self) -> u8 {
        (self.pasid_capabilities & 0x1f) as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortSmmu {
    pub registers: MmioAddrRange,
    pub model: u32,
    pub flags: u32,
    pub global_interrupt_offset: u32,
    pub context_interrupt_count: u32,
    pub context_interrupt_offset: u32,
    pub pmu_interrupt_count: u32,
    pub pmu_interrupt_offset: u32,
    pub header: IortNodeHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortSmmuGlobalInterrupt {
    pub nsg_irpt: u32,
    pub nsg_irpt_flags: u32,
    pub nsg_cfg_irpt: u32,
    pub nsg_cfg_irpt_flags: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortSmmuInterrupt {
    pub gsiv: u32,
    pub flags: u32,
}

pub struct IortSmmuInterrupts<'a> {
    table: IortTable<'a>,
    offset: usize,
    remaining: u32,
}

impl Iterator for IortSmmuInterrupts<'_> {
    type Item = Result<IortSmmuInterrupt, IortError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let offset = self.offset;
        self.offset += 8;
        self.remaining -= 1;
        Some(
            (|| -> Result<IortSmmuInterrupt, IortError> {
                Ok(IortSmmuInterrupt {
                    gsiv: read_u32(self.table.sdt, offset)?,
                    flags: read_u32(self.table.sdt, offset + 4)?,
                })
            })()
            .map_err(IortError::from),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortSmmuV3 {
    pub base_address: MmioAddr,
    pub flags: u32,
    pub vatos_address: Option<MmioAddr>,
    pub model: u32,
    pub event_gsiv: u32,
    pub pri_gsiv: u32,
    pub gerr_gsiv: u32,
    pub sync_gsiv: u32,
    pub pxm: u32,
    pub id_mapping_index: u32,
    pub header: IortNodeHeader,
}

impl IortSmmuV3 {
    #[inline]
    pub const fn pxm_valid(self) -> bool {
        (self.flags & (1 << 3)) != 0
    }

    #[inline]
    pub const fn device_id_valid(self) -> bool {
        (self.flags & (1 << 4)) != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortPmcg {
    pub page0_base_address: MmioAddr,
    pub overflow_gsiv: u32,
    pub node_reference: u32,
    pub page1_base_address: Option<MmioAddr>,
    pub header: IortNodeHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortReservedMemory {
    pub flags: u32,
    pub descriptor_count: u32,
    pub descriptor_offset: u32,
    pub header: IortNodeHeader,
}

impl IortReservedMemory {
    #[inline]
    pub const fn remap_permitted(self) -> bool {
        (self.flags & 1) != 0
    }

    #[inline]
    pub const fn privileged_access(self) -> bool {
        (self.flags & (1 << 1)) != 0
    }

    #[inline]
    pub const fn access_attributes(self) -> u8 {
        ((self.flags >> 2) & 0xff) as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IortRmrDescriptor {
    pub memory: PhysAddrRange,
    pub reserved: u32,
}

pub struct IortRmrDescriptors<'a> {
    table: IortTable<'a>,
    offset: usize,
    remaining: u32,
}

impl Iterator for IortRmrDescriptors<'_> {
    type Item = Result<IortRmrDescriptor, IortError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let offset = self.offset;
        self.offset += RMR_DESCRIPTOR_LENGTH;
        self.remaining -= 1;
        Some((|| {
            let base = read_u64(self.table.sdt, offset)?;
            let length = read_u64(self.table.sdt, offset + 8)?;
            Ok(IortRmrDescriptor {
                memory: phys_range_from_start_size(base, length)?,
                reserved: read_u32(self.table.sdt, offset + 16)?,
            })
        })())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IortNode, IortNodeKind, IortReservedMemory, IortRootComplex, IortSmmuV3, IortTable,
    };
    use crate::firm::pcie::{Bdf, BdfRange, PciDevice};
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

    fn write_node_header(
        bytes: &mut [u8],
        offset: usize,
        kind: u8,
        length: usize,
        identifier: u32,
        mapping_count: u32,
        mapping_offset: u32,
    ) {
        bytes[offset] = kind;
        bytes[offset + 1..offset + 3].copy_from_slice(&(length as u16).to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&identifier.to_le_bytes());
        bytes[offset + 8..offset + 12].copy_from_slice(&mapping_count.to_le_bytes());
        bytes[offset + 12..offset + 16].copy_from_slice(&mapping_offset.to_le_bytes());
    }

    fn write_id_mapping(
        bytes: &mut [u8],
        offset: usize,
        input_base: u32,
        id_count: u32,
        output_base: u32,
        output_reference: u32,
        flags: u32,
    ) {
        bytes[offset..offset + 4].copy_from_slice(&input_base.to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&id_count.to_le_bytes());
        bytes[offset + 8..offset + 12].copy_from_slice(&output_base.to_le_bytes());
        bytes[offset + 12..offset + 16].copy_from_slice(&output_reference.to_le_bytes());
        bytes[offset + 16..offset + 20].copy_from_slice(&flags.to_le_bytes());
    }

    #[test]
    fn parses_root_complex_smmuv3_and_id_mapping() {
        const ROOT: usize = 48;
        const ROOT_LEN: usize = 56;
        const SMMU: usize = ROOT + ROOT_LEN;
        const SMMU_LEN: usize = 68;
        const LEN: usize = SMMU + SMMU_LEN;

        let mut iort = [0u8; LEN];
        write_sdt_header(&mut iort, Signature::IORT, LEN);
        iort[36..40].copy_from_slice(&2u32.to_le_bytes());
        iort[40..44].copy_from_slice(&(ROOT as u32).to_le_bytes());

        write_node_header(
            &mut iort,
            ROOT,
            super::IORT_NODE_ROOT_COMPLEX,
            ROOT_LEN,
            7,
            1,
            36,
        );
        iort[ROOT + 16..ROOT + 20].copy_from_slice(&1u32.to_le_bytes());
        iort[ROOT + 20] = 0x0f;
        iort[ROOT + 23] = 0x07;
        iort[ROOT + 24..ROOT + 28].copy_from_slice(&7u32.to_le_bytes());
        iort[ROOT + 28..ROOT + 32].copy_from_slice(&3u32.to_le_bytes());
        iort[ROOT + 32] = 48;
        iort[ROOT + 33..ROOT + 35].copy_from_slice(&0x0014u16.to_le_bytes());
        write_id_mapping(&mut iort, ROOT + 36, 0x100, 0x20, 0x200, SMMU as u32, 1);

        write_node_header(
            &mut iort,
            SMMU,
            super::IORT_NODE_SMMU_V3,
            SMMU_LEN,
            11,
            0,
            0,
        );
        iort[SMMU + 16..SMMU + 24].copy_from_slice(&0xfee0_0000u64.to_le_bytes());
        iort[SMMU + 24..SMMU + 28].copy_from_slice(&(1u32 << 3).to_le_bytes());
        iort[SMMU + 40..SMMU + 44].copy_from_slice(&2u32.to_le_bytes());
        iort[SMMU + 44..SMMU + 48].copy_from_slice(&33u32.to_le_bytes());
        iort[SMMU + 48..SMMU + 52].copy_from_slice(&34u32.to_le_bytes());
        iort[SMMU + 52..SMMU + 56].copy_from_slice(&35u32.to_le_bytes());
        iort[SMMU + 56..SMMU + 60].copy_from_slice(&36u32.to_le_bytes());
        iort[SMMU + 60..SMMU + 64].copy_from_slice(&9u32.to_le_bytes());
        iort[SMMU + 64..SMMU + 68].copy_from_slice(&0u32.to_le_bytes());

        finish_sdt_checksum(&mut iort);

        let mapping = table_mapping(&iort);
        let table = unsafe { IortTable::from_mapping(&mapping) }.unwrap();
        let nodes: heapless::Vec<_, 4> = table.nodes().unwrap().collect::<Result<_, _>>().unwrap();
        assert!(matches!(
            nodes[0],
            IortNode::RootComplex(IortRootComplex {
                pci_segment_number: 3,
                memory_address_limit: 48,
                ..
            })
        ));
        assert!(matches!(
            nodes[1],
            IortNode::SmmuV3(IortSmmuV3 {
                event_gsiv: 33,
                pri_gsiv: 34,
                gerr_gsiv: 35,
                sync_gsiv: 36,
                pxm: 9,
                ..
            })
        ));
        assert!(matches!(
            table.node_by_reference(SMMU as u32).unwrap(),
            Some(IortNode::SmmuV3(_))
        ));

        let IortNode::RootComplex(root) = nodes[0] else {
            panic!("expected root complex");
        };
        assert!(root.ats_supported());
        assert!(root.pri_supported());
        assert!(root.pasid_forward_supported());
        assert_eq!(root.max_pasid_width(), 20);

        let mappings: heapless::Vec<_, 2> = table
            .id_mappings(nodes[0])
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(mappings[0].input_base, 0x100);
        assert_eq!(mappings[0].id_count, 0x20);
        assert_eq!(mappings[0].output_base, 0x200);
        assert_eq!(mappings[0].output_reference, SMMU as u32);
        assert!(mappings[0].is_single_mapping());

        let requester = PciDevice::new(3, 1, 0, 0).unwrap();
        assert_eq!(
            table.root_complex_requester_match(requester).unwrap(),
            Some(super::IortRequesterMatch::Covered)
        );
        assert_eq!(
            table
                .root_complex_bdf_ranges(3)
                .unwrap()
                .unwrap()
                .as_slice(),
            &[BdfRange::inclusive(Bdf::from_u16(0), Bdf::from_u16(u16::MAX)).unwrap()]
        );

        let translation = table
            .iommu_for_pci_requester(requester)
            .unwrap()
            .expect("expected IOMMU mapping");
        assert!(matches!(translation.node, IortNode::SmmuV3(_)));
        assert_eq!(translation.id, 0x200);
    }

    #[test]
    fn parses_its_group_and_reserved_memory_descriptors() {
        const ITS: usize = 48;
        const ITS_LEN: usize = 28;
        const RMR: usize = ITS + ITS_LEN;
        const RMR_LEN: usize = 68;
        const LEN: usize = RMR + RMR_LEN;

        let mut iort = [0u8; LEN];
        write_sdt_header(&mut iort, Signature::IORT, LEN);
        iort[36..40].copy_from_slice(&2u32.to_le_bytes());
        iort[40..44].copy_from_slice(&(ITS as u32).to_le_bytes());

        write_node_header(&mut iort, ITS, super::IORT_NODE_ITS_GROUP, ITS_LEN, 1, 0, 0);
        iort[ITS + 16..ITS + 20].copy_from_slice(&2u32.to_le_bytes());
        iort[ITS + 20..ITS + 24].copy_from_slice(&7u32.to_le_bytes());
        iort[ITS + 24..ITS + 28].copy_from_slice(&8u32.to_le_bytes());

        write_node_header(&mut iort, RMR, super::IORT_NODE_RMR, RMR_LEN, 2, 1, 48);
        iort[RMR + 16..RMR + 20].copy_from_slice(&0x15u32.to_le_bytes());
        iort[RMR + 20..RMR + 24].copy_from_slice(&1u32.to_le_bytes());
        iort[RMR + 24..RMR + 28].copy_from_slice(&28u32.to_le_bytes());
        iort[RMR + 28..RMR + 36].copy_from_slice(&0x4000u64.to_le_bytes());
        iort[RMR + 36..RMR + 44].copy_from_slice(&0x1000u64.to_le_bytes());
        write_id_mapping(&mut iort, RMR + 48, 0x200, 0, 0x200, ITS as u32, 0);

        finish_sdt_checksum(&mut iort);

        let mapping = table_mapping(&iort);
        let table = unsafe { IortTable::from_mapping(&mapping) }.unwrap();
        let nodes: heapless::Vec<_, 4> = table.nodes().unwrap().collect::<Result<_, _>>().unwrap();
        assert!(matches!(nodes[0].header().kind, IortNodeKind::ItsGroup));

        let IortNode::ItsGroup(group) = nodes[0] else {
            panic!("expected ITS group");
        };
        let ids: heapless::Vec<_, 4> = table
            .its_identifiers(group)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(ids[0].identifier, 7);
        assert_eq!(ids[1].identifier, 8);

        let IortNode::ReservedMemory(memory) = nodes[1] else {
            panic!("expected RMR");
        };
        assert!(matches!(
            memory,
            IortReservedMemory {
                descriptor_count: 1,
                ..
            }
        ));
        assert!(memory.remap_permitted());
        assert!(!memory.privileged_access());
        assert_eq!(memory.access_attributes(), 5);

        let descriptors: heapless::Vec<_, 2> = table
            .rmr_descriptors(memory)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(descriptors[0].memory.start.as_usize(), 0x4000);
        assert_eq!(descriptors[0].memory.end.as_usize(), 0x5000);
        assert_eq!(
            table
                .rmr_bdf_ranges(descriptors[0].memory)
                .unwrap()
                .unwrap()
                .as_slice(),
            &[BdfRange::single(Bdf::from_u16(0x200))]
        );
    }
}
