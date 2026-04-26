use memory_addr::{MemoryAddr, PhysAddr};

use riscv::{
    asm::sfence_vma_all,
    register::{
        satp::{self, Mode},
        sstatus,
    },
};

use crate::{AddrSpaceActivation, PageSize, PagingError, PagingResult};

/// RISC-V `satp` values to apply when activating an address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rv64SatpControls {
    mode: Mode,
    asid: u16,
    fence_after: bool,
}

impl Rv64SatpControls {
    #[inline]
    pub const fn new(mode: Mode) -> Self {
        Self {
            mode,
            asid: 0,
            fence_after: true,
        }
    }

    #[inline]
    pub const fn with_asid(mut self, asid: u16) -> Self {
        self.asid = asid;
        self
    }

    #[inline]
    pub const fn with_fence_after(mut self, fence_after: bool) -> Self {
        self.fence_after = fence_after;
        self
    }

    #[inline]
    pub const fn mode(self) -> Mode {
        self.mode
    }

    #[inline]
    pub const fn asid(self) -> u16 {
        self.asid
    }

    #[inline]
    pub const fn fence_after(self) -> bool {
        self.fence_after
    }
}

/// Installed RISC-V address-space token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rv64SatpToken {
    root: PhysAddr,
    controls: Rv64SatpControls,
    ppn: usize,
}

impl Rv64SatpToken {
    #[inline]
    pub const fn root(self) -> PhysAddr {
        self.root
    }

    #[inline]
    pub const fn controls(self) -> Rv64SatpControls {
        self.controls
    }

    #[inline]
    pub const fn ppn(self) -> usize {
        self.ppn
    }
}

/// CPU-local RISC-V `satp` activation policy.
#[derive(Clone, Copy, Debug)]
pub struct Rv64SatpActivation {
    controls: Rv64SatpControls,
}

impl Rv64SatpActivation {
    #[inline]
    pub const fn new(controls: Rv64SatpControls) -> Self {
        Self { controls }
    }

    #[inline]
    pub const fn controls(self) -> Rv64SatpControls {
        self.controls
    }

    /// Write `satp` directly from a page-table root.
    ///
    /// # Safety
    ///
    /// The caller must ensure the selected mode is supported and that the new
    /// address space maps the instruction stream and stack needed to continue.
    #[inline]
    pub unsafe fn write_satp(root: PhysAddr, controls: Rv64SatpControls) -> PagingResult {
        let ppn = ppn_from_root(root)?;
        with_irq_disabled(|| unsafe {
            write_satp_ppn(ppn, controls)?;
            if controls.fence_after() {
                sfence_vma_all();
            }
            Ok(())
        })
    }
}

impl AddrSpaceActivation for Rv64SatpActivation {
    type Token = Rv64SatpToken;

    #[inline]
    fn install(&mut self, root: PhysAddr) -> PagingResult<Self::Token> {
        Ok(Rv64SatpToken {
            root,
            controls: self.controls,
            ppn: ppn_from_root(root)?,
        })
    }

    #[inline]
    unsafe fn activate(&mut self, token: Self::Token) -> PagingResult {
        with_irq_disabled(|| unsafe {
            write_satp_ppn(token.ppn, token.controls)?;
            if token.controls.fence_after() {
                sfence_vma_all();
            }
            Ok(())
        })
    }

    #[inline]
    fn current(&self) -> PagingResult<Option<Self::Token>> {
        with_irq_disabled(|| {
            let satp = satp::read();
            let mode = satp
                .try_mode()
                .map_err(|_| PagingError::InvalidMappingShape)?;
            let controls = Rv64SatpControls::new(mode).with_asid(satp.asid() as u16);
            let root = PhysAddr::from(satp.ppn() << 12);

            Ok(Some(Rv64SatpToken {
                root,
                controls,
                ppn: satp.ppn(),
            }))
        })
    }
}

#[inline]
fn ppn_from_root(root: PhysAddr) -> PagingResult<usize> {
    if !root.is_aligned(PageSize::Size4K.bytes()) {
        return Err(PagingError::NotAligned);
    }

    let ppn = root.as_usize() >> 12;
    if ppn > 0x0fff_ffff_ffff {
        return Err(PagingError::AddressOutOfRange);
    }
    Ok(ppn)
}

#[inline]
unsafe fn write_satp_ppn(ppn: usize, controls: Rv64SatpControls) -> PagingResult {
    unsafe {
        satp::try_set(controls.mode(), controls.asid() as usize, ppn)
            .map_err(|_| PagingError::AddressOutOfRange)
    }
}

#[inline]
fn with_irq_disabled<R>(f: impl FnOnce() -> R) -> R {
    let interrupts_enabled = sstatus::read().sie();
    unsafe {
        sstatus::clear_sie();
    }
    let result = f();
    if interrupts_enabled {
        unsafe {
            sstatus::set_sie();
        }
    }
    result
}
