use memory_addr::{MemoryAddr, PhysAddr};

use x86_64::{
    PhysAddr as X86PhysAddr,
    instructions::{interrupts::without_interrupts, tlb::Pcid},
    registers::control::{Cr0, Cr0Flags, Cr3, Cr3Flags, Cr4, Cr4Flags},
    structures::paging::PhysFrame,
};

use crate::{AddrSpaceActivation, PageSize, PagingError, PagingResult};

/// How an x86_64 CR3 switch should encode the low CR3 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86Cr3Mode {
    /// Use legacy CR3 cache-control flags. This mode is valid when PCID is
    /// disabled in CR4.
    Flags(Cr3Flags),
    /// Use a PCID tag. The caller must have enabled CR4.PCIDE before
    /// activating a token in this mode.
    Pcid {
        pcid: Pcid,
        preserve_tlb_entries: bool,
    },
}

/// x86_64 paging-control values to apply around a CR3 switch.
///
/// `cr4` is applied before CR3 so callers can enable mechanisms such as PAE,
/// LA57, or PCID before loading a root that depends on them. `cr0` is applied
/// after CR3 so callers can load a root before enabling paging on a freshly
/// booted AP. Callers that need a different transition sequence can use the
/// direct `write_*` helpers below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86PagingControls {
    cr0: Option<Cr0Flags>,
    cr3: X86Cr3Mode,
    cr4: Option<Cr4Flags>,
}

impl X86PagingControls {
    #[inline]
    pub const fn new(cr3: X86Cr3Mode) -> Self {
        match cr3 {
            X86Cr3Mode::Flags(flags) => Self {
                cr0: None,
                cr3: X86Cr3Mode::Flags(flags),
                cr4: None,
            },
            X86Cr3Mode::Pcid {
                pcid,
                preserve_tlb_entries,
            } => Self {
                cr0: None,
                cr3: X86Cr3Mode::Pcid {
                    pcid,
                    preserve_tlb_entries,
                },
                cr4: None,
            },
        }
    }

    #[inline]
    pub const fn legacy(flags: Cr3Flags) -> Self {
        Self::new(X86Cr3Mode::Flags(flags))
    }

    #[inline]
    pub const fn pcid(pcid: Pcid, preserve_tlb_entries: bool) -> Self {
        Self::new(X86Cr3Mode::Pcid {
            pcid,
            preserve_tlb_entries,
        })
    }

    #[inline]
    pub const fn with_cr0(mut self, flags: Cr0Flags) -> Self {
        self.cr0 = Some(flags);
        self
    }

    #[inline]
    pub const fn without_cr0(mut self) -> Self {
        self.cr0 = None;
        self
    }

    #[inline]
    pub const fn with_cr4(mut self, flags: Cr4Flags) -> Self {
        self.cr4 = Some(flags);
        self
    }

    #[inline]
    pub const fn without_cr4(mut self) -> Self {
        self.cr4 = None;
        self
    }

    #[inline]
    pub const fn cr0(self) -> Option<Cr0Flags> {
        self.cr0
    }

    #[inline]
    pub const fn cr3(self) -> X86Cr3Mode {
        self.cr3
    }

    #[inline]
    pub const fn cr4(self) -> Option<Cr4Flags> {
        self.cr4
    }
}

/// Installed x86_64 address-space token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86PagingToken {
    root: PhysAddr,
    controls: X86PagingControls,
}

impl X86PagingToken {
    #[inline]
    pub const fn root(self) -> PhysAddr {
        self.root
    }

    #[inline]
    pub const fn controls(self) -> X86PagingControls {
        self.controls
    }

    #[inline]
    pub const fn cr3(self) -> X86Cr3Mode {
        self.controls.cr3()
    }
}

/// CPU-local x86_64 paging activation policy.
///
/// This type applies caller-provided CR0/CR3/CR4 values. It does not choose
/// feature bits, allocate PCIDs, or install PAT; those are boot/per-CPU policy
/// decisions that must happen at the layer constructing the controls.
#[derive(Clone, Copy, Debug)]
pub struct X86PagingActivation {
    controls: X86PagingControls,
}

impl X86PagingActivation {
    #[inline]
    pub const fn new(controls: X86PagingControls) -> Self {
        Self { controls }
    }

    #[inline]
    pub const fn legacy(flags: Cr3Flags) -> Self {
        Self::new(X86PagingControls::legacy(flags))
    }

    #[inline]
    pub const fn pcid(pcid: Pcid, preserve_tlb_entries: bool) -> Self {
        Self::new(X86PagingControls::pcid(pcid, preserve_tlb_entries))
    }

    #[inline]
    pub const fn with_cr0(mut self, flags: Cr0Flags) -> Self {
        self.controls = self.controls.with_cr0(flags);
        self
    }

    #[inline]
    pub const fn with_cr4(mut self, flags: Cr4Flags) -> Self {
        self.controls = self.controls.with_cr4(flags);
        self
    }

    #[inline]
    pub const fn controls(self) -> X86PagingControls {
        self.controls
    }

    /// Write CR0 directly.
    ///
    /// # Safety
    ///
    /// The caller must ensure `flags` are legal for the current CPU mode and
    /// preserve the mappings/invariants needed to continue execution.
    #[inline]
    pub unsafe fn write_cr0(flags: Cr0Flags) {
        without_interrupts(|| unsafe {
            Cr0::write(flags);
        });
    }

    /// Write CR3 directly from a page-table root and CR3 mode.
    ///
    /// # Safety
    ///
    /// The caller must ensure the root and CR3 low bits are compatible with the
    /// currently enabled CR0/CR4 paging features.
    #[inline]
    pub unsafe fn write_cr3(root: PhysAddr, mode: X86Cr3Mode) -> PagingResult {
        let frame = frame_from_root(root)?;
        without_interrupts(|| unsafe {
            write_cr3_frame(frame, mode);
        });
        Ok(())
    }

    /// Write CR4 directly.
    ///
    /// # Safety
    ///
    /// The caller must ensure `flags` are supported and legal for the current
    /// paging transition. Some bits, such as LA57 and PCIDE, have architectural
    /// sequencing constraints.
    #[inline]
    pub unsafe fn write_cr4(flags: Cr4Flags) {
        without_interrupts(|| unsafe {
            Cr4::write(flags);
        });
    }
}

impl AddrSpaceActivation for X86PagingActivation {
    type Token = X86PagingToken;

    #[inline]
    fn install(&mut self, root: PhysAddr) -> PagingResult<Self::Token> {
        frame_from_root(root)?;
        Ok(X86PagingToken {
            root,
            controls: self.controls,
        })
    }

    #[inline]
    unsafe fn activate(&mut self, token: Self::Token) -> PagingResult {
        let frame = frame_from_root(token.root)?;

        without_interrupts(|| {
            if let Some(flags) = token.controls.cr4() {
                unsafe {
                    Cr4::write(flags);
                }
            }

            unsafe {
                write_cr3_frame(frame, token.controls.cr3());
            }

            if let Some(flags) = token.controls.cr0() {
                unsafe {
                    Cr0::write(flags);
                }
            }
        });

        Ok(())
    }

    #[inline]
    fn current(&self) -> PagingResult<Option<Self::Token>> {
        without_interrupts(|| {
            let cr0 = Some(Cr0::read());
            let cr4 = Some(Cr4::read());
            let token = match self.controls.cr3() {
                X86Cr3Mode::Flags(_) => {
                    let (frame, flags) = Cr3::read();
                    X86PagingToken {
                        root: root_from_frame(frame),
                        controls: X86PagingControls {
                            cr0,
                            cr3: X86Cr3Mode::Flags(flags),
                            cr4,
                        },
                    }
                }
                X86Cr3Mode::Pcid {
                    preserve_tlb_entries,
                    ..
                } => {
                    let (frame, pcid) = Cr3::read_pcid();
                    X86PagingToken {
                        root: root_from_frame(frame),
                        controls: X86PagingControls {
                            cr0,
                            cr3: X86Cr3Mode::Pcid {
                                pcid,
                                preserve_tlb_entries,
                            },
                            cr4,
                        },
                    }
                }
            };
            Ok(Some(token))
        })
    }
}

#[inline]
unsafe fn write_cr3_frame(frame: PhysFrame, mode: X86Cr3Mode) {
    match mode {
        X86Cr3Mode::Flags(flags) => unsafe {
            Cr3::write(frame, flags);
        },
        X86Cr3Mode::Pcid {
            pcid,
            preserve_tlb_entries: false,
        } => unsafe {
            Cr3::write_pcid(frame, pcid);
        },
        X86Cr3Mode::Pcid {
            pcid,
            preserve_tlb_entries: true,
        } => unsafe {
            Cr3::write_pcid_no_flush(frame, pcid);
        },
    }
}

#[inline]
fn frame_from_root(root: PhysAddr) -> PagingResult<PhysFrame> {
    if !root.is_aligned(PageSize::Size4K.bytes()) {
        return Err(PagingError::NotAligned);
    }

    let raw = root.as_usize() as u64;
    let addr = X86PhysAddr::try_new(raw).map_err(|_| PagingError::AddressOutOfRange)?;
    PhysFrame::from_start_address(addr).map_err(|_| PagingError::NotAligned)
}

#[inline]
fn root_from_frame(frame: PhysFrame) -> PhysAddr {
    PhysAddr::from(frame.start_address().as_u64() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_validates_cr3_root_alignment() {
        let mut activation = X86PagingActivation::legacy(Cr3Flags::empty());
        assert_eq!(
            activation.install(PhysAddr::from(0x1234usize)),
            Err(PagingError::NotAligned)
        );

        let token = activation.install(PhysAddr::from(0x4000usize)).unwrap();
        assert_eq!(token.root(), PhysAddr::from(0x4000usize));
        assert_eq!(token.cr3(), X86Cr3Mode::Flags(Cr3Flags::empty()));
    }

    #[test]
    fn pcid_mode_is_carried_into_installed_tokens() {
        let pcid = Pcid::new(7).unwrap();
        let mut activation = X86PagingActivation::pcid(pcid, true);
        let token = activation.install(PhysAddr::from(0x8000usize)).unwrap();

        assert_eq!(
            token.cr3(),
            X86Cr3Mode::Pcid {
                pcid,
                preserve_tlb_entries: true
            }
        );
    }

    #[test]
    fn activation_carries_cr0_and_cr4_controls() {
        let controls = X86PagingControls::legacy(Cr3Flags::empty())
            .with_cr4(Cr4Flags::PHYSICAL_ADDRESS_EXTENSION)
            .with_cr0(Cr0Flags::PAGING | Cr0Flags::WRITE_PROTECT);
        let mut activation = X86PagingActivation::new(controls);

        let token = activation.install(PhysAddr::from(0xc000usize)).unwrap();
        assert_eq!(token.controls(), controls);
        assert_eq!(
            token.controls().cr4(),
            Some(Cr4Flags::PHYSICAL_ADDRESS_EXTENSION)
        );
        assert_eq!(
            token.controls().cr0(),
            Some(Cr0Flags::PAGING | Cr0Flags::WRITE_PROTECT)
        );
    }
}
