//! x86 MSI/MSI-X delivery-message helpers.

use crate::{Error, MsiMessage, Result};

const MSI_ADDRESS_BASE: u64 = 0xfee0_0000;
const MSI_DESTINATION_SHIFT: u64 = 12;
const MSI_REDIRECTION_HINT: u64 = 1 << 3;
const MSI_DESTINATION_MODE_LOGICAL: u64 = 1 << 2;

const MSI_DELIVERY_MODE_SHIFT: u32 = 8;
const MSI_LEVEL_ASSERT: u32 = 1 << 14;
const MSI_TRIGGER_LEVEL: u32 = 1 << 15;

/// CPU interrupt vector usable for external MSI/MSI-X delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct X86InterruptVector(u8);

impl X86InterruptVector {
    pub const MIN_EXTERNAL: u8 = 32;

    #[inline]
    pub const fn new(vector: u8) -> Result<Self> {
        if vector < Self::MIN_EXTERNAL {
            return Err(Error::InvalidRange);
        }
        Ok(Self(vector))
    }

    #[inline]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Plain xAPIC MSI destination field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum X86MsiDestination {
    Physical(u8),
    Logical(u8),
}

impl X86MsiDestination {
    #[inline]
    pub const fn id(self) -> u8 {
        match self {
            Self::Physical(id) | Self::Logical(id) => id,
        }
    }

    #[inline]
    pub const fn is_logical(self) -> bool {
        matches!(self, Self::Logical(_))
    }
}

/// x86 MSI delivery mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum X86MsiDeliveryMode {
    Fixed = 0b000,
    LowestPriority = 0b001,
    Smi = 0b010,
    Nmi = 0b100,
    Init = 0b101,
    ExtInt = 0b111,
}

/// x86 MSI trigger mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum X86MsiTriggerMode {
    #[default]
    Edge,
    Level,
}

/// x86 MSI level bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum X86MsiLevel {
    Deassert,
    Assert,
}

/// Builder for an x86 APIC MSI/MSI-X delivery message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct X86MsiDelivery {
    destination: X86MsiDestination,
    vector: X86InterruptVector,
    delivery_mode: X86MsiDeliveryMode,
    trigger_mode: X86MsiTriggerMode,
    level: X86MsiLevel,
    redirection_hint: bool,
}

impl X86MsiDelivery {
    #[inline]
    pub const fn fixed(destination: X86MsiDestination, vector: X86InterruptVector) -> Self {
        Self {
            destination,
            vector,
            delivery_mode: X86MsiDeliveryMode::Fixed,
            trigger_mode: X86MsiTriggerMode::Edge,
            level: X86MsiLevel::Assert,
            redirection_hint: false,
        }
    }

    #[inline]
    pub const fn new(
        destination: X86MsiDestination,
        vector: X86InterruptVector,
        delivery_mode: X86MsiDeliveryMode,
    ) -> Self {
        Self {
            destination,
            vector,
            delivery_mode,
            trigger_mode: X86MsiTriggerMode::Edge,
            level: X86MsiLevel::Assert,
            redirection_hint: false,
        }
    }

    #[inline]
    pub const fn with_trigger_mode(mut self, trigger_mode: X86MsiTriggerMode) -> Self {
        self.trigger_mode = trigger_mode;
        self
    }

    #[inline]
    pub const fn with_level(mut self, level: X86MsiLevel) -> Self {
        self.level = level;
        self
    }

    #[inline]
    pub const fn with_redirection_hint(mut self, enabled: bool) -> Self {
        self.redirection_hint = enabled;
        self
    }

    #[inline]
    pub const fn destination(self) -> X86MsiDestination {
        self.destination
    }

    #[inline]
    pub const fn vector(self) -> X86InterruptVector {
        self.vector
    }

    #[inline]
    pub const fn delivery_mode(self) -> X86MsiDeliveryMode {
        self.delivery_mode
    }

    #[inline]
    pub const fn trigger_mode(self) -> X86MsiTriggerMode {
        self.trigger_mode
    }

    #[inline]
    pub const fn level(self) -> X86MsiLevel {
        self.level
    }

    #[inline]
    pub const fn redirection_hint(self) -> bool {
        self.redirection_hint
    }

    #[inline]
    pub const fn message(self) -> MsiMessage {
        let mut address =
            MSI_ADDRESS_BASE | ((self.destination.id() as u64) << MSI_DESTINATION_SHIFT);
        if self.destination.is_logical() {
            address |= MSI_DESTINATION_MODE_LOGICAL;
        }
        if self.redirection_hint {
            address |= MSI_REDIRECTION_HINT;
        }

        let mut data = self.vector.get() as u32;
        data |= (self.delivery_mode as u32) << MSI_DELIVERY_MODE_SHIFT;
        if matches!(self.level, X86MsiLevel::Assert) {
            data |= MSI_LEVEL_ASSERT;
        }
        if matches!(self.trigger_mode, X86MsiTriggerMode::Level) {
            data |= MSI_TRIGGER_LEVEL;
        }

        MsiMessage::new(address, data)
    }
}

impl From<X86MsiDelivery> for MsiMessage {
    #[inline]
    fn from(value: X86MsiDelivery) -> Self {
        value.message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_exception_vectors_for_msi_delivery() {
        assert_eq!(X86InterruptVector::new(31), Err(Error::InvalidRange));
        assert_eq!(X86InterruptVector::new(32).unwrap().get(), 32);
    }

    #[test]
    fn fixed_physical_delivery_encodes_apic_msi_message() {
        let message = X86MsiDelivery::fixed(
            X86MsiDestination::Physical(0x2a),
            X86InterruptVector::new(0x45).unwrap(),
        )
        .message();

        assert_eq!(message.address(), 0xfee2_a000);
        assert_eq!(message.data(), 0x4045);
    }

    #[test]
    fn logical_lowest_priority_delivery_sets_route_bits() {
        let message = X86MsiDelivery::new(
            X86MsiDestination::Logical(0x03),
            X86InterruptVector::new(0x80).unwrap(),
            X86MsiDeliveryMode::LowestPriority,
        )
        .with_trigger_mode(X86MsiTriggerMode::Level)
        .with_redirection_hint(true)
        .message();

        assert_eq!(message.address(), 0xfee0_300c);
        assert_eq!(message.data(), 0xc180);
    }
}
