//! Parameter presets. Each is a set of `pub global` constants, passed to gadgets as
//! generic arguments (ADR-004: Field-valued generics must be supplied via a `global`
//! reference, not a literal). All preset values were validated before release.

pub mod bfv_1024_27;
pub mod bfv_1024_55;
