//! Exit codes used by sshpass 1.10 (`enum program_return_codes` in main.c).

pub const NOERROR: i32 = 0;
pub const INVALID_ARGUMENTS: i32 = 1;
pub const CONFLICTING_ARGUMENTS: i32 = 2;
pub const RUNTIME_ERROR: i32 = 3;
pub const PARSE_ERROR: i32 = 4;
pub const INCORRECT_PASSWORD: i32 = 5;
pub const HOST_KEY_UNKNOWN: i32 = 6;
pub const HOST_KEY_CHANGED: i32 = 7;
