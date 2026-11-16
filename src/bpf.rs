//! Test support: a classic-BPF interpreter for the instructions seccompiler emits, run over a
//! `seccomp_data`, so a policy's tests can show what its compiled filter allows without installing
//! it. Panics on an instruction seccompiler does not emit.

use seccompiler::BpfProgram;

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;
pub const RET_ALLOW: u32 = 0x7fff_0000;
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
/// `SECCOMP_RET_ERRNO`; the low 16 bits carry the errno.
pub const RET_ERRNO: u32 = 0x0005_0000;

/// The filter's return value for syscall `nr` with `args` from architecture `arch`.
pub fn run(prog: &BpfProgram, arch: u32, nr: i64, args: [u64; 6]) -> u32 {
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&(nr as u32).to_le_bytes());
    data[4..8].copy_from_slice(&arch.to_le_bytes());
    for (i, a) in args.iter().enumerate() {
        data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes());
    }
    let (mut acc, mut pc) = (0u32, 0usize);
    loop {
        let ins = &prog[pc];
        pc += 1;
        let k = ins.k;
        match ins.code {
            0x20 => {
                let o = k as usize;
                acc = u32::from_le_bytes(data[o..o + 4].try_into().expect("4 bytes"));
            }
            0x54 => acc &= k,
            0x05 => pc += k as usize,
            0x15 | 0x25 | 0x35 | 0x45 => {
                let t = match ins.code {
                    0x15 => acc == k,
                    0x25 => acc > k,
                    0x35 => acc >= k,
                    _ => acc & k != 0,
                };
                pc += usize::from(if t { ins.jt } else { ins.jf });
            }
            0x06 => return k,
            c => panic!("unexpected BPF opcode {c:#x} at {}", pc - 1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seccompiler::sock_filter;

    fn ins(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
        sock_filter { code, jt, jf, k }
    }

    #[test]
    fn interprets_loads_jumps_and_returns() {
        // if arch != x86_64 kill; if nr == 1 allow; if arg0 & 0xf0 allow; kill.
        let prog = vec![
            ins(0x20, 0, 0, 4),
            ins(0x15, 1, 0, AUDIT_ARCH_X86_64),
            ins(0x06, 0, 0, RET_KILL_PROCESS),
            ins(0x20, 0, 0, 0),
            ins(0x15, 0, 1, 1),
            ins(0x06, 0, 0, RET_ALLOW),
            ins(0x20, 0, 0, 16),
            ins(0x45, 0, 1, 0xf0),
            ins(0x05, 0, 0, 1),
            ins(0x06, 0, 0, RET_KILL_PROCESS),
            ins(0x06, 0, 0, RET_ALLOW),
        ];
        assert_eq!(run(&prog, AUDIT_ARCH_X86_64, 1, [0; 6]), RET_ALLOW);
        assert_eq!(run(&prog, AUDIT_ARCH_I386, 1, [0; 6]), RET_KILL_PROCESS);
        assert_eq!(
            run(&prog, AUDIT_ARCH_X86_64, 2, [0x10, 0, 0, 0, 0, 0]),
            RET_ALLOW
        );
        assert_eq!(
            run(&prog, AUDIT_ARCH_X86_64, 2, [0x0f, 0, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
    }

    #[test]
    fn unsigned_comparisons() {
        let prog = vec![
            ins(0x20, 0, 0, 0),
            ins(0x25, 2, 0, 10),
            ins(0x35, 2, 0, 10),
            ins(0x06, 0, 0, 1),
            ins(0x06, 0, 0, 3),
            ins(0x06, 0, 0, 2),
        ];
        assert_eq!(run(&prog, 0, 11, [0; 6]), 3);
        assert_eq!(run(&prog, 0, 10, [0; 6]), 2);
        assert_eq!(run(&prog, 0, 9, [0; 6]), 1);
    }
}
