use std::collections::HashMap;
use crate::opcodes;
use crate::bus::Bus;

bitflags! {
    // http://wiki.nesdev.com/w/index.php/Status_flags
    // NV_BDIZC (b7 to b0)
    // C = carry, Z = zero, I = interrupt disable, D = decimal (not used)
    // B = break, V = overflow, N = negative
    pub struct CpuFlags: u8 {
        const CARRY = 0b00000001;
        const ZERO = 0b00000010;
        const INTERRUPT_DISABLE = 0b00000100;
        const DECIMAL_MODE = 0b00001000;
        const BREAK = 0b00010000;
        const BREAK2 = 0b00100000;
        const OVERFLOW = 0b01000000;
        const NEGATIV = 0b10000000;
    }
}

const STACK: u16 = 0x0100;
const STACK_RESET: u8 = 0xfd;
pub struct CPU {
    pub reg_a: u8,
    pub reg_x: u8,
    pub reg_y: u8,
    pub status: CpuFlags,
    pub program_ctr: u16, // increments through sequence of opcodes
    pub stack_ptr: u8,
    pub bus: Bus, // replaces direct memory access
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum AddressingMode {
    Immediate,
    ZeroPage,
    ZeroPage_X,
    ZeroPage_Y,
    Absolute,
    Absolute_X,
    Absolute_Y,
    Indirect_X,
    Indirect_Y,
    NoneAddressing,
}

pub trait Memory {
    fn mem_read(&self, addr: u16) -> u8; 

    fn mem_write(&mut self, addr: u16, data: u8);
    
    // needed for little endian NES addressing
    fn mem_read_u16(&self, pos: u16) -> u16 {
        let lo = self.mem_read(pos) as u16;
        let hi = self.mem_read(pos + 1) as u16;
        (hi << 8) | (lo as u16)
    }

    // needed for little endian NES addressing
    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(pos, lo);
        self.mem_write(pos + 1, hi);
    }
}


impl Memory for CPU {
    fn mem_read(&self, addr: u16) -> u8 {
        self.bus.mem_read(addr)
    }
 
    fn mem_write(&mut self, addr: u16, data: u8) {
        self.bus.mem_write(addr, data)
    }
    fn mem_read_u16(&self, pos: u16) -> u16 {
        self.bus.mem_read_u16(pos)
    }
  
    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        self.bus.mem_write_u16(pos, data)
    }
 }

impl CPU {
    pub fn new(bus: Bus) -> Self {
        CPU {
            reg_a: 0,
            reg_x: 0,
            reg_y: 0,
            status: CpuFlags::from_bits_truncate(0b100100),
            program_ctr: 0,
            stack_ptr: STACK_RESET,
            bus: bus,
        }
    }

    pub fn get_absolute_address(&self, mode: &AddressingMode, addr: u16) -> u16 {
        match mode {
            AddressingMode::ZeroPage => self.mem_read(addr) as u16,

            AddressingMode::Absolute => self.mem_read_u16(addr),

            AddressingMode::ZeroPage_X => {
                let pos = self.mem_read(addr);
                let addr = pos.wrapping_add(self.reg_x) as u16;
                addr
            }
            AddressingMode::ZeroPage_Y => {
                let pos = self.mem_read(addr);
                let addr = pos.wrapping_add(self.reg_y) as u16;
                addr
            }

            AddressingMode::Absolute_X => {
                let base = self.mem_read_u16(addr);
                let addr = base.wrapping_add(self.reg_x as u16);
                addr
            }
            AddressingMode::Absolute_Y => {
                let base = self.mem_read_u16(addr);
                let addr = base.wrapping_add(self.reg_y as u16);
                addr
            }

            AddressingMode::Indirect_X => {
                let base = self.mem_read(addr);

                let ptr: u8 = (base as u8).wrapping_add(self.reg_x);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            }
            AddressingMode::Indirect_Y => {
                let base = self.mem_read(addr);

                let lo = self.mem_read(base as u16);
                let hi = self.mem_read((base as u8).wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                let deref = deref_base.wrapping_add(self.reg_y as u16);
                deref
            }

            _ => {
                panic!("mode {:?} is not supported", mode);
            }
        }
    }

    fn get_op_address(&self, mode: &AddressingMode) -> u16 {
        match mode {
            AddressingMode::Immediate => self.program_ctr,
            _ => self.get_absolute_address(mode, self.program_ctr),
        }
    }

    pub fn reset(&mut self) {
        self.reg_a = 0;
        self.reg_x = 0;
        self.reg_y = 0;
        self.status = CpuFlags::from_bits_truncate(0b100100);
        self.stack_ptr = STACK_RESET;
        self.program_ctr = self.mem_read_u16(0xFFFC);
    }

    pub fn load(&mut self, program: Vec<u8>) {
        for i in 0..(program.len() as u16) {
            self.mem_write(0x0600 + i, program[i as usize]);
        }
        self.mem_write_u16(0xFFFC, 0x0600);
    }

    pub fn run(&mut self) {
        self.run_with_callback(|_| {});
    }

    pub fn run_with_callback<F>(&mut self, mut callback: F)
    where F: FnMut(&mut CPU),
    {
        let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            let code = self.mem_read(self.program_ctr);
            self.program_ctr += 1;
            let program_ctr_state = self.program_ctr;

            let opcode = opcodes.get(&code).unwrap();

            match code {
                /* ----- loads/stores ----- */
                // LDA
                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.mode);
                }

                // LDX
                0xa2 | 0xa6 | 0xb6 | 0xae | 0xbe => {
                    self.ldx(&opcode.mode);
                }

                // LDY
                0xa0 | 0xa4 | 0xb4 | 0xac | 0xbc => {
                    self.ldy(&opcode.mode);
                }

                // STA
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.mode);
                }

                // STX
                0x86 | 0x96 | 0x8e => {
                    self.stx(&opcode.mode);
                }

                // STY
                0x84 | 0x94 | 0x8c => {
                    self.sty(&opcode.mode);
                }

                /* ----- transfers ----- */
                // TAX
                0xAA => {
                    self.reg_x = self.reg_a;
                    self.update_zero_neg_flags(self.reg_x);
                }

                // TXA
                0x8A => {
                    self.reg_a = self.reg_x;
                    self.update_zero_neg_flags(self.reg_a);
                }

                // TAY
                0xA8 => {
                    self.reg_y = self.reg_a;
                    self.update_zero_neg_flags(self.reg_y);
                }

                // TYA
                0x98 => {
                    self.reg_a = self.reg_y;
                    self.update_zero_neg_flags(self.reg_a);
                }

                // TSX
                0xBA => {
                    self.reg_x = self.stack_ptr;
                    self.update_zero_neg_flags(self.reg_x);
                }

                // TXS
                0x9a => {
                    self.stack_ptr = self.reg_x;
                }

                /* ----- flag clears/sets ----- */
                // CLC
                0x18 => self.clear_carry_flag(),

                // CLD 
                0xd8 => self.status.remove(CpuFlags::DECIMAL_MODE),

                // CLI
                0x58 => self.status.remove(CpuFlags::INTERRUPT_DISABLE),

                // CLV
                0xb8 => self.status.remove(CpuFlags::OVERFLOW),

                // SEC
                0x38 => self.set_carry_flag(),

                // SED 
                0xf8 => self.status.insert(CpuFlags::DECIMAL_MODE),

                // SEI
                0x78 => self.status.insert(CpuFlags::INTERRUPT_DISABLE),

                /* ----- shifts/increments/compares ----- */
                // ASL
                0x0a => self.asl_accumulator(),
                0x06 | 0x16 | 0x0e | 0x1e => {
                    self.asl(&opcode.mode);
                }

                // LSR
                0x4a => self.lsr_accumulator(),
                0x46 | 0x56 | 0x4e | 0x5e => {
                    self.lsr(&opcode.mode);
                }

                // ROL
                0x2a => self.rol_accumulator(),
                0x26 | 0x36 | 0x2e | 0x3e => {
                    self.rol(&opcode.mode);
                }

                // ROR
                0x6a => self.ror_accumulator(),
                0x66 | 0x76 | 0x6e | 0x7e => {
                    self.ror(&opcode.mode);
                }

                // INC
                0xe6 | 0xf6 | 0xee | 0xfe => {
                    self.inc(&opcode.mode);
                }

                // INX
                0xe8 => self.inx(),

                // INY
                0xc8 => self.iny(),

                // DEC 
                0xc6 | 0xd6 | 0xce | 0xde => {
                    self.dec(&opcode.mode);
                }

                // DEX
                0xca => self.dex(),

                // DEY
                0x88 => self.dey(),

                // CMP
                0xc9 | 0xc5 | 0xd5 | 0xcd | 0xdd | 0xd9 | 0xc1 | 0xd1 => self.compare(&opcode.mode, self.reg_a),

                // CPX
                0xe0 | 0xe4 | 0xec => self.compare(&opcode.mode, self.reg_x),

                // CPY
                0xc0 | 0xc4 | 0xcc => self.compare(&opcode.mode, self.reg_y),

                /* ----- arithmetic ----- */
                // ADC
                0x69 | 0x65 | 0x75 | 0x6d | 0x7d | 0x79 | 0x61 | 0x71 => {
                    self.adc(&opcode.mode);
                }

                // AND
                0x29 | 0x25 | 0x35 | 0x2d | 0x3d | 0x39 | 0x21 | 0x31 => {
                    self.and(&opcode.mode);
                }

                // EOR
                0x49 | 0x45 | 0x55 | 0x4d | 0x5d | 0x59 | 0x41 | 0x51 => {
                    self.eor(&opcode.mode);
                }

                // ORA
                0x09 | 0x05 | 0x15 | 0x0d | 0x1d | 0x19 | 0x01 | 0x11 => {
                    self.ora(&opcode.mode);
                }

                // SBC
                0xe9 | 0xe5 | 0xf5 | 0xed | 0xfd | 0xf9 | 0xe1 | 0xf1 => {
                    self.sbc(&opcode.mode);
                }

                /* ----- branching ----- */
                // BCC
                0x90 => self.branch(!self.status.contains(CpuFlags::CARRY)),

                // BCS
                0xb0 => self.branch(self.status.contains(CpuFlags::CARRY)),

                // BEQ
                0xf0 => self.branch(self.status.contains(CpuFlags::ZERO)),

                // BMI
                0x30 => self.branch(self.status.contains(CpuFlags::NEGATIV)),

                // BNE
                0xd0 => self.branch(!self.status.contains(CpuFlags::ZERO)),

                // BPL
                0x10 => self.branch(!self.status.contains(CpuFlags::NEGATIV)),

                // BVC
                0x50 => self.branch(!self.status.contains(CpuFlags::OVERFLOW)),

                // BVS
                0x70 => self.branch(self.status.contains(CpuFlags::OVERFLOW)),

                // JMP absolute
                0x4c => {
                    // set program ctr to address given by operand
                    self.program_ctr = self.mem_read_u16(self.program_ctr);
                }

                // JMP indirect
                0x6c => {
                    let addr = self.mem_read_u16(self.program_ctr);
                    // 6502 bug if indirect ref address includes page boundary xxFF - will take lsb from xxFF but msb from xx00
                    // ensure that the indirect ref isn't on a page boundary
                    let indirect_ref = 
                        if (addr & 0x00FF) == 0x00FF {
                            let lo = self.mem_read(addr);
                            let hi = self.mem_read(addr & 0xFF00);
                            (hi as u16) << 8 | (lo as u16)
                        } else {
                            self.mem_read_u16(addr)
                        };
                    self.program_ctr = indirect_ref;
                }

                // JSR
                0x20 => {
                    self.stack_push_u16(self.program_ctr + 2 - 1);
                    self.program_ctr = self.mem_read_u16(self.program_ctr);
                }

                // RTS
                0x60 => {
                    self.program_ctr = self.stack_pop_u16() + 1;
                }

                // RTI
                0x40 => {
                    // get flags from the stack, then pop the counter
                    self.status.bits = self.stack_pop();
                    self.status.remove(CpuFlags::BREAK);
                    self.status.insert(CpuFlags::BREAK2);
                    self.program_ctr = self.stack_pop_u16();
                }

                // BIT
                0x24 | 0x2c => self.bit(&opcode.mode),

                /* ----- stack ----- */
                // PHA
                0x48 => self.stack_push(self.reg_a),

                // PHP
                0x08 => {
                    // BREAK and BREAK2 are always set
                    let mut flags = self.status.clone();
                    flags.insert(CpuFlags::BREAK);
                    flags.insert(CpuFlags::BREAK2);
                    self.stack_push(flags.bits());
                }

                // PLA
                0x68 => {
                    let data = self.stack_pop();
                    self.set_reg_a(data);
                }

                // PLP
                0x28 => {
                    self.status.bits = self.stack_pop();
                    self.status.remove(CpuFlags::BREAK);
                    self.status.insert(CpuFlags::BREAK2);
                }

                /* ----- other ----- */
                0x00 => return, // BRK
                0xea => {}, // NOP
                _ => todo!(),
            }

            if program_ctr_state == self.program_ctr {
                self.program_ctr += (opcode.len - 1) as u16;
            }

            callback(self);
        }
    }

    pub fn load_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run();
    }

    /* ----- opcode functions ----- */
    pub fn update_zero_neg_flags(&mut self, result: u8) {
        if result == 0 {
            self.status.insert(CpuFlags::ZERO);
        } else {
            self.status.remove(CpuFlags::ZERO);
        }

        if result & 0b1000_0000 != 0 {
            self.status.insert(CpuFlags::NEGATIV);
        } else {
            self.status.remove(CpuFlags::NEGATIV);
        }
    }

    // loads/stores
    fn lda(&mut self, mode: &AddressingMode) { // load A
        let addr = self.get_op_address(mode);
        let value = self.mem_read(addr);
       
        self.reg_a = value;
        self.update_zero_neg_flags(self.reg_a);
    }

    fn ldx(&mut self, mode: &AddressingMode) { // load X
        let addr = self.get_op_address(mode);
        let data = self.mem_read(addr);
        self.reg_x = data;
        self.update_zero_neg_flags(self.reg_x);
    }

    fn ldy(&mut self, mode: &AddressingMode) { // load Y
        let addr = self.get_op_address(mode);
        let data = self.mem_read(addr);
        self.reg_y = data;
        self.update_zero_neg_flags(self.reg_y);
    }

    fn sta(&mut self, mode: &AddressingMode) { // store A
        let addr = self.get_op_address(mode);
        self.mem_write(addr, self.reg_a);
    }

    fn stx(&mut self, mode: &AddressingMode) { // store X 
        let addr = self.get_op_address(mode);
        self.mem_write(addr, self.reg_x);
    }

    fn sty(&mut self, mode: &AddressingMode) { // store Y 
        let addr = self.get_op_address(mode);
        self.mem_write(addr, self.reg_y);
    }

    // arithmetic
    fn set_reg_a(&mut self, value: u8) {
        self.reg_a = value;
        self.update_zero_neg_flags(self.reg_a);
    }
    
    fn add_to_a(&mut self, data: u8) { // used for both ADC and SBC
        // do the addition (using carry flag)
        let sum = self.reg_a as u16 + data as u16
                       + (if self.status.contains(CpuFlags::CARRY) {1} else {0}) as u16;

        // set/clear carry flag based on result
        if sum > 0xff {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        // set/clear overflow flag based on result
        // formula from https://www.righto.com/2012/12/the-6502-overflow-flag-explained.html
        let result = sum as u8;
        if (data ^ result) & (result ^ self.reg_a) & 0x80 != 0 {
            self.status.insert(CpuFlags::OVERFLOW);
        } else {
            self.status.remove(CpuFlags::OVERFLOW);
        }
    }

    fn adc(&mut self, mode: &AddressingMode) { // add with carry
        // don't need to worry about decimal mode
        let addr = self.get_op_address(mode);
        self.add_to_a(self.mem_read(addr));
    }

    fn sbc(&mut self, mode: &AddressingMode) { // subtract with carry
        // M - N - borrow B = M - N - (1-C) + 256 = M + (one's complement of N) + C
        let addr = self.get_op_address(mode);
        let data = self.mem_read(addr);
        let complement = (data as i8).wrapping_neg().wrapping_sub(1) as u8;
        self.add_to_a(complement);
    }

    fn and(&mut self, mode: &AddressingMode) { // logical and with register A
        let addr = self.get_op_address(mode);
        let data = self.mem_read(addr);
        self.set_reg_a(data & self.reg_a);
    }

    fn eor(&mut self, mode: &AddressingMode) { // logical xor with register A
        let addr = self.get_op_address(mode);
        let data = self.mem_read(addr);
        self.set_reg_a(data ^ self.reg_a);
    }

    fn ora(&mut self, mode: &AddressingMode) { // logical or with register A
        let addr = self.get_op_address(mode);
        let data = self.mem_read(addr);
        self.set_reg_a(data | self.reg_a);
    }

    // shifts/increments/compares
    fn inc(&mut self, mode: &AddressingMode) -> u8 { // increment memory
        let addr = self.get_op_address(mode);
        let mut data = self.mem_read(addr);
        data = data.wrapping_add(1);
        self.mem_write(addr, data);
        self.update_zero_neg_flags(data);
        data
    }

    fn inx(&mut self) { // increment X
        self.reg_x = self.reg_x.wrapping_add(1);
        self.update_zero_neg_flags(self.reg_x);
    }

    fn iny(&mut self) { // increment Y
        self.reg_y = self.reg_y.wrapping_add(1);
        self.update_zero_neg_flags(self.reg_y);
    }

    fn dec(&mut self, mode: &AddressingMode) -> u8 { // decrement memory
        let addr = self.get_op_address(mode);
        let data = self.mem_read(addr);
        self.mem_write(addr, data.wrapping_sub(1));
        self.update_zero_neg_flags(data);
        data
    }

    fn dex(&mut self) { // decrement X
        self.reg_x = self.reg_x.wrapping_sub(1);
        self.update_zero_neg_flags(self.reg_x);
    }

    fn dey(&mut self) { // decrement Y
        self.reg_y = self.reg_y.wrapping_sub(1);
        self.update_zero_neg_flags(self.reg_y);
    }

    fn compare(&mut self, mode: &AddressingMode, compare_to: u8) { // set carry flag if address data <= compare_to, set zero flag if data = compare_to
        let addr = self.get_op_address(mode);
        let data = self.mem_read(addr);
        if data <= compare_to {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY)
        }
        self.update_zero_neg_flags(compare_to.wrapping_sub(data));
    }

    fn bit(&mut self, mode: &AddressingMode) { // bit test
        let addr = self.get_op_address(mode);
        let data = self.mem_read(addr);

        // determine zero flag with (A & data)
        if (self.reg_a & data) == 0 {
            self.status.insert(CpuFlags::ZERO);
        } else {
            self.status.remove(CpuFlags::ZERO);
        }
        
        // set bits 6 and 7 to V and N
        self.status.set(CpuFlags::OVERFLOW, data & 0b01000000 > 0);
        self.status.set(CpuFlags::NEGATIV, data & 0b10000000 > 0);

    }
    
    fn asl_accumulator(&mut self) { // arithmetic shift left on reg a
        let mut data = self.reg_a;
        if data >> 7 == 1 {
            self.set_carry_flag();
        } else {
            self.clear_carry_flag();
        }
        data = data << 1;
        self.set_reg_a(data);
    }

    fn asl(&mut self, mode: &AddressingMode) -> u8 { // arithmetic shift left
        let addr = self.get_op_address(mode);
        let mut data = self.mem_read(addr);
        if data >> 7 == 1 {
            self.set_carry_flag();
        } else {
            self.clear_carry_flag();
        }
        data = data << 1;
        self.mem_write(addr, data);
        self.update_zero_neg_flags(data);
        data
    }

    fn lsr_accumulator(&mut self) { // logical shift right on reg a
        let mut data = self.reg_a;
        if data & 1 == 1 {
            self.set_carry_flag();
        } else {
            self.clear_carry_flag();
        }
        data = data >> 1;
        self.set_reg_a(data);
    }

    fn lsr(&mut self, mode: &AddressingMode) -> u8 { // logical shift right
        let addr = self.get_op_address(mode);
        let mut data = self.mem_read(addr);
        if data & 1 == 1 {
            self.set_carry_flag();
        } else {
            self.clear_carry_flag();
        }
        data = data >> 1;
        self.mem_write(addr, data);
        self.update_zero_neg_flags(data);
        data
    }

    fn rol_accumulator(&mut self) { // rotate left on reg a
        let mut data = self.reg_a;
        let carry = self.status.contains(CpuFlags::CARRY);
        if data >> 7 == 1 {
            self.set_carry_flag();
        } else {
            self.clear_carry_flag();
        }
        data = data << 1;
        if carry {
            data = data | 1;
        }
        self.set_reg_a(data);
    }

    fn rol(&mut self, mode: &AddressingMode) -> u8 { // rotate left
        let addr = self.get_op_address(mode);
        let mut data = self.mem_read(addr);
        let carry = self.status.contains(CpuFlags::CARRY);
        if data >> 7 == 1 {
            self.set_carry_flag();
        } else {
            self.clear_carry_flag();
        }
        data = data << 1;
        if carry {
            data = data | 1;
        }
        self.mem_write(addr, data);
        self.update_zero_neg_flags(data);
        data
    }

    fn ror_accumulator(&mut self) { // rotate right on reg a
        let mut data = self.reg_a;
        let carry = self.status.contains(CpuFlags::CARRY);
        if data & 1 == 1 {
            self.set_carry_flag();
        } else {
            self.clear_carry_flag();
        }
        data = data >> 1;
        if carry {
            data = data | 1;
        }
        self.set_reg_a(data);
    }

    fn ror(&mut self, mode: &AddressingMode) -> u8 { // rotate right
        let addr = self.get_op_address(mode);
        let mut data = self.mem_read(addr);
        let carry = self.status.contains(CpuFlags::CARRY);
        if data & 1 == 1 {
            self.set_carry_flag();
        } else {
            self.clear_carry_flag();
        }
        data = data >> 1;
        if carry {
            data = data | 1;
        }
        self.mem_write(addr, data);
        self.update_zero_neg_flags(data);
        data
    }

    // branching implemented in run()
    fn branch(&mut self, condition: bool) {
        if condition {
            let jump: i8 = self.mem_read(self.program_ctr) as i8;
            let jump_addr = self.program_ctr.wrapping_add(1).wrapping_add(jump as u16);
            self.program_ctr = jump_addr
        }
    }

    // stack
    fn stack_pop(&mut self) -> u8 {
        self.stack_ptr = self.stack_ptr.wrapping_add(1);
        self.mem_read((STACK as u16) + self.stack_ptr as u16)
    }

    fn stack_push(&mut self, data: u8) {
        self.mem_write((STACK as u16) + self.stack_ptr as u16, data);
        self.stack_ptr = self.stack_ptr.wrapping_sub(1)
    }

    fn stack_push_u16(&mut self, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.stack_push(hi);
        self.stack_push(lo);
    }

    fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop() as u16;
        let hi = self.stack_pop() as u16;

        hi << 8 | lo
    }

    // flag clears/sets implemented in run()
    fn set_carry_flag(&mut self) {
        self.status.insert(CpuFlags::CARRY)
    }

    fn clear_carry_flag(&mut self) {
        self.status.remove(CpuFlags::CARRY)
    }
    
    // transfers implemented in run()   
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cartridge::test;

    #[test]
    fn test_lda() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_run(vec![0xa9, 0x05, 0x00]);
        assert_eq!(cpu.reg_a, 5);
        assert!(cpu.status.bits() & 0b0000_0010 == 0b00);
        assert!(cpu.status.bits() & 0b1000_0000 == 0);
    }

    #[test]
    fn test_tax() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.reg_a = 10;
        cpu.load_run(vec![0xaa, 0x00]);

        assert_eq!(cpu.reg_x, 10)
    }

    #[test]
    fn test_5_ops() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.reg_x, 0xc1)
    }

    #[test]
    fn test_inx_overflow() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.reg_x = 0xff;
        cpu.load_run(vec![0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.reg_x, 1)
    }

    #[test]
    fn test_lda_from_memory() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x10, 0x55);

        cpu.load_run(vec![0xa5, 0x10, 0x00]);

        assert_eq!(cpu.reg_a, 0x55);
    }
}