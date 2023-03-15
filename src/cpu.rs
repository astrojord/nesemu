use std::collections::HashMap;
use crate::opcodes;
pub struct CPU {
    pub reg_a: u8,
    pub reg_x: u8,
    pub reg_y: u8,
    pub status: u8,
    pub program_ctr: u16, // increments through sequence of opcodes
    memory: [u8; 0xFFFF], // full address space
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

trait Memory {
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
        self.memory[addr as usize]
    }

    fn mem_write(&mut self, addr: u16, data: u8) { 
        self.memory[addr as usize] = data;
    }
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            reg_a: 0,
            reg_x: 0,
            reg_y: 0,
            status: 0,
            program_ctr: 0,
            memory: [0; 0xFFFF],
        }
    }

    fn get_op_address(&self, mode: &AddressingMode) -> u16 {
        match mode {
            AddressingMode::Immediate => self.program_ctr,

            AddressingMode::ZeroPage  => self.mem_read(self.program_ctr) as u16,
            
            AddressingMode::Absolute => self.mem_read_u16(self.program_ctr),
          
            AddressingMode::ZeroPage_X => {
                let pos = self.mem_read(self.program_ctr);
                let addr = pos.wrapping_add(self.reg_x) as u16;
                addr
            }
            AddressingMode::ZeroPage_Y => {
                let pos = self.mem_read(self.program_ctr);
                let addr = pos.wrapping_add(self.reg_y) as u16;
                addr
            }

            AddressingMode::Absolute_X => {
                let base = self.mem_read_u16(self.program_ctr);
                let addr = base.wrapping_add(self.reg_x as u16);
                addr
            }
            AddressingMode::Absolute_Y => {
                let base = self.mem_read_u16(self.program_ctr);
                let addr = base.wrapping_add(self.reg_y as u16);
                addr
            }

            AddressingMode::Indirect_X => {
                let base = self.mem_read(self.program_ctr);

                let ptr: u8 = (base as u8).wrapping_add(self.reg_x);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            }
            AddressingMode::Indirect_Y => {
                let base = self.mem_read(self.program_ctr);

                let lo = self.mem_read(base as u16);
                let hi = self.mem_read((base as u8).wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                let deref = deref_base.wrapping_add(self.reg_y as u16);
                deref
            }
           
            AddressingMode::NoneAddressing => {
                panic!("mode {:?} is not supported", mode);
            }
        }

    }

    pub fn reset(&mut self) {
        self.reg_a = 0;
        self.reg_x = 0;
        self.reg_y = 0;
        self.status = 0;
        self.program_ctr = self.mem_read_u16(0xFFFC);
    }

    pub fn load(&mut self, program: Vec<u8>) {
        self.memory[0x8000 .. (0x8000 + program.len())].copy_from_slice(&program[..]); // 0x8000 to 0xFFFF reserved for program ROM
        self.mem_write_u16(0xFFFC, 0x8000);
    }

    pub fn run(&mut self) {
        let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            let code = self.mem_read(self.program_ctr);
            self.program_ctr += 1;
            let program_ctr_state = self.program_ctr;

            let opcode = opcodes.get(&code).expect(&format!("opcode {:x} not recognized", code));

            match code {
                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.mode);
                }

                /* STA */
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.mode);
                }
                
                0xAA => self.tax(),
                0xe8 => self.inx(),
                0x00 => return,
                _ => todo!(),
            }

            if program_ctr_state == self.program_ctr {
                self.program_ctr += (opcode.len - 1) as u16;
            }
        }
    }

    pub fn load_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run();
    }

    // opcode functions
    pub fn update_zero_neg_flags(&mut self, result: u8) {
        if result == 0 {
            self.status = self.status | 0b0000_0010;
        } else {
            self.status = self.status & 0b1111_1101;
        }

        if result & 0b1000_0000 != 0 {
            self.status = self.status | 0b1000_0000;
        } else {
            self.status = self.status & 0b0111_1111;
        }
    }

    fn lda(&mut self, mode: &AddressingMode) {
        let addr = self.get_op_address(mode);
        let value = self.mem_read(addr);
       
        self.reg_a = value;
        self.update_zero_neg_flags(self.reg_a);
    }

    fn ldx(&mut self, x: u8) {
        self.reg_x = x;
        self.update_zero_neg_flags(self.reg_x);
    }

    fn tax(&mut self) {
        self.reg_x = self.reg_a;
        self.update_zero_neg_flags(self.reg_x);
    }

    fn inx(&mut self) {
        self.reg_x = self.reg_x.wrapping_add(1);
        self.update_zero_neg_flags(self.reg_x);
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let addr = self.get_op_address(mode);
        self.mem_write(addr, self.reg_a);
    }

    
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_lda() {
        let mut cpu = CPU::new();
        cpu.load_run(vec![0xa9, 0x05, 0x00]);
        assert_eq!(cpu.reg_a, 5);
        assert!(cpu.status & 0b0000_0010 == 0);
        assert!(cpu.status & 0b1000_0000 == 0);
    }

    #[test]
    fn test_lda_zero() {
        let mut cpu = CPU::new();
        cpu.load_run(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status & 0b0000_0010 == 0b10);
    }

    #[test]
    fn test_tax() {
        let mut cpu = CPU::new();
        cpu.load_run(vec![0xa9, 0x0A, 0xaa, 0x00]);

        assert_eq!(cpu.reg_x, 10)
    }

    #[test]
    fn test_5_ops() {
        let mut cpu = CPU::new();
        cpu.load_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.reg_x, 0xc1)
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        cpu.load_run(vec![0xa9, 0xff, 0xaa,0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.reg_x, 1)
    }

    #[test]
    fn test_lda_from_memory() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x10, 0x55);

        cpu.load_run(vec![0xa5, 0x10, 0x00]);

        assert_eq!(cpu.reg_a, 0x55);
    }
}