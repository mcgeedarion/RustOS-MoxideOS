//! 16550 UART serial driver (COM1 = 0x3F8).

const COM1: u16 = 0x3F8;

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("outb %al, %dx", in("dx") port, in("al") val, options(att_syntax));
}
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("inb %dx, %al", out("al") v, in("dx") port, options(att_syntax, nostack));
    v
}

pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00); // disable interrupts
        outb(COM1 + 3, 0x80); // DLAB on
        outb(COM1 + 0, 0x03); // 38400 baud lo
        outb(COM1 + 1, 0x00); // baud hi
        outb(COM1 + 3, 0x03); // 8N1, DLAB off
        outb(COM1 + 2, 0xC7); // FIFO 14-byte
        outb(COM1 + 4, 0x0B); // RTS+DTR
    }
}

pub fn write_byte(b: u8) {
    unsafe {
        while inb(COM1 + 5) & 0x20 == 0 {}
        outb(COM1, b);
        if b == b'\n' { write_byte(b'\r'); }
    }
}

pub fn write_str(s: &str) { for b in s.bytes() { write_byte(b); } }
