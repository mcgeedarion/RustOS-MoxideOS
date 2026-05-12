//! Wayland compositor surface management.

use alloc::vec::Vec;

/// A Wayland surface — the basic unit of compositing.
pub struct Surface {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub buffer_id: Option<u32>,
    pub x: i32,
    pub y: i32,
    pub visible: bool,
}

impl Surface {
    pub fn new(id: u32) -> Self {
        Self { id, width: 0, height: 0, buffer_id: None, x: 0, y: 0, visible: false }
    }

    pub fn attach_buffer(&mut self, buffer_id: u32, width: u32, height: u32) {
        self.buffer_id = Some(buffer_id);
        self.width = width;
        self.height = height;
    }

    pub fn commit(&mut self) {
        self.visible = self.buffer_id.is_some();
    }
}

/// The compositor manages a Z-ordered list of surfaces.
pub struct Compositor {
    surfaces: Vec<Surface>,
    next_id: u32,
}

impl Compositor {
    pub fn new() -> Self {
        Self { surfaces: Vec::new(), next_id: 1 }
    }

    pub fn create_surface(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.surfaces.push(Surface::new(id));
        id
    }

    pub fn destroy_surface(&mut self, id: u32) {
        self.surfaces.retain(|s| s.id != id);
    }

    pub fn get_surface_mut(&mut self, id: u32) -> Option<&mut Surface> {
        self.surfaces.iter_mut().find(|s| s.id == id)
    }

    pub fn visible_surfaces(&self) -> impl Iterator<Item = &Surface> {
        self.surfaces.iter().filter(|s| s.visible)
    }
}
