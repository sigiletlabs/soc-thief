//! The org palette, as truecolor.

use crate::snapshot::{Category, Status, Tuning};
use ratatui::style::{Color, Modifier, Style};

pub const BG: Color = Color::Rgb(0x07, 0x08, 0x0a);
pub const PANEL: Color = Color::Rgb(0x14, 0x16, 0x1b);
pub const PANEL_HI: Color = Color::Rgb(0x1d, 0x20, 0x27);
pub const BORDER: Color = Color::Rgb(0x2a, 0x2f, 0x37);
pub const TEXT: Color = Color::Rgb(0xc9, 0xd1, 0xd9);
pub const DIM: Color = Color::Rgb(0x8b, 0x94, 0x9e);
pub const AMBER: Color = Color::Rgb(0xf2, 0xcc, 0x60);
pub const ORANGE: Color = Color::Rgb(0xe8, 0x89, 0x3a);
pub const GREEN: Color = Color::Rgb(0x7e, 0xe7, 0x87);
pub const RED: Color = Color::Rgb(0xff, 0x4d, 0x6d);

pub fn base() -> Style {
    Style::new().fg(TEXT).bg(BG)
}

pub fn panel() -> Style {
    Style::new().fg(TEXT).bg(PANEL)
}

pub fn border() -> Style {
    Style::new().fg(BORDER)
}

pub fn label() -> Style {
    Style::new().fg(DIM).add_modifier(Modifier::BOLD)
}

pub fn title() -> Style {
    Style::new().fg(AMBER).add_modifier(Modifier::BOLD)
}

pub fn status(s: &Status) -> Style {
    let c = match s {
        Status::Ok => GREEN,
        Status::Attention => ORANGE,
        Status::Failed => RED,
        Status::Unknown => DIM,
    };
    Style::new().fg(c).add_modifier(Modifier::BOLD)
}

pub fn category(c: Category) -> Style {
    let col = match c {
        Category::Failed => RED,
        Category::New => AMBER,
        Category::Spike => ORANGE,
        Category::Recurring => DIM,
        Category::Unknown => DIM,
    };
    Style::new().fg(col).add_modifier(Modifier::BOLD)
}

pub fn tuning(t: Tuning) -> Style {
    match t {
        Tuning::None => Style::new().fg(DIM),
        Tuning::Low => Style::new().fg(ORANGE),
        Tuning::Mute => Style::new().fg(RED),
        Tuning::Unknown => Style::new().fg(DIM),
    }
}

pub fn alarm() -> Style {
    Style::new().fg(BG).bg(RED).add_modifier(Modifier::BOLD)
}

pub fn badge() -> Style {
    Style::new().fg(BG).bg(AMBER).add_modifier(Modifier::BOLD)
}
