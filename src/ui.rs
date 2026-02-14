//! UI rendering for Cipher Workshop.

extern crate alloc;
use alloc::format;
use alloc::string::String;

use gam::*;
use graphics_server::api::GlyphStyle;
use graphics_server::{DrawStyle, PixelColor, Point, Rectangle, TextBounds};

use crate::app::*;
use crate::ciphers::*;

const SCREEN_W: i16 = 336;
const HEADER_H: i16 = 30;
const FOOTER_H: i16 = 46;
const LINE_H: i16 = 22;

fn draw_header(gam: &Gam, canvas: Canvas, text: &str) {
    let header_rect = Rectangle::new(
        Point::new(0, 0),
        Point::new(SCREEN_W - 1, HEADER_H - 1),
    );
    gam.draw_rectangle(canvas, header_rect.style(
        DrawStyle::new(PixelColor::Dark, PixelColor::Dark, 0),
    )).ok();

    let tb = TextBounds::BoundingBox(Rectangle::new(
        Point::new(4, 2),
        Point::new(SCREEN_W - 4, HEADER_H - 2),
    ));
    gam.draw_textview(
        canvas,
        tv::TextView::new(tb, text)
            .style(GlyphStyle::Bold)
            .draw_border(false)
            .invert(true),
    ).ok();
}

fn draw_footer(gam: &Gam, canvas: Canvas, text: &str) {
    let y = 536 - FOOTER_H;
    gam.draw_line(canvas, Point::new(0, y), Point::new(SCREEN_W - 1, y),
        DrawStyle::new(PixelColor::Dark, PixelColor::Dark, 1),
    ).ok();

    let tb = TextBounds::BoundingBox(Rectangle::new(
        Point::new(4, y + 4),
        Point::new(SCREEN_W - 4, 536 - 2),
    ));
    gam.draw_textview(
        canvas,
        tv::TextView::new(tb, text)
            .style(GlyphStyle::Small)
            .draw_border(false),
    ).ok();
}

fn draw_text(gam: &Gam, canvas: Canvas, x: i16, y: i16, text: &str, style: GlyphStyle) {
    let tb = TextBounds::BoundingBox(Rectangle::new(
        Point::new(x, y),
        Point::new(SCREEN_W - 4, y + LINE_H),
    ));
    gam.draw_textview(
        canvas,
        tv::TextView::new(tb, text)
            .style(style)
            .draw_border(false),
    ).ok();
}

fn draw_text_inverted(gam: &Gam, canvas: Canvas, x: i16, y: i16, w: i16, text: &str) {
    let bg = Rectangle::new(Point::new(x, y), Point::new(x + w, y + LINE_H));
    gam.draw_rectangle(canvas, bg.style(
        DrawStyle::new(PixelColor::Dark, PixelColor::Dark, 0),
    )).ok();

    let tb = TextBounds::BoundingBox(Rectangle::new(
        Point::new(x + 2, y),
        Point::new(x + w - 2, y + LINE_H),
    ));
    gam.draw_textview(
        canvas,
        tv::TextView::new(tb, text)
            .style(GlyphStyle::Regular)
            .draw_border(false)
            .invert(true),
    ).ok();
}

/// Draw wrapped text, returning next Y position.
fn draw_wrapped(gam: &Gam, canvas: Canvas, x: i16, y: i16, text: &str, max_chars: usize, style: GlyphStyle) -> i16 {
    let mut cy = y;
    let mut pos = 0;
    let chars: alloc::vec::Vec<char> = text.chars().collect();
    while pos < chars.len() {
        let end = (pos + max_chars).min(chars.len());
        let line: String = chars[pos..end].iter().collect();
        draw_text(gam, canvas, x, cy, &line, style);
        cy += LINE_H;
        pos = end;
        if cy > 536 - FOOTER_H - LINE_H {
            break;
        }
    }
    cy
}

pub fn draw(app: &CipherApp, gam: &Gam, canvas: Canvas) {
    gam.draw_rectangle(
        canvas,
        Rectangle::new(Point::new(0, 0), Point::new(SCREEN_W - 1, 535))
            .style(DrawStyle::new(PixelColor::Light, PixelColor::Light, 0)),
    ).ok();

    match app.state {
        AppState::CipherSelect => draw_cipher_select(app, gam, canvas),
        AppState::Input => draw_input(app, gam, canvas),
        AppState::KeyEntry => draw_key_entry(app, gam, canvas),
        AppState::Output => draw_output(app, gam, canvas),
        AppState::Frequency => draw_frequency(app, gam, canvas),
        AppState::Saved => draw_saved(app, gam, canvas),
    }

    gam.redraw().ok();
}

fn draw_cipher_select(app: &CipherApp, gam: &Gam, canvas: Canvas) {
    let mode_label = match app.mode {
        Mode::Encrypt => "ENCRYPT",
        Mode::Decrypt => "DECRYPT",
    };
    let header = format!("Cipher Workshop — {}", mode_label);
    draw_header(gam, canvas, &header);

    let mut y = HEADER_H + 8;
    let ciphers = CipherType::all();
    for (i, cipher) in ciphers.iter().enumerate() {
        let line = format!("{}", cipher.label());
        if i == app.cipher_cursor {
            draw_text_inverted(gam, canvas, 8, y, SCREEN_W - 16, &line);
            y += LINE_H + 2;
            draw_text(gam, canvas, 20, y, cipher.description(), GlyphStyle::Small);
        } else {
            draw_text(gam, canvas, 12, y, &line, GlyphStyle::Regular);
        }
        y += LINE_H + 4;
    }

    draw_footer(
        gam,
        canvas,
        "Up/Down=Select  Enter=Go  M)ode  S)aved  Menu=Quit",
    );
}

fn draw_input(app: &CipherApp, gam: &Gam, canvas: Canvas) {
    let mode_label = match app.mode {
        Mode::Encrypt => "Plaintext",
        Mode::Decrypt => "Ciphertext",
    };
    let header = format!("{} — {}", app.selected_cipher.label(), mode_label);
    draw_header(gam, canvas, &header);

    let mut y = HEADER_H + 10;
    let prompt = format!("Enter {} to {}:", mode_label.to_lowercase(), match app.mode {
        Mode::Encrypt => "encrypt",
        Mode::Decrypt => "decrypt",
    });
    draw_text(gam, canvas, 8, y, &prompt, GlyphStyle::Small);
    y += 18;

    let display = if app.input_text.is_empty() {
        String::from("_")
    } else {
        format!("{}_", app.input_text)
    };
    y = draw_wrapped(gam, canvas, 8, y, &display, 36, GlyphStyle::Regular);
    y += 10;

    draw_text(gam, canvas, 8, y, "Type message, then Enter", GlyphStyle::Small);

    draw_footer(gam, canvas, "Type text + Enter  Backspace=Delete  Menu=Back");
}

fn draw_key_entry(app: &CipherApp, gam: &Gam, canvas: Canvas) {
    let header = format!("{} — Key", app.selected_cipher.label());
    draw_header(gam, canvas, &header);

    let mut y = HEADER_H + 20;

    draw_text(gam, canvas, 8, y, app.selected_cipher.key_hint(), GlyphStyle::Small);
    y += 20;

    match app.selected_cipher {
        CipherType::Caesar => {
            let display = format!("Shift: < {} >  (use </> arrows)", app.caesar_shift);
            draw_text_inverted(gam, canvas, 8, y, SCREEN_W - 16, &display);
            y += LINE_H + 20;

            // Show preview of A→?
            let preview = format!(
                "A -> {}  |  Z -> {}",
                (b'A' + (app.caesar_shift % 26)) as char,
                (b'A' + ((25 + app.caesar_shift as u32) % 26) as u8) as char
            );
            draw_text(gam, canvas, 8, y, &preview, GlyphStyle::Regular);
        }
        CipherType::RailFence => {
            let display = format!("Rails: < {} >  (use </> arrows)", app.rail_count);
            draw_text_inverted(gam, canvas, 8, y, SCREEN_W - 16, &display);
        }
        _ => {
            let display = if app.key_text.is_empty() {
                String::from("_")
            } else {
                format!("{}_", app.key_text)
            };
            draw_text_inverted(gam, canvas, 8, y, SCREEN_W - 16, &display);
        }
    }

    draw_footer(gam, canvas, "Enter=Apply  Menu=Back");
}

fn draw_output(app: &CipherApp, gam: &Gam, canvas: Canvas) {
    let mode_label = match app.mode {
        Mode::Encrypt => "Encrypted",
        Mode::Decrypt => "Decrypted",
    };
    draw_header(gam, canvas, &format!("{} — {}", app.selected_cipher.label(), mode_label));

    let mut y = HEADER_H + 6;

    // Input label
    let in_label = match app.mode {
        Mode::Encrypt => "Plain:",
        Mode::Decrypt => "Cipher:",
    };
    draw_text(gam, canvas, 8, y, in_label, GlyphStyle::Small);
    y += 16;
    y = draw_wrapped(gam, canvas, 8, y, &app.input_text, 38, GlyphStyle::Small);
    y += 6;

    // Separator
    gam.draw_line(canvas, Point::new(8, y), Point::new(SCREEN_W - 8, y),
        DrawStyle::new(PixelColor::Dark, PixelColor::Dark, 1),
    ).ok();
    y += 6;

    // Output
    let out_label = match app.mode {
        Mode::Encrypt => "Cipher:",
        Mode::Decrypt => "Plain:",
    };
    draw_text(gam, canvas, 8, y, out_label, GlyphStyle::Small);
    y += 16;
    draw_wrapped(gam, canvas, 8, y, &app.output_text, 38, GlyphStyle::Regular);

    draw_footer(
        gam,
        canvas,
        "F)req  S)ave  R)everse  Menu=Back",
    );
}

fn draw_frequency(app: &CipherApp, gam: &Gam, canvas: Canvas) {
    draw_header(gam, canvas, "Frequency Analysis");

    let mut y = HEADER_H + 4;
    let max_count = app.freq_data.iter().map(|&(_, c)| c).max().unwrap_or(1);

    let start = app.freq_scroll;
    let end = (start + 18).min(26);

    for i in start..end {
        let (letter, count) = app.freq_data[i];
        let bar = frequency_bar(letter, count, max_count, 20);
        draw_text(gam, canvas, 8, y, &bar, GlyphStyle::Small);
        y += 16;
        if y > 536 - FOOTER_H - 16 {
            break;
        }
    }

    draw_footer(gam, canvas, "Up/Down=Scroll  Enter/Menu=Back");
}

fn draw_saved(app: &CipherApp, gam: &Gam, canvas: Canvas) {
    let header = format!("Saved ({} messages)", app.saved.len());
    draw_header(gam, canvas, &header);

    let mut y = HEADER_H + 4;

    if app.saved.is_empty() {
        draw_text(gam, canvas, 8, y, "No saved messages", GlyphStyle::Regular);
    } else {
        for (i, msg) in app.saved.iter().enumerate() {
            let line = format!(
                "[{}] {} ...",
                msg.cipher_name,
                if msg.plaintext.len() > 20 {
                    &msg.plaintext[..20]
                } else {
                    &msg.plaintext
                }
            );
            if i == app.saved_cursor {
                draw_text_inverted(gam, canvas, 4, y, SCREEN_W - 8, &line);
                y += LINE_H + 2;
                // Show details
                let detail = format!("Key: {}  CT: {}", msg.key_info,
                    if msg.ciphertext.len() > 24 {
                        &msg.ciphertext[..24]
                    } else {
                        &msg.ciphertext
                    }
                );
                draw_text(gam, canvas, 12, y, &detail, GlyphStyle::Small);
            } else {
                draw_text(gam, canvas, 8, y, &line, GlyphStyle::Regular);
            }
            y += LINE_H + 4;
            if y > 536 - FOOTER_H - LINE_H {
                break;
            }
        }
    }

    draw_footer(gam, canvas, "Up/Down=Navigate  D)elete  Menu=Back");
}
