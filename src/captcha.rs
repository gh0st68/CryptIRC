// captcha.rs — self-contained distorted math-question CAPTCHA.
//
// No image/font crates: we ship a tiny 5x7 bitmap font for the handful of glyphs a
// math question needs (digits, + - x = ?), draw the question onto an RGB buffer with
// per-glyph jitter, a sine warp, interference lines and speckle noise, then encode it
// as a PNG by hand (stored-deflate zlib + CRC32/Adler32). The rendered text lives only
// in pixels — it is never present as machine-readable text/SVG in the response — so a
// bot has to actually OCR the warped image. (Honest scope: this stops scripts and casual
// scrapers and raises the bar a lot; no homemade captcha is fully proof against a
// determined modern OCR/AI, but combined with rate limits it makes bulk signup costly.)

use rand::Rng;

pub struct Captcha {
    /// The numeric answer the user must type.
    pub answer: i64,
    /// PNG bytes (RGB) of the rendered, distorted question.
    pub png: Vec<u8>,
}

/// Build a fresh captcha: a random simple arithmetic problem + its rendered image.
pub fn generate() -> Captcha {
    let mut rng = rand::thread_rng();
    let (text, answer) = make_problem(&mut rng);
    let png = render(&text, &mut rng);
    Captcha { answer, png }
}

fn make_problem<R: Rng>(rng: &mut R) -> (String, i64) {
    // EASY problems (small single-digit-ish operands) — but a mix of +/-/x so the answer
    // isn't one obvious number. The per-IP register/login throttles are the real anti-bot bound.
    match rng.gen_range(0..3) {
        0 => { let a = rng.gen_range(2..=12); let b = rng.gen_range(1..=9); (format!("{} + {} = ?", a, b), a + b) }
        1 => { let a = rng.gen_range(8..=15); let b = rng.gen_range(1..=7); (format!("{} - {} = ?", a, b), a - b) }
        _ => { let a = rng.gen_range(2..=9);  let b = rng.gen_range(2..=3); (format!("{} x {} = ?", a, b), a * b) }
    }
}

// ── 5x7 bitmap font ─────────────────────────────────────────────────────────
// Each glyph is 7 rows; the low 5 bits of each byte are the columns (bit4 = leftmost).
fn glyph(c: char) -> [u8; 7] {
    match c {
        '0' => [0x0E,0x11,0x13,0x15,0x19,0x11,0x0E],
        '1' => [0x04,0x0C,0x04,0x04,0x04,0x04,0x0E],
        '2' => [0x0E,0x11,0x01,0x02,0x04,0x08,0x1F],
        '3' => [0x1F,0x02,0x04,0x02,0x01,0x11,0x0E],
        '4' => [0x02,0x06,0x0A,0x12,0x1F,0x02,0x02],
        '5' => [0x1F,0x10,0x1E,0x01,0x01,0x11,0x0E],
        '6' => [0x06,0x08,0x10,0x1E,0x11,0x11,0x0E],
        '7' => [0x1F,0x01,0x02,0x04,0x08,0x08,0x08],
        '8' => [0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E],
        '9' => [0x0E,0x11,0x11,0x0F,0x01,0x02,0x0C],
        '+' => [0x00,0x04,0x04,0x1F,0x04,0x04,0x00],
        '-' => [0x00,0x00,0x00,0x1F,0x00,0x00,0x00],
        'x' => [0x00,0x00,0x11,0x0A,0x04,0x0A,0x11],
        '=' => [0x00,0x00,0x1F,0x00,0x1F,0x00,0x00],
        '?' => [0x0E,0x11,0x01,0x02,0x04,0x00,0x04],
        _   => [0x00,0x00,0x00,0x00,0x00,0x00,0x00], // space / unknown
    }
}

const GW: usize = 5;   // glyph width  (font cells)
const GH: usize = 7;   // glyph height (font cells)

fn render<R: Rng>(text: &str, rng: &mut R) -> Vec<u8> {
    let scale: usize = 6;
    let gap: usize = 7;
    let pad: usize = 16;
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let content_w = n * GW * scale + n.saturating_sub(1) * gap;
    let w = content_w + 2 * pad;
    let h = GH * scale + 2 * pad;

    // Background: a clean, light tone (subtle per-pixel noise only) so the digits stay easy
    // to read.
    let bg = (rng.gen_range(236..=249), rng.gen_range(236..=249), rng.gen_range(236..=249));
    // Foreground: a dark, high-contrast tone for legibility.
    let fg = (rng.gen_range(10..=42), rng.gen_range(10..=42), rng.gen_range(10..=42));

    let mut buf = vec![0u8; w * h * 3];
    let put = |buf: &mut [u8], x: usize, y: usize, c: (u8, u8, u8)| {
        if x < w && y < h {
            let i = (y * w + x) * 3;
            buf[i] = c.0; buf[i + 1] = c.1; buf[i + 2] = c.2;
        }
    };
    // Fill background with light speckle noise.
    for y in 0..h {
        for x in 0..w {
            let jitter = rng.gen_range(-6i32..=6) as i32;
            let cl = |v: i32| v.clamp(0, 255) as u8;
            put(&mut buf, x, y, (cl(bg.0 as i32 + jitter), cl(bg.1 as i32 + jitter), cl(bg.2 as i32 + jitter)));
        }
    }

    // Draw each glyph with independent jitter + slight colour variation.
    for (i, &ch) in chars.iter().enumerate() {
        let g = glyph(ch);
        let jx = rng.gen_range(-1i32..=1);
        let jy = rng.gen_range(-2i32..=2);
        let vary = |base: u8, r: &mut R| -> u8 {
            (base as i32 + r.gen_range(-6i32..=6)).clamp(0, 255) as u8
        };
        let gc = (vary(fg.0, rng), vary(fg.1, rng), vary(fg.2, rng));
        let x0 = pad as i32 + (i * (GW * scale + gap)) as i32 + jx;
        let y0 = pad as i32 + jy;
        for r in 0..GH {
            let row = g[r];
            for c in 0..GW {
                if (row >> (GW - 1 - c)) & 1 == 1 {
                    // Draw a scale x scale block for this font pixel.
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = x0 + (c * scale + dx) as i32;
                            let py = y0 + (r * scale + dy) as i32;
                            if px >= 0 && py >= 0 { put(&mut buf, px as usize, py as usize, gc); }
                        }
                    }
                }
            }
        }
    }

    // Interference: ONE thin, light line through the text — enough to break naive OCR
    // without obscuring the digits.
    let mid = (rng.gen_range(150..=190), rng.gen_range(150..=190), rng.gen_range(150..=190));
    for _ in 0..1 {
        let (mut x0, mut y0) = (rng.gen_range(0..w) as i32, rng.gen_range(0..h) as i32);
        let (x1, y1) = (rng.gen_range(0..w) as i32, rng.gen_range(0..h) as i32);
        // Bresenham
        let dx = (x1 - x0).abs(); let sx = if x0 < x1 { 1 } else { -1 };
        let dy = -(y1 - y0).abs(); let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;
        loop {
            put(&mut buf, x0 as usize, y0 as usize, mid);
            if x0 == x1 && y0 == y1 { break; }
            let e2 = 2 * err;
            if e2 >= dy { err += dy; x0 += sx; }
            if e2 <= dx { err += dx; y0 += sy; }
        }
    }
    // Light, sparse speckle in a mid tone (faint texture, not obscuring dots).
    for _ in 0..(w * h / 220) {
        let x = rng.gen_range(0..w); let y = rng.gen_range(0..h);
        put(&mut buf, x, y, mid);
    }

    // Sine warp: remap each output pixel from a source shifted by sin(y) horizontally
    // and sin(x) vertically — gives the wavy, hard-to-segment look.
    let ampx = rng.gen_range(1.2f32..=2.2);
    let ampy = rng.gen_range(0.8f32..=1.6);
    let fx = std::f32::consts::TAU / rng.gen_range(26.0f32..=38.0);
    let fy = std::f32::consts::TAU / rng.gen_range(34.0f32..=48.0);
    let px = rng.gen_range(0.0f32..=std::f32::consts::TAU);
    let py = rng.gen_range(0.0f32..=std::f32::consts::TAU);
    let mut out = vec![0u8; w * h * 3];
    for y in 0..h {
        for x in 0..w {
            let sxo = (ampx * (y as f32 * fx + px).sin()).round() as i32;
            let syo = (ampy * (x as f32 * fy + py).sin()).round() as i32;
            let sx = (x as i32 + sxo).clamp(0, w as i32 - 1) as usize;
            let sy = (y as i32 + syo).clamp(0, h as i32 - 1) as usize;
            let si = (sy * w + sx) * 3;
            let di = (y * w + x) * 3;
            out[di] = buf[si]; out[di + 1] = buf[si + 1]; out[di + 2] = buf[si + 2];
        }
    }

    png_rgb(w as u32, h as u32, &out)
}

// ── Minimal PNG encoder (8-bit RGB, stored-deflate zlib) ─────────────────────
fn png_rgb(w: u32, h: u32, rgb: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rgb.len() + 256);
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    // IHDR
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(2); // colour type: 2 = truecolour (RGB)
    ihdr.push(0); // compression: deflate
    ihdr.push(0); // filter: adaptive
    ihdr.push(0); // interlace: none
    write_chunk(&mut out, b"IHDR", &ihdr);
    // IDAT: each scanline prefixed with filter byte 0 (None), zlib-wrapped.
    let mut raw = Vec::with_capacity((w * h * 3 + h) as usize);
    let stride = (w * 3) as usize;
    for y in 0..h as usize {
        raw.push(0);
        let s = y * stride;
        raw.extend_from_slice(&rgb[s..s + stride]);
    }
    let zlib = zlib_store(&raw);
    write_chunk(&mut out, b"IDAT", &zlib);
    write_chunk(&mut out, b"IEND", &[]);
    out
}

fn write_chunk(out: &mut Vec<u8>, typ: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(typ);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32(typ, data).to_be_bytes());
}

/// zlib stream wrapping the data in stored (uncompressed) deflate blocks.
fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.push(0x78); out.push(0x01); // CMF/FLG (32K window, no dict); (0x7801 % 31 == 0)
    let mut i = 0;
    if data.is_empty() {
        out.push(1); out.extend_from_slice(&0u16.to_le_bytes()); out.extend_from_slice(&(!0u16).to_le_bytes());
    }
    while i < data.len() {
        let end = (i + 65535).min(data.len());
        let chunk = &data[i..end];
        let last = end == data.len();
        out.push(if last { 1 } else { 0 }); // BFINAL, BTYPE=00 (stored)
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
        i = end;
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn crc32(a: &[u8], b: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &x in a.iter().chain(b.iter()) {
        crc ^= x as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &x in data {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}
