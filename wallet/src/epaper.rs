//! # Passive 1.54" NFC e-Paper Image Converter
//!
//! Handles 3-color (Black/White/Red) Floyd-Steinberg dithering and packs
//! the buffers into the correct format for NFC transmission.

use wasm_bindgen::prelude::*;
use image::{GenericImageView, Pixel};

/// e-Paper pixel choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpaperColor {
    Black,
    White,
    Red,
}

/// Image converter for 1.54" e-Paper.
pub struct EpaperConverter {
    pub width: u32,
    pub height: u32,
}

impl EpaperConverter {
    /// Converts input image bytes (PNG, JPEG, SVG) to dithered Black/White/Red buffers.
    /// Returns a packed byte vector containing the B/W buffer first, then the Red buffer,
    /// prefixed frame header.
    pub fn convert(&self, image_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let img = image::load_from_memory(image_bytes)
            .map_err(|e| format!("Failed to parse image bytes: {e}"))?;
        
        let resized = img.resize_exact(self.width, self.height, image::imageops::FilterType::Lanczos3);
        
        // Floyd-Steinberg 3-color Dithering
        let mut pixels = vec![EpaperColor::White; (self.width * self.height) as usize];
        let mut errors = vec![0.0f32; (self.width * self.height) as usize * 3]; // RGB error buffers
        
        for y in 0..self.height {
            for x in 0..self.width {
                let idx = (y * self.width + x) as usize;
                let pixel = resized.get_pixel(x, y);
                let rgb = pixel.to_rgb();
                
                // Add accumulated errors
                let r = rgb[0] as f32 + errors[idx * 3];
                let g = rgb[1] as f32 + errors[idx * 3 + 1];
                let b = rgb[2] as f32 + errors[idx * 3 + 2];
                
                // Find closest 3-color palette color
                let (chosen, tr, tg, tb) = self.closest_color(r, g, b);
                pixels[idx] = chosen;
                
                // Compute error
                let err_r = r - tr;
                let err_g = g - tg;
                let err_b = b - tb;
                
                // Distribute errors to neighbors (Floyd-Steinberg coefficients)
                self.distribute_error(&mut errors, x, y, err_r, err_g, err_b);
            }
        }

        // Pack into B/W and Red bit-buffers
        let buffer_size = ((self.width * self.height) / 8) as usize;
        let mut bw_buffer = vec![0xFFu8; buffer_size]; // 1 = White, 0 = Black
        let mut red_buffer = vec![0x00u8; buffer_size]; // 1 = Red, 0 = Non-Red

        for y in 0..self.height {
            for x in 0..self.width {
                let idx = (y * self.width + x) as usize;
                let byte_idx = idx / 8;
                let bit_idx = 7 - (idx % 8);
                
                match pixels[idx] {
                    EpaperColor::Black => {
                        bw_buffer[byte_idx] &= !(1 << bit_idx);
                    }
                    EpaperColor::White => {
                        // White is default (1)
                    }
                    EpaperColor::Red => {
                        red_buffer[byte_idx] |= 1 << bit_idx;
                        // Turn off black bit so it doesn't render dual-color
                        bw_buffer[byte_idx] |= 1 << bit_idx;
                    }
                }
            }
        }

        // Build epaper JTNFC frame format: magic "JTNFC" (5 bytes) || width (2 bytes) || height (2 bytes) || B/W buffer || Red buffer || checksum
        let mut frame = Vec::new();
        frame.extend_from_slice(b"JTNFC");
        frame.extend_from_slice(&(self.width as u16).to_be_bytes());
        frame.extend_from_slice(&(self.height as u16).to_be_bytes());
        frame.extend_from_slice(&bw_buffer);
        frame.extend_from_slice(&red_buffer);
        
        let checksum = frame.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
        frame.push(checksum);

        Ok(frame)
    }

    fn closest_color(&self, r: f32, g: f32, b: f32) -> (EpaperColor, f32, f32, f32) {
        // Red threshold: highly saturated red
        if r > 120.0 && g < 90.0 && b < 90.0 {
            (EpaperColor::Red, 255.0, 0.0, 0.0)
        } else {
            // Convert to grayscale for B/W selection
            let gray = 0.299 * r + 0.587 * g + 0.114 * b;
            if gray < 128.0 {
                (EpaperColor::Black, 0.0, 0.0, 0.0)
            } else {
                (EpaperColor::White, 255.0, 255.0, 255.0)
            }
        }
    }

    fn distribute_error(&self, errors: &mut [f32], x: u32, y: u32, err_r: f32, err_g: f32, err_b: f32) {
        let coords = [
            (x + 1, y, 7.0 / 16.0),
            (x.wrapping_sub(1), y + 1, 3.0 / 16.0),
            (x, y + 1, 5.0 / 16.0),
            (x + 1, y + 1, 1.0 / 16.0),
        ];

        for &(nx, ny, weight) in &coords {
            if nx < self.width && ny < self.height {
                let idx = (ny * self.width + nx) as usize;
                errors[idx * 3] += err_r * weight;
                errors[idx * 3 + 1] += err_g * weight;
                errors[idx * 3 + 2] += err_b * weight;
            }
        }
    }
}

/// JS-accessible 152x152 image converter binding
#[wasm_bindgen]
pub fn convert_to_epaper_152(image_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    EpaperConverter { width: 152, height: 152 }
        .convert(image_bytes)
        .map_err(|e| JsValue::from_str(&e))
}

/// JS-accessible 200x200 image converter binding
#[wasm_bindgen]
pub fn convert_to_epaper_200(image_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    EpaperConverter { width: 200, height: 200 }
        .convert(image_bytes)
        .map_err(|e| JsValue::from_str(&e))
}
