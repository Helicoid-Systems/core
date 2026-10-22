//! Bounded CPU screen frames passed from an admitted platform capture adapter.
//!
//! This value validates memory shape and source generations only. Constructing
//! a frame does not grant observation authority or make it safe to retain it
//! after the matching interaction ends.

use crate::bounds::{MAX_SCREEN_FRAME_BYTES, MAX_SCREEN_FRAME_HEIGHT, MAX_SCREEN_FRAME_WIDTH};
use crate::error::{Error, Result};
use crate::id::{DesktopGeneration, DisplayId, InteractionGeneration, LayoutGeneration};
use crate::reason::ReasonCode;

/// Pixel layout accepted at the CPU frame boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenPixelFormat {
    /// 8-bit blue, green, red, alpha channels in memory order.
    Bgra8,
}

impl ScreenPixelFormat {
    const fn bytes_per_pixel(self) -> usize {
        match self {
            Self::Bgra8 => 4,
        }
    }
}

/// A borrowed, validated screen frame with the display and generations that
/// produced it. The pixels are never serialized by this type.
pub struct ScreenFrame<'a> {
    display_id: DisplayId,
    desktop_generation: DesktopGeneration,
    layout_generation: LayoutGeneration,
    interaction_generation: InteractionGeneration,
    format: ScreenPixelFormat,
    width: u32,
    height: u32,
    stride_bytes: usize,
    pixels: &'a [u8],
}

impl<'a> ScreenFrame<'a> {
    /// Validate one CPU frame using checked row and buffer-size arithmetic.
    pub fn new(
        display_id: DisplayId,
        desktop_generation: DesktopGeneration,
        layout_generation: LayoutGeneration,
        interaction_generation: InteractionGeneration,
        format: ScreenPixelFormat,
        width: u32,
        height: u32,
        stride_bytes: usize,
        pixels: &'a [u8],
    ) -> Result<Self> {
        if desktop_generation.0 == 0 || layout_generation.0 == 0 || interaction_generation.0 == 0 {
            return Err(invalid_frame("screen_frame.generation"));
        }
        if width == 0
            || height == 0
            || width > MAX_SCREEN_FRAME_WIDTH
            || height > MAX_SCREEN_FRAME_HEIGHT
        {
            return Err(invalid_frame("screen_frame.dimensions"));
        }

        let row_bytes = usize::try_from(width)
            .ok()
            .and_then(|width| width.checked_mul(format.bytes_per_pixel()))
            .ok_or_else(|| invalid_frame("screen_frame.stride"))?;
        if stride_bytes < row_bytes {
            return Err(invalid_frame("screen_frame.stride"));
        }
        let expected_bytes = stride_bytes
            .checked_mul(
                usize::try_from(height).map_err(|_| invalid_frame("screen_frame.dimensions"))?,
            )
            .filter(|length| *length <= MAX_SCREEN_FRAME_BYTES)
            .ok_or_else(|| invalid_frame("screen_frame.byte_length"))?;
        if pixels.len() != expected_bytes {
            return Err(invalid_frame("screen_frame.byte_length"));
        }

        Ok(Self {
            display_id,
            desktop_generation,
            layout_generation,
            interaction_generation,
            format,
            width,
            height,
            stride_bytes,
            pixels,
        })
    }

    pub const fn display_id(&self) -> &DisplayId {
        &self.display_id
    }

    pub const fn desktop_generation(&self) -> DesktopGeneration {
        self.desktop_generation
    }

    pub const fn layout_generation(&self) -> LayoutGeneration {
        self.layout_generation
    }

    pub const fn interaction_generation(&self) -> InteractionGeneration {
        self.interaction_generation
    }

    pub const fn format(&self) -> ScreenPixelFormat {
        self.format
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn height(&self) -> u32 {
        self.height
    }

    pub const fn stride_bytes(&self) -> usize {
        self.stride_bytes
    }

    pub const fn pixels(&self) -> &'a [u8] {
        self.pixels
    }

    /// Whether this frame still belongs to the caller's current source.
    pub fn matches_source(
        &self,
        display_id: &DisplayId,
        desktop_generation: DesktopGeneration,
        layout_generation: LayoutGeneration,
        interaction_generation: InteractionGeneration,
    ) -> bool {
        self.display_id == *display_id
            && self.desktop_generation == desktop_generation
            && self.layout_generation == layout_generation
            && self.interaction_generation == interaction_generation
    }
}

fn invalid_frame(field: &'static str) -> Error {
    Error::InvalidInput {
        field,
        reason: ReasonCode::InvalidInput,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display() -> DisplayId {
        DisplayId::new("display-1").expect("display identity is valid")
    }

    fn frame(
        width: u32,
        height: u32,
        stride_bytes: usize,
        pixels: &[u8],
    ) -> Result<ScreenFrame<'_>> {
        ScreenFrame::new(
            display(),
            DesktopGeneration::INITIAL,
            LayoutGeneration::INITIAL,
            InteractionGeneration::INITIAL,
            ScreenPixelFormat::Bgra8,
            width,
            height,
            stride_bytes,
            pixels,
        )
    }

    #[test]
    fn accepts_bounded_bgra_frames_with_row_padding() {
        let pixels = [0; 16];
        let frame = frame(1, 2, 8, &pixels).expect("padded two-row BGRA frame is valid");

        assert_eq!(frame.width(), 1);
        assert_eq!(frame.height(), 2);
        assert_eq!(frame.stride_bytes(), 8);
        assert_eq!(frame.pixels(), &pixels);
    }

    #[test]
    fn rejects_zero_and_oversized_dimensions_and_invalid_stride_or_length() {
        let pixels = [0; 16];

        assert!(frame(0, 1, 4, &pixels).is_err());
        assert!(frame(1, 0, 4, &pixels).is_err());
        assert!(frame(MAX_SCREEN_FRAME_WIDTH + 1, 1, 4, &pixels).is_err());
        assert!(frame(1, MAX_SCREEN_FRAME_HEIGHT + 1, 4, &pixels).is_err());
        assert!(frame(2, 1, 4, &pixels).is_err());
        assert!(frame(1, 1, 4, &pixels).is_err());
    }

    #[test]
    fn rejects_byte_count_overflow_before_reading_pixels() {
        assert!(frame(1, 2, usize::MAX, &[]).is_err());
    }

    #[test]
    fn rejects_zero_source_generations() {
        let pixels = [0; 4];
        let result = ScreenFrame::new(
            display(),
            DesktopGeneration(0),
            LayoutGeneration::INITIAL,
            InteractionGeneration::INITIAL,
            ScreenPixelFormat::Bgra8,
            1,
            1,
            4,
            &pixels,
        );

        assert!(result.is_err());
    }
}
