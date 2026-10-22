//! Single-slot handoff for validated screen frames.
//!
//! A producer replaces the previous frame instead of building a history. The
//! mailbox fences callbacks by display, desktop, layout, and interaction
//! generation. Create it only for a current endpoint admission and clear it as
//! soon as that admission ends. It does not verify the admission grant itself.

use crate::error::{Error, Result};
use crate::id::{DesktopGeneration, DisplayId, InteractionGeneration, LayoutGeneration};
use crate::reason::ReasonCode;
use crate::screen_frame::{ScreenFrame, ScreenPixelFormat};
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrameSource {
    display_id: DisplayId,
    desktop_generation: DesktopGeneration,
    layout_generation: LayoutGeneration,
    interaction_generation: InteractionGeneration,
}

impl FrameSource {
    fn from_parts(
        display_id: DisplayId,
        desktop_generation: DesktopGeneration,
        layout_generation: LayoutGeneration,
        interaction_generation: InteractionGeneration,
    ) -> Result<Self> {
        if desktop_generation.0 == 0 || layout_generation.0 == 0 || interaction_generation.0 == 0 {
            return Err(invalid_frame_source());
        }
        Ok(Self {
            display_id,
            desktop_generation,
            layout_generation,
            interaction_generation,
        })
    }

    fn matches(&self, frame: &ScreenFrame<'_>) -> bool {
        frame.matches_source(
            &self.display_id,
            self.desktop_generation,
            self.layout_generation,
            self.interaction_generation,
        )
    }
}

struct MailboxState {
    active: bool,
    frame: Option<OwnedScreenFrame>,
}

/// Owns one validated frame so capture memory can be released after publish.
pub struct OwnedScreenFrame {
    display_id: DisplayId,
    desktop_generation: DesktopGeneration,
    layout_generation: LayoutGeneration,
    interaction_generation: InteractionGeneration,
    format: ScreenPixelFormat,
    width: u32,
    height: u32,
    stride_bytes: usize,
    pixels: Vec<u8>,
}

impl OwnedScreenFrame {
    fn copy_from(frame: &ScreenFrame<'_>) -> Self {
        Self {
            display_id: frame.display_id().clone(),
            desktop_generation: frame.desktop_generation(),
            layout_generation: frame.layout_generation(),
            interaction_generation: frame.interaction_generation(),
            format: frame.format(),
            width: frame.width(),
            height: frame.height(),
            stride_bytes: frame.stride_bytes(),
            pixels: frame.pixels().to_vec(),
        }
    }

    /// Borrow this owned frame through the same validated view used at ingress.
    pub fn as_frame(&self) -> Result<ScreenFrame<'_>> {
        ScreenFrame::new(
            self.display_id.clone(),
            self.desktop_generation,
            self.layout_generation,
            self.interaction_generation,
            self.format,
            self.width,
            self.height,
            self.stride_bytes,
            &self.pixels,
        )
    }

    /// Pixel storage for the current frame only.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
}

impl Drop for OwnedScreenFrame {
    fn drop(&mut self) {
        zeroize_pixels(&mut self.pixels);
    }
}

fn zeroize_pixels(pixels: &mut [u8]) {
    for pixel in pixels {
        // SAFETY: the mutable slice provides a valid, uniquely borrowed byte
        // aligned for u8. Volatile writes keep the wipe observable to rustc.
        unsafe { std::ptr::write_volatile(pixel, 0) };
    }
}

/// Latest-frame handoff for one admitted observation source.
///
/// The mailbox retains at most one frame, bounded by `MAX_SCREEN_FRAME_BYTES`.
/// Each mailbox belongs to one observation interaction. Clearing it retires
/// it permanently, so a late callback cannot publish into a later interaction.
pub struct LatestScreenFrameMailbox {
    source: FrameSource,
    state: Mutex<MailboxState>,
}

impl LatestScreenFrameMailbox {
    /// Bind a new mailbox to the source admitted by the caller.
    pub fn new(
        display_id: DisplayId,
        desktop_generation: DesktopGeneration,
        layout_generation: LayoutGeneration,
        interaction_generation: InteractionGeneration,
    ) -> Result<Self> {
        let source = FrameSource::from_parts(
            display_id,
            desktop_generation,
            layout_generation,
            interaction_generation,
        )?;
        Ok(Self {
            source,
            state: Mutex::new(MailboxState {
                active: true,
                frame: None,
            }),
        })
    }

    /// Copy and publish a frame only while its source generations are current.
    /// An older asynchronous callback is rejected and cannot replace pixels
    /// from the current desktop.
    pub fn publish(&self, frame: &ScreenFrame<'_>) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| mailbox_unavailable())?;
        if !state.active || !self.source.matches(frame) {
            return Err(late_frame());
        }
        state.frame = Some(OwnedScreenFrame::copy_from(frame));
        Ok(())
    }

    /// Take the newest frame. A successful take empties the slot.
    pub fn take(&self) -> Result<Option<OwnedScreenFrame>> {
        let mut state = self.state.lock().map_err(|_| mailbox_unavailable())?;
        if !state.active {
            state.frame = None;
            return Ok(None);
        }
        let Some(frame) = state.frame.take() else {
            return Ok(None);
        };
        let is_current = self.source.matches(&frame.as_frame()?);
        if is_current {
            Ok(Some(frame))
        } else {
            Ok(None)
        }
    }

    /// End this source permanently and drop any retained pixels.
    pub fn clear(&self) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| mailbox_unavailable())?;
        state.active = false;
        state.frame = None;
        Ok(())
    }
}

fn invalid_frame_source() -> Error {
    Error::InvalidInput {
        field: "screen_frame.source_generation",
        reason: ReasonCode::InvalidInput,
    }
}

fn late_frame() -> Error {
    Error::Refused {
        reason: ReasonCode::LateGeneration,
    }
}

fn mailbox_unavailable() -> Error {
    Error::EngineUnavailable {
        reason: ReasonCode::EngineUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display() -> DisplayId {
        DisplayId::new("display-1").expect("display identity is valid")
    }

    fn frame<'a>(
        pixels: &'a [u8],
        desktop_generation: u64,
        layout_generation: u64,
        interaction_generation: u64,
    ) -> ScreenFrame<'a> {
        ScreenFrame::new(
            display(),
            DesktopGeneration(desktop_generation),
            LayoutGeneration(layout_generation),
            InteractionGeneration(interaction_generation),
            ScreenPixelFormat::Bgra8,
            1,
            1,
            4,
            pixels,
        )
        .expect("single-pixel BGRA frame is valid")
    }

    fn mailbox() -> LatestScreenFrameMailbox {
        LatestScreenFrameMailbox::new(
            display(),
            DesktopGeneration(1),
            LayoutGeneration(1),
            InteractionGeneration(1),
        )
        .expect("nonzero source generations are valid")
    }

    #[test]
    fn take_returns_only_the_latest_published_frame_once() {
        let mailbox = mailbox();
        let first_pixels = [1, 2, 3, 4];
        let latest_pixels = [5, 6, 7, 8];

        mailbox.publish(&frame(&first_pixels, 1, 1, 1)).unwrap();
        mailbox.publish(&frame(&latest_pixels, 1, 1, 1)).unwrap();

        let taken = mailbox.take().unwrap().expect("latest frame is available");
        assert_eq!(taken.pixels(), latest_pixels);
        assert!(mailbox.take().unwrap().is_none());
    }

    #[test]
    fn late_generation_cannot_replace_the_current_frame() {
        let mailbox = mailbox();
        let current_pixels = [1, 1, 1, 1];
        let late_pixels = [2, 2, 2, 2];

        mailbox.publish(&frame(&current_pixels, 1, 1, 1)).unwrap();
        assert!(mailbox.publish(&frame(&late_pixels, 2, 1, 1)).is_err());

        let taken = mailbox
            .take()
            .unwrap()
            .expect("current frame remains available");
        assert_eq!(taken.pixels(), current_pixels);
    }

    #[test]
    fn clear_retires_the_mailbox_and_rejects_late_callbacks() {
        let mailbox = mailbox();
        let pixels = [9, 8, 7, 6];

        mailbox.publish(&frame(&pixels, 1, 1, 1)).unwrap();
        mailbox.clear().unwrap();

        assert!(mailbox.take().unwrap().is_none());
        assert!(mailbox.publish(&frame(&pixels, 1, 1, 1)).is_err());
    }

    #[test]
    fn pixel_wipe_overwrites_each_byte() {
        let mut pixels = [1, 2, 3, 4];

        zeroize_pixels(&mut pixels);

        assert_eq!(pixels, [0; 4]);
    }
}
