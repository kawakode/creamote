//! Capture Windows par DXGI Desktop Duplication (Windows 8+). Le GPU copie
//! l'image du bureau dans une texture de transfert lue par le CPU. Les images
//! ne sont livrées que lorsque l'écran change.
//!
//! Le curseur n'est pas inclus dans l'image dupliquée : le viewer affiche le
//! sien ; la forme du curseur distant sera transmise à part (M3).
#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_NOT_FOUND, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_FRAME_INFO, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource,
};
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForMonitor, MDT_EFFECTIVE_DPI,
    SetProcessDpiAwarenessContext,
};
use windows::core::Interface;

use crate::{CaptureError, Capturer, DisplayInfo, Frame, Result, copy_rows};

fn err(context: &str, e: windows::core::Error) -> CaptureError {
    CaptureError::Backend(format!("{context} : {e}"))
}

pub fn init() {
    // SAFETY : appel sans pointeur ; échoue sans effet si déjà configuré.
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
}

struct Output {
    adapter: IDXGIAdapter1,
    output: IDXGIOutput1,
    info: DisplayInfo,
}

/// Sorties attachées au bureau, dans l'ordre adaptateur puis sortie.
fn outputs() -> Result<Vec<Output>> {
    // SAFETY : API COM ; les interfaces retournées sont comptées par référence.
    unsafe {
        let factory: IDXGIFactory1 =
            CreateDXGIFactory1().map_err(|e| err("CreateDXGIFactory1", e))?;
        let mut found = Vec::new();
        for a in 0.. {
            let adapter = match factory.EnumAdapters1(a) {
                Ok(a) => a,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(err("EnumAdapters1", e)),
            };
            for o in 0.. {
                let output = match adapter.EnumOutputs(o) {
                    Ok(o) => o,
                    Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                    Err(e) => return Err(err("EnumOutputs", e)),
                };
                let desc = output.GetDesc().map_err(|e| err("GetDesc", e))?;
                if !desc.AttachedToDesktop.as_bool() {
                    continue;
                }
                let Ok(output) = output.cast::<IDXGIOutput1>() else {
                    continue;
                };
                let r = desc.DesktopCoordinates;
                let name_len = desc.DeviceName.iter().position(|&c| c == 0).unwrap_or(32);
                let (mut dpi_x, mut dpi_y) = (96u32, 96u32);
                let _ = GetDpiForMonitor(desc.Monitor, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y);
                let info = DisplayInfo {
                    id: found.len() as u32,
                    name: String::from_utf16_lossy(&desc.DeviceName[..name_len]),
                    x: r.left,
                    y: r.top,
                    width: (r.right - r.left) as u32,
                    height: (r.bottom - r.top) as u32,
                    scale: dpi_x as f32 / 96.0,
                    primary: r.left == 0 && r.top == 0,
                };
                found.push(Output {
                    adapter: adapter.clone(),
                    output,
                    info,
                });
            }
        }
        Ok(found)
    }
}

pub fn displays() -> Result<Vec<DisplayInfo>> {
    Ok(outputs()?.into_iter().map(|o| o.info).collect())
}

pub fn open(display: DisplayInfo) -> Result<Box<dyn Capturer>> {
    let out = outputs()?
        .into_iter()
        .find(|o| o.info == display)
        .ok_or(CaptureError::UnknownDisplay(display.id))?;
    // SAFETY : API COM ; les pointeurs de sortie sont des Option locales.
    let (device, context) = unsafe {
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        D3D11CreateDevice(
            &out.adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .map_err(|e| err("D3D11CreateDevice", e))?;
        (
            device.ok_or_else(|| CaptureError::Backend("pas de device D3D11".into()))?,
            context.ok_or_else(|| CaptureError::Backend("pas de contexte D3D11".into()))?,
        )
    };
    let dup = duplicate(&out.output, &device)?;
    Ok(Box::new(DxgiCapturer {
        display: out.info,
        output: out.output,
        device,
        context,
        dup,
        staging: None,
        holding: false,
    }))
}

fn duplicate(output: &IDXGIOutput1, device: &ID3D11Device) -> Result<IDXGIOutputDuplication> {
    // SAFETY : API COM.
    unsafe { output.DuplicateOutput(device) }.map_err(|e| {
        // E_ACCESSDENIED : bureau sécurisé (UAC, écran de verrouillage) ;
        // DXGI_ERROR_UNSUPPORTED : session sans GPU (certains RDP).
        err("DuplicateOutput", e)
    })
}

struct DxgiCapturer {
    display: DisplayInfo,
    output: IDXGIOutput1,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    dup: IDXGIOutputDuplication,
    staging: Option<(ID3D11Texture2D, u32, u32)>,
    holding: bool,
}

impl DxgiCapturer {
    fn staging(&mut self, width: u32, height: u32) -> Result<ID3D11Texture2D> {
        if let Some((t, w, h)) = &self.staging
            && (*w, *h) == (width, height)
        {
            return Ok(t.clone());
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut tex = None;
        // SAFETY : descripteur valide, pointeur de sortie local.
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex)) }
            .map_err(|e| err("CreateTexture2D", e))?;
        let tex = tex.ok_or_else(|| CaptureError::Backend("texture non créée".into()))?;
        self.staging = Some((tex.clone(), width, height));
        Ok(tex)
    }

    fn release(&mut self) {
        if self.holding {
            // SAFETY : une image est détenue.
            let _ = unsafe { self.dup.ReleaseFrame() };
            self.holding = false;
        }
    }
}

impl Capturer for DxgiCapturer {
    fn display(&self) -> &DisplayInfo {
        &self.display
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>> {
        self.release();
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        // SAFETY : pointeurs de sortie locaux.
        match unsafe { self.dup.AcquireNextFrame(ms, &mut info, &mut resource) } {
            Ok(()) => self.holding = true,
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                // Changement de mode, bureau sécurisé, plein écran exclusif :
                // on recrée la duplication et on réessaiera.
                tracing::debug!("duplication perdue, recréation");
                self.dup = duplicate(&self.output, &self.device)?;
                return Ok(None);
            }
            Err(e) => return Err(err("AcquireNextFrame", e)),
        }
        let captured_at = Instant::now();
        // Seul le curseur a bougé : pas de nouvelle image.
        if info.LastPresentTime == 0 {
            return Ok(None);
        }
        let resource =
            resource.ok_or_else(|| CaptureError::Backend("image DXGI absente".into()))?;
        // SAFETY : API COM ; la texture est lue avant ReleaseFrame, la copie
        // mappée avant Unmap.
        unsafe {
            let tex: ID3D11Texture2D = resource.cast().map_err(|e| err("cast", e))?;
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            tex.GetDesc(&mut desc);
            if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
                return Err(CaptureError::Unsupported(format!(
                    "format de bureau {:?} (HDR ?)",
                    desc.Format
                )));
            }
            let staging = self.staging(desc.Width, desc.Height)?;
            self.context.CopyResource(&staging, &tex);
            self.release();
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|e| err("Map", e))?;
            let pitch = mapped.RowPitch as usize;
            let src =
                std::slice::from_raw_parts(mapped.pData as *const u8, pitch * desc.Height as usize);
            let data = copy_rows(src, pitch, desc.Width, desc.Height);
            self.context.Unmap(&staging, 0);
            Ok(Some(Frame {
                width: desc.Width,
                height: desc.Height,
                stride: desc.Width as usize * 4,
                data,
                captured_at,
            }))
        }
    }
}

impl Drop for DxgiCapturer {
    fn drop(&mut self) {
        self.release();
    }
}
