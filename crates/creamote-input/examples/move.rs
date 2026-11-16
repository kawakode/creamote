//! Déplace le pointeur au centre de l'écran principal et tape « a ».
//! `cargo run -p creamote-input --example move`

use creamote_input::{Injector, Pointer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    creamote_capture::init();
    let display = creamote_capture::displays()?
        .into_iter()
        .next()
        .ok_or("aucun écran")?;
    let mut inj = Injector::open(display)?;
    inj.pointer(&Pointer {
        x: 0.5,
        y: 0.5,
        ..Default::default()
    })?;
    inj.key(0x04, true)?;
    inj.key(0x04, false)?;
    #[cfg(target_os = "linux")]
    {
        use x11rb::connection::Connection;
        use x11rb::protocol::xproto::ConnectionExt;
        let (conn, screen) = x11rb::connect(None)?;
        let p = conn
            .query_pointer(conn.setup().roots[screen].root)?
            .reply()?;
        println!("pointeur X11 : {} {}", p.root_x, p.root_y);
    }
    Ok(())
}
