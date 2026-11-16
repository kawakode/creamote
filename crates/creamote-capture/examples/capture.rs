//! Capture quelques images de l'écran principal et affiche leur cadence.
//! `cargo run -p creamote-capture --example capture`

use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    creamote_capture::init();
    for d in creamote_capture::displays()? {
        println!("{d:?}");
    }
    let mut c = creamote_capture::open(None)?;
    let start = Instant::now();
    let mut n = 0;
    while start.elapsed() < Duration::from_secs(3) {
        if let Some(f) = c.next_frame(Duration::from_millis(500))? {
            n += 1;
            println!(
                "image {n} : {}×{} en {:?}",
                f.width,
                f.height,
                f.captured_at - start
            );
        }
    }
    Ok(())
}
