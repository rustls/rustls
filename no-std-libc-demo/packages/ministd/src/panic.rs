use core::{
    panic::PanicInfo,
    sync::atomic::{self, AtomicBool},
};

use crate::process;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    static PANICKED: AtomicBool = AtomicBool::new(false);

    // NOTE assuming the program is single-threaded
    let ordering = atomic::Ordering::Relaxed;
    if PANICKED
        .compare_exchange(false, true, ordering, ordering)
        .is_ok()
    {
        let _ = eprintln!("{}", info);
    } else {
        let _ = eprintln!(" (..)\npanicked while processing panic. aborting.");
        process::abort()
    }

    process::exit(101)
}
