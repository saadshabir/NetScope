mod capture_run;
mod capture_source;
mod cli;
mod output_paths;
mod pcap_rotation;
mod runtime_config;

use clap::Parser;
use netscope::metrics;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use capture_run::run_capture;
use capture_source::list_interfaces;
use runtime_config::load_config;

fn main() {
    metrics::initialize();

    let args = cli::Cli::parse();

    // Initialize tracing/logging
    let log_level = match args.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Handle --list-interfaces
    if args.list_interfaces {
        list_interfaces();
        return;
    }

    let config = match load_config(&args) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }
    };

    // Set up Ctrl-C handler
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    ctrlc::set_handler(move || {
        running_clone.store(false, Ordering::SeqCst);
        eprintln!("\nInterrupt received, stopping capture...");
    })
    .expect("failed to set Ctrl-C handler");

    // Run the capture loop
    if let Err(e) = run_capture(&config, &running) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
