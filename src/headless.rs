//! Headless capture program.
//!
//! Captures from an attached analyzer straight to a pcap-ng file, without
//! the GUI or the decoder, so that captures can be scripted. Packets are
//! written as they arrive, so the length of a capture is limited only by
//! disk space.

// This binary uses only part of the modules it shares with the GUI.
#![allow(dead_code)]

// We need the bitfield macro.
#[macro_use]
extern crate bitfield;

// Include build-time info.
pub mod built {
    // The file has been placed there by the build script.
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

mod backend;
mod capture;
mod database;
mod event;
mod file;
mod usb;
mod util;
mod version;

use std::fs::File;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Error, anyhow, bail};
use futures_lite::future::block_on;

use backend::{BackendHandle, PowerConfig, ProbeResult, TimestampedEvent};
use capture::CaptureMetadata;
use event::{EventType, StopReason};
use file::{GenericSaver, PcapNgSaver};
use usb::Speed;
use version::version;

const USAGE: &str = "\
Usage: packetry-capture [OPTIONS] FILE.pcapng
       packetry-capture --list

Capture USB traffic from an analyzer to a pcap-ng file, until the duration
elapses or the program receives SIGINT (Ctrl-C) or SIGTERM.

Options:
  --speed SPEED          high, full, low or auto [default: high]
  --duration SECONDS     stop after this long
  --comment TEXT         store a comment in the file
  --device N             use analyzer N from --list, if several are attached
  --list                 list attached analyzers and exit

Power control, on analyzers that support it:
  --power-source NAME    which source powers the target, e.g. TARGET-C
  --power on|off         turn target power on or off before capture starts
  --power-on-start       turn target power on when capture starts
  --power-off-stop       turn target power off when capture stops

  --version              print version information
  --help                 print this help

Exit status is 0 for a complete capture, 1 on error, and 2 if the analyzer
reported that its buffer overflowed, so packets are missing from the file.";

/// Settings given on the command line.
#[derive(Default)]
struct Options {
    output: Option<PathBuf>,
    speed: Option<Speed>,
    duration: Option<Duration>,
    comment: Option<String>,
    device: Option<usize>,
    list: bool,
    power_source: Option<String>,
    power_on: Option<bool>,
    power_on_start: bool,
    power_off_stop: bool,
}

/// Why the capture is being stopped.
enum Stop {
    /// SIGINT or SIGTERM was received.
    Signal,
    /// The requested duration elapsed.
    Duration,
    /// The capture ended by itself, e.g. the analyzer was unplugged.
    Ended(Result<(), Error>),
    /// Writing the file failed.
    WriteFailed,
}

/// Counts of what has been written, shared with the writer thread.
#[derive(Default)]
struct Counts {
    packets: AtomicU64,
    events: AtomicU64,
    bytes: AtomicU64,
    overflow: AtomicBool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("packetry-capture: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Error> {
    let Some(options) = parse_args(std::env::args().skip(1))? else {
        return Ok(ExitCode::SUCCESS)
    };

    let analyzers = block_on(backend::scan())
        .context("Failed to scan for analyzers")?;

    if options.list {
        list(&analyzers);
        return Ok(ExitCode::SUCCESS)
    }

    let Some(path) = &options.output else {
        bail!("No output file given\n\n{USAGE}")
    };

    // Refuse to overwrite a previous capture.
    let file = File::create_new(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;

    let result = capture(&options, analyzers, file);

    // Don't leave an empty file behind if the capture never started.
    if result.is_err() && std::fs::metadata(path).is_ok_and(|m| m.len() == 0) {
        let _ = std::fs::remove_file(path);
    }

    result
}

fn capture(options: &Options, analyzers: Vec<ProbeResult>, file: File)
    -> Result<ExitCode, Error>
{
    // Select and open the analyzer.
    let analyzer = select(analyzers, options.device)?;
    let name = analyzer.name;
    let device = analyzer.result
        .map_err(|e| anyhow!("{name} is not usable: {e}"))?;
    let mut handle = block_on(device.open_as_generic())
        .with_context(|| format!("Failed to open {name}"))?;

    let speed = options.speed.unwrap_or(Speed::High);
    if !handle.supported_speeds().contains(&speed) {
        bail!("{name} does not support {} speed", speed.description());
    }

    configure_power(options, handle.as_mut())?;

    // Describe the capture as the GUI does.
    let mut meta = CaptureMetadata {
        application: Some(format!("Packetry {}", version())),
        os: Some(std::env::consts::OS.to_string()),
        hardware: Some(std::env::consts::ARCH.to_string()),
        comment: options.comment.clone(),
        iface_speed: Some(speed),
        start_time: Some(unix_time()?),
        .. handle.metadata().clone()
    };
    let mut saver = PcapNgSaver::new(file, Arc::new(meta.clone()))?;

    // Everything that can stop the capture sends to this channel.
    let (stop_tx, stop_rx) = mpsc::channel();

    // Stop on the first signal; exit at once on the second, in case stopping
    // the analyzer hangs.
    let signalled = AtomicBool::new(false);
    let signal_tx = stop_tx.clone();
    ctrlc::set_handler(move || {
        if signalled.swap(true, Ordering::AcqRel) {
            eprintln!("\nSecond signal received, exiting without stopping");
            std::process::exit(130);
        }
        let _ = signal_tx.send(Stop::Signal);
    }).context("Failed to install signal handler")?;

    // Start capture. The handler runs when the capture thread finishes,
    // whether because we stopped it or because it failed.
    let ended_tx = stop_tx.clone();
    let (events, stop_handle) = handle
        .start(speed, Box::new(move |result| {
            let _ = ended_tx.send(Stop::Ended(result));
        }))
        .with_context(|| format!("Failed to start capture on {name}"))?;
    let started = Instant::now();

    // Write events to the file as they arrive.
    let counts = Arc::new(Counts::default());
    let writer_counts = counts.clone();
    let write_failed_tx = stop_tx;
    let writer = thread::Builder::new()
        .name("writer".to_string())
        .spawn(move || {
            let result = write_events(events, &mut saver, &writer_counts);
            if result.is_err() {
                let _ = write_failed_tx.send(Stop::WriteFailed);
            }
            result.map(|()| saver)
        })
        .context("Failed to start writer thread")?;

    // Wait for a reason to stop.
    let deadline = options.duration.map(|duration| started + duration);
    let progress = std::io::stderr().is_terminal();
    let stop = loop {
        let now = Instant::now();
        if deadline.is_some_and(|deadline| now >= deadline) {
            break Stop::Duration
        }
        let wait = deadline.map_or(Duration::from_secs(1), |deadline|
            (deadline - now).min(Duration::from_secs(1)));
        match stop_rx.recv_timeout(wait) {
            Ok(stop) => break stop,
            Err(RecvTimeoutError::Timeout) if progress =>
                show_progress(&counts, started.elapsed()),
            Err(RecvTimeoutError::Timeout) => {},
            Err(RecvTimeoutError::Disconnected) =>
                bail!("Capture ended without reporting why"),
        }
    };
    if progress {
        eprintln!();
    }

    // Stop the analyzer, unless it has stopped already.
    let mut capture_result = match stop {
        Stop::Ended(result) => Some(result),
        _ => None,
    };
    stop_handle.stop().context("Failed to stop capture")?;
    let elapsed = started.elapsed();

    // The capture thread reports how it ended once it has been stopped.
    for stop in stop_rx.try_iter() {
        if let Stop::Ended(result) = stop {
            capture_result.get_or_insert(result);
        }
    }

    // Finish writing everything the analyzer sent before it stopped.
    let mut saver = util::handle_thread_panic(writer.join())?
        .context("Failed to write capture")?;
    meta.end_time = Some(unix_time()?);
    saver.update_metadata(Arc::new(meta));
    saver.close().context("Failed to finish capture file")?;

    let packets = counts.packets.load(Ordering::Acquire);
    let events = counts.events.load(Ordering::Acquire);
    let bytes = counts.bytes.load(Ordering::Acquire);
    eprintln!("Captured {packets} packets and {events} events, {}, in {:.1} s",
              util::fmt_size(bytes), elapsed.as_secs_f64());

    if let Some(Err(e)) = capture_result {
        return Err(e.context("Capture failed; the file holds what was \
                              received before the failure"))
    }

    if counts.overflow.load(Ordering::Acquire) {
        eprintln!("The analyzer's buffer overflowed: packets are missing \
                   from this capture");
        return Ok(ExitCode::from(2))
    }

    Ok(ExitCode::SUCCESS)
}

/// Write each event from the analyzer to the file.
fn write_events(
    events: Box<dyn backend::EventIterator>,
    saver: &mut PcapNgSaver<File>,
    counts: &Counts,
) -> Result<(), Error> {
    for event in events {
        use TimestampedEvent::*;
        match event.context("Error processing raw capture data")? {
            Packet { timestamp_ns, bytes } => {
                saver.add_packet(&bytes, timestamp_ns)?;
                counts.packets.fetch_add(1, Ordering::Relaxed);
                counts.bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            },
            Event { timestamp_ns, event_type } => {
                match &event_type {
                    EventType::CaptureStart(_) =>
                        eprintln!("{event_type}"),
                    EventType::CaptureStop(StopReason::BufferFull) =>
                        counts.overflow.store(true, Ordering::Release),
                    _ => {},
                }
                saver.add_event(event_type, timestamp_ns)?;
                counts.events.fetch_add(1, Ordering::Relaxed);
            },
        }
    }
    Ok(())
}

/// Apply the power options, if any were given.
fn configure_power(options: &Options, handle: &mut dyn BackendHandle)
    -> Result<(), Error>
{
    let requested =
        options.power_source.is_some() ||
        options.power_on.is_some() ||
        options.power_on_start ||
        options.power_off_stop;
    if !requested {
        return Ok(())
    }

    let (Some(sources), Some(current)) =
        (handle.power_sources(), block_on(handle.power_config()))
    else {
        bail!("This analyzer does not support power control")
    };

    let source_index = match &options.power_source {
        None => current.source_index,
        Some(name) => sources
            .iter()
            .position(|source| source.eq_ignore_ascii_case(name))
            .with_context(|| format!(
                "Unknown power source {name}; this analyzer has {}",
                sources.join(", ")))?,
    };

    let config = PowerConfig {
        source_index,
        on_now: options.power_on.unwrap_or(current.on_now),
        start_on: options.power_on_start,
        stop_off: options.power_off_stop,
    };
    eprintln!("Target power from {}, {} now{}{}",
        sources[source_index],
        if config.on_now { "on" } else { "off" },
        if config.start_on { ", on when capture starts" } else { "" },
        if config.stop_off { ", off when capture stops" } else { "" });
    block_on(handle.set_power_config(config))
        .context("Failed to set power configuration")
}

/// Choose the analyzer to use.
fn select(mut analyzers: Vec<ProbeResult>, index: Option<usize>)
    -> Result<ProbeResult, Error>
{
    match (index, analyzers.len()) {
        (_, 0) => bail!("No supported analyzer found"),
        (None, 1) => Ok(analyzers.remove(0)),
        (None, _) => bail!(
            "Several analyzers found; choose one with --device N \
             (see --list)"),
        (Some(i), n) if i < n => Ok(analyzers.remove(i)),
        (Some(i), _) => bail!("No analyzer {i}; see --list"),
    }
}

/// Print the attached analyzers.
fn list(analyzers: &[ProbeResult]) {
    if analyzers.is_empty() {
        println!("No supported analyzers found");
    }
    for (i, analyzer) in analyzers.iter().enumerate() {
        let info = &analyzer.info;
        let serial = info.serial_number().unwrap_or("no serial");
        let status = match &analyzer.result {
            Ok(_) => String::new(),
            Err(e) => format!(": not usable: {e}"),
        };
        println!("{i}: {} ({serial}){status}", analyzer.name);
    }
}

fn show_progress(counts: &Counts, elapsed: Duration) {
    let packets = counts.packets.load(Ordering::Relaxed);
    let bytes = counts.bytes.load(Ordering::Relaxed);
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "\r{:.0} s: {packets} packets, {}\x1b[K",
                   elapsed.as_secs_f64(), util::fmt_size(bytes));
    let _ = stderr.flush();
}

fn unix_time() -> Result<Duration, Error> {
    Ok(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?)
}

/// Parse the command line, returning `None` if there is nothing to capture.
fn parse_args(mut args: impl Iterator<Item=String>)
    -> Result<Option<Options>, Error>
{
    let mut options = Options::default();
    while let Some(arg) = args.next() {
        let mut value = || args
            .next()
            .with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(None)
            },
            "--version" => {
                println!("packetry-capture {}", version());
                return Ok(None)
            },
            "--list" => options.list = true,
            "--speed" => options.speed = Some(parse_speed(&value()?)?),
            "--duration" => {
                let text = value()?;
                let seconds: f64 = text.parse()
                    .ok()
                    .filter(|s: &f64| s.is_finite() && *s > 0.0)
                    .with_context(|| format!(
                        "--duration needs a positive number of seconds, \
                         not {text}"))?;
                options.duration = Some(Duration::from_secs_f64(seconds));
            },
            "--comment" => options.comment = Some(value()?),
            "--device" => {
                let text = value()?;
                options.device = Some(text.parse().with_context(||
                    format!("--device needs a number, not {text}"))?);
            },
            "--power-source" => options.power_source = Some(value()?),
            "--power" => options.power_on = Some(match value()?.as_str() {
                "on" => true,
                "off" => false,
                other => bail!("--power needs on or off, not {other}"),
            }),
            "--power-on-start" => options.power_on_start = true,
            "--power-off-stop" => options.power_off_stop = true,
            _ if arg.starts_with('-') && arg != "-" =>
                bail!("Unknown option {arg}\n\n{USAGE}"),
            _ if options.output.is_some() =>
                bail!("More than one output file given"),
            _ => options.output = Some(PathBuf::from(arg)),
        }
    }
    Ok(Some(options))
}

fn parse_speed(text: &str) -> Result<Speed, Error> {
    use Speed::*;
    Ok(match text.to_ascii_lowercase().as_str() {
        "high" | "hs" => High,
        "full" | "fs" => Full,
        "low" | "ls" => Low,
        "auto" => Auto,
        _ => bail!("Unknown speed {text}; use high, full, low or auto"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Options>, Error> {
        parse_args(args.iter().map(|arg| arg.to_string()))
    }

    #[test]
    fn parses_a_timed_capture() {
        let options = parse(&[
            "--speed", "full", "--duration", "2.5", "--comment", "run 1",
            "out.pcapng",
        ]).unwrap().unwrap();
        assert_eq!(options.speed, Some(Speed::Full));
        assert_eq!(options.duration, Some(Duration::from_millis(2500)));
        assert_eq!(options.comment.as_deref(), Some("run 1"));
        assert_eq!(options.output, Some(PathBuf::from("out.pcapng")));
    }

    #[test]
    fn parses_power_options() {
        let options = parse(&[
            "--power-source", "target-c", "--power", "off",
            "--power-on-start", "--power-off-stop", "out.pcapng",
        ]).unwrap().unwrap();
        assert_eq!(options.power_source.as_deref(), Some("target-c"));
        assert_eq!(options.power_on, Some(false));
        assert!(options.power_on_start);
        assert!(options.power_off_stop);
    }

    #[test]
    fn rejects_bad_arguments() {
        assert!(parse(&["--speed", "warp", "out.pcapng"]).is_err());
        assert!(parse(&["--duration", "0", "out.pcapng"]).is_err());
        assert!(parse(&["--duration", "-1", "out.pcapng"]).is_err());
        assert!(parse(&["--duration"]).is_err());
        assert!(parse(&["--power", "maybe", "out.pcapng"]).is_err());
        assert!(parse(&["--bogus", "out.pcapng"]).is_err());
        assert!(parse(&["a.pcapng", "b.pcapng"]).is_err());
    }

    /// Replays a fixed list of events, as if from an analyzer.
    struct Replay(std::vec::IntoIter<TimestampedEvent>);

    impl Iterator for Replay {
        type Item = backend::EventResult;
        fn next(&mut self) -> Option<Self::Item> {
            self.0.next().map(Ok)
        }
    }

    impl backend::EventIterator for Replay {}

    /// A packet's bytes or an event's type, with its timestamp.
    type Item = (u64, Result<Vec<u8>, EventType>);

    fn item(event: &TimestampedEvent) -> Item {
        use TimestampedEvent::*;
        match event {
            Packet { timestamp_ns, bytes } =>
                (*timestamp_ns, Ok(bytes.clone())),
            Event { timestamp_ns, event_type } =>
                (*timestamp_ns, Err(event_type.clone())),
        }
    }

    #[test]
    fn writes_everything_the_analyzer_sends() {
        use TimestampedEvent::*;
        use file::{GenericLoader, GenericPacket, LoaderItem, PcapNgLoader};

        let sent = vec![
            Event { timestamp_ns: 0,
                    event_type: EventType::CaptureStart(Speed::High) },
            Packet { timestamp_ns: 16, bytes: vec![0xA5, 0x00, 0x10] },
            Packet { timestamp_ns: 125_033, bytes: vec![0x69, 0x82, 0x18] },
            Packet { timestamp_ns: 125_300,
                     bytes: vec![0xC3, 0x01, 0x02, 0x03, 0x2E, 0x6F] },
            Event { timestamp_ns: 250_050, event_type: EventType::BusReset },
            Event { timestamp_ns: 3_000_000_016,
                    event_type: EventType::CaptureStop(
                        StopReason::BufferFull) },
        ];
        let expected: Vec<Item> = sent.iter().map(item).collect();

        // Write the events as a capture would.
        let path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let meta = CaptureMetadata {
            start_time: Some(Duration::from_secs(1_000)),
            .. Default::default()
        };
        let file = File::create(&path).unwrap();
        let mut saver = PcapNgSaver::new(file, Arc::new(meta.clone())).unwrap();
        let counts = Counts::default();
        write_events(Box::new(Replay(sent.into_iter())), &mut saver, &counts)
            .unwrap();
        let end_time = Duration::from_secs(1_003);
        saver.update_metadata(Arc::new(CaptureMetadata {
            end_time: Some(end_time),
            .. meta
        }));
        saver.close().unwrap();

        assert_eq!(counts.packets.load(Ordering::Acquire), 3);
        assert_eq!(counts.events.load(Ordering::Acquire), 3);
        assert_eq!(counts.bytes.load(Ordering::Acquire), 12);
        assert!(counts.overflow.load(Ordering::Acquire));

        // Read the file back as the GUI would load it.
        let mut loader = PcapNgLoader::new(File::open(&path).unwrap()).unwrap();
        let mut received = Vec::new();
        let mut end_times = Vec::new();
        loop {
            match loader.next() {
                LoaderItem::Packet(packet) => received.push(
                    (packet.timestamp_ns(), Ok(packet.bytes().to_vec()))),
                LoaderItem::Event(event) => received.push(
                    (event.timestamp_ns, Err(event.event_type))),
                LoaderItem::Metadata(meta) => end_times.extend(meta.end_time),
                LoaderItem::Ignore => {},
                LoaderItem::LoadError(e) => panic!("{e:#}"),
                LoaderItem::End => break,
            }
        }
        assert_eq!(received, expected);
        assert_eq!(end_times, vec![end_time]);
    }

    #[test]
    fn help_and_version_capture_nothing() {
        assert!(parse(&["--help"]).unwrap().is_none());
        assert!(parse(&["--version"]).unwrap().is_none());
    }
}
