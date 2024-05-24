use std::path::Path;

use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

pub fn init_tracing_subscriber(save_logs_file: bool, output_dir: &Path, filename: &str) {
    // base for the subscriber
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::CLOSE);

    if save_logs_file {
        let filename = format!("{}.log", filename);
        let file_appender = RollingFileAppender::new(Rotation::NEVER, output_dir, filename);
        let suscriber = subscriber
            .with_ansi(false)
            .with_file(false)
            .with_target(false)
            .with_writer(file_appender)
            .finish();

        // add log in terminal as an additional layer
        let stdout_layer = layer()
            .with_span_events(FmtSpan::CLOSE)
            .with_ansi(true)
            .with_file(false)
            .with_target(false);

        // init the subscriber
        tracing::subscriber::set_global_default(suscriber.with(stdout_layer))
            .expect("Unable to set global subscriber with 2 layer");
    } else {
        let suscriber = subscriber
            // -- DEV
            .without_time()
            .with_thread_ids(true)
            // -- DEV
            .with_ansi(true)
            .with_file(false)
            .with_target(false)
            .finish();

        // init the subscriber
        tracing::subscriber::set_global_default(suscriber)
            .expect("Unable to set global subscriber with 2 layer");
    }
}
