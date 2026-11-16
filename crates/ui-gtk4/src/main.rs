//! `whatsnative` (`Kestrel Companion`) binary entrypoint.
//! Initializes XDG Base Directories (`0700`), probes D-Bus desktop capabilities,
//! supports headless `--export-diagnostics <file.json>`, and launches the native
//! GTK4 + `libadwaita 1.5` desktop application.

mod app;
mod cli;
mod qr_widget;
mod style;

use anyhow::Result;
use cli::CliArgs;
use whatsnative_domain::{DiagnosticCounterSnapshot, HistorySyncStats, PUBLIC_APP_TITLE};
use whatsnative_platform_xdg::{
    DesktopCapabilities, KeyUnlockOutcome, KeystoreManager, RedactedDiagnosticsRing, XdgLayout,
};
use whatsnative_store::VaultStore;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = CliArgs::parse_from_iter(std::env::args())?;
    if cli.show_help {
        print!("{}", CliArgs::usage_text());
        return Ok(());
    }
    if cli.show_version {
        println!(
            "{PUBLIC_APP_TITLE} (whatsnative) {}",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }

    let layout = if let Some(profile_root) = &cli.profile_dir {
        XdgLayout::from_root_for_profile(profile_root)?
    } else {
        XdgLayout::resolve_default()?
    };

    let diagnostics = RedactedDiagnosticsRing::new(&layout.state_log_dir, 500);
    diagnostics.record_sanitized_event(
        "startup",
        if cli.mock_mode {
            "Initializing Kestrel Companion in --mock offline fixture mode"
        } else {
            "Initializing Kestrel Companion"
        },
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .thread_name("kestrel-tokio")
        .build()?;

    let caps = runtime.block_on(DesktopCapabilities::probe_live());
    diagnostics.record_sanitized_event(
        "xdg-probe",
        &format!(
            "session={} desktop={} close_policy={:?}",
            caps.session_type, caps.current_desktop, caps.close_policy
        ),
    );

    // Headless data audit mode
    if cli.inspect_data {
        let keystore = KeystoreManager::new(layout.keystore_manifest_path.clone());
        if let Ok(KeyUnlockOutcome::Unlocked(master_key)) =
            keystore.unlock_or_initialize(&caps, cli.passphrase.as_deref())
        {
            let vault = VaultStore::open_encrypted(
                &layout.vault_db_path,
                &layout.cache_media_dir,
                &master_key,
            )?;
            let bak_path = layout
                .vault_db_path
                .with_file_name("vault.db.bak_before_repair");
            let _ = vault.inspect_backup(&bak_path, &master_key);
            vault.run_data_attribution_audit()?;
        } else {
            eprintln!("Failed to unlock keystore");
        }
        return Ok(());
    }

    // Headless zero-PII diagnostic export mode (works even without a Wayland/X11 display)
    if let Some(export_path) = &cli.export_diagnostics {
        let mut sync_stats = HistorySyncStats::default();
        let keystore = KeystoreManager::new(layout.keystore_manifest_path.clone());
        if let Ok(KeyUnlockOutcome::Unlocked(master_key)) =
            keystore.unlock_or_initialize(&caps, cli.passphrase.as_deref())
            && let Ok(vault) = VaultStore::open_encrypted(
                &layout.vault_db_path,
                &layout.cache_media_dir,
                &master_key,
            )
        {
            if cli.mock_mode {
                let (tx, _rx) = async_channel::unbounded();
                let mock = whatsnative_adapter_wa::MockCompanionAdapter::new(vault.clone(), tx);
                let _ = mock.seed_fixture_archive();
            }
            sync_stats = vault.sync_stats().unwrap_or_default();
        }

        let counters = DiagnosticCounterSnapshot {
            messages_persisted: sync_stats.messages_committed,
            retry_receipts_quarantined: 0,
            history_chunks_staged: sync_stats.chunks_staged,
            outbound_commands_paced: 0,
            call_signals_observed: 0,
            circuit_breaker_trips: 0,
            last_protocol_anomaly: None,
        };
        diagnostics.export_bundle(export_path, caps, counters, sync_stats)?;
        println!(
            "Exported zero-PII redacted diagnostic bundle to {}",
            export_path.display()
        );
        return Ok(());
    }

    let exit_code =
        app::run_gtk_application(cli, runtime.handle().clone(), layout, caps, diagnostics);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}
