//! Log view (FR-040, US5): snapshot + live lines, level filter, copy all.

use crate::app::App;
use eframe::egui::{self, Color32, RichText};

const LEVELS: [&str; 5] = ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

fn rank(level: &str) -> usize {
    LEVELS.iter().position(|l| *l == level).unwrap_or(2)
}

fn color(level: &str) -> Color32 {
    match level {
        "ERROR" => Color32::from_rgb(0xd6, 0x3a, 0x3a),
        "WARN" => Color32::from_rgb(0xe8, 0xa3, 0x17),
        "DEBUG" | "TRACE" => Color32::GRAY,
        _ => Color32::PLACEHOLDER,
    }
}

fn time_of_day(ms: u64) -> String {
    let s = (ms / 1000) % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03} UTC",
        s / 3600,
        (s / 60) % 60,
        s % 60,
        ms % 1000
    )
}

impl App {
    pub fn log_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Show");
            egui::ComboBox::from_id_salt("loglevel")
                .selected_text(LEVELS[self.log_level])
                .show_ui(ui, |ui| {
                    for (i, l) in LEVELS.iter().enumerate() {
                        ui.selectable_value(&mut self.log_level, i, *l);
                    }
                });
            if ui.button("Copy all").clicked() {
                let text: String = self
                    .logs
                    .iter()
                    .map(|l| {
                        format!(
                            "{} {:5} {}: {}\n",
                            time_of_day(l.ts_unix_ms),
                            l.level,
                            l.target,
                            l.message
                        )
                    })
                    .collect();
                ui.ctx().copy_text(text);
            }
            ui.label(RichText::new(format!("{} lines", self.logs.len())).weak());
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for l in self
                    .logs
                    .iter()
                    .filter(|l| rank(&l.level) <= self.log_level)
                {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(time_of_day(l.ts_unix_ms)).monospace().weak());
                        ui.label(
                            RichText::new(format!("{:5}", l.level))
                                .monospace()
                                .color(color(&l.level)),
                        );
                        ui.label(RichText::new(&l.target).monospace().weak());
                        ui.label(RichText::new(&l.message).monospace());
                    });
                }
            });
    }
}
