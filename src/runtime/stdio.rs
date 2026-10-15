// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::launcher::ServiceLauncher;
use hyper_os::{handle::*, task::ProcessBuilder};

#[derive(Clone, Copy)]
enum LogSink {
    Journal,
    RawConsole,
}

impl ServiceLauncher {
    /// Formal services always log through journal; a missing collector is a
    /// startup error, not an implicit grant of direct console output.
    pub(super) fn stdio(
        &self,
        builder: &ProcessBuilder,
        name: &str,
        generation: u64,
    ) -> hyper_os::Result<()> {
        if !self.authorities.journal_active {
            return Err(hyper_os::Error::Status(hyper_os::Status::BAD_STATE));
        }
        self.attach_stdio(builder, name, generation, LogSink::Journal)
    }

    /// Journal cannot capture its own startup errors before it is running.
    pub(super) fn journal_stdio(
        &self,
        builder: &ProcessBuilder,
        name: &str,
    ) -> hyper_os::Result<()> {
        if self.authorities.journal_active {
            return Err(hyper_os::Error::Status(hyper_os::Status::BAD_STATE));
        }
        self.attach_stdio(builder, name, 1, LogSink::RawConsole)
    }

    fn attach_stdio(
        &self,
        builder: &ProcessBuilder,
        name: &str,
        generation: u64,
        sink: LogSink,
    ) -> hyper_os::Result<()> {
        let (input, eof) = hyper_os::channel::create_pair()?;
        drop(eof);
        builder
            .add_handle_move(
                input,
                hyper_service::stdio::STANDARD_INPUT.as_raw(),
                RightsOffer::Exact(
                    Rights::READ
                        .union(Rights::WAIT)
                        .union(Rights::DUPLICATE)
                        .union(Rights::TRANSFER),
                ),
            )
            .map_err(|f| f.error())?;
        for (purpose, stream) in [
            (
                hyper_service::stdio::STANDARD_OUTPUT,
                hyper_journal::Stream::Stdout,
            ),
            (
                hyper_service::stdio::STANDARD_ERROR,
                hyper_journal::Stream::Stderr,
            ),
        ] {
            let (writer, reader) = hyper_os::channel::create_pair()?;
            if matches!(sink, LogSink::Journal) {
                hyper_journal::register(
                    self.authorities.log_connector.as_handle_ref(),
                    &hyper_journal::Source {
                        component: name.into(),
                        generation,
                        stream,
                    },
                    reader,
                )?;
            } else {
                hyper_service::console::register_log(
                    self.authorities.log_connector.as_handle_ref(),
                    name,
                    reader,
                )?;
            }
            builder
                .add_handle_move(
                    writer,
                    purpose.as_raw(),
                    RightsOffer::Exact(
                        Rights::WRITE
                            .union(Rights::WAIT)
                            .union(Rights::DUPLICATE)
                            .union(Rights::TRANSFER),
                    ),
                )
                .map_err(|f| f.error())?;
        }
        Ok(())
    }
}
