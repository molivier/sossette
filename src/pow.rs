// SPDX-FileCopyrightText: 2023-2025 erdnaxe
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use rand::distr::Alphanumeric;
use rand::{RngExt, rng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const POW_HEADER_MESSAGE: &[u8] = b"= Proof of Work protection =\r\n\
To launch this challenge, you need to solve a proof-of-work.\r\n\
More details can be found on <https://fcsc.fr/pow>.\r\n";

/// Proof-of-Work prompt
///
/// Ask client to solve a hard challenge. This is used as anti-DDoS protection.
pub async fn proof_of_work_prompt<S: AsyncReadExt + AsyncWriteExt + std::marker::Unpin>(
    socket: &mut S,
    difficulty: u32,
    backdoor: Option<String>,
) -> Result<bool> {
    // Generate prefix using OS random
    let prefix: [u8; 16] = rng()
        .sample_iter(Alphanumeric)
        .take(16)
        .collect::<Vec<u8>>()
        .as_slice()
        .try_into()
        .context("Failed to generate random prefix")?;

    // Prompt user
    socket.write_all(POW_HEADER_MESSAGE).await?;
    let prompt = format!(
        "Please provide an ASCII printable string S such that SHA256({} || S) starts with {} bits equal to 0 (the string concatenation is denoted ||): ",
        String::from_utf8(prefix.into())?,
        difficulty
    );
    socket.write_all(prompt.as_bytes()).await?;
    let mut buf = [0u8; 256];
    let mut buf_n: usize = 0;
    while buf_n < 256 {
        let byte = buf
            .get_mut(buf_n..=buf_n)
            .context("read index out of bounds")?;
        let n = socket.read(byte).await?;
        if n == 0 {
            return Ok(false); // socket closed
        }

        let current = byte.first().context("index out of bounds")?;
        if *current == b'\0' || *current == b'\n' {
            break; // telnet uses \r\0, netcat \r\n
        }
        if !(32..127).contains(current) {
            continue; // ignore non ascii printable
        }
        buf_n = buf_n.checked_add(n).context("buffer index overflow")?;
    }

    // Get the user input as a slice
    let mut suffix = buf.get(..buf_n).context("slice out of bounds")?;

    // Trim trailing carriage return
    while let Some(last) = suffix.last()
        && (*last == b'\n' || *last == b'\r' || *last == b'\0')
    {
        suffix
            .split_off_last()
            .context("failed to remove trailing")?;
    }

    // Backdoor for staff testing
    if let Some(bd) = backdoor
        && bd.as_bytes() == suffix
    {
        return Ok(true);
    }

    // Compute hash
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(suffix);
    let hash: [u8; 32] = hasher.finalize().into();

    // Count zeros
    let mut measured_difficulty: u32 = 0;
    for hash_byte in &hash {
        if *hash_byte == 0 {
            measured_difficulty = measured_difficulty.saturating_add(8);
        } else {
            measured_difficulty = measured_difficulty.saturating_add(hash_byte.leading_zeros());
            break;
        }
    }

    if measured_difficulty < difficulty {
        let message = format!(
            "Wrong proof-of-work, hash starts with only {measured_difficulty} bits equal to 0.\r\n"
        );
        socket.write_all(message.as_bytes()).await?;
        Ok(false)
    } else {
        socket.write_all(b"Thank you for solving our proof-of-work, we hope you had a great time! Launching challenge...\r\n\r\n").await?;
        Ok(true)
    }
}
