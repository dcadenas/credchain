//! Interactive value prompting for `--set`, including `--noecho`.
//!
//! Echo mode reads a line from stdin. Noecho mode disables terminal echo via
//! `termios`, reads a line, and restores echo — matching envchain's behavior.
//! Secret bytes live only in the returned buffer.

use std::io::{self, BufRead, Write};

pub struct PromptResult {
    pub value: Vec<u8>,
    /// `true` if the read hit EOF without any bytes (user aborted with Ctrl-D).
    pub eof: bool,
}

/// Prompt and read one value. `prompt` is a non-secret label like `ns.VAR`.
/// If `noecho`, the terminal's echo is disabled for the duration of the read.
pub fn read_value(prompt: &str, noecho: bool) -> Result<PromptResult, io::Error> {
    if noecho {
        read_noecho(prompt)
    } else {
        print!("{prompt}: ");
        io::stdout().flush()?;
        read_line()
    }
}

fn read_line() -> Result<PromptResult, io::Error> {
    let mut buf = Vec::new();
    let n = io::stdin().lock().read_until(b'\n', &mut buf)?;
    let eof = n == 0 && buf.is_empty();
    // Strip a trailing newline (and CR for CRLF terminals).
    if !buf.is_empty() && buf.last() == Some(&b'\n') {
        buf.pop();
        if !buf.is_empty() && buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    Ok(PromptResult { value: buf, eof })
}

fn read_noecho(prompt: &str) -> Result<PromptResult, io::Error> {
    use std::os::unix::io::AsRawFd;
    let fd = io::stdin().as_raw_fd();
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } < 0 {
        return Err(io::Error::other("--noecho requires stdin to be a terminal"));
    }
    let mut new = orig;
    new.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &new) } < 0 {
        return Err(io::Error::other("tcsetattr failed"));
    }
    print!("{prompt} (noecho): ");
    io::stdout().flush()?;
    let res = read_line();
    // Always restore echo.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &orig) } < 0 {
        // Best-effort; surface the read result, not the restore failure, unless
        // the read succeeded in which case the restore failure is the error.
        if res.is_ok() {
            return Err(io::Error::other("tcsetattr restore failed"));
        }
    }
    println!();
    res
}
