// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Owned plaintext staging. Growth wipes the old allocation before freeing it.
use std::io::{self, Read};
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn reserve(bytes: &mut Zeroizing<Vec<u8>>, additional: usize) -> io::Result<()> {
    let needed = bytes
        .len()
        .checked_add(additional)
        .ok_or_else(|| io::Error::other("plaintext buffer size overflow"))?;
    if needed <= bytes.capacity() {
        return Ok(());
    }
    let capacity = needed.max(bytes.capacity().saturating_mul(2));
    let mut replacement = Zeroizing::new(Vec::new());
    replacement
        .try_reserve_exact(capacity)
        .map_err(io::Error::other)?;
    replacement.extend_from_slice(bytes);
    // Do not let Vec::reserve/realloc release an allocation containing secrets.
    bytes.as_mut_slice().zeroize();
    #[cfg(test)]
    WIPED_GROWTH.with(|n| {
        assert!(bytes.iter().all(|&b| b == 0));
        n.set(n.get() + usize::from(!bytes.is_empty()));
    });
    *bytes = replacement;
    Ok(())
}

pub(crate) fn reserve_vec(bytes: &mut Vec<u8>, additional: usize) -> io::Result<()> {
    let mut protected = Zeroizing::new(std::mem::take(bytes));
    let result = reserve(&mut protected, additional);
    *bytes = std::mem::take(&mut *protected);
    result
}

pub(crate) fn read_to_end(
    reader: &mut impl Read,
    bytes: &mut Zeroizing<Vec<u8>>,
) -> io::Result<()> {
    let mut scratch = Zeroizing::new([0u8; 64 * 1024]);
    loop {
        let n = match reader.read(&mut *scratch) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            return Ok(());
        }
        reserve(bytes, n)?;
        bytes.extend_from_slice(&scratch[..n]);
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static WIPED_GROWTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn growth_wipes_old_live_storage_and_preserves_bytes() {
        let data = vec![0xa7; 3 * 1024 * 1024];
        let mut output = Zeroizing::new(Vec::new());
        WIPED_GROWTH.with(|n| n.set(0));
        read_to_end(&mut data.as_slice(), &mut output).unwrap();
        assert_eq!(*output, data);
        assert!(WIPED_GROWTH.with(|n| n.get()) > 0);
    }
}
