use std::io::{self, Write};
use zentinel_modsec::variables::{ByteCollection, RequestData};

fn main() -> io::Result<()> {
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut seed = 2039u64;
    let mut next = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (seed >> 32) as usize
    };
    for case in 0..256 {
        let mut form = Vec::new();
        let fields = 1 + next() % 350;
        for i in 0..fields {
            if i > 0 { form.push(b'&'); }
            if next() % 8 == 0 { continue; }
            let n = next() % 12;
            form.extend_from_slice(if next() % 3 == 0 { b"KeY" } else { b"key" });
            form.push(b'A' + n as u8);
            if next() % 9 == 0 { continue; }
            form.push(b'=');
            let size = if i == 0 && case % 8 == 0 { 1020 + case % 9 } else { next() % 30 };
            for _ in 0..size {
                if case % 3 == 0 { form.push(b'a' + (next() % 26) as u8); }
                else {
                    let fragments: &[&[u8]] = &[b"z", b"%", b"%G0", b"%26", b"%ff", b"+", b"\xff", b"=", b"&", b"", "Ö".as_bytes(), b"\0"];
                    form.extend_from_slice(fragments[next() % fragments.len()]);
                }
            }
        }
        let mut r = RequestData::new();
        let mut uri = b"/?".to_vec();
        uri.extend_from_slice(&form);
        r.set_uri_bytes(&uri);
        r.body.extend_from_slice(&form);
        r.parse_form_body();
        let get = r.args_get.all_bytes_with_names();
        assert_eq!(get, r.args_post.all_bytes_with_names());
        output.write_all(&(get.len() as u64).to_le_bytes())?;
        for (folded, raw, val) in get {
            for data in [folded, raw, val] {
                output.write_all(&(data.len() as u64).to_le_bytes())?;
                output.write_all(data)?;
            }
        }
    }
    Ok(())
}
