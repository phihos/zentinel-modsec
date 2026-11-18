use std::io::{self, Write};
use zentinel_modsec::variables::{ByteCollection, HashMapCollection, RequestData};

fn dump(output: &mut impl Write, args: &HashMapCollection) -> io::Result<()> {
    let items = args.all_bytes_with_names();
    output.write_all(&(items.len() as u64).to_le_bytes())?;
    for (lookup, observed, value) in items {
        for bytes in [lookup, observed, value] {
            output.write_all(&(bytes.len() as u64).to_le_bytes())?;
            output.write_all(bytes)?;
        }
    }
    Ok(())
}

fn inspect(output: &mut impl Write, request: &mut RequestData, input: &[u8]) -> io::Result<()> {
    let mut uri = b"/form?".to_vec();
    uri.extend_from_slice(input);
    request.set_uri_bytes(&uri);
    dump(output, &request.args_get)?;
    request.args_post.clear();
    request.body = input.to_vec();
    request.parse_form_body();
    dump(output, &request.args_post)
}

fn main() -> io::Result<()> {
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut request = RequestData::default();
    // Include invalid UTF-8, malformed and valid escapes, raw and encoded
    // separators, duplicates, empty fields, fragment separators and bare keys.
    let atoms: &[&[u8]] = &[
        b"a",
        b"A",
        b"=",
        b"&",
        b"%",
        b"+",
        b"%41",
        b"%ff",
        b"%2B",
        b"%26",
        b"%3d",
        b"%0",
        b"%xx",
        "é".as_bytes(),
        b"\xff",
        b"\x00",
        b"#",
        b"0",
    ];
    let mut cases = 0;
    for a in atoms {
        for b in atoms {
            for c in atoms {
                let mut input = b"a=1&A=".to_vec();
                input.extend_from_slice(a);
                input.extend_from_slice(b);
                input.extend_from_slice(c);
                input.extend_from_slice(b"&=a&b");
                inspect(&mut output, &mut request, &input)?;
                cases += 1;
            }
        }
    }
    for length in [0, 1, 63, 1022, 1023, 1024, 1025, 2047, 2048, 8192] {
        for atom in atoms {
            for late in [false, true] {
                let mut large = vec![b'x'; length];
                if late {
                    large.extend_from_slice(atom);
                } else {
                    large.splice(0..0, atom.iter().copied());
                }
                let input = [b"k=".as_slice(), &large, b"&k=LAST&"].concat();
                inspect(&mut output, &mut request, &input)?;
                cases += 1;
            }
        }
    }
    output.flush()?;
    eprintln!("{cases} inputs, GET and form POST");
    Ok(())
}
