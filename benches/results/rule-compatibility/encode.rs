use zentinel_modsec::transformations::{Transformation, UrlEncode};
fn main() {
    let input: Vec<u8> = (0..=255).collect();
    let bytes = UrlEncode.transform_bytes(&input).unwrap();
    print!("{}", std::str::from_utf8(&bytes).unwrap());
}
