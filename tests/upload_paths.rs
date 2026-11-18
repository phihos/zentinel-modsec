use std::path::{Path, PathBuf};
use zentinel_modsec::{variables::Collection, ModSecurity};

const BODY: &[u8] = b"--B\r\nContent-Disposition: form-data; name=\"one\"; filename=\"example.txt\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nA=00B\r\n--B\r\nContent-Disposition: form-data; name=\"two\"; filename=\"second\"\r\n\r\nC\r\n--B--\r\n";

fn process(directory: &Path, rules: &str) -> zentinel_modsec::Transaction {
    let engine = ModSecurity::from_string(&format!(
        "SecRequestBodyAccess On\nSecUploadDir {}\n{rules}",
        directory.display()
    ))
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=B")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.write_request_body(BODY).unwrap();
    tx.process_request_body().unwrap();
    tx
}

#[test]
fn multipart_paths_preserve_decoded_content_and_are_removed_at_transaction_end() {
    let dir = tempfile::tempdir().unwrap();
    let mut tx = process(
        dir.path(),
        r#"SecRule &FILES_TMPNAMES "@eq 2" "id:1,phase:2,pass"
SecAction "id:2,phase:5,pass,setvar:tx.path=%{FILES_TMPNAMES}""#,
    );
    tx.process_logging().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    let path = PathBuf::from(tx.tx().get("path").unwrap()[0]);
    assert_eq!(path.parent(), Some(dir.path()));
    assert_eq!(std::fs::read(&path).unwrap(), b"A\0B");
    let contents: Vec<_> = dir
        .path()
        .read_dir()
        .unwrap()
        .map(|file| std::fs::read(file.unwrap().path()).unwrap())
        .collect();
    assert_eq!(contents.len(), 2);
    assert!(contents.contains(&vec![b'C']));
    drop(tx);
    assert_eq!(dir.path().read_dir().unwrap().count(), 0);
}

#[test]
fn a_macro_alone_requests_paths_and_ordinary_file_metadata_needs_no_disk_copy() {
    let dir = tempfile::tempdir().unwrap();
    let tx = process(
        dir.path(),
        r#"SecAction "id:1,phase:2,pass,setvar:tx.file=%{files_tmpnames}""#,
    );
    assert!(Path::new(tx.tx().get("file").unwrap()[0]).exists());
    drop(tx);
    let tx = process(dir.path(), r#"SecRule &FILES "@eq 2" "id:1,phase:2,pass""#);
    assert_eq!(tx.matched_rules(), ["1"]);
    assert_eq!(dir.path().read_dir().unwrap().count(), 0);
}

#[test]
fn missing_upload_directory_fails_loading() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        ModSecurity::from_string(&format!("SecUploadDir {}/missing", dir.path().display()))
            .is_err()
    );
}
