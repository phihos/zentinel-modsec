use std::path::{Path, PathBuf};
use std::sync::Arc;
use zentinel_modsec::error::SourceLocation;
use zentinel_modsec::parser::{Directive, Parser, ParserHost};
use zentinel_modsec::{Error, Result};

struct Files(PathBuf);

impl ParserHost for Files {
    fn includes(&self, file: Option<&Path>, operand: &Path) -> Result<Vec<PathBuf>> {
        Ok(vec![file
            .and_then(Path::parent)
            .unwrap_or(&self.0)
            .join(operand)])
    }

    fn data_file(&self, _: Option<&Path>, operand: &Path) -> Result<PathBuf> {
        Ok(self.0.join("data").join(operand))
    }

    fn unknown_directive(&self, name: &str, _: &str, location: &SourceLocation) -> Result<()> {
        Err(Error::parse(
            format!("unsupported {name}"),
            location.to_string(),
        ))
    }
}

#[test]
fn connector_paths_and_errors_follow_nested_includes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("conf")).unwrap();
    std::fs::write(dir.path().join("root.conf"), "Include conf/child.conf").unwrap();
    let child = dir.path().join("conf/child.conf");
    std::fs::write(
        &child,
        "SecRule ARGS \"@pmFromFile words\" \"id:1,phase:2,pass\"",
    )
    .unwrap();
    let mut parser = Parser::new().with_host(Arc::new(Files(dir.path().into())));
    parser.parse("Include root.conf").unwrap();
    let Directive::SecRule(rule) = &parser.directives()[0] else {
        panic!("missing nested rule");
    };
    assert_eq!(
        Path::new(&rule.operator.argument),
        dir.path().join("data/words")
    );
    assert_eq!(rule.location.file.as_ref(), Some(&child));

    std::fs::write(&child, "\nSecUnknown value").unwrap();
    let error = parser.parse("Include root.conf").unwrap_err();
    assert!(error
        .to_string()
        .contains(&format!("{}:2:1", child.display())));
    assert_eq!(parser.directives().len(), 3);
}
