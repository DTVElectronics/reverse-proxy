
use minify_html::{Cfg, minify};
use std::{fs::{File, self}, io::Read, io::Write};

fn main() {
    fs::create_dir_all("src/static/minified").unwrap();
    let files = vec!["404.html", "500.html", "502.html"];
    let mut cfg = Cfg::new();
    cfg.do_not_minify_doctype = true;
    cfg.keep_html_and_head_opening_tags = true;
    cfg.keep_closing_tags = true;
    for filename in files {
        let input = format!("src/static/{}", filename);
        let output = format!("src/static/minified/{}", filename);
        println!("cargo:rerun-if-changed={}", input);
        let metadata = fs::metadata(&input).expect("unable to read metadata");
        let mut file = File::open(input).unwrap();
        let mut buffer = vec![0; metadata.len() as usize];
        file.read(&mut buffer).expect("buffer overflow");
        let minified = minify(&buffer, &cfg);
        let mut file = File::create(output).unwrap();
        file.write_all(&minified).unwrap();
    }
}
