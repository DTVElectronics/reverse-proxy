use minify_html::{minify, Cfg};
use std::{
    fs::{self, File},
    io::Read,
    io::Write,
};

static FILES: [&str; 3] = ["421.html", "500.html", "502.html"];

fn main() {
    fs::create_dir_all("src/static/minified").unwrap();
    let mut cfg = Cfg::new();
    cfg.do_not_minify_doctype = true;
    cfg.keep_html_and_head_opening_tags = true;
    cfg.keep_closing_tags = true;
    for filename in FILES {
        let input = format!("src/static/{}", filename);
        let output = format!("src/static/minified/{}", filename);
        println!("cargo:rerun-if-changed={}", input);
        let metadata = fs::metadata(&input).expect("unable to read metadata");
        let mut file = File::open(input).unwrap();
        let mut buffer = vec![0; metadata.len() as usize];
        file.read_exact(&mut buffer).expect("Read error");
        let minified = minify(&buffer, &cfg);
        let mut file = File::create(output).unwrap();
        file.write_all(&minified).unwrap();
    }
}
