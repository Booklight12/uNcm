use std::collections::HashSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use uncm::ncm::{Decoder, Headers};

const HELP: &str = r#"uNcm 0.1.0 - 纯标准库 NCM 批量解密器

用法:
  uNcm [选项] <文件或目录>...

选项:
  -o, --output <目录>  把所有输出写到指定目录（默认写在源文件旁）
  -r, --recursive      递归扫描输入目录
  -f, --force          覆盖已存在的目标文件
      --info           仅解析并显示信息，不写音频
  -h, --help           显示帮助
  -V, --version        显示版本

示例:
  uNcm "D:\\CloudMusic\\VipSongsDownload"
  uNcm -r -o "D:\\Music\\Decoded" "D:\\CloudMusic"
"#;

#[derive(Default)]
struct Options {
    output: Option<PathBuf>,
    recursive: bool,
    force: bool,
    info: bool,
    inputs: Vec<PathBuf>,
}

enum ParseResult {
    Run(Options),
    Exit,
}

fn main() -> ExitCode {
    let options = match parse_args(env::args_os().skip(1)) {
        Ok(ParseResult::Run(options)) => options,
        Ok(ParseResult::Exit) => return ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("错误: {message}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };

    let files = match collect_inputs(&options.inputs, options.recursive) {
        Ok(files) if !files.is_empty() => files,
        Ok(_) => {
            eprintln!("没有找到 .ncm 文件");
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("扫描输入失败: {error}");
            return ExitCode::from(1);
        }
    };

    if let Some(output) = &options.output
        && !options.info
        && let Err(error) = fs::create_dir_all(output)
    {
        eprintln!("无法创建输出目录 {}: {error}", output.display());
        return ExitCode::from(1);
    }

    let total = files.len();
    let (mut succeeded, mut skipped, mut failed) = (0usize, 0usize, 0usize);
    for (index, source) in files.iter().enumerate() {
        print!("[{}/{}] {} ... ", index + 1, total, source.display());
        let _ = io::stdout().flush();
        match process_one(source, &options) {
            Ok(ProcessResult::Written {
                target,
                bytes,
                headers,
            }) => {
                succeeded += 1;
                println!(
                    "完成 -> {} ({}，{})",
                    target.display(),
                    format_size(bytes),
                    headers.format
                );
                print_metadata_warning(&headers);
            }
            Ok(ProcessResult::Info(headers)) => {
                succeeded += 1;
                println!(
                    "{}，音频 {}，封面 {}",
                    headers.format,
                    format_size(headers.audio_bytes),
                    format_size(headers.cover_bytes)
                );
                print_metadata(&headers);
                print_metadata_warning(&headers);
            }
            Ok(ProcessResult::Skipped(target)) => {
                skipped += 1;
                println!("跳过（已存在）: {}", target.display());
            }
            Err(error) => {
                failed += 1;
                println!("失败: {error}");
            }
        }
    }

    println!("汇总: 成功 {succeeded}，跳过 {skipped}，失败 {failed}");
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

enum ProcessResult {
    Written {
        target: PathBuf,
        bytes: u64,
        headers: Headers,
    },
    Info(Headers),
    Skipped(PathBuf),
}

fn process_one(source: &Path, options: &Options) -> Result<ProcessResult, String> {
    let mut decoder = Decoder::open(source).map_err(|e| e.to_string())?;
    let headers = decoder.headers().clone();
    if options.info {
        return Ok(ProcessResult::Info(headers));
    }

    let filename = source
        .file_stem()
        .ok_or_else(|| "源文件没有可用文件名".to_owned())?;
    let mut output_name = PathBuf::from(filename);
    output_name.set_extension(headers.format.extension());
    let target = match &options.output {
        Some(directory) => directory.join(output_name),
        None => source.with_extension(headers.format.extension()),
    };

    if target == source {
        return Err("目标路径与源文件相同".into());
    }
    if target.exists() && !options.force {
        return Ok(ProcessResult::Skipped(target));
    }
    let parent = target
        .parent()
        .ok_or_else(|| "目标路径没有父目录".to_owned())?;
    fs::create_dir_all(parent).map_err(|e| format!("创建输出目录失败: {e}"))?;

    let mut temporary = TemporaryOutput::create(&target)?;
    let bytes = decoder
        .decode_to_writer(temporary.file_mut())
        .map_err(|e| e.to_string())?;
    temporary
        .file_mut()
        .flush()
        .map_err(|e| format!("刷新临时文件失败: {e}"))?;
    temporary
        .file_mut()
        .sync_all()
        .map_err(|e| format!("同步临时文件失败: {e}"))?;
    temporary.commit(&target, options.force)?;

    let actual = fs::metadata(&target)
        .map_err(|e| format!("读取输出文件信息失败: {e}"))?
        .len();
    if actual != bytes {
        return Err(format!("输出长度校验失败：预期 {bytes}，实际 {actual}"));
    }
    Ok(ProcessResult::Written {
        target,
        bytes,
        headers,
    })
}

struct TemporaryOutput {
    path: PathBuf,
    file: Option<File>,
}

impl TemporaryOutput {
    fn create(target: &Path) -> Result<Self, String> {
        let parent = target
            .parent()
            .ok_or_else(|| "目标路径没有父目录".to_owned())?;
        let base = target.file_name().unwrap_or_else(|| OsStr::new("output"));
        for attempt in 0..1000u32 {
            let mut name = OsString::from(".");
            name.push(base);
            name.push(format!(".{}.{}.part", std::process::id(), attempt));
            let path = parent.join(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("创建临时文件失败: {error}")),
            }
        }
        Err("无法分配唯一的临时文件名".into())
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("临时文件仍打开")
    }

    fn commit(mut self, target: &Path, force: bool) -> Result<(), String> {
        drop(self.file.take());
        if force {
            if target.exists() {
                fs::remove_file(target).map_err(|e| format!("移除旧目标文件失败: {e}"))?;
            }
            fs::rename(&self.path, target).map_err(|e| format!("提交目标文件失败: {e}"))?;
        } else {
            // Hard-link creation is an atomic no-clobber commit on the same filesystem.
            fs::hard_link(&self.path, target).map_err(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    "提交时目标文件已被其他进程创建".to_owned()
                } else {
                    format!("原子提交目标文件失败: {e}")
                }
            })?;
            fs::remove_file(&self.path).map_err(|e| format!("清理临时文件链接失败: {e}"))?;
        }
        self.path.clear();
        Ok(())
    }
}

impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn parse_args(args: impl Iterator<Item = OsString>) -> Result<ParseResult, String> {
    let mut options = Options::default();
    let mut args = args.peekable();
    let mut positional_only = false;
    while let Some(argument) = args.next() {
        if !positional_only {
            match argument.to_str() {
                Some("--") => {
                    positional_only = true;
                    continue;
                }
                Some("-h" | "--help") => {
                    print!("{HELP}");
                    return Ok(ParseResult::Exit);
                }
                Some("-V" | "--version") => {
                    println!("uNcm {}", env!("CARGO_PKG_VERSION"));
                    return Ok(ParseResult::Exit);
                }
                Some("-r" | "--recursive") => {
                    options.recursive = true;
                    continue;
                }
                Some("-f" | "--force") => {
                    options.force = true;
                    continue;
                }
                Some("--info") => {
                    options.info = true;
                    continue;
                }
                Some("-o" | "--output") => {
                    options.output =
                        Some(PathBuf::from(args.next().ok_or("--output 缺少目录参数")?));
                    continue;
                }
                Some(value) if value.starts_with('-') => return Err(format!("未知选项: {value}")),
                _ => {}
            }
        }
        options.inputs.push(PathBuf::from(argument));
    }
    if options.inputs.is_empty() {
        return Err("至少需要一个文件或目录".into());
    }
    Ok(ParseResult::Run(options))
}

fn collect_inputs(inputs: &[PathBuf], recursive: bool) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for input in inputs {
        let metadata = fs::metadata(input)?;
        if metadata.is_file() {
            if is_ncm(input) {
                files.push(input.clone());
            }
        } else if metadata.is_dir() {
            collect_directory(input, recursive, &mut files)?;
        }
    }
    files.sort_by(|a, b| a.as_os_str().cmp(b.as_os_str()));
    let mut seen = HashSet::new();
    files.retain(|path| match fs::canonicalize(path) {
        Ok(canonical) => seen.insert(canonical),
        Err(_) => true,
    });
    Ok(files)
}

fn collect_directory(root: &Path, recursive: bool, files: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut entries = fs::read_dir(root)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_file() && is_ncm(&path) {
            files.push(path);
        } else if recursive && file_type.is_dir() {
            collect_directory(&path, true, files)?;
        }
    }
    Ok(())
}

fn is_ncm(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case("ncm"))
}

fn print_metadata(headers: &Headers) {
    if let Some(metadata) = &headers.metadata {
        if let Some(title) = &metadata.title {
            println!("    标题: {title}");
        }
        if let Some(album) = &metadata.album {
            println!("    专辑: {album}");
        }
        if let Some(hint) = &metadata.format_hint {
            println!("    格式提示: {hint}");
        }
    }
}

fn print_metadata_warning(headers: &Headers) {
    if let Some(warning) = &headers.metadata_warning {
        println!("    警告: 元数据解析失败，但音频已独立解密: {warning}");
    }
}

fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}
