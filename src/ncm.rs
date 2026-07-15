use crate::aes::decrypt_ecb_pkcs7;
use std::error::Error as StdError;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

const MAGIC: &[u8; 8] = b"CTENFDAM";
const CORE_KEY: &[u8; 16] = b"hzHRAmso5kInbaxW";
const META_KEY: &[u8; 16] = b"#14ljk_!\\]&0U<'(";
const KEY_PREFIX: &[u8] = b"neteasecloudmusic";
const META_PREFIX: &[u8] = b"163 key(Don't modify):";
const JSON_PREFIX: &[u8] = b"music:";
const MAX_KEY_BLOB: u64 = 1024 * 1024;
const MAX_META_BLOB: u64 = 16 * 1024 * 1024;
const STREAM_BUFFER_SIZE: usize = 64 * 1024;

pub type Result<T> = std::result::Result<T, NcmError>;

#[derive(Debug)]
pub enum NcmError {
    Io(io::Error),
    Invalid(String),
}

impl fmt::Display for NcmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O 错误: {error}"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl StdError for NcmError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl From<io::Error> for NcmError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioFormat {
    Mp3,
    Flac,
    M4a,
    Wav,
    Ogg,
    Unknown,
}

impl AudioFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Mp3 => "mp3",
            Self::Flac => "flac",
            Self::M4a => "m4a",
            Self::Wav => "wav",
            Self::Ogg => "ogg",
            Self::Unknown => "bin",
        }
    }

    fn from_hint(hint: &str) -> Self {
        match hint.trim().to_ascii_lowercase().as_str() {
            "mp3" => Self::Mp3,
            "flac" => Self::Flac,
            "m4a" | "mp4" | "aac" => Self::M4a,
            "wav" => Self::Wav,
            "ogg" | "oga" => Self::Ogg,
            _ => Self::Unknown,
        }
    }

    fn detect(bytes: &[u8]) -> Self {
        if bytes.starts_with(b"ID3")
            || bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] & 0xe0 == 0xe0
        {
            Self::Mp3
        } else if bytes.starts_with(b"fLaC") {
            Self::Flac
        } else if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
            Self::M4a
        } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE" {
            Self::Wav
        } else if bytes.starts_with(b"OggS") {
            Self::Ogg
        } else {
            Self::Unknown
        }
    }
}

impl fmt::Display for AudioFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.extension())
    }
}

#[derive(Clone, Debug)]
pub struct Metadata {
    pub raw_json: String,
    pub title: Option<String>,
    pub album: Option<String>,
    pub format_hint: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Headers {
    pub metadata: Option<Metadata>,
    pub metadata_warning: Option<String>,
    pub cover_bytes: u64,
    pub audio_bytes: u64,
    pub format: AudioFormat,
}

pub struct Decoder {
    file: File,
    cipher: StreamCipher,
    audio_start: u64,
    headers: Headers,
}

impl Decoder {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return invalid("不是有效的 NCM 文件：文件头不是 CTENFDAM");
        }
        skip_exact(&mut file, file_len, 2, "文件头保留区")?;

        let key_len = read_u32(&mut file)? as u64;
        let mut key_blob = read_bounded_blob(&mut file, file_len, key_len, MAX_KEY_BLOB, "密钥")?;
        for byte in &mut key_blob {
            *byte ^= 0x64;
        }
        let decrypted_key = decrypt_ecb_pkcs7(CORE_KEY, &key_blob)
            .map_err(|e| NcmError::Invalid(format!("密钥解密失败：{e}")))?;
        let key = decrypted_key
            .strip_prefix(KEY_PREFIX)
            .ok_or_else(|| NcmError::Invalid("密钥明文缺少 neteasecloudmusic 前缀".into()))?;
        if key.is_empty() {
            return invalid("NCM 流密钥为空");
        }
        let cipher = StreamCipher::new(key);

        let meta_len = read_u32(&mut file)? as u64;
        let meta_blob = read_bounded_blob(&mut file, file_len, meta_len, MAX_META_BLOB, "元数据")?;
        let (metadata, metadata_warning) = if meta_blob.is_empty() {
            (None, None)
        } else {
            match decode_metadata(meta_blob) {
                Ok(value) => (Some(value), None),
                Err(error) => (None, Some(error.to_string())),
            }
        };

        skip_exact(&mut file, file_len, 4, "CRC32")?;
        skip_exact(&mut file, file_len, 5, "封面保留区")?;
        let cover_bytes = read_u32(&mut file)? as u64;
        skip_exact(&mut file, file_len, cover_bytes, "封面数据")?;
        let audio_start = file.stream_position()?;
        let audio_bytes = file_len
            .checked_sub(audio_start)
            .ok_or_else(|| NcmError::Invalid("音频偏移超出文件长度".into()))?;
        if audio_bytes == 0 {
            return invalid("NCM 文件不包含音频数据");
        }

        let sniff_len = audio_bytes.min(16) as usize;
        let mut head = vec![0u8; sniff_len];
        file.read_exact(&mut head)?;
        cipher.apply(&mut head, 0);
        file.seek(SeekFrom::Start(audio_start))?;
        let detected = AudioFormat::detect(&head);
        let hinted = metadata
            .as_ref()
            .and_then(|m| m.format_hint.as_deref())
            .map(AudioFormat::from_hint)
            .unwrap_or(AudioFormat::Unknown);
        let format = if detected == AudioFormat::Unknown {
            hinted
        } else {
            detected
        };
        if format == AudioFormat::Unknown {
            return invalid("解密后的音频格式无法识别，且元数据没有可用的格式提示");
        }

        Ok(Self {
            file,
            cipher,
            audio_start,
            headers: Headers {
                metadata,
                metadata_warning,
                cover_bytes,
                audio_bytes,
                format,
            },
        })
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn decode_to_writer(&mut self, output: &mut impl Write) -> Result<u64> {
        self.file.seek(SeekFrom::Start(self.audio_start))?;
        let mut offset = 0usize;
        let mut total = 0u64;
        let mut buffer = [0u8; STREAM_BUFFER_SIZE];
        loop {
            let read = self.file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            self.cipher.apply(&mut buffer[..read], offset);
            output.write_all(&buffer[..read])?;
            offset = offset
                .checked_add(read)
                .ok_or_else(|| NcmError::Invalid("音频偏移溢出 usize".into()))?;
            total += read as u64;
        }
        if total != self.headers.audio_bytes {
            return invalid(format!(
                "音频长度发生变化：预期 {} 字节，实际 {total} 字节",
                self.headers.audio_bytes
            ));
        }
        Ok(total)
    }
}

struct StreamCipher {
    table: [u8; 256],
}

impl StreamCipher {
    fn new(key: &[u8]) -> Self {
        let mut table = [0u8; 256];
        for (index, value) in table.iter_mut().enumerate() {
            *value = index as u8;
        }
        let mut j = 0usize;
        for i in 0..256 {
            j = (j + table[i] as usize + key[i % key.len()] as usize) & 0xff;
            table.swap(i, j);
        }
        Self { table }
    }

    fn apply(&self, bytes: &mut [u8], offset: usize) {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let j = (offset + index + 1) & 0xff;
            let a = self.table[j] as usize;
            let b = self.table[(a + j) & 0xff] as usize;
            *byte ^= self.table[(a + b) & 0xff];
        }
    }
}

fn decode_metadata(mut blob: Vec<u8>) -> Result<Metadata> {
    for byte in &mut blob {
        *byte ^= 0x63;
    }
    let encoded = blob
        .strip_prefix(META_PREFIX)
        .ok_or_else(|| NcmError::Invalid("元数据缺少 163 key 前缀".into()))?;
    let encrypted = decode_base64(encoded)?;
    let decrypted = decrypt_ecb_pkcs7(META_KEY, &encrypted)
        .map_err(|e| NcmError::Invalid(format!("元数据 AES 解密失败：{e}")))?;
    let json = decrypted
        .strip_prefix(JSON_PREFIX)
        .ok_or_else(|| NcmError::Invalid("元数据明文缺少 music: 前缀".into()))?;
    let raw_json = String::from_utf8(json.to_vec())
        .map_err(|_| NcmError::Invalid("元数据 JSON 不是 UTF-8".into()))?;
    Ok(Metadata {
        title: extract_json_string(&raw_json, "musicName"),
        album: extract_json_string(&raw_json, "album"),
        format_hint: extract_json_string(&raw_json, "format"),
        raw_json,
    })
}

fn decode_base64(input: &[u8]) -> Result<Vec<u8>> {
    let mut clean: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if clean.len() % 4 == 1 {
        return invalid("Base64 长度无效");
    }
    while !clean.len().is_multiple_of(4) {
        clean.push(b'=');
    }
    let mut output = Vec::with_capacity(clean.len() / 4 * 3);
    let groups = clean.len() / 4;
    for (group_index, group) in clean.chunks_exact(4).enumerate() {
        let last = group_index + 1 == groups;
        if (group[2] == b'=' || group[3] == b'=') && !last {
            return invalid("Base64 填充不在末尾");
        }
        if group[2] == b'=' && group[3] != b'=' {
            return invalid("Base64 填充顺序无效");
        }
        let a = base64_value(group[0])?;
        let b = base64_value(group[1])?;
        output.push((a << 2) | (b >> 4));
        if group[2] != b'=' {
            let c = base64_value(group[2])?;
            output.push((b << 4) | (c >> 2));
            if group[3] != b'=' {
                let d = base64_value(group[3])?;
                output.push((c << 6) | d);
            }
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => invalid(format!("Base64 包含无效字节 0x{byte:02x}")),
    }
}

fn extract_json_string(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let bytes = json.as_bytes();
    let mut search_from = 0;
    while let Some(relative) = json[search_from..].find(&needle) {
        let mut index = search_from + relative + needle.len();
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if bytes.get(index) != Some(&b':') {
            search_from = index;
            continue;
        }
        index += 1;
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if bytes.get(index) == Some(&b'\"') {
            return parse_json_string(bytes, index);
        }
        search_from = index;
    }
    None
}

fn parse_json_string(bytes: &[u8], start: usize) -> Option<String> {
    let mut index = start + 1;
    let mut output = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b'\"' => return String::from_utf8(output).ok(),
            b'\\' => {
                index += 1;
                match *bytes.get(index)? {
                    b'\"' => output.push(b'\"'),
                    b'\\' => output.push(b'\\'),
                    b'/' => output.push(b'/'),
                    b'b' => output.push(8),
                    b'f' => output.push(12),
                    b'n' => output.push(b'\n'),
                    b'r' => output.push(b'\r'),
                    b't' => output.push(b'\t'),
                    b'u' => {
                        let code = parse_hex4(bytes, index + 1)?;
                        index += 4;
                        let scalar = if (0xd800..=0xdbff).contains(&code) {
                            if bytes.get(index + 1..index + 3)? != b"\\u" {
                                return None;
                            }
                            let low = parse_hex4(bytes, index + 3)?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return None;
                            }
                            index += 6;
                            0x10000 + (((code - 0xd800) as u32) << 10) + (low - 0xdc00) as u32
                        } else {
                            code as u32
                        };
                        let ch = char::from_u32(scalar)?;
                        let mut encoded = [0u8; 4];
                        output.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
                    }
                    _ => return None,
                }
            }
            0x00..=0x1f => return None,
            byte => output.push(byte),
        }
        index += 1;
    }
    None
}

fn parse_hex4(bytes: &[u8], start: usize) -> Option<u16> {
    let mut value = 0u16;
    for &byte in bytes.get(start..start + 4)? {
        value = (value << 4)
            | match byte {
                b'0'..=b'9' => (byte - b'0') as u16,
                b'a'..=b'f' => (byte - b'a' + 10) as u16,
                b'A'..=b'F' => (byte - b'A' + 10) as u16,
                _ => return None,
            };
    }
    Some(value)
}

fn read_u32(reader: &mut impl Read) -> Result<u32> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_bounded_blob(
    file: &mut File,
    file_len: u64,
    len: u64,
    max: u64,
    name: &str,
) -> Result<Vec<u8>> {
    if len > max {
        return invalid(format!("{name}区长度 {len} 超过安全上限 {max}"));
    }
    ensure_remaining(file, file_len, len, name)?;
    let len =
        usize::try_from(len).map_err(|_| NcmError::Invalid(format!("{name}区长度无法放入内存")))?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn skip_exact(file: &mut File, file_len: u64, len: u64, name: &str) -> Result<()> {
    ensure_remaining(file, file_len, len, name)?;
    let position = file.stream_position()?;
    file.seek(SeekFrom::Start(position + len))?;
    Ok(())
}

fn ensure_remaining(file: &mut File, file_len: u64, len: u64, name: &str) -> Result<()> {
    let position = file.stream_position()?;
    let end = position
        .checked_add(len)
        .ok_or_else(|| NcmError::Invalid(format!("{name}区偏移溢出")))?;
    if end > file_len {
        return invalid(format!(
            "{name}区被截断：需要到偏移 {end}，文件仅 {file_len} 字节"
        ));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(NcmError::Invalid(message.into()))
}

#[cfg(test)]
mod tests {
    use super::{AudioFormat, Decoder, StreamCipher, decode_base64, extract_json_string};
    use std::fs;

    #[test]
    fn base64_vectors() {
        assert_eq!(decode_base64(b"").unwrap(), b"");
        assert_eq!(decode_base64(b"Zg==").unwrap(), b"f");
        assert_eq!(decode_base64(b"Zm8=").unwrap(), b"fo");
        assert_eq!(decode_base64(b"Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn stream_cipher_is_chunk_independent() {
        let cipher = StreamCipher::new(b"test key material");
        let mut whole = (0..=255).cycle().take(1000).collect::<Vec<_>>();
        let mut chunked = whole.clone();
        cipher.apply(&mut whole, 0);
        cipher.apply(&mut chunked[..333], 0);
        cipher.apply(&mut chunked[333..], 333);
        assert_eq!(whole, chunked);
        cipher.apply(&mut whole, 0);
        assert_eq!(whole, (0..=255).cycle().take(1000).collect::<Vec<_>>());
    }

    #[test]
    fn detects_audio_formats() {
        assert_eq!(AudioFormat::detect(b"ID3anything"), AudioFormat::Mp3);
        assert_eq!(AudioFormat::detect(b"fLaCanything"), AudioFormat::Flac);
        assert_eq!(AudioFormat::detect(b"....ftypanything"), AudioFormat::M4a);
        assert_eq!(AudioFormat::detect(b"RIFF....WAVE"), AudioFormat::Wav);
        assert_eq!(AudioFormat::detect(b"OggSanything"), AudioFormat::Ogg);
    }

    #[test]
    fn extracts_escaped_json_strings() {
        let json = r#"{"musicName":"落华\nLive","album":"A \u4e2d\u6587","format":"flac"}"#;
        assert_eq!(
            extract_json_string(json, "musicName").as_deref(),
            Some("落华\nLive")
        );
        assert_eq!(
            extract_json_string(json, "album").as_deref(),
            Some("A 中文")
        );
        assert_eq!(extract_json_string(json, "format").as_deref(), Some("flac"));
    }

    #[test]
    fn rejects_truncated_container_without_panicking() {
        let path = std::env::temp_dir().join(format!("uncm-truncated-{}.ncm", std::process::id()));
        fs::write(&path, b"CTENFDAM").unwrap();
        let result = Decoder::open(&path);
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }
}
