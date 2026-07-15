# uNcm

`uNcm` 是一个只使用 Rust 标准库的 NCM 批量解密器。它不上传文件，不进行音频转码，也不依赖任何第三方 crate。

## 原理

NCM 是容器而不是新的音频编码。文件依次包含魔数、加密的流密钥、加密的 JSON 元数据、CRC/保留字段、封面和加密音频：

1. 验证文件头 `CTENFDAM`，所有长度按小端序解析。
2. 密钥块逐字节异或 `0x64`，用固定密钥进行 AES-128-ECB 解密并验证 PKCS#7 填充，去掉 `neteasecloudmusic` 前缀。
3. 元数据块逐字节异或 `0x63`，去掉 `163 key(Don't modify):` 前缀，Base64 解码，再用另一固定 AES 密钥解出 `music:` 开头的 JSON。
4. 用解出的流密钥生成 256 字节置换表。音频每个字节的密钥流只取决于其绝对偏移，因此可以固定内存分块解密。
5. 通过解密后音频的魔数识别 MP3、FLAC、M4A、WAV 或 OGG；元数据格式只作为识别失败时的后备。

## 构建与使用

```powershell
cargo build --release
cargo run -- "D:\CloudMusic\VipSongsDownload"
cargo run -- --info "D:\CloudMusic\VipSongsDownload"
cargo run -- -r -o "D:\Music\Decoded" "D:\CloudMusic"
```

选项：

- `-o, --output <目录>`：集中写入指定目录；默认写在每个源文件旁边。
- `-r, --recursive`：递归扫描目录。
- `-f, --force`：覆盖已有输出。
- `--info`：只解析容器和元数据，不写文件。

## 稳定性边界

- 解密前检查各段长度和文件边界，并限制需要载入内存的密钥/元数据块。
- 音频使用 64 KiB 缓冲区流式处理。
- 先在目标目录写入临时文件并 `sync_all`，成功后才提交最终文件；默认提交使用同文件系统硬链接，避免并发覆盖已有文件。
- 单个文件失败不会中断整批任务；最终退出码会反映是否存在失败。
- 输出字节数会与容器中的音频段长度核对。
- 当前实现只剥离 NCM 加密层，不转码，也不会重写 MP3/FLAC 标签；原音频负载中已有的标签会原样保留。
