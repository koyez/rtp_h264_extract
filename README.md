# RTP H.264 Extractor

从 `pcap`/`pcapng` 抓包中提取 RTP 承载的 H.264，并输出 Annex-B 格式的 `.264` 文件。程序使用 tshark 读取 RTP 和 RTSP SDP，支持 RFC 6184 的以下负载形式：

- Single NAL Unit
- STAP-A
- FU-A

它会自动读取 RTSP SDP 中的 `sprop-parameter-sets`，将 Base64 编码的 SPS/PPS 写入输出，并从抓包中第一个 IDR 帧开始输出。这样抓包从一个 GOP 中间开始时，开头的 P 帧不会阻止播放器初始化。

## 工作流程

程序按下面的顺序处理数据：

1. 调用 tshark，按 Wireshark display filter 读取一个 RTP 视频流。
2. 读取 RTSP `DESCRIBE` 响应中的 `a=fmtp` 和 `sprop-parameter-sets`。
3. 检查 RTP sequence number，并报告丢包或乱序。
4. 重组 Single NAL、STAP-A 和 FU-A。
5. 从 SPS、PPS 和第一个 IDR NAL 开始写入 Annex-B H.264。

输出文件是裸 H.264，没有容器时间戳。RTP 时间戳可以用于估算帧率，再交给 FFmpeg 封装为 MP4。

## 环境要求

- Python 3.10 或更高版本
- Wireshark 中的 `tshark`
- 如果要运行测试：`pytest`
- 如果要封装 MP4 或验证解码：`ffmpeg`/`ffprobe`

macOS 安装 Wireshark 后，默认路径通常是：

```text
/Applications/Wireshark.app/Contents/MacOS/tshark
```

Linux 可通过发行版包管理器安装 `tshark`。程序也会优先使用 `PATH` 中的 `tshark`。

## 安装

建议使用虚拟环境和 editable install：

```sh
cd /Users/mindely/code/github/koyez/rtp_h264_extract
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

安装后有两个等价入口：

```sh
rtp-h264-extract --help
python -m rtp_h264_extract --help
```

激活虚拟环境后，可以在任意目录执行 `rtp-h264-extract`。输入和输出可以使用绝对路径；`-o video.h264` 这样的相对输出路径会写入当前执行目录。

## 基本用法

过滤器必须只选中一个 RTP 视频流。推荐使用 IP、端口和 SSRC；`udp.stream` 是 Wireshark 针对某一份抓包生成的编号，在其他抓包中通常会变化。

```sh
rtp-h264-extract 1.pcap \
  -Y 'ip.src==172.16.100.13 && udp.srcport==28000 && ip.dst==172.16.100.14 && udp.dstport==23036 && rtp.ssrc==0xd4c1700a' \
  -o video.264
```

也可以使用原来的 Wireshark 过滤器：

```sh
rtp-h264-extract 1.pcap \
  -Y 'udp.stream==140 && rtp.ssrc==0xd4c1700a' \
  -o video.264
```

典型输出如下：

```text
RTP packets: 1175; NAL units: 1370
stream: 172.16.100.13:28000 -> 172.16.100.14:23036, SSRC=0xd4c1700a, PT=97
sequence gaps: 0; FU-A packets: 894; STAP-A packets: 135
parameter sets: SDP; pre-IDR NALs dropped: 20; written NALs: 1352
```

## 将 UDP 强制解析为 RTP

有些抓包没有足够的信令让 tshark 自动识别 RTP。这时，即使 UDP 包确实存在，包含 `rtp.ssrc` 的过滤器也会匹配到 0 包。使用 `-d/--decode-as` 显式指定解析方式，无需临时 tshark 包装脚本：

```sh
rtp-h264-extract 1.pcap \
  -d udp.port==28000,rtp \
  -Y 'ip.dst==172.16.100.13 && udp.dstport==28000 && rtp.ssrc==0xd4c1700a' \
  -o video.h264
```

`udp.port==28000,rtp` 表示将源端口或目的端口为 `28000` 的 UDP 包按 RTP 解析。这份抓包中，该命令选择的是上行流 `172.16.100.13:32142 → 172.16.100.13:28000`，与前面发往播放器的下行流不同。其他抓包应使用对应的端口和过滤条件。

`--decode-as udp.port==28000,rtp` 与 `-d udp.port==28000,rtp` 等价。参数可以重复，例如同时指定 UDP/RTP 和非标准端口上的 RTSP：

```sh
rtp-h264-extract 1.pcap \
  -d udp.port==28000,rtp \
  -d tcp.port==28554,rtsp \
  -Y 'ip.dst==172.16.100.13 && udp.dstport==28000 && rtp.ssrc==0xd4c1700a' \
  -o video.h264
```

这些规则会传给读取 RTP 和读取 RTSP SDP 的两次 tshark 调用。该参数负责协议识别；SPS/PPS 的读取和 H.264 分片重组仍由程序处理。已被 tshark 自动识别为 RTP 的流可以省略 `-d`。

`--tshark` 仍可用于指定 tshark 可执行文件的位置，例如 `--tshark /Applications/Wireshark.app/Contents/MacOS/tshark`，通常无需手动指定。

## 封装为 MP4

裸 H.264 不携带 RTP 时间戳。可以根据 RTP 时间戳计算出的实际帧率封装：

```sh
ffmpeg -r 15.145 -i video.264 -c:v copy video.mp4
```

如果只需要确认码流能否解码：

```sh
ffprobe -hide_banner -v error -count_frames \
  -show_entries stream=codec_name,width,height,profile,level,nb_read_frames \
  -of default=noprint_wrappers=1 video.264

ffmpeg -hide_banner -loglevel error -i video.264 -f null -
```

## 没有 RTSP SDP 的抓包

如果抓包只包含 UDP/RTP，没有 RTSP `DESCRIBE` 响应，程序无法自动获得带外 SPS/PPS。可以从信令、播放器日志或发送端 SDP 中取出 Base64 参数集：

```sh
rtp-h264-extract capture.pcap \
  -Y 'ip.src==192.0.2.10 && udp.srcport==5004 && rtp.ssrc==0x12345678' \
  --sps 'Z0LAKdoHgUabgQEAoAAAAwAgACvyEeMGVA==' \
  --pps 'aM4PyA==' \
  -o video.264
```

`--sps` 和 `--pps` 可以使用 Base64，也可以使用十六进制字节串。两者必须同时提供。如果 RTP 内部本身带有 type 7/8 NAL，程序会在没有 SDP 时缓存并使用它们。

如果既没有 SDP，也没有 RTP 内嵌的 SPS/PPS，则不能从普通 P 帧可靠推导出 SPS/PPS。

## 动态 Payload Type

如果程序输出 `no RTP packets matched`：

1. 检查源/目的 IP、端口和 SSRC 是否对应目标方向。
2. 对未自动识别的 UDP 流增加 `-d udp.port==实际端口,rtp`。
3. 用 `rtp.ssrc`、源/目的 IP 和端口确保过滤器只选中一个 RTP H.264 视频流。

Wireshark 界面中的 **Decode As... → RTP** 设置不会由本程序自动传给独立的 tshark 进程；命令行使用 `-d` 显式指定即可。程序读取 `rtp.payload` 并自行解析 H.264 NAL，不依赖 tshark 将动态 PT 进一步识别为 H.264，也不需要通过 Wireshark 菜单运行 Lua。

## 测试

```sh
python -m pip install -e '.[test]'
pytest
```

测试覆盖 Single NAL、STAP-A、FU-A 重组，以及首个 IDR 前 P 帧的处理。对真实抓包的验证可以直接运行上面的命令，再用 `ffprobe`/`ffmpeg` 检查输出。

## 项目结构

```text
.
├── pyproject.toml
├── README.md
├── src/rtp_h264_extract/
│   ├── __init__.py
│   ├── __main__.py
│   └── extractor.py
└── tests/
```

程序不修改原始抓包，只生成指定的输出文件；发现 RTP sequence gap 时会报告，并丢弃受影响的未完成 FU-A。
