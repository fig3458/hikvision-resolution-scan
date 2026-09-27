# AIGC START
"""Hikvision camera streaming config — read-only ISAPI scanner.

Safety: this module issues GET requests only. No PUT/POST/DELETE/PATCH.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPBasicAuthHandler,
    HTTPDigestAuthHandler,
    HTTPPasswordMgrWithDefaultRealm,
    Request,
    build_opener,
)

# Hard allowlist — never send mutating verbs.
ALLOWED_METHODS = frozenset({"GET", "HEAD"})

# Main stream channel id used by most Hikvision IPC.
MAIN_STREAM_CHANNEL = "101"

LogFn = Callable[[str], None]


@dataclass
class StreamInfo:
    ip: str
    ok: bool
    error: str = ""
    device_name: str = ""
    model: str = ""
    stream_type: str = "主码流"
    video_type: str = ""
    resolution: str = ""
    bitrate_type: str = ""
    image_quality: str = ""
    frame_rate: str = ""
    max_bitrate: str = ""
    avg_bitrate: str = ""
    video_codec: str = ""
    encoding_complexity: str = ""
    smart_codec: str = ""
    iframe_interval: str = ""
    stream_smoothing: str = ""
    storage_estimate: str = ""
    raw_notes: str = ""

    def to_row(self) -> dict[str, str]:
        d = asdict(self)
        d.pop("ok", None)
        d.pop("raw_notes", None)
        d["status"] = "成功" if self.ok else "失败"
        # Keep a stable column order for CSV
        return {
            "IP": self.ip,
            "状态": d["status"],
            "设备名称": self.device_name,
            "型号": self.model,
            "码流类型": self.stream_type,
            "视频类型": self.video_type,
            "分辨率": self.resolution,
            "码率类型": self.bitrate_type,
            "图像质量": self.image_quality,
            "视频帧率": self.frame_rate,
            "码率上限": self.max_bitrate,
            "平均码率": self.avg_bitrate,
            "视频编码": self.video_codec,
            "编码复杂度": self.encoding_complexity,
            "超级智能编码": self.smart_codec,
            "I帧间隔": self.iframe_interval,
            "码流平滑": self.stream_smoothing,
            "预计存储": self.storage_estimate,
            "错误": self.error,
        }


@dataclass
class ScanOptions:
    username: str
    password: str
    timeout: float = 4.0
    workers: int = 6
    port: int = 80
    use_https: bool = False
    probe_port_first: bool = True


def parse_targets(text: str) -> list[str]:
    """Parse IPs / ranges / CIDR from multiline or comma-separated text.

    Supported:
      192.168.22.133
      192.168.22.1-254
      192.168.22.0/24
      192.168.22.1-192.168.22.50
    """
    found: list[str] = []
    seen: set[str] = set()

    chunks = re.split(r"[\s,;]+", text.strip())
    for chunk in chunks:
        if not chunk or chunk.startswith("#"):
            continue
        for ip in _expand_chunk(chunk):
            if ip not in seen:
                seen.add(ip)
                found.append(ip)
    return found


def _expand_chunk(chunk: str) -> list[str]:
    # CIDR
    if "/" in chunk:
        net = ipaddress.ip_network(chunk, strict=False)
        return [str(h) for h in net.hosts()]

    # a.b.c.d-e  (same /24 last octet range) or full IP-IP
    m = re.fullmatch(
        r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})",
        chunk,
    )
    if m:
        start_s, end_s = m.group(1), m.group(2)
        if "." not in end_s:
            prefix = ".".join(start_s.split(".")[:3])
            end_s = f"{prefix}.{end_s}"
        start = int(ipaddress.IPv4Address(start_s))
        end = int(ipaddress.IPv4Address(end_s))
        if end < start:
            start, end = end, start
        if end - start > 65535:
            raise ValueError(f"范围过大（>{65535}）：{chunk}")
        return [str(ipaddress.IPv4Address(i)) for i in range(start, end + 1)]

    # single IP
    ipaddress.IPv4Address(chunk)  # validate
    return [chunk]


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _find_text(root: ET.Element, names: Iterable[str]) -> str:
    want = {n.lower() for n in names}
    for el in root.iter():
        if _local(el.tag).lower() in want and el.text and el.text.strip():
            return el.text.strip()
    return ""


def _bool_cn(text: str) -> str:
    t = (text or "").strip().lower()
    if t in {"true", "1", "yes", "enable", "enabled", "on"}:
        return "开启"
    if t in {"false", "0", "no", "disable", "disabled", "off"}:
        return "关闭"
    return text or ""


def _quality_cn(raw: str) -> str:
    """Map fixedQuality numeric/string to rough 高/中/低 labels when possible."""
    if not raw:
        return ""
    try:
        n = int(float(raw))
    except ValueError:
        mapping = {
            "highest": "最高",
            "higher": "较高",
            "medium": "中",
            "low": "低",
            "lowest": "最低",
        }
        return mapping.get(raw.lower(), raw)
    # Common Hikvision scale ~20-100; UI often shows 高/中/低
    if n >= 80:
        return f"高({n})"
    if n >= 50:
        return f"中({n})"
    if n > 0:
        return f"低({n})"
    return raw


def _bitrate_type_cn(raw: str) -> str:
    t = (raw or "").upper()
    if t == "CBR":
        return "定码率"
    if t == "VBR":
        return "变码率"
    return raw or ""


def _frame_rate(raw: str) -> str:
    if not raw:
        return ""
    try:
        n = float(raw)
        # Many firmwares store fps * 100 (e.g. 2500 => 25)
        if n > 100:
            n = n / 100.0
        if n == int(n):
            return str(int(n))
        return str(n)
    except ValueError:
        return raw


def _estimate_storage_gb_per_day(bitrate_kbps: str) -> str:
    if not bitrate_kbps:
        return ""
    try:
        kbps = float(bitrate_kbps)
    except ValueError:
        return ""
    if kbps <= 0:
        return ""
    # bits/s → bytes/day → GB (1024-based, matching many UI estimates roughly)
    gb = kbps * 1000 / 8 * 86400 / (1024**3)
    return f"约{gb:.0f}GB/天"


def parse_streaming_xml(xml_text: str) -> dict[str, str]:
    root = ET.fromstring(xml_text)

    width = _find_text(root, ["videoResolutionWidth", "resolutionWidth", "width"])
    height = _find_text(root, ["videoResolutionHeight", "resolutionHeight", "height"])
    resolution = f"{width}*{height}" if width and height else ""

    bitrate_type_raw = _find_text(root, ["videoQualityControlType"])
    bitrate_type = _bitrate_type_cn(bitrate_type_raw)

    constant = _find_text(root, ["constantBitRate", "CBR"])
    vbr_cap = _find_text(root, ["vbrUpperCap", "maxBitRate", "BitRate"])
    avg = _find_text(root, ["vbrAverageCap", "averageBitRate"])

    if bitrate_type_raw.upper() == "CBR":
        max_bitrate = constant or vbr_cap
        avg_bitrate = constant or avg
    else:
        max_bitrate = vbr_cap or constant
        avg_bitrate = avg or ""

    # Video vs complex stream: if Audio enabled under channel → 复合流
    audio_enabled = ""
    for el in root.iter():
        if _local(el.tag).lower() == "audio":
            en = ""
            for child in el:
                if _local(child.tag).lower() == "enabled":
                    en = (child.text or "").strip().lower()
                    break
            audio_enabled = en
            break
    if audio_enabled in {"true", "1"}:
        video_type = "复合流"
    elif audio_enabled in {"false", "0"}:
        video_type = "视频流"
    else:
        explicit = _find_text(root, ["videoType", "VideoType"])
        video_type = explicit or ""

    smart_nested = ""
    for el in root.iter():
        tag = _local(el.tag).lower()
        if tag in {"smartcodec", "h265smart", "supersmartcodec"}:
            for child in el:
                if _local(child.tag).lower() == "enabled" and child.text:
                    smart_nested = child.text.strip()
                    break
            if smart_nested:
                break

    complexity = _find_text(
        root,
        ["H264Profile", "H265Profile", "encodingComplexity", "Profile"],
    )
    complexity_map = {
        "Baseline": "低",
        "Main": "中",
        "High": "高",
        "Extended": "扩展",
    }
    complexity_cn = complexity_map.get(complexity, complexity)

    codec = _find_text(root, ["videoCodecType", "codecType", "VideoCodecType"])
    frame = _frame_rate(_find_text(root, ["maxFrameRate", "videoFrameRate", "frameRate"]))
    gov = _find_text(root, ["GovLength", "govLength", "IFrameInterval", "keyFrameInterval"])
    smoothing = _find_text(root, ["smoothing", "StreamSmoothing"])
    quality = _quality_cn(_find_text(root, ["fixedQuality", "videoQuality", "quality"]))

    return {
        "video_type": video_type,
        "resolution": resolution,
        "bitrate_type": bitrate_type,
        "image_quality": quality,
        "frame_rate": frame,
        "max_bitrate": max_bitrate,
        "avg_bitrate": avg_bitrate,
        "video_codec": codec,
        "encoding_complexity": complexity_cn,
        "smart_codec": _bool_cn(smart_nested),
        "iframe_interval": gov,
        "stream_smoothing": smoothing,
        "storage_estimate": _estimate_storage_gb_per_day(max_bitrate or avg_bitrate),
    }


def parse_device_xml(xml_text: str) -> tuple[str, str]:
    root = ET.fromstring(xml_text)
    name = _find_text(root, ["deviceName", "DeviceName", "name"])
    model = _find_text(root, ["model", "Model", "deviceType"])
    return name, model


class ReadOnlyHttpClient:
    """HTTP client that refuses any non-GET/HEAD method."""

    def __init__(self, username: str, password: str, timeout: float):
        self.username = username
        self.password = password
        self.timeout = timeout
        self._opener = None

    def _build_opener(self, base_url: str):
        passman = HTTPPasswordMgrWithDefaultRealm()
        passman.add_password(None, base_url, self.username, self.password)
        return build_opener(
            HTTPDigestAuthHandler(passman),
            HTTPBasicAuthHandler(passman),
        )

    def get(self, url: str) -> str:
        method = "GET"
        if method not in ALLOWED_METHODS:
            raise RuntimeError(f"拒绝非只读方法: {method}")
        # Parse base for auth realm registration
        # http://ip or http://ip:port
        m = re.match(r"^(https?://[^/]+)", url)
        base = m.group(1) if m else url
        opener = self._build_opener(base)
        req = Request(url, method="GET")
        req.add_header(
            "User-Agent",
            "HikvisionResolutionScan/1.0 (read-only)",
        )
        req.add_header("Accept", "application/xml, text/xml, */*")
        # Belt-and-suspenders: urllib Request.method is GET; block if mutated
        if getattr(req, "get_method", lambda: method)() not in ALLOWED_METHODS:
            raise RuntimeError("请求方法被篡改，已中止")
        with opener.open(req, timeout=self.timeout) as resp:
            # Never follow into write endpoints — we only call known GET paths
            return resp.read().decode("utf-8", errors="replace")


def port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=min(timeout, 2.0)):
            return True
    except OSError:
        return False


def query_camera(ip: str, opt: ScanOptions) -> StreamInfo:
    """Read-only query of one camera. Never modifies device config."""
    scheme = "https" if opt.use_https else "http"
    host = f"{ip}:{opt.port}" if opt.port not in (80, 443) else ip
    base = f"{scheme}://{host}"

    if opt.probe_port_first and not port_open(ip, opt.port, opt.timeout):
        return StreamInfo(ip=ip, ok=False, error=f"端口 {opt.port} 不可达")

    client = ReadOnlyHttpClient(opt.username, opt.password, opt.timeout)
    info = StreamInfo(ip=ip, ok=False)

    try:
        # 1) Device info (optional, still GET-only)
        try:
            dev_xml = client.get(f"{base}/ISAPI/System/deviceInfo")
            name, model = parse_device_xml(dev_xml)
            info.device_name = name
            info.model = model
        except Exception as exc:  # noqa: BLE001 — keep scanning stream even if this fails
            info.raw_notes = f"deviceInfo: {exc}"

        # 2) Main stream — the fields shown on 视频参数 page
        stream_xml = client.get(
            f"{base}/ISAPI/Streaming/channels/{MAIN_STREAM_CHANNEL}"
        )
        fields = parse_streaming_xml(stream_xml)
        for k, v in fields.items():
            setattr(info, k, v)
        info.stream_type = "主码流"
        info.ok = True
        return info
    except HTTPError as exc:
        info.error = f"HTTP {exc.code}: {exc.reason}"
        return info
    except URLError as exc:
        info.error = f"连接失败: {exc.reason}"
        return info
    except ET.ParseError as exc:
        info.error = f"XML 解析失败: {exc}"
        return info
    except Exception as exc:  # noqa: BLE001
        info.error = f"{type(exc).__name__}: {exc}"
        return info


def scan_targets(
    ips: list[str],
    opt: ScanOptions,
    on_result: Callable[[StreamInfo], None] | None = None,
    on_log: LogFn | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> list[StreamInfo]:
    """Scan many IPs with limited concurrency. GET-only per camera."""
    results: list[StreamInfo] = []
    workers = max(1, min(opt.workers, 16))  # hard cap — stay conservative
    log = on_log or (lambda _m: None)

    log(
        f"开始只读扫描：共 {len(ips)} 个地址，并发 {workers}，"
        f"超时 {opt.timeout}s，仅 GET，不会改写任何配置"
    )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(query_camera, ip, opt): ip for ip in ips}
        for fut in as_completed(futures):
            if should_stop and should_stop():
                log("收到停止请求，取消剩余任务…")
                for f in futures:
                    f.cancel()
                break
            ip = futures[fut]
            try:
                info = fut.result()
            except Exception as exc:  # noqa: BLE001
                info = StreamInfo(ip=ip, ok=False, error=str(exc))
            results.append(info)
            if info.ok:
                log(
                    f"[成功] {info.ip}  {info.resolution or '-'}  "
                    f"{info.video_codec or '-'}  {info.max_bitrate or '-'}"
                )
            else:
                log(f"[失败] {info.ip}  {info.error}")
            if on_result:
                on_result(info)

    ok_n = sum(1 for r in results if r.ok)
    log(f"扫描结束：成功 {ok_n} / 合计 {len(results)}")
    return results


# AIGC END
