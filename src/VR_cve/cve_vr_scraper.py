import requests
import pandas as pd
import time
import logging
from typing import Any

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# ================= 配置常量 =================
# NVD API v2.0 官方端点 (公开可用)
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RECORD_URL_TEMPLATE = "https://nvd.nist.gov/vuln/detail/{cve_id}"
OUTPUT_CSV_PATH = "nvd_vr_cve_records.csv"

# 速率限制：无 API Key 时 5 请求/30 秒 [[43]]
REQUEST_DELAY = 6.5  # 保守间隔，避免触发限流
TRANSLATE_DELAY = 0.6

# 全面覆盖的关键词矩阵（建议分批运行）
VR_KEYWORDS: list[str] = [
    "Virtual Reality", "VR", "Head-Mounted Display", "HMD",
    "Oculus", "Meta Quest", "HTC Vive", "Valve Index",
    "PlayStation VR", "PSVR", "Pico", "Varjo",
    "Windows Mixed Reality", "SteamVR", "OpenVR", "OpenXR", "WebXR",
    "6DOF", "3DOF", "VR Tracking", "Spatial Computing"
]

# ================= 核心函数 =================

def fetch_cves_from_nvd(keyword: str, max_results: int = 100) -> list[dict[str, Any]]:
    """
    调用 NVD API v2.0 搜索指定关键词的 CVE 记录。

    Args:
        keyword: 搜索关键词（支持子串匹配）[[22]].
        max_results: 该关键词最大获取数量（NVD 单次最多返回 2000 条）.

    Returns:
        包含原始 vulnerability 字典的列表。
    """
    all_vulns: list[dict[str, Any]] = []
    start_index = 0
    results_per_page = 100  # NVD 推荐分页大小
    
    headers = {"User-Agent": "NVD-VR-Scraper/1.0 (Python/3.10+)"}
    
    logging.info(f"🔍 NVD 检索: '{keyword}' ...")
    
    while len(all_vulns) < max_results:
        params = {
            "keywordSearch": keyword,
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        }
        
        try:
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
                
            all_vulns.extend(vulns)
            logging.info(f"  ↳ 获取 {len(vulns)} 条 (累计 {len(all_vulns)}/{max_results})")
            
            # 检查是否还有更多数据
            if len(vulns) < results_per_page or len(all_vulns) >= max_results:
                break
                
            start_index += results_per_page
            time.sleep(REQUEST_DELAY)  # 遵守速率限制 [[43]]
            
        except requests.RequestException as e:
            logging.error(f"  ❌ API 请求异常: {e}")
            break
        except ValueError as e:
            logging.error(f"  ❌ JSON 解析异常: {e}")
            break
            
    return all_vulns[:max_results]


def aggregate_unique_vulns(keywords: list[str], max_per_kw: int) -> dict[str, dict[str, Any]]:
    """
    多关键词检索并基于 CVE ID 全局去重。
    """
    unique_vulns: dict[str, dict[str, Any]] = {}
    
    for kw in keywords:
        vuln_list = fetch_cves_from_nvd(kw, max_per_kw)
        for item in vuln_list:
            cve_id = item["cve"]["id"]
            if cve_id not in unique_vulns:
                unique_vulns[cve_id] = item["cve"]  # 存储内部 cve 对象
        logging.info(f"✅ 去重后累计: {len(unique_vulns)} 条")
        time.sleep(1)
        
    return unique_vulns


def parse_nvd_cve(cve_data: dict[str, Any]) -> dict[str, str]:
    """
    解析 NVD CVE JSON 结构为目标字段。
    """
    cve_id = cve_data.get("id", "N/A")
    pub_date = cve_data.get("published", "N/A")
    link = NVD_RECORD_URL_TEMPLATE.format(cve_id=cve_id)
    
    # 提取 CWE
    cwe_list: list[str] = []
    for problem in cve_data.get("weaknesses", []):
        for desc in problem.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                cwe_list.append(desc["value"])
    cwe_mapping = ", ".join(sorted(set(cwe_list))) if cwe_list else "N/A"
    
    # 提取受影响产品 (CPE 解析)
    products: list[str] = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                # 简化提取 product 部分: cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*
                if cpe and cpe.startswith("cpe:2.3:"):
                    parts = cpe.split(":")
                    if len(parts) >= 6:
                        vendor, product = parts[4], parts[5]
                        if product and product not in ("*", "-"):
                            products.append(f"{vendor}/{product}")
    product_field = ", ".join(sorted(set(products))) if products else "N/A"
    
    # 提取英文描述
    desc_en = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            desc_en = desc.get("value", "").strip()
            break
    
    # 提取 CVSS v3.x 危害等级
    severity = "N/A"
    metrics = cve_data.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            cvss = metrics[key][0].get("cvssData", {})
            severity = cvss.get("baseSeverity", "N/A")
            if severity != "N/A":
                break
    
    return {
        "编号": cve_id,
        "发布时间": pub_date,
        "CWE映射": cwe_mapping,
        "产品": product_field,
        "描述_英文": desc_en,
        "描述_中文": "",
        "危害等级": severity,
        "链接": link
    }


def translate_text(text: str) -> str:
    """
    英文技术描述翻译为中文（deep-translator + 分段降级策略）。
    """
    if not text or text == "N/A":
        return "N/A"
    
    try:
        from deep_translator import GoogleTranslator
        translator = GoogleTranslator(source="en", target="zh-CN")
        
        chunk_size = 4000
        if len(text) <= chunk_size:
            return translator.translate(text)
        
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        return " ".join(translator.translate(chunk) for chunk in chunks)
        
    except ImportError:
        logging.warning("⚠️ 未安装 'deep-translator'，跳过翻译。")
        return "[依赖缺失] " + text
    except Exception as e:
        logging.warning(f"⚠️ 翻译异常: {e}")
        return "[翻译受限] " + text


def export_to_csv(data: list[dict[str, str]], filepath: str) -> None:
    """导出为 UTF-8-SIG 编码 CSV，合并双语文本。"""
    df = pd.DataFrame(data)
    
    df["描述"] = df.apply(
        lambda row: f"【EN】{row['描述_英文']}\n\n【CN】{row['描述_中文']}",
        axis=1
    )
    df = df.drop(columns=["描述_英文", "描述_中文"])
    
    cols = ["编号", "发布时间", "危害等级", "CWE映射", "产品", "描述", "链接"]
    df = df[cols]
    df.to_csv(filepath, index=False, encoding="utf-8-sig")
    logging.info(f"📁 导出 {len(df)} 条记录 → {filepath}")


def main() -> None:
    """主流程：检索 → 去重 → 解析 → 翻译 → 导出"""
    logging.info("🚀 启动 NVD VR CVE 采集任务 (API v2.0)...")
    
    unique_cves = aggregate_unique_vulns(VR_KEYWORDS, max_per_kw=50)
    if not unique_cves:
        logging.error("❌ 未获取到任何记录，请检查网络或关键词。")
        return
    
    logging.info(f"📊 解析 {len(unique_cves)} 条记录...")
    parsed = [parse_nvd_cve(cve) for cve in unique_cves.values()]
    
    logging.info("🌍 启动翻译（免费接口，请耐心等待）...")
    for idx, item in enumerate(parsed, 1):
        if item["描述_英文"] and item["描述_英文"] != "N/A":
            item["描述_中文"] = translate_text(item["描述_英文"])
            time.sleep(TRANSLATE_DELAY)
        logging.info(f"  📝 {idx}/{len(parsed)} | {item['编号']}")
    
    export_to_csv(parsed, OUTPUT_CSV_PATH)
    logging.info("🎉 任务完成！")


if __name__ == "__main__":
    main()