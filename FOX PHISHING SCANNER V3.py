#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Scanner Bot v3.1 - All-in-One (Bugfix)
Kaynaklar: PhishTank, URLhaus, OpenPhish, Google Safe Browsing, VirusTotal
Çıktı: İnteraktif CLI + TXT Rapor
"""

import os
import sys
import io
import csv
import re
import time
from datetime import datetime

import requests
import urllib3
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

BANNER = """
[bold red]╔══════════════════════════════════════════════════╗
║       🔍 SECURITY SCANNER BOT v3.1               ║
║       All-in-One Threat Intelligence             ║
╚══════════════════════════════════════════════════╝[/bold red]
[dim]⚠  Sadece eğitim, savunma ve farkındalık amaçlıdır.[/dim]
"""

FEED_SOURCES = {
    "phishtank": {
        "name": "PhishTank (Verified Phishing)",
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "type": "csv",
        "col": "url"
    },
    "urlhaus": {
        "name": "URLhaus (Recent Malware URLs)",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "csv_tab",
        "col": "url"
    },
    "openphish": {
        "name": "OpenPhish (Phishing Feed)",
        "url": "https://openphish.com/feed.txt",
        "type": "txt"
    }
}

API_SOURCES = {
    "virustotal": {
        "name": "VirusTotal",
        "needs_key": True,
        "desc": "Ücretsiz API key: https://www.virustotal.com/gui/my-apikey"
    },
    "google_safebrowsing": {
        "name": "Google Safe Browsing",
        "needs_key": True,
        "desc": "Ücretsiz API key: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com"
    }
}

REF_LINKS = {
    "usom": "https://www.usom.gov.tr/bildirim-formu",
    "btk": "https://www.btk.gov.tr/bilgi-guvenligi/ihbar"
}


class SecurityScanner:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
        })
        self.session.verify = False

        self.all_urls = []
        self.results = []
        self.stats = {"toplam": 0, "aktif": 0, "zararli_api": 0, "hata": 0}

    # ---------- FEED ÇEKME ----------
    def fetch_feeds(self, progress, task):
        for key, src in FEED_SOURCES.items():
            if not self.config["feeds"].get(key):
                continue
            progress.update(task, description=f"[cyan]Feed çekiliyor:[/] {src['name']}")
            try:
                r = self.session.get(src["url"], timeout=30)
                r.raise_for_status()
                urls = []
                if src["type"] == "csv":
                    reader = csv.DictReader(io.StringIO(r.text))
                    for row in reader:
                        u = row.get(src["col"], "").strip()
                        if u.startswith("http"):
                            urls.append(u)
                elif src["type"] == "csv_tab":
                    reader = csv.DictReader(io.StringIO(r.text), delimiter="\t")
                    for row in reader:
                        u = row.get(src["col"], "").strip()
                        if u.startswith("http"):
                            urls.append(u)
                else:
                    for line in r.text.splitlines():
                        line = line.strip()
                        if line.startswith("http"):
                            urls.append(line)

                self.all_urls.extend([(u, src["name"]) for u in urls])
            except Exception as e:
                console.print(f"[yellow]⚠ {src['name']} hatası: {str(e)[:50]}[/yellow]")
            progress.advance(task)

        seen = set()
        unique = []
        for url, src in self.all_urls:
            if url not in seen:
                seen.add(url)
                unique.append((url, src))
        self.all_urls = unique

        if self.config["max_urls"]:
            self.all_urls = self.all_urls[:self.config["max_urls"]]
        self.stats["toplam"] = len(self.all_urls)

    # ---------- HEAD CHECK ----------
    def head_check(self, url):
        try:
            r = self.session.head(url, timeout=self.config["timeout"], allow_redirects=True)
            return r.status_code < 400, str(r.status_code)
        except Exception:
            return False, "timeout/error"

    # ---------- VIRUSTOTAL API ----------
    def check_virustotal(self, url):
        """Her zaman (bool|None, str) tuple döndürür"""
        key = self.config.get("vt_key")
        if not key:
            return None, ""
        try:
            r = self.session.get(
                "https://www.virustotal.com/api/v3/urls/url_report",
                params={"url": url},
                headers={"x-apikey": key},
                timeout=15
            )
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                return malicious > 0, f"malicious={malicious}"
            return None, f"VT HTTP {r.status_code}"
        except Exception as e:
            return None, f"VT err: {str(e)[:30]}"

    # ---------- GOOGLE SAFE BROWSING API ----------
    def check_google_sb(self, url):
        """Her zaman (bool|None, str) tuple döndürür"""
        key = self.config.get("gsb_key")
        if not key:
            return None, ""
        try:
            payload = {
                "client": {"clientId": "scanner-bot", "clientVersion": "3.1"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            r = self.session.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                json=payload, timeout=15
            )
            if r.status_code == 200:
                matches = r.json().get("matches", [])
                if matches:
                    types = [m.get("threatType", "?") for m in matches]
                    return True, ",".join(types)
                return False, "clean"
            return None, f"GSB HTTP {r.status_code}"
        except Exception as e:
            return None, f"GSB err: {str(e)[:30]}"

    # ---------- ANA TARAMA ----------
    def scan(self):
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(), console=console
        ) as progress:
            feed_task = progress.add_task("Feed'ler çekiliyor...", total=len(FEED_SOURCES))
            self.fetch_feeds(progress, feed_task)
            console.print(f"[green]✓ {self.stats['toplam']} benzersiz URL toplandı[/green]\n")

            if self.stats["toplam"] == 0:
                return

            scan_task = progress.add_task("URL'ler taranıyor...", total=self.stats["toplam"])
            for url, source in self.all_urls:
                progress.update(scan_task, description=f"[cyan]Taranıyor:[/] {url[:60]}")

                active, code = self.head_check(url)

                # API key varsa sorgula, yoksa (None, "") döner → güvenli unpack
                vt_result, vt_detail = self.check_virustotal(url)
                gsb_result, gsb_detail = self.check_google_sb(url)

                detail_parts = [f"HEAD:{code}"]
                is_malicious = False

                if vt_result is not None:
                    detail_parts.append(f"VT:{vt_detail}")
                    if vt_result:
                        is_malicious = True
                if gsb_result is not None:
                    detail_parts.append(f"GSB:{gsb_detail}")
                    if gsb_result:
                        is_malicious = True

                status = "AKTIF" if active else "PASIF"
                if is_malicious:
                    status = "ZARARLI"
                    self.stats["zararli_api"] += 1
                elif active:
                    self.stats["aktif"] += 1
                else:
                    self.stats["hata"] += 1

                self.results.append((url, source, status, " | ".join(detail_parts)))
                progress.advance(scan_task)
                time.sleep(0.1)

    # ---------- KAYDETME ----------
    def save(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"{self.config['output']}_{ts}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"# Security Scan Report v3.1\n")
            f.write(f"# Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Toplam: {self.stats['toplam']} | Aktif: {self.stats['aktif']} | Zararlı(API): {self.stats['zararli_api']}\n")
            f.write(f"# USOM İhbar: {REF_LINKS['usom']}\n")
            f.write(f"# BTK İhbar: {REF_LINKS['btk']}\n")
            f.write(f"#{'='*70}\n\n")
            for url, source, status, detail in self.results:
                f.write(f"[{status}] [{source}] {detail} -> {url}\n")
        return fname

    def print_summary(self, fname):
        table = Table(title="📊 Tarama Özeti", title_style="bold green")
        table.add_column("Metrik", style="cyan")
        table.add_column("Değer", justify="right", style="yellow")
        table.add_row("Toplanan URL", str(self.stats["toplam"]))
        table.add_row("✅ Aktif (HEAD)", str(self.stats["aktif"]))
        table.add_row("🔴 Zararlı (API Doğrulama)", str(self.stats["zararli_api"]))
        table.add_row("❌ Pasif/Hata", str(self.stats["hata"]))
        table.add_row("📄 Rapor Dosyası", fname)
        console.print(table)

        ref_table = Table(title="🏛️ Resmi İhbar Kanalları", border_style="blue")
        ref_table.add_column("Kurum", style="cyan")
        ref_table.add_column("Link", style="green")
        ref_table.add_row("USOM (Ulusal Siber Olaylara Müdahale)", REF_LINKS["usom"])
        ref_table.add_row("BTK Bilgi Güvenliği İhbar", REF_LINKS["btk"])
        console.print(ref_table)


# ==================== İNTERAKTİF MENÜ ====================
def interactive_menu():
    console.print(BANNER)
    config = {}

    console.print("[bold green]📡 Feed Kaynakları:[/bold green]")
    for i, (k, v) in enumerate(FEED_SOURCES.items(), 1):
        console.print(f"  {i}. {v['name']}")
    console.print("  4. Tümü\n")
    while True:
        sec = Prompt.ask("[bold]Feed seçimi[/bold] (örn: 1,3 veya 4)", default="4").strip()
        if sec == "4":
            config["feeds"] = {k: True for k in FEED_SOURCES}
            break
        try:
            idxs = [int(x)-1 for x in re.split(r"[,\s]+", sec) if x.isdigit()]
            keys = list(FEED_SOURCES.keys())
            selected = {keys[i]: True for i in idxs if 0 <= i < len(keys)}
            if selected:
                config["feeds"] = selected
                break
        except Exception:
            pass
        console.print("[red]❌ Geçersiz seçim[/red]")

    console.print("\n[bold green]🔑 API Anahtarları (opsiyonel, boş bırakılabilir):[/bold green]")
    for k, v in API_SOURCES.items():
        console.print(f"  [dim]{v['desc']}[/dim]")
        key = Prompt.ask(f"  {v['name']} API Key", default="").strip()
        if k == "virustotal":
            config["vt_key"] = key if key else None
        elif k == "google_safebrowsing":
            config["gsb_key"] = key if key else None

    config["max_urls"] = IntPrompt.ask("[bold green]🔢 Max URL[/bold green] [dim](0=sınırsız)[/dim]", default=200)
    if config["max_urls"] == 0:
        config["max_urls"] = None
    config["timeout"] = IntPrompt.ask("[bold green]⏱️  Timeout (sn)[/bold green]", default=8)
    config["output"] = Prompt.ask("[bold green]📄 Çıktı dosyası öneki[/bold green]", default="security_scan")

    return config


def confirm_screen(config):
    feeds = ", ".join(FEED_SOURCES[k]["name"] for k in config["feeds"])
    apis = []
    if config.get("vt_key"): apis.append("VirusTotal ✓")
    if config.get("gsb_key"): apis.append("Google SB ✓")
    api_text = ", ".join(apis) if apis else "API key girilmedi (sadece HEAD tarama)"

    panel = Panel.fit(
        f"[cyan]Feed'ler:[/cyan] {feeds}\n"
        f"[cyan]API'ler:[/cyan] {api_text}\n"
        f"[cyan]Max URL:[/cyan] {config['max_urls'] or 'Sınırsız'}\n"
        f"[cyan]Timeout:[/cyan] {config['timeout']} sn\n"
        f"[cyan]Çıktı:[/cyan] {config['output']}_<tarih>.txt",
        title="[bold yellow]⚙️ Ayarlar[/bold yellow]", border_style="yellow"
    )
    console.print(panel)
    return Confirm.ask("[bold green]🚀 Başlatılsın mı?[/bold green]", default=True)


def main():
    try:
        while True:
            config = interactive_menu()
            if not confirm_screen(config):
                console.print("[yellow]↩️  Yeniden...[/yellow]\n")
                continue

            scanner = SecurityScanner(config)
            scanner.scan()
            fname = scanner.save()
            scanner.print_summary(fname)

            console.print("\n[bold green]🎉 Tarama tamamlandı![/bold green]")
            if not Confirm.ask("[bold]Yeni tarama?[/bold]", default=False):
                break
            console.print("\n" + "="*50 + "\n")

    except KeyboardInterrupt:
        console.print("\n[yellow]👋 İptal edildi.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()