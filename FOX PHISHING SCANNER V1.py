#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Scanner Bot v1.0
- PhishTank & URLhaus feed'lerini çeker
- Aktif URL'leri tarar (HEAD request - güvenli)
- Sonuçları txt'ye kaydeder
"""

import os
import sys
import time
import csv
import io
import re
from datetime import datetime

import requests
import urllib3
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.progress import (
    Progress, SpinnerColumn, TextColumn,
    BarColumn, TimeElapsedColumn, MofNCompleteColumn
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

BANNER = """
[bold red]╔══════════════════════════════════════════╗
║       🔍 SECURITY SCANNER BOT v1.0       ║
║     Phish/Malware URL Tarayıcı           ║
╚══════════════════════════════════════════╝[/bold red]
[dim]⚠  Sadece eğitim ve savunma amaçlıdır[/dim]
"""

# ==================== KAYNAKLAR ====================
SOURCES = {
    "phishtank": {
        "name": "PhishTank (Doğrulanmış Phishing)",
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "type": "csv",
        "url_column": "url"
    },
    "urlhaus_recent": {
        "name": "URLhaus (Son Malware URL'leri)",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "csv",
        "url_column": "url"
    },
    "openphish": {
        "name": "OpenPhish (Phishing Feed)",
        "url": "https://openphish.com/feed.txt",
        "type": "txt"
    }
}


class ScannerBot:
    def __init__(self, sources, output_file, timeout=8, max_urls=None):
        self.sources = sources
        self.output_file = output_file
        self.timeout = timeout
        self.max_urls = max_urls

        self.collected_urls = []
        self.active_urls = []
        self.stats = {
            "toplam": 0,
            "aktif": 0,
            "kapali": 0,
            "hata": 0,
            "kaynaklar": {}
        }

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36"
        })
        self.session.verify = False

    # ---------- KAYNAK ÇEKME ----------
    def fetch_source(self, key, source, progress, task):
        progress.update(task, description=f"[cyan]Çekiliyor:[/] {source['name']}")
        try:
            r = self.session.get(source["url"], timeout=30)
            r.raise_for_status()

            urls = []
            if source["type"] == "csv":
                # URLhaus \t ayraçlı CSV kullanır
                delimiter = "\t" if "urlhaus" in key else ","
                reader = csv.DictReader(io.StringIO(r.text), delimiter=delimiter)
                col = source["url_column"]
                for row in reader:
                    u = row.get(col, "").strip()
                    if u and u.startswith("http"):
                        urls.append(u)
            else:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and line.startswith("http"):
                        urls.append(line)

            self.stats["kaynaklar"][source["name"]] = len(urls)
            return urls

        except Exception as e:
            console.print(f"[yellow]⚠ {source['name']} çekilemedi: {str(e)[:60]}[/yellow]")
            self.stats["kaynaklar"][source["name"]] = 0
            return []

    def collect_all(self):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Kaynaklar çekiliyor...", total=len(self.sources))
            for key, src in self.sources.items():
                urls = self.fetch_source(key, src, progress, task)
                self.collected_urls.extend(urls)
                progress.advance(task)

        # Tekilleştir
        self.collected_urls = list(dict.fromkeys(self.collected_urls))

        if self.max_urls:
            self.collected_urls = self.collected_urls[:self.max_urls]

        self.stats["toplam"] = len(self.collected_urls)
        console.print(f"\n[green]✓ Toplam {len(self.collected_urls)} benzersiz URL toplandı[/green]\n")

    # ---------- TARAMA ----------
    def check_url(self, url):
        """HEAD request ile güvenli kontrol"""
        try:
            r = self.session.head(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
            if r.status_code < 400:
                return "aktif", r.status_code
            return "kapali", r.status_code
        except requests.exceptions.Timeout:
            return "timeout", 0
        except Exception:
            return "hata", 0

    def scan_all(self):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("URL'ler taranıyor...", total=len(self.collected_urls))

            for url in self.collected_urls:
                progress.update(task, description=f"[cyan]Taranıyor:[/] {url[:65]}")
                status, code = self.check_url(url)

                if status == "aktif":
                    self.active_urls.append((url, code))
                    self.stats["aktif"] += 1
                elif status == "kapali":
                    self.stats["kapali"] += 1
                else:
                    self.stats["hata"] += 1

                progress.advance(task)
                time.sleep(0.05)  # Rate limiting

    # ---------- KAYDETME ----------
    def save_results(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_file}_{timestamp}.txt"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# Security Scan Report\n")
            f.write(f"# Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Toplam URL: {self.stats['toplam']}\n")
            f.write(f"# Aktif URL: {self.stats['aktif']}\n")
            f.write(f"#{'='*60}\n\n")

            for url, code in self.active_urls:
                f.write(f"[{code}] {url}\n")

        return filename

    # ---------- ÇALIŞTIR ----------
    def run(self):
        start = time.time()
        self.collect_all()

        if self.stats["toplam"] == 0:
            console.print("[red]❌ Hiç URL toplanamadı![/red]")
            return

        self.scan_all()
        filename = self.save_results()

        # Özet Tablosu
        table = Table(title="📊 Tarama Özeti", title_style="bold green")
        table.add_column("Metrik", style="cyan")
        table.add_column("Değer", style="yellow", justify="right")
        table.add_row("Toplanan URL", str(self.stats["toplam"]))
        table.add_row("✅ Aktif", f"[green]{self.stats['aktif']}[/green]")
        table.add_row("❌ Kapalı", str(self.stats["kapali"]))
        table.add_row("⚠ Hata/Timeout", str(self.stats["hata"]))
        table.add_row("Süre", f"{time.time() - start:.1f} sn")
        table.add_row("Kayıt dosyası", filename)

        console.print()
        console.print(table)

        # Kaynak bazında döküm
        src_table = Table(title="Kaynak Bazında Dağılım", border_style="blue")
        src_table.add_column("Kaynak", style="cyan")
        src_table.add_column("URL Sayısı", justify="right", style="yellow")
        for name, count in self.stats["kaynaklar"].items():
            src_table.add_row(name, str(count))
        console.print(src_table)


# ==================== İNTERAKTİF MENÜ ====================
def menu():
    console.print(BANNER)

    # 1) Kaynak seçimi
    console.print("[bold green]📡 Tarama kaynakları:[/bold green]")
    for i, (key, src) in enumerate(SOURCES.items(), 1):
        console.print(f"  {i}. {src['name']}")
    console.print("  4. Tümü\n")

    while True:
        secim = Prompt.ask(
            "[bold]Hangi kaynakları tarayalım?[/bold] (örn: 1,3 veya 4)",
            default="4"
        ).strip()

        if secim == "4":
            selected = list(SOURCES.keys())
            break
        try:
            indices = [int(x) - 1 for x in re.split(r"[,\s]+", secim) if x.isdigit()]
            keys = list(SOURCES.keys())
            selected = [keys[i] for i in indices if 0 <= i < len(keys)]
            if selected:
                break
            console.print("[red]❌ Geçerli seçim yok[/red]")
        except Exception:
            console.print("[red]❌ Geçersiz giriş[/red]")

    selected_sources = {k: SOURCES[k] for k in selected}

    # 2) Max URL
    max_urls = IntPrompt.ask(
        "[bold green]🔢 Maksimum kaç URL taransın?[/bold green] [dim](0 = sınırsız)[/dim]",
        default=100
    )
    max_urls = None if max_urls == 0 else max_urls

    # 3) Timeout
    timeout = IntPrompt.ask(
        "[bold green]⏱️  Timeout (saniye)[/bold green]",
        default=8
    )

    # 4) Çıktı dosyası adı
    output = Prompt.ask(
        "[bold green]📄 Çıktı dosyası öneki[/bold green]",
        default="scan_result"
    ).strip()

    return selected_sources, max_urls, timeout, output


def onay(selected_sources, max_urls, timeout, output):
    sources_text = "\n".join(f"  • {s['name']}" for s in selected_sources.values())
    panel = Panel.fit(
        f"[cyan]Kaynaklar:[/cyan]\n{sources_text}\n\n"
        f"[cyan]Max URL:[/cyan] {max_urls or 'Sınırsız'}\n"
        f"[cyan]Timeout:[/cyan] {timeout} sn\n"
        f"[cyan]Çıktı:[/cyan] {output}_<tarih>.txt",
        title="[bold yellow]⚙️ Ayarlar[/bold yellow]",
        border_style="yellow"
    )
    console.print(panel)
    return Confirm.ask("[bold green]🚀 Tarama başlatılsın mı?[/bold green]", default=True)


def main():
    try:
        while True:
            selected, max_urls, timeout, output = menu()

            if not onay(selected, max_urls, timeout, output):
                console.print("[yellow]↩️  Yeniden başlatılıyor...[/yellow]\n")
                continue

            bot = ScannerBot(selected, output, timeout, max_urls)
            bot.run()

            console.print("\n[bold green]🎉 Tarama tamamlandı![/bold green]")
            if not Confirm.ask("[bold]Yeni tarama yapmak ister misin?[/bold]", default=False):
                break
            console.print("\n" + "=" * 50 + "\n")

    except KeyboardInterrupt:
        console.print("\n[yellow]👋 İptal edildi.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()