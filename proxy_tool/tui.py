
from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal, VerticalScroll
from textual.widgets import Header, Footer, Input, Label, Switch, Static, TextArea
import asyncio
import re
from .proxy_core import ProxyServer

class ProxyTui(App):
    CSS = """
    Screen {
        layout: grid;
        grid-size: 2;
        grid-columns: 2fr 3fr;
        grid-rows: 1fr;
    }
    
    .sidebar {
        height: 100%;
        overflow-y: auto;
    }
    
    .main {
        height: 100%;
        padding: 1;
    }
    
    .control-box {
        background: $panel;
        border: solid $accent;
        padding: 1 2;
        margin: 1;
        height: auto;
    }
    
    .box-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
        padding-bottom: 1;
    }
    
    Input {
        width: 100%;
        margin-bottom: 1;
        margin-top: 0;
    }
    
    Label {
        margin-top: 1;
        margin-bottom: 0;
    }
    
    Horizontal {
        margin-bottom: 1;
        height: auto;
    }
    
    Switch {
        margin-right: 1;
    }
    
    .status-on {
        color: $success;
        text-style: bold;
    }
    
    .status-off {
        color: $error;
        text-style: bold;
    }
    
    #logs {
        height: 100%;
        border: solid $accent;
    }
    
    VerticalScroll {
        height: 100%;
        scrollbar-gutter: stable;
        padding-bottom: 2;
    }
    
    .input-pair {
        layout: horizontal;
        height: auto;
        margin-bottom: 1;
    }
    
    .input-pair Input {
        width: 1fr;
        margin-right: 1;
        margin-bottom: 0;
    }
    """

    def __init__(self):
        super().__init__()
        self.proxy_server = None
        self.proxy_worker = None
        self.log_queue = asyncio.Queue()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with VerticalScroll(classes="sidebar"):
            # Proxy Control
            with Container(classes="control-box"):
                yield Label(" Proxy Control", classes="box-title")
                with Horizontal():
                    yield Switch(id="toggle_proxy")
                    yield Label(" OFFLINE", id="status_label", classes="status-off")
                yield Label("Listen Port (proxy server port)")
                yield Input(placeholder="8080", value="8080", id="port", type="integer")
            
            # Core Settings
            with Container(classes="control-box"):
                yield Label("⚙ Core Settings", classes="box-title")
                yield Label("Fragment Size (split packets into N-byte chunks)")
                yield Input(placeholder="0", value="0", id="fragment", type="integer")
                yield Label("TTL (packet time-to-live, 0=OS default)")
                yield Input(placeholder="0", value="0", id="ttl", type="integer")
                yield Label("Custom Header (inject HTTP header)")
                yield Input(placeholder="X-Custom: Value", id="header")
            
            # Evasion Techniques
            with Container(classes="control-box"):
                yield Label(" Evasion Techniques", classes="box-title")
                yield Label("Delay Range (random ms delay between fragments)")
                with Horizontal(classes="input-pair"):
                    yield Input(placeholder="Min", value="0", id="min_delay", type="integer")
                    yield Input(placeholder="Max", value="0", id="max_delay", type="integer")
                
                with Horizontal():
                    yield Switch(id="rotate_ua")
                    yield Label(" User-Agent Rotation (randomize browser UA)")
                
                yield Label("Domain Fronting (override Host header)")
                yield Input(placeholder="cdn.cloudflare.com", id="front_domain")
                
                yield Label("Padding (add random bytes to packets)")
                yield Input(placeholder="0", value="0", id="padding", type="integer")
            
            # Security & Privacy
            with Container(classes="control-box"):
                yield Label(" Security & Privacy", classes="box-title")
                with Horizontal():
                    yield Switch(id="use_doh")
                    yield Label(" DNS-over-HTTPS (encrypted DNS via Cloudflare)")
                
                with Horizontal():
                    yield Switch(id="privacy_mode")
                    yield Label(" Privacy Mode (hide full URLs in logs)")
        
        with Container(classes="main"):
            yield Label("📋 Traffic Logs (Select text, Ctrl+C to copy)")
            yield TextArea(id="logs", read_only=True, show_line_numbers=False)
        
        yield Footer()

    async def on_mount(self):
        self.log_worker = asyncio.create_task(self.process_logs())

    async def process_logs(self):
        log_widget = self.query_one("#logs", TextArea)
        while True:
            msg = await self.log_queue.get()
            clean_msg = re.sub(r'\[.*?\]', '', msg)
            current_text = log_widget.text
            log_widget.load_text(current_text + clean_msg + "\n")

    async def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "toggle_proxy":
            status_label = self.query_one("#status_label", Label)
            if event.value:
                status_label.update(" ONLINE")
                status_label.remove_class("status-off")
                status_label.add_class("status-on")
                await self.start_proxy()
            else:
                status_label.update(" OFFLINE")
                status_label.remove_class("status-on")
                status_label.add_class("status-off")
                self.stop_proxy()

    async def start_proxy(self):
        port = int(self.query_one("#port", Input).value or "8080")
        frag_size = int(self.query_one("#fragment", Input).value or "0")
        ttl = int(self.query_one("#ttl", Input).value or "0")
        header_input = self.query_one("#header", Input).value
        
        min_delay = int(self.query_one("#min_delay", Input).value or "0")
        max_delay = int(self.query_one("#max_delay", Input).value or "0")
        rotate_ua = self.query_one("#rotate_ua", Switch).value
        front_domain = self.query_one("#front_domain", Input).value or None
        padding = int(self.query_one("#padding", Input).value or "0")
        
        use_doh = self.query_one("#use_doh", Switch).value
        privacy_mode = self.query_one("#privacy_mode", Switch).value
        
        custom_headers = {}
        if ":" in header_input:
            k, v = header_input.split(":", 1)
            custom_headers[k.strip()] = v.strip()

        self.proxy_server = ProxyServer(
            port=port,
            fragment_size=frag_size,
            ttl=ttl,
            custom_headers=custom_headers,
            min_delay=min_delay,
            max_delay=max_delay,
            rotate_ua=rotate_ua,
            front_domain=front_domain,
            padding_size=padding,
            use_doh=use_doh,
            privacy_mode=privacy_mode
        )
        self.proxy_server.log_queue = self.log_queue
        
        self.proxy_worker = asyncio.create_task(self.proxy_server.start())
        await self.log_queue.put(f"✓ Proxy started on port {port}")
        
        features = []
        if frag_size > 0:
            features.append(f"Frag:{frag_size}B")
        if ttl > 0:
            features.append(f"TTL:{ttl}")
        if min_delay > 0 or max_delay > 0:
            features.append(f"Delay:{min_delay}-{max_delay}ms")
        if rotate_ua:
            features.append("UA-Rotation")
        if front_domain:
            features.append(f"Fronting:{front_domain}")
        if padding > 0:
            features.append(f"Pad:{padding}B")
        if use_doh:
            features.append("DoH")
        if privacy_mode:
            features.append("Privacy")
        
        if features:
            await self.log_queue.put(f"  Active: {', '.join(features)}")

    def stop_proxy(self):
        if self.proxy_server:
            self.proxy_server.stop()
        if self.proxy_worker:
            self.proxy_worker.cancel()
        
        asyncio.create_task(self.log_queue.put("✗ Proxy stopped"))

