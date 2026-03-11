"""
Gotzi TUI — Wireshark-like packet list, detail view, and hex dump.
Run: python -m udp_probe --tui   or   gotzi --tui
Requires root/sudo for raw socket capture.
"""
from __future__ import annotations

import time
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import ScrollableContainer
from textual.widgets import (
    DataTable,
    Static,
    Input,
    Label,
    Footer,
    TabbedContent,
    TabPane,
)
from textual.widgets.data_table import RowKey
from textual import on

from udp_probe.capture import PacketStore, ParsedPacket, start_live_sniffer_thread


def format_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int((ts % 1) * 1000):03d}"


def hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<48}  {ascii_part}")
    return "\n".join(lines)


class PacketTable(DataTable):
    BINDINGS = [
        Binding("c", "clear", "Clear"),
        Binding("r", "refresh", "Refresh"),
    ]

    def action_clear(self) -> None:
        self.clear(columns=True)
        if self.column_keys:
            self.add_columns(*self.column_keys)

    def action_refresh(self) -> None:
        pass


class PacketDetailTree(Static):
    """Shows selected packet as expandable sections (Frame, IP, UDP, Payload)."""

    def show_packet(self, packet: Optional[ParsedPacket]) -> None:
        if packet is None:
            self.update("(Select a packet from the list)")
            return
        lines = [
            "[bold]Frame[/]",
            f"  Index: {packet.index}",
            f"  Time: {format_ts(packet.timestamp)}",
            "",
            "[bold]Internet Protocol[/]",
            f"  Source:      {packet.src_ip}",
            f"  Destination: {packet.dest_ip}",
            "",
            "[bold]User Datagram Protocol[/]",
            f"  Source port:      {packet.src_port}",
            f"  Destination port: {packet.dest_port}",
            f"  Length:           {packet.length}",
            f"  Checksum:         0x{packet.checksum:04x}",
            "",
            "[bold]Payload[/]",
            f"  {packet.summary}",
        ]
        self.update("\n".join(lines))


class HexDump(Static):
    """Hex + ASCII dump of selected packet."""

    def show_packet(self, packet: Optional[ParsedPacket]) -> None:
        if packet is None:
            self.update("(Select a packet from the list)")
            return
        self.update(hex_dump(packet.raw))


class UDPProbeTUI(App):
    TITLE = "Gotzi — Packet Sniffer"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("f", "focus_filter", "Filter"),
        Binding("c", "clear_all", "Clear all"),
    ]

    filter_port: Optional[int] = None
    filter_ip: str = ""

    def __init__(self, store: Optional[PacketStore] = None, filter_port: Optional[int] = None):
        super().__init__()
        self.store = store or PacketStore(max_packets=20_000)
        self._filter_port = filter_port
        self._stop_event: Optional[object] = None
        self._selected_packet: Optional[ParsedPacket] = None
        self._packet_rows: dict[RowKey, ParsedPacket] = {}

    def compose(self) -> ComposeResult:
        yield Label(" Gotzi — Packet list | Detail | Hex dump ", id="title")
        yield Input(placeholder="Filter: port (e.g. 12345) or IP substring", id="filter_input")
        with TabbedContent(id="tabs"):
            with TabPane("Packet list", id="list_tab"):
                yield PacketTable(id="packet_table")
            with TabPane("Detail", id="detail_tab"):
                yield ScrollableContainer(PacketDetailTree(id="detail_tree"))
            with TabPane("Hex dump", id="hex_tab"):
                yield ScrollableContainer(HexDump(id="hex_dump"))
        yield Label(" No packet selected ", id="status")
        yield Footer()

    def _get_detail_widget(self) -> PacketDetailTree:
        return self.query_one("#detail_tree", PacketDetailTree)

    def _get_hex_widget(self) -> HexDump:
        return self.query_one("#hex_dump", HexDump)

    def on_mount(self) -> None:
        table = self.query_one("#packet_table", PacketTable)
        table.add_columns("#", "Time", "Source", "Dest", "Sport", "Dport", "Len", "Info")
        table.cursor_type = "row"

        try:
            _, self._stop_event = start_live_sniffer_thread(
                self.store,
                filter_port=self._filter_port,
            )
            self.query_one("#status", Label).update(" Sniffing... (raw socket) ")
        except Exception as e:
            self.query_one("#status", Label).update(f" Sniffer error: {e} ")

        self.set_interval(0.3, self._poll_store)

    def _poll_store(self) -> None:
        table = self.query_one("#packet_table", PacketTable)
        packets = self.store.get_all()
        port = self.filter_port
        ip = (self.filter_ip or "").strip().lower()
        existing = {p.index for p in self._packet_rows.values()}
        for p in packets:
            if p.index in existing:
                continue
            if port is not None and p.src_port != port and p.dest_port != port:
                continue
            if ip and ip not in p.src_ip.lower() and ip not in p.dest_ip.lower():
                continue
            row_key = table.add_row(
                str(p.index),
                format_ts(p.timestamp),
                p.src_ip,
                p.dest_ip,
                str(p.src_port),
                str(p.dest_port),
                str(p.length),
                (p.summary[:40] + "..." if len(p.summary) > 40 else p.summary),
                key=str(p.index),
            )
            self._packet_rows[row_key] = p
        try:
            self.query_one("#status", Label).update(
                f" Packets: {self.store.count()} | Select row + Enter for detail "
            )
        except Exception:
            pass

    @on(Input.Submitted, "#filter_input")
    def _filter_submitted(self) -> None:
        value = self.query_one("#filter_input", Input).value.strip()
        self.filter_port = int(value) if value.isdigit() else None
        self.filter_ip = value if not (value and value.isdigit()) else ""
        self._packet_rows.clear()
        table = self.query_one("#packet_table", PacketTable)
        table.clear(columns=True)
        table.add_columns("#", "Time", "Source", "Dest", "Sport", "Dport", "Len", "Info")
        self._poll_store()

    def action_focus_filter(self) -> None:
        self.query_one("#filter_input", Input).focus()

    def action_clear_all(self) -> None:
        self.store.clear()
        self._packet_rows.clear()
        table = self.query_one("#packet_table", PacketTable)
        table.clear(columns=True)
        table.add_columns("#", "Time", "Source", "Dest", "Sport", "Dport", "Len", "Info")
        self._selected_packet = None
        self._get_detail_widget().show_packet(None)
        self._get_hex_widget().show_packet(None)
        self.query_one("#status", Label).update(" Cleared. ")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key
        p = self._packet_rows.get(row_key)
        self._selected_packet = p
        if p:
            self._get_detail_widget().show_packet(p)
            self._get_hex_widget().show_packet(p)
            self.query_one("#status", Label).update(
                f" #{p.index} {p.src_ip}:{p.src_port} → {p.dest_ip}:{p.dest_port} "
            )

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        if event.tab.id == "detail_tab":
            self._get_detail_widget().show_packet(self._selected_packet)
        elif event.tab.id == "hex_tab":
            self._get_hex_widget().show_packet(self._selected_packet)

    def on_unmount(self) -> None:
        if self._stop_event:
            self._stop_event.set()


def main() -> None:
    UDPProbeTUI().run()
