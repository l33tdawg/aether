"""
Settings screen — provides access to configuration, setup wizard,
API key management, model selection, and triage tuning.

Ports the settings flow from cli/subflows.py to a Textual Screen
with a selection list and dialog-based input.
"""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, ListView, ListItem, Label, Static

from cli.tui.dialogs.confirm import ConfirmDialog
from cli.tui.dialogs.select import SelectDialog
from cli.tui.dialogs.text_input import TextInputDialog


_MENU_OPTIONS = [
    ("wizard", "Run full setup wizard"),
    ("view", "View current configuration"),
    ("keys", "Reconfigure API keys"),
    ("models", "Reconfigure model selections"),
    ("triage", "Triage settings"),
    ("clear", "Clear data"),
    ("back", "Back to dashboard"),
]


class SettingsScreen(Screen):
    """Settings menu with options for configuration management."""

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold cyan]Settings[/bold cyan]", id="settings-title")
        yield ListView(
            *[
                ListItem(Label(label), name=value)
                for value, label in _MENU_OPTIONS
            ],
            id="settings-list",
        )
        yield Static("", id="settings-detail")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#settings-list", ListView).focus()

    # ── Menu selection ────────────────────────────────────────────

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        choice = event.item.name
        if choice == "back":
            self.app.pop_screen()
        else:
            self.run_worker(self._handle_choice(choice), exclusive=True)

    async def _handle_choice(self, choice: str) -> None:
        if choice == "wizard":
            await self._run_full_wizard()
        elif choice == "view":
            self._view_config()
        elif choice == "keys":
            await self._configure_api_keys()
        elif choice == "models":
            await self._configure_models()
        elif choice == "triage":
            await self._edit_triage_settings()
        elif choice == "clear":
            await self._clear_data()

    # ── API key configuration ──────────────────────────────────────

    async def _configure_api_keys(self) -> None:
        """Configure API keys via sequential TextInputDialog prompts."""
        detail = self.query_one("#settings-detail", Static)

        try:
            from core.config_manager import ConfigManager
            config_mgr = ConfigManager()
            config = config_mgr.config

            detail.update("[bold]Configure API Keys[/bold]\n\nEnter keys (leave blank to skip).")

            # OpenAI
            current = getattr(config, 'openai_api_key', '') or ''
            masked = f"***{current[-4:]}" if current and len(current) > 4 else ("set" if current else "not set")
            new_val = await self.app.push_screen_wait(
                TextInputDialog(f"OpenAI API key (current: {masked})", default="")
            )
            if new_val is None:
                return
            if new_val:
                config.openai_api_key = new_val

            # Gemini
            current = getattr(config, 'gemini_api_key', '') or ''
            masked = f"***{current[-4:]}" if current and len(current) > 4 else ("set" if current else "not set")
            new_val = await self.app.push_screen_wait(
                TextInputDialog(f"Gemini API key (current: {masked})", default="")
            )
            if new_val is None:
                return
            if new_val:
                config.gemini_api_key = new_val

            # Anthropic
            current = getattr(config, 'anthropic_api_key', '') or ''
            masked = f"***{current[-4:]}" if current and len(current) > 4 else ("set" if current else "not set")
            new_val = await self.app.push_screen_wait(
                TextInputDialog(f"Anthropic API key (current: {masked})", default="")
            )
            if new_val is None:
                return
            if new_val:
                config.anthropic_api_key = new_val

            # Etherscan
            current = getattr(config, 'etherscan_api_key', '') or ''
            masked = f"***{current[-4:]}" if current and len(current) > 4 else ("set" if current else "not set")
            new_val = await self.app.push_screen_wait(
                TextInputDialog(f"Etherscan API key (current: {masked})", default="")
            )
            if new_val is None:
                return
            if new_val:
                config.etherscan_api_key = new_val

            config_mgr.save_config()
            detail.update("[green]API keys saved.[/green]")
        except Exception as e:
            detail.update(f"[red]Error configuring API keys: {e}[/red]")

    # ── Model configuration ────────────────────────────────────────

    _OPENAI_MODELS = [
        "gpt-5.3-chat-latest", "gpt-5.3-mini",
        "gpt-5-chat-latest", "gpt-5-pro", "gpt-5-mini", "gpt-5-nano",
        "gpt-4o", "gpt-4o-mini", "gpt-4-turbo",
    ]
    _GEMINI_MODELS = [
        "gemini-3.0-flash", "gemini-3.0-pro",
        "gemini-2.5-flash", "gemini-2.5-pro",
        "gemini-1.5-flash", "gemini-1.5-pro",
    ]
    _ANTHROPIC_MODELS = [
        "claude-opus-4-6",
        "claude-sonnet-4-5-20250929",
        "claude-haiku-4-5-20251001",
    ]

    async def _configure_models(self) -> None:
        """Configure model selections via SelectDialog prompts."""
        detail = self.query_one("#settings-detail", Static)

        try:
            from core.config_manager import ConfigManager
            config_mgr = ConfigManager()
            config = config_mgr.config

            detail.update("[bold]Configure Models[/bold]\n\nSelect models for each provider.")

            # OpenAI model
            if getattr(config, 'openai_api_key', ''):
                current = getattr(config, 'openai_model', self._OPENAI_MODELS[0])
                choices = list(self._OPENAI_MODELS)
                if current and current not in choices:
                    choices.insert(0, current)
                selected = await self.app.push_screen_wait(
                    SelectDialog(f"OpenAI model (current: {current})", choices)
                )
                if selected is None:
                    return
                config.openai_model = selected

            # Gemini model
            if getattr(config, 'gemini_api_key', ''):
                current = getattr(config, 'gemini_model', self._GEMINI_MODELS[0])
                choices = list(self._GEMINI_MODELS)
                if current and current not in choices:
                    choices.insert(0, current)
                selected = await self.app.push_screen_wait(
                    SelectDialog(f"Gemini model (current: {current})", choices)
                )
                if selected is None:
                    return
                config.gemini_model = selected

            # Anthropic model
            if getattr(config, 'anthropic_api_key', ''):
                current = getattr(config, 'anthropic_model', self._ANTHROPIC_MODELS[0])
                choices = list(self._ANTHROPIC_MODELS)
                if current and current not in choices:
                    choices.insert(0, current)
                selected = await self.app.push_screen_wait(
                    SelectDialog(f"Anthropic model (current: {current})", choices)
                )
                if selected is None:
                    return
                config.anthropic_model = selected

            config_mgr.save_config()
            detail.update("[green]Model selections saved.[/green]")
        except Exception as e:
            detail.update(f"[red]Error configuring models: {e}[/red]")

    # ── Full wizard ────────────────────────────────────────────────

    async def _run_full_wizard(self) -> None:
        """Run API key configuration followed by model configuration."""
        await self._configure_api_keys()
        await self._configure_models()

    # ── View config ───────────────────────────────────────────────

    def _view_config(self) -> None:
        """Display the current configuration in the detail pane."""
        detail = self.query_one("#settings-detail", Static)
        try:
            from core.config_manager import ConfigManager
            config_mgr = ConfigManager()
            config = config_mgr.config

            # Build a formatted view of key config fields
            lines = ["[bold]Current Configuration[/bold]\n"]

            # Core
            lines.append(f"  [bold]Workspace:[/bold]       {getattr(config, 'workspace', 'N/A')}")
            lines.append(f"  [bold]Output dir:[/bold]      {getattr(config, 'output_dir', 'N/A')}")
            lines.append(f"  [bold]Reports dir:[/bold]     {getattr(config, 'reports_dir', 'N/A')}")
            lines.append("")

            # Analysis
            lines.append(f"  [bold]Max analysis time:[/bold]    {getattr(config, 'max_analysis_time', 'N/A')}s")
            lines.append(f"  [bold]Parallel analysis:[/bold]    {getattr(config, 'parallel_analysis', 'N/A')}")
            lines.append(f"  [bold]Max concurrent:[/bold]       {getattr(config, 'max_concurrent_contracts', 'N/A')}")
            lines.append("")

            # API keys (masked)
            openai_key = getattr(config, 'openai_api_key', '')
            gemini_key = getattr(config, 'gemini_api_key', '')
            anthropic_key = getattr(config, 'anthropic_api_key', '')
            lines.append(f"  [bold]OpenAI API key:[/bold]      {'***' + openai_key[-4:] if openai_key and len(openai_key) > 4 else ('set' if openai_key else '[red]not set[/red]')}")
            lines.append(f"  [bold]Gemini API key:[/bold]      {'***' + gemini_key[-4:] if gemini_key and len(gemini_key) > 4 else ('set' if gemini_key else '[red]not set[/red]')}")
            lines.append(f"  [bold]Anthropic API key:[/bold]   {'***' + anthropic_key[-4:] if anthropic_key and len(anthropic_key) > 4 else ('set' if anthropic_key else '[red]not set[/red]')}")
            lines.append("")

            # Models
            lines.append(f"  [bold]OpenAI model:[/bold]        {getattr(config, 'openai_model', 'N/A')}")
            lines.append(f"  [bold]Gemini model:[/bold]        {getattr(config, 'gemini_model', 'N/A')}")
            lines.append(f"  [bold]Anthropic model:[/bold]     {getattr(config, 'anthropic_model', 'N/A')}")
            lines.append("")

            # Triage
            lines.append(f"  [bold]Triage min severity:[/bold]    {getattr(config, 'triage_min_severity', 'medium')}")
            lines.append(f"  [bold]Triage confidence:[/bold]      {getattr(config, 'triage_confidence_threshold', 0.5)}")
            lines.append(f"  [bold]Triage max findings:[/bold]    {getattr(config, 'triage_max_findings', 50)}")

            detail.update("\n".join(lines))
        except Exception as e:
            detail.update(f"[red]Error displaying config: {e}[/red]")

    # ── Triage settings ───────────────────────────────────────────

    async def _edit_triage_settings(self) -> None:
        """Inline editing of triage thresholds via dialogs."""
        detail = self.query_one("#settings-detail", Static)

        try:
            from core.config_manager import ConfigManager
            config_mgr = ConfigManager()
            config = config_mgr.config

            current_severity = getattr(config, 'triage_min_severity', 'medium')
            current_threshold = getattr(config, 'triage_confidence_threshold', 0.5)
            current_max = getattr(config, 'triage_max_findings', 50)

            detail.update(
                "[bold]Current Triage Settings[/bold]\n\n"
                f"  Min severity:         {current_severity}\n"
                f"  Confidence threshold: {current_threshold}\n"
                f"  Max findings:         {current_max}"
            )

            # Minimum severity
            new_severity = await self.app.push_screen_wait(
                SelectDialog(
                    "Minimum severity for triage",
                    ["critical", "high", "medium", "low", "informational"],
                )
            )
            if new_severity:
                config.triage_min_severity = new_severity

            # Confidence threshold
            threshold_str = await self.app.push_screen_wait(
                TextInputDialog(
                    "Confidence threshold (0.0 - 1.0)",
                    default=str(current_threshold),
                )
            )
            if threshold_str:
                try:
                    threshold = float(threshold_str)
                    if 0.0 <= threshold <= 1.0:
                        config.triage_confidence_threshold = threshold
                except ValueError:
                    pass

            # Max findings
            max_str = await self.app.push_screen_wait(
                TextInputDialog(
                    "Max findings to display",
                    default=str(current_max),
                )
            )
            if max_str:
                try:
                    config.triage_max_findings = int(max_str)
                except ValueError:
                    pass

            config_mgr.save_config()
            detail.update("[green]Triage settings saved.[/green]")
        except Exception as e:
            detail.update(f"[red]Error editing triage settings: {e}[/red]")

    # ── Clear data ──────────────────────────────────────────────

    async def _clear_data(self) -> None:
        """Present sub-menu for clearing databases and caches."""
        detail = self.query_one("#settings-detail", Static)

        clear_options = [
            "Clear local audit database",
            "Clear GitHub audit database",
            "Clear analysis cache",
            "Clear all data",
        ]
        selected = await self.app.push_screen_wait(
            SelectDialog("Select data to clear", clear_options)
        )
        if not selected:
            return

        if selected == "Clear local audit database":
            await self._clear_local_db(detail)
        elif selected == "Clear GitHub audit database":
            await self._clear_github_db(detail)
        elif selected == "Clear analysis cache":
            await self._clear_analysis_cache(detail)
        elif selected == "Clear all data":
            await self._clear_all_data(detail)

    async def _clear_local_db(self, detail: Static) -> None:
        """Clear the local audit database after confirmation."""
        try:
            from core.database_manager import DatabaseManager
            db = DatabaseManager()
            counts = db.get_record_counts()
            total = sum(counts.values())

            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    f"[bold red]Clear local audit database?[/bold red]\n\n"
                    f"This will delete {total} records:\n"
                    f"  Audits: {counts.get('audit_results', 0)}\n"
                    f"  Findings: {counts.get('vulnerability_findings', 0)}\n"
                    f"  Patterns: {counts.get('learning_patterns', 0)}\n"
                    f"  Metrics: {counts.get('audit_metrics', 0)}\n\n"
                    f"This action cannot be undone."
                )
            )
            if confirmed:
                if db.clear_all():
                    detail.update("[green]Local audit database cleared.[/green]")
                else:
                    detail.update("[red]Failed to clear local audit database.[/red]")
            else:
                detail.update("Cancelled.")
        except Exception as e:
            detail.update(f"[red]Error: {e}[/red]")

    async def _clear_github_db(self, detail: Static) -> None:
        """Clear the GitHub audit database after confirmation."""
        try:
            from core.database_manager import AetherDatabase
            db = AetherDatabase()
            counts = db.get_record_counts()
            total = sum(counts.values())

            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    f"[bold red]Clear GitHub audit database?[/bold red]\n\n"
                    f"This will delete {total} records:\n"
                    f"  Projects: {counts.get('projects', 0)}\n"
                    f"  Contracts: {counts.get('contracts', 0)}\n"
                    f"  Results: {counts.get('analysis_results', 0)}\n"
                    f"  Scopes: {counts.get('audit_scopes', 0)}\n\n"
                    f"This action cannot be undone."
                )
            )
            if confirmed:
                if db.clear_all():
                    detail.update("[green]GitHub audit database cleared.[/green]")
                else:
                    detail.update("[red]Failed to clear GitHub audit database.[/red]")
            else:
                detail.update("Cancelled.")
        except Exception as e:
            detail.update(f"[red]Error: {e}[/red]")

    async def _clear_analysis_cache(self, detail: Static) -> None:
        """Clear the analysis cache after confirmation."""
        try:
            from core.analysis_cache import AnalysisCache
            cache = AnalysisCache()
            stats = cache.get_stats()
            disk_entries = stats.get('disk_entries', 0)
            mem_entries = stats.get('memory_entries', 0)

            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    f"[bold red]Clear analysis cache?[/bold red]\n\n"
                    f"Disk entries: {disk_entries}\n"
                    f"Memory entries: {mem_entries}\n\n"
                    f"Cached results will need to be recomputed."
                )
            )
            if confirmed:
                cache.clear_all()
                detail.update("[green]Analysis cache cleared.[/green]")
            else:
                detail.update("Cancelled.")
        except Exception as e:
            detail.update(f"[red]Error: {e}[/red]")

    async def _clear_all_data(self, detail: Static) -> None:
        """Clear all databases and caches after double confirmation."""
        confirmed = await self.app.push_screen_wait(
            ConfirmDialog(
                "[bold red]Clear ALL data?[/bold red]\n\n"
                "This will delete:\n"
                "  - All local audit results and findings\n"
                "  - All GitHub audit projects and scopes\n"
                "  - All cached analysis results\n\n"
                "This action cannot be undone."
            )
        )
        if not confirmed:
            detail.update("Cancelled.")
            return

        errors = []
        try:
            from core.database_manager import DatabaseManager
            db = DatabaseManager()
            if not db.clear_all():
                errors.append("local audit database")
        except Exception as e:
            errors.append(f"local DB ({e})")

        try:
            from core.database_manager import AetherDatabase
            db = AetherDatabase()
            if not db.clear_all():
                errors.append("GitHub audit database")
        except Exception as e:
            errors.append(f"GitHub DB ({e})")

        try:
            from core.analysis_cache import AnalysisCache
            cache = AnalysisCache()
            cache.clear_all()
        except Exception as e:
            errors.append(f"analysis cache ({e})")

        if errors:
            detail.update(
                f"[yellow]Partially cleared. Errors with: {', '.join(errors)}[/yellow]"
            )
        else:
            detail.update("[green]All data cleared successfully.[/green]")

    # ── Bindings ──────────────────────────────────────────────────

    def action_go_back(self) -> None:
        self.app.pop_screen()
