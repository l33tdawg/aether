#!/usr/bin/env python3
"""
Scope Manager for smart resume workflow

Handles scope persistence, detection, and resume options for bug bounty audits.
"""

from typing import Dict, List, Optional, Any
from rich.console import Console
from pathlib import Path
import curses
import json
import time

from core.database_manager import AetherDatabase


class ScopeManager:
    """Manages audit scope persistence and resume workflow."""
    
    def __init__(self, db: Optional[AetherDatabase] = None):
        self.console = Console()
        self.db = db or AetherDatabase()
        # Temporary selection cache directory
        self.cache_dir = Path.home() / '.aether' / 'selection_cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_selection_cache_file(self, items_hash: str) -> Path:
        """Get cache file path for a specific set of items."""
        return self.cache_dir / f"selection_{items_hash}.json"
    
    def _compute_items_hash(self, items: List[Dict[str, Any]]) -> str:
        """Compute a hash of the item list to identify the selection context."""
        import hashlib
        # Use file paths to create a unique hash for this set of contracts
        paths = '|'.join(item.get('file_path', '') for item in items)
        return hashlib.md5(paths.encode()).hexdigest()[:8]
    
    def _save_selection_cache(self, items_hash: str, selected_indices: List[int]) -> None:
        """Save the current selection to a cache file."""
        try:
            cache_file = self._get_selection_cache_file(items_hash)
            cache_data = {
                'timestamp': time.time(),
                'selected_indices': selected_indices,
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            # Silently fail - don't break the workflow for cache issues
            pass
    
    def _load_selection_cache(self, items_hash: str) -> Optional[List[int]]:
        """Load previously saved selection from cache."""
        try:
            cache_file = self._get_selection_cache_file(items_hash)
            if cache_file.exists():
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                    # Cache is valid if less than 24 hours old
                    if time.time() - cache_data.get('timestamp', 0) < 86400:
                        return cache_data.get('selected_indices', [])
        except Exception:
            pass
        return None
    
    def _clear_selection_cache(self, items_hash: str) -> None:
        """Clear cache for a specific item set."""
        try:
            cache_file = self._get_selection_cache_file(items_hash)
            if cache_file.exists():
                cache_file.unlink()
        except Exception:
            pass
    
    def interactive_select(self, items: List[Dict[str, Any]], disabled_indices: Optional[List[int]] = None, pre_selected: Optional[List[int]] = None, project_context: Optional[str] = None, previously_audited_indices: Optional[List[int]] = None) -> List[int]:
        """
        Interactive multi-select using curses with arrow keys and spacebar.
        
        Args:
            items: List of dicts with 'file_path' and 'contract_name' keys
            disabled_indices: List of indices that are disabled/already selected
            pre_selected: List of indices that should start as checked
            project_context: Optional context string for better cache management
            previously_audited_indices: List of indices that were previously audited (shown in green but still selectable)
            
        Returns:
            List of selected indices
        """
        try:
            return curses.wrapper(self._curses_select, items, disabled_indices or [], pre_selected or [], project_context, previously_audited_indices or [])
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Selection cancelled[/yellow]")
            return []
        except Exception as e:
            self.console.print(f"[red]Selection error: {e}[/red]")
            return []
    
    def _curses_select(self, stdscr, items: List[Dict[str, Any]], disabled_indices: List[int], pre_selected: List[int], project_context: Optional[str] = None, previously_audited_indices: List[int] = None) -> List[int]:
        """Curses-based interactive selector."""
        items_hash = self._compute_items_hash(items)
        previously_audited_indices = previously_audited_indices or []
        
        # Try to load cached selection
        cached_selection = self._load_selection_cache(items_hash) if not pre_selected else None
        
        curses.curs_set(0)  # Hide cursor
        selected = [i in (cached_selection or pre_selected) for i in range(len(items))]
        position = 0
        filter_text = ""  # For filtering items
        
        # Color pairs
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Highlight
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Selected
        curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)   # Info
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_BLACK)  # Disabled (dimmed)
        curses.init_pair(5, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Filter active
        curses.init_pair(6, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Previously audited
        
        def get_filtered_indices():
            """Return indices that match the current filter."""
            if not filter_text:
                return list(range(len(items)))
            return [i for i in range(len(items)) if filter_text.lower() in items[i].get('file_path', '').lower()]
        
        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            # Get filtered items
            filtered_indices = get_filtered_indices()
            
            # Draw header
            header = "📋 SELECT CONTRACTS TO AUDIT (Use ↑↓ arrows, SPACE to toggle, ENTER to confirm)"
            stdscr.addstr(0, 0, header[:width], curses.color_pair(3) | curses.A_BOLD)
            
            # Draw filter status if filtering
            if filter_text:
                filter_line = f"🔍 Filter: '{filter_text}' ({len(filtered_indices)} matches)  [ESC] Clear filter"
                stdscr.addstr(1, 0, filter_line[:width], curses.color_pair(5) | curses.A_BOLD)
                info_row = 2
            else:
                info_row = 1
            
            # Draw instructions
            new_selected_count = sum(1 for i, s in enumerate(selected) if s and i not in disabled_indices)
            available_count = len([i for i in range(len(items)) if i not in disabled_indices])
            previously_audited_count = len(previously_audited_indices)
            if previously_audited_count > 0:
                instructions = f"Selected: {new_selected_count} / {available_count}  |  Previously audited: {previously_audited_count} (green)  |  [F]ilter | [A]ll | [N]one | [Q]uit"
            else:
                instructions = f"Selected: {new_selected_count} / {available_count}  |  [F]ilter | [A]ll | [N]one | [Q]uit"
            stdscr.addstr(info_row, 0, instructions[:width], curses.color_pair(3))
            
            # Draw separator
            stdscr.addstr(info_row + 1, 0, "─" * width, curses.color_pair(3))
            
            # Draw items
            start_row = info_row + 2
            max_visible = height - info_row - 4
            
            # Handle position bounds with filtered list
            if filtered_indices and position >= len(filtered_indices):
                position = len(filtered_indices) - 1
            
            # Calculate scroll position
            if filtered_indices:
                scroll_offset = max(0, min(position - max_visible // 2, len(filtered_indices) - max_visible))
            else:
                scroll_offset = 0
            
            for i, filtered_idx in enumerate(filtered_indices[scroll_offset:scroll_offset + max_visible]):
                actual_index = filtered_idx
                row = start_row + i
                
                item = items[actual_index]
                file_path = item.get('file_path', '')
                contract_name = item.get('contract_name', 'Unknown')
                
                # Format the line
                is_disabled = actual_index in disabled_indices
                is_previously_audited = actual_index in previously_audited_indices
                is_current = (i + scroll_offset == position)
                
                if is_disabled:
                    checkbox = "✓"  # Already selected (cannot toggle)
                    status = "[ALREADY SELECTED]"
                else:
                    checkbox = "✓" if selected[actual_index] else " "
                    status = "[PREVIOUSLY AUDITED]" if is_previously_audited else ""
                
                line = f"[{checkbox}] [{actual_index:3d}] {file_path:<40} ({contract_name}) {status}"
                line = line[:width - 1]  # Trim to screen width
                
                # Apply styling
                if is_disabled:
                    # Disabled contracts in dim gray (cannot toggle)
                    attr = curses.A_DIM
                elif is_current:
                    # Current selection highlighted
                    attr = curses.color_pair(1) | curses.A_BOLD
                elif is_previously_audited:
                    # Previously audited in green (but still selectable)
                    if selected[actual_index]:
                        attr = curses.color_pair(6) | curses.A_BOLD  # Green and bold if selected
                    else:
                        attr = curses.color_pair(6)  # Just green if not selected
                elif selected[actual_index]:
                    attr = curses.color_pair(2)
                else:
                    attr = curses.A_NORMAL
                
                stdscr.addstr(row, 0, line, attr)
            
            # Draw footer
            footer_row = height - 1
            footer = "[↑/↓] Move | [SPACE] Toggle | [ENTER] Confirm | [F]ilter"
            stdscr.addstr(footer_row, 0, footer[:width], curses.color_pair(3))
            
            stdscr.refresh()
            
            # Handle input
            try:
                key = stdscr.getch()
                
                if key == ord('q') or key == ord('Q'):
                    # Auto-save current selection before exiting
                    current_selection = [i for i, s in enumerate(selected) if s and i not in disabled_indices]
                    if current_selection:
                        self._save_selection_cache(items_hash, current_selection)
                        # Show confirmation that selection was saved
                        try:
                            curses.curs_set(1)  # Show cursor temporarily
                            stdscr.clear()
                            stdscr.addstr(0, 0, "Your selection has been saved!")
                            stdscr.addstr(1, 0, f"Selected: {len(current_selection)} contracts")
                            stdscr.addstr(2, 0, "Next time you run the selector, your choices will be pre-loaded.")
                            stdscr.addstr(4, 0, "Press any key to exit...")
                            stdscr.refresh()
                            stdscr.getch()
                            curses.curs_set(0)
                        except:
                            pass
                    return []
                
                elif key == ord('\x1b'):  # ESC key - clear filter
                    filter_text = ""
                    position = 0
                
                elif key == ord('f') or key == ord('F'):  # Filter
                    # Prompt for filter text
                    curses.curs_set(1)  # Show cursor
                    filter_input = ""
                    while True:
                        stdscr.clear()
                        stdscr.addstr(0, 0, "Enter filter text (e.g., '/old', 'mock'): ")
                        stdscr.addstr(1, 0, f"Current: {filter_input}")
                        stdscr.refresh()
                        
                        try:
                            ch = stdscr.getch()
                            if ch == ord('\n'):  # Enter
                                filter_text = filter_input
                                position = 0
                                curses.curs_set(0)  # Hide cursor
                                break
                            elif ch == 127 or ch == curses.KEY_BACKSPACE:  # Backspace
                                filter_input = filter_input[:-1]
                            elif 32 <= ch <= 126:  # Printable characters
                                filter_input += chr(ch)
                            elif ch == ord('\x1b'):  # ESC - cancel filter
                                curses.curs_set(0)
                                break
                        except:
                            pass
                
                elif key == ord(' '):  # Spacebar
                    # Only toggle if not disabled and we have filtered items
                    if filtered_indices and position < len(filtered_indices):
                        actual_index = filtered_indices[position]
                        if actual_index not in disabled_indices:
                            selected[actual_index] = not selected[actual_index]
                            # Auto-save selection on every change
                            current_selection = [i for i, s in enumerate(selected) if s and i not in disabled_indices]
                            if current_selection:
                                self._save_selection_cache(items_hash, current_selection)
                
                elif key == curses.KEY_UP:
                    if filtered_indices:
                        position = (position - 1) % len(filtered_indices)
                
                elif key == curses.KEY_DOWN:
                    if filtered_indices:
                        position = (position + 1) % len(filtered_indices)
                
                elif key == curses.KEY_HOME:
                    position = 0
                
                elif key == curses.KEY_END:
                    if filtered_indices:
                        position = len(filtered_indices) - 1
                
                elif key == ord('\n'):  # Enter/Return
                    new_selections = [i for i, s in enumerate(selected) if s and i not in disabled_indices]
                    if len(new_selections) == 0:
                        self.console.print("[red]Please select at least one new contract[/red]")
                        stdscr.getch()  # Wait for user
                        continue
                    # Clear cache on successful completion
                    self._clear_selection_cache(items_hash)
                    return new_selections
                
                elif key == ord('a') or key == ord('A'):  # Select all (in filtered view)
                    for idx in filtered_indices:
                        if idx not in disabled_indices:
                            selected[idx] = True
                    # Auto-save
                    current_selection = [i for i, s in enumerate(selected) if s and i not in disabled_indices]
                    if current_selection:
                        self._save_selection_cache(items_hash, current_selection)
                
                elif key == ord('n') or key == ord('N'):  # Select none (in filtered view)
                    for idx in filtered_indices:
                        selected[idx] = False
                    # Auto-save (even if empty)
                    self._save_selection_cache(items_hash, [])
                
            except KeyboardInterrupt:
                # Auto-save on Ctrl+C
                current_selection = [i for i, s in enumerate(selected) if s and i not in disabled_indices]
                if current_selection:
                    self._save_selection_cache(items_hash, current_selection)
                return []
    
    def detect_and_handle_saved_scope(self, project_id: int, all_discovered_contracts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Detect if a project has a saved scope and offer resume options.
        Returns the selected scope and action to take, or None if starting fresh.
        """
        # Check for active scope first (incomplete)
        active_scope = self.db.get_active_scope(project_id)
        
        if not active_scope:
            # No active scope - check for ALL scopes (including completed)
            all_scopes = self.db.get_all_scopes(project_id)
            if all_scopes and len(all_scopes) > 0:
                # Show scope selection menu if multiple scopes exist
                if len(all_scopes) > 1:
                    selected_scope = self._select_scope_from_multiple(all_scopes, all_discovered_contracts)
                    if selected_scope:
                        return self._handle_completed_scope(selected_scope, all_discovered_contracts, project_id)
                    return None
                else:
                    # Single completed scope
                    return self._handle_completed_scope(all_scopes[0], all_discovered_contracts, project_id)
            return None  # No saved scope at all, start fresh
        
        # Loop to handle menu options (allowing user to cancel operations and return to menu)
        while True:
            # Display saved scope info
            self._display_saved_scope_menu(active_scope, all_discovered_contracts)
            
            # Get user choice
            while True:
                try:
                    choice = self.console.input("\n[bold green]Select option: [/bold green]").strip()
                    
                    if choice == "1":
                        return {"action": "continue", "scope": active_scope}
                    elif choice == "2":
                        # Try to add contracts, but allow user to cancel and return to menu
                        added = self.handle_add_contracts(active_scope, all_discovered_contracts)
                        if added:
                            active_scope = added  # Update scope with newly added contracts
                            self.console.print("[yellow]Returning to menu...[/yellow]\n")
                            break  # Break inner loop to redisplay menu
                        else:
                            # User cancelled (pressed 'q'), return to menu
                            self.console.print("[yellow]Returning to menu...[/yellow]\n")
                            break  # Break inner loop to redisplay menu
                    elif choice == "3":
                        removed = self.handle_remove_contracts(active_scope, all_discovered_contracts)
                        if removed:
                            active_scope = removed
                            self.console.print("[yellow]Returning to menu...[/yellow]\n")
                            break  # Break inner loop to redisplay menu
                        else:
                            # User cancelled, return to menu
                            self.console.print("[yellow]Returning to menu...[/yellow]\n")
                            break  # Break inner loop to redisplay menu
                    elif choice == "4":
                        return {"action": "reaudit", "scope": active_scope}
                    elif choice == "5":
                        return {"action": "new_scope", "scope": None}
                    elif choice == "6":
                        return {"action": "view_report", "scope": active_scope}
                    elif choice == "7":
                        self.console.print("[yellow]Audit cancelled[/yellow]")
                        return {"action": "cancel", "scope": None}
                    else:
                        self.console.print("[red]Invalid option. Please select 1-7[/red]")
                except KeyboardInterrupt:
                    self.console.print("\n[yellow]Audit cancelled[/yellow]")
                    return {"action": "cancel", "scope": None}
            # If we get here, loop back to show menu again
    
    def _select_scope_from_multiple(
        self,
        scopes: List[Dict[str, Any]],
        all_discovered_contracts: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Allow user to select from multiple available scopes."""
        self.console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold cyan]📋 MULTIPLE AUDIT SCOPES FOUND[/bold cyan]")
        self.console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]\n")
        
        self.console.print("[bold]Select a scope to work with:[/bold]\n")
        
        for idx, scope in enumerate(scopes, 1):
            status_emoji = "✅" if scope['status'] == 'completed' else "⏳"
            status_text = scope['status'].upper()
            
            self.console.print(f"[bold]  [{idx}] {status_emoji} {scope.get('scope_name', 'Unnamed')}[/bold]")
            self.console.print(f"       Created: {scope.get('created_at', 'Unknown')}")
            self.console.print(f"       Status: {status_text}")
            self.console.print(f"       Contracts: {scope['total_audited']}/{scope['total_selected']} audited\n")
        
        self.console.print(f"  [0] Create new scope\n")
        self.console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
        
        while True:
            try:
                choice = self.console.input("\n[bold green]Select scope (0 to create new): [/bold green]").strip()
                
                if choice == "0":
                    return None  # Create new scope
                
                try:
                    idx = int(choice)
                    if 1 <= idx <= len(scopes):
                        return scopes[idx - 1]
                    else:
                        self.console.print(f"[red]Invalid option. Please select 0-{len(scopes)}[/red]")
                except ValueError:
                    self.console.print(f"[red]Invalid input. Please enter a number 0-{len(scopes)}[/red]")
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Cancelled[/yellow]")
                return None
    
    def _handle_completed_scope(
        self, 
        completed_scope: Dict[str, Any], 
        all_discovered_contracts: List[Dict[str, Any]],
        project_id: int
    ) -> Optional[Dict[str, Any]]:
        """
        Handle completed scope - offer options to view report, add more contracts, or create new scope.
        """
        while True:
            self._display_completed_scope_menu(completed_scope, all_discovered_contracts)
            
            # Get user choice
            while True:
                try:
                    choice = self.console.input("\n[bold green]Select option: [/bold green]").strip()
                    
                    if choice == "1":
                        # View report for completed scope
                        return {"action": "view_report", "scope": completed_scope}
                    elif choice == "2":
                        # Add more contracts and reactivate scope
                        self.db.reactivate_scope(completed_scope['id'])  # Change status back to 'active'
                        added = self.handle_add_contracts(completed_scope, all_discovered_contracts)
                        if added:
                            self.console.print("[green]✅ Scope reactivated with new contracts[/green]")
                            return {"action": "continue", "scope": added}
                        else:
                            # User cancelled
                            self.console.print("[yellow]Returning to menu...[/yellow]\n")
                            break
                    elif choice == "3":
                        # Re-audit the completed scope
                        return {"action": "reaudit", "scope": completed_scope}
                    elif choice == "4":
                        # Create new scope
                        return {"action": "new_scope", "scope": None}
                    elif choice == "5":
                        # Cancel
                        self.console.print("[yellow]Audit cancelled[/yellow]")
                        return {"action": "cancel", "scope": None}
                    else:
                        self.console.print("[red]Invalid option. Please select 1-5[/red]")
                except KeyboardInterrupt:
                    self.console.print("\n[yellow]Audit cancelled[/yellow]")
                    return {"action": "cancel", "scope": None}
            # Loop back to show menu again
    
    def _display_completed_scope_menu(self, scope: Dict[str, Any], all_contracts: List[Dict[str, Any]]) -> None:
        """Display completed scope info and options menu."""
        selected_paths = scope['selected_contracts']
        audited = scope['total_audited']
        
        # Get contract names
        audited_names = []
        
        for contract in all_contracts:
            path = contract.get('file_path', '')
            name = contract.get('contract_name', 'Unknown')
            
            if path in selected_paths:
                audited_names.append(f"{path} ({name})")
        
        self.console.print("\n[bold green]═══════════════════════════════════════════════════════[/bold green]")
        self.console.print("[bold green]✅ PREVIOUS AUDIT SCOPE COMPLETED[/bold green]")
        self.console.print("[bold green]═══════════════════════════════════════════════════════[/bold green]\n")
        
        self.console.print(f"[bold]Scope:[/bold] {scope.get('scope_name', 'Unnamed')}")
        self.console.print(f"[bold]Created:[/bold] {scope.get('created_at', 'Unknown')}")
        self.console.print(f"[bold]Completed:[/bold] {scope.get('modified_at', 'Unknown')}\n")
        
        self.console.print(f"[bold green]✓ All {audited} contracts audited successfully![/bold green]\n")
        
        if audited_names:
            self.console.print("[bold]Audited Contracts:[/bold]")
            for name in audited_names[:10]:  # Show first 10
                self.console.print(f"  ✓ {name}")
            if len(audited_names) > 10:
                self.console.print(f"  ... and {len(audited_names) - 10} more")
        
        self.console.print("\n[bold green]═══════════════════════════════════════════════════════[/bold green]")
        self.console.print("[bold]What would you like to do?[/bold]\n")
        self.console.print(f"  [1] View audit report for this scope")
        self.console.print(f"  [2] Add more contracts to this scope (reactivates scope)")
        self.console.print(f"  [3] Re-audit all {audited} contracts (fresh analysis)")
        self.console.print(f"  [4] Create new scope with different contracts")
        self.console.print(f"  [5] Cancel (exit)")
        self.console.print("[bold green]═══════════════════════════════════════════════════════[/bold green]")
    
    def _display_saved_scope_menu(self, scope: Dict[str, Any], all_contracts: List[Dict[str, Any]]) -> None:
        """Display saved scope info and resume menu."""
        selected_paths = scope['selected_contracts']
        audited = scope['total_audited']
        pending = scope['total_pending']
        
        # Get contract names
        selected_names = []
        audited_names = []
        pending_names = []
        
        for contract in all_contracts:
            path = contract.get('file_path', '')
            name = contract.get('contract_name', 'Unknown')
            
            if path in selected_paths:
                if audited > 0 and len(audited_names) < audited:
                    audited_names.append(f"{path} ({name})")
                elif pending > 0:
                    pending_names.append(f"{path} ({name})")
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold cyan]📋 PREVIOUS AUDIT SCOPE FOUND[/bold cyan]")
        self.console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]\n")
        
        self.console.print(f"[bold]Scope:[/bold] {scope.get('scope_name', 'Unnamed')}")
        self.console.print(f"[bold]Created:[/bold] {scope.get('created_at', 'Unknown')}")
        self.console.print(f"[bold]Last Modified:[/bold] {scope.get('modified_at', 'Unknown')}\n")
        
        self.console.print(f"[bold]Saved Scope: {len(selected_paths)} contracts selected[/bold]")
        self.console.print(f"  ├─ ✓ Audited: {audited} contracts")
        self.console.print(f"  ├─ ⏳ Pending: {pending} contracts")
        self.console.print(f"  └─ ✕ Not selected: {len(all_contracts) - len(selected_paths)} contracts\n")
        
        if audited_names:
            self.console.print("[bold]Contracts Audited:[/bold]")
            for name in audited_names:
                self.console.print(f"  ✓ {name}")
        
        if pending_names:
            self.console.print("\n[bold]Contracts Pending:[/bold]")
            for name in pending_names[:5]:  # Show first 5
                self.console.print(f"  ⏳ {name}")
            if len(pending_names) > 5:
                self.console.print(f"  ... and {len(pending_names) - 5} more")
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold]What would you like to do?[/bold]\n")
        self.console.print(f"  [1] Continue audit (analyze {pending} pending contracts)")
        self.console.print(f"  [2] Add more contracts to scope")
        self.console.print(f"  [3] Remove contracts from scope")
        self.console.print(f"  [4] Re-audit all {len(selected_paths)} contracts (fresh analysis)")
        self.console.print(f"  [5] New scope selection (start from scratch)")
        self.console.print(f"  [6] View audit report (show findings so far)")
        self.console.print(f"  [7] Cancel")
        self.console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
    
    def handle_add_contracts(self, scope: Dict[str, Any], all_contracts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Allow user to add more contracts to existing scope."""
        current = scope['selected_contracts']
        
        # Filter to available (unselected) contracts
        available_contracts = [c for c in all_contracts if c['file_path'] not in current]
        
        if not available_contracts:
            self.console.print("[yellow]All contracts already selected![/yellow]")
            return None
        
        # Create a list of indices for contracts that are already selected (in all_contracts)
        already_selected_indices = [all_contracts.index(c) for c in all_contracts if c['file_path'] in current]
        
        # Display current scope status before showing selector
        self._display_add_contracts_status(scope, all_contracts, already_selected_indices)
        
        self.console.print(f"\n[bold cyan]Available to add: {len(available_contracts)} contracts[/bold cyan]\n")
        self.console.print("[bold cyan]Launching interactive selector for additional contracts...[/bold cyan]")
        self.console.print("[italic yellow]Already selected contracts are shown in dim text (cannot toggle)[/italic yellow]\n")
        
        # Use interactive selector for ALL contracts, passing already selected indices as disabled
        selected_indices = self.interactive_select(all_contracts, already_selected_indices)
        
        if not selected_indices:
            self.console.print("[yellow]No additional contracts selected[/yellow]")
            return None
        
        # Map selected indices to paths
        new_paths = [all_contracts[i]['file_path'] for i in selected_indices]
        updated_paths = current + new_paths
        
        # Update database
        self.db.update_scope_contracts(scope['id'], updated_paths)
        scope['selected_contracts'] = updated_paths
        scope['total_selected'] = len(updated_paths)
        scope['total_pending'] += len(new_paths)
        
        self.console.print(f"\n[green]✓ Added {len(new_paths)} contracts. Total: {len(updated_paths)}[/green]")
        return scope
    
    def _display_add_contracts_status(self, scope: Dict[str, Any], all_contracts: List[Dict[str, Any]], already_selected_indices: List[int]) -> None:
        """Display current scope status when adding contracts."""
        current = scope['selected_contracts']
        audited = scope['total_audited']
        pending = scope['total_pending']
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold cyan]📋 CURRENT SCOPE STATUS[/bold cyan]")
        self.console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]\n")
        
        self.console.print(f"[bold]Total in scope: {len(current)} contracts[/bold]")
        self.console.print(f"  ├─ ✓ Audited: {audited} contracts")
        self.console.print(f"  └─ ⏳ Pending: {pending} contracts\n")
        
        # Show which contracts are already in scope with their status
        self.console.print("[bold]Contracts already in scope:[/bold]")
        
        audited_in_scope = []
        pending_in_scope = []
        
        # Build list of audited vs pending contracts
        for idx in already_selected_indices:
            contract = all_contracts[idx]
            file_path = contract.get('file_path', '')
            contract_name = contract.get('contract_name', 'Unknown')
            
            # Check if this contract has been audited (approximate based on order)
            # The first 'audited' contracts are marked as audited
            if len(audited_in_scope) < audited:
                audited_in_scope.append((file_path, contract_name))
            else:
                pending_in_scope.append((file_path, contract_name))
        
        # Display audited contracts
        if audited_in_scope:
            for path, name in audited_in_scope[:10]:
                self.console.print(f"  ✓ {path} ({name})")
            if len(audited_in_scope) > 10:
                self.console.print(f"  ✓ ... and {len(audited_in_scope) - 10} more audited contracts")
        
        # Display pending contracts
        if pending_in_scope:
            for path, name in pending_in_scope[:10]:
                self.console.print(f"  ⏳ {path} ({name})")
            if len(pending_in_scope) > 10:
                self.console.print(f"  ⏳ ... and {len(pending_in_scope) - 10} more pending contracts")
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
    
    def handle_remove_contracts(self, scope: Dict[str, Any], all_contracts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Allow user to remove contracts from scope using interactive selector."""
        current = scope['selected_contracts']
        
        # Filter to selected contracts only
        selected_contracts = [c for c in all_contracts if c['file_path'] in current]
        
        if not selected_contracts:
            self.console.print("[yellow]No contracts to remove![/yellow]")
            return None
        
        # Create a list of indices for contracts that are NOT in selected_contracts (in all_contracts)
        # These will be disabled in the selector
        not_selected_indices = [all_contracts.index(c) for c in all_contracts if c['file_path'] not in current]
        
        # Display current scope status before showing selector
        already_selected_indices = [all_contracts.index(c) for c in all_contracts if c['file_path'] in current]
        self._display_remove_contracts_status(scope, all_contracts, already_selected_indices)
        
        self.console.print(f"\n[bold cyan]Available to remove: {len(selected_contracts)} contracts[/bold cyan]\n")
        self.console.print("[bold cyan]Launching interactive selector to remove contracts...[/bold cyan]")
        self.console.print("[italic yellow]Check contracts = will be REMOVED | Uncheck to keep | Dimmed contracts are not in scope[/italic yellow]\n")
        
        # Use interactive selector for ALL contracts, with unselected indices disabled
        # Note: We do NOT pre-select the currently selected contracts - user must explicitly check to remove
        selected_indices = self.interactive_select(all_contracts, not_selected_indices, pre_selected=[])
        
        if not selected_indices:
            self.console.print("[yellow]No contracts selected for removal[/yellow]")
            return None
        
        # Map selected indices to paths to remove
        remove_paths = {all_contracts[i]['file_path'] for i in selected_indices}
        updated_paths = [p for p in current if p not in remove_paths]
        
        # Update database
        self.db.update_scope_contracts(scope['id'], updated_paths)
        scope['selected_contracts'] = updated_paths
        scope['total_selected'] = len(updated_paths)
        scope['total_pending'] = max(0, scope['total_pending'] - len(remove_paths))
        
        self.console.print(f"\n[green]✓ Removed {len(remove_paths)} contracts. Total: {len(updated_paths)}[/green]")
        return scope
    
    def _display_remove_contracts_status(self, scope: Dict[str, Any], all_contracts: List[Dict[str, Any]], already_selected_indices: List[int]) -> None:
        """Display current scope status when removing contracts."""
        current = scope['selected_contracts']
        audited = scope['total_audited']
        pending = scope['total_pending']
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold cyan]📋 CURRENT SCOPE STATUS[/bold cyan]")
        self.console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]\n")
        
        self.console.print(f"[bold]Total in scope: {len(current)} contracts[/bold]")
        self.console.print(f"  ├─ ✓ Audited: {audited} contracts")
        self.console.print(f"  └─ ⏳ Pending: {pending} contracts\n")
        
        # Show which contracts are in scope with their status
        self.console.print("[bold]Contracts in scope (available to remove):[/bold]")
        
        audited_in_scope = []
        pending_in_scope = []
        
        # Build list of audited vs pending contracts
        for idx in already_selected_indices:
            contract = all_contracts[idx]
            file_path = contract.get('file_path', '')
            contract_name = contract.get('contract_name', 'Unknown')
            
            # Check if this contract has been audited (approximate based on order)
            # The first 'audited' contracts are marked as audited
            if len(audited_in_scope) < audited:
                audited_in_scope.append((file_path, contract_name))
            else:
                pending_in_scope.append((file_path, contract_name))
        
        # Display audited contracts
        if audited_in_scope:
            for path, name in audited_in_scope[:10]:
                self.console.print(f"  ✓ {path} ({name})")
            if len(audited_in_scope) > 10:
                self.console.print(f"  ✓ ... and {len(audited_in_scope) - 10} more audited contracts")
        
        # Display pending contracts
        if pending_in_scope:
            for path, name in pending_in_scope[:10]:
                self.console.print(f"  ⏳ {path} ({name})")
            if len(pending_in_scope) > 10:
                self.console.print(f"  ⏳ ... and {len(pending_in_scope) - 10} more pending contracts")
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
    
    def handle_reaudit(self, scope: Dict[str, Any]) -> Dict[str, Any]:
        """Reset scope for fresh re-analysis."""
        self.db.reset_scope_for_reaudit(scope['id'])
        scope['total_audited'] = 0
        scope['total_pending'] = scope['total_selected']
        scope['last_audited_contract_id'] = None
        self.console.print(f"\n[green]✓ Scope reset for re-audit. {scope['total_selected']} contracts ready.[/green]")
        return scope

