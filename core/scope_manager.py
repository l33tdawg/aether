#!/usr/bin/env python3
"""
Scope Manager for smart resume workflow

Handles scope persistence, detection, and resume options for bug bounty audits.
"""

from typing import Dict, List, Optional, Any
from rich.console import Console
from pathlib import Path

from core.database_manager import AetherDatabase


class ScopeManager:
    """Manages audit scope persistence and resume workflow."""
    
    def __init__(self, db: Optional[AetherDatabase] = None):
        self.console = Console()
        self.db = db or AetherDatabase()
    
    def detect_and_handle_saved_scope(self, project_id: int, all_discovered_contracts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Detect if a project has a saved scope and offer resume options.
        Returns the selected scope and action to take, or None if starting fresh.
        """
        active_scope = self.db.get_active_scope(project_id)
        
        if not active_scope:
            return None  # No saved scope, start fresh
        
        # Display saved scope info
        self._display_saved_scope_menu(active_scope, all_discovered_contracts)
        
        # Get user choice
        while True:
            try:
                choice = self.console.input("\n[bold green]Select option: [/bold green]").strip()
                
                if choice == "1":
                    return {"action": "continue", "scope": active_scope}
                elif choice == "2":
                    return {"action": "add_contracts", "scope": active_scope, "all_contracts": all_discovered_contracts}
                elif choice == "3":
                    return {"action": "remove_contracts", "scope": active_scope}
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
        
        self.console.print("\n[bold]Currently selected contracts:[/bold]")
        self.console.print(f"  {','.join(str(i) for i, c in enumerate(all_contracts) if c['file_path'] in current)}\n")
        
        # Show available contracts not yet selected
        available_indices = [i for i, c in enumerate(all_contracts) if c['file_path'] not in current]
        if not available_indices:
            self.console.print("[yellow]All contracts already selected![/yellow]")
            return None
        
        self.console.print(f"[bold]Available to add (indices: {','.join(map(str, available_indices[:10]))}...)[/bold]")
        user_input = self.console.input("[bold green]Enter indices to add (comma-separated) or 'cancel': [/bold green]").strip()
        
        if user_input.lower() == 'cancel':
            return None
        
        try:
            new_indices = [int(x.strip()) for x in user_input.split(',')]
            new_paths = [all_contracts[i]['file_path'] for i in new_indices if i < len(all_contracts)]
            updated_paths = current + new_paths
            
            self.db.update_scope_contracts(scope['id'], updated_paths)
            scope['selected_contracts'] = updated_paths
            scope['total_selected'] = len(updated_paths)
            scope['total_pending'] += len(new_paths)
            
            self.console.print(f"\n[green]✓ Added {len(new_paths)} contracts. Total: {len(updated_paths)}[/green]")
            return scope
        except (ValueError, IndexError):
            self.console.print("[red]Invalid input[/red]")
            return None
    
    def handle_remove_contracts(self, scope: Dict[str, Any], all_contracts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Allow user to remove contracts from scope."""
        current = scope['selected_contracts']
        
        self.console.print("\n[bold]Currently selected contracts:[/bold]")
        for i, c in enumerate(all_contracts):
            if c['file_path'] in current:
                self.console.print(f"  [{i}] {c['file_path']} ({c.get('contract_name', 'Unknown')})")
        
        user_input = self.console.input("\n[bold green]Enter indices to remove (comma-separated) or 'cancel': [/bold green]").strip()
        
        if user_input.lower() == 'cancel':
            return None
        
        try:
            remove_indices = [int(x.strip()) for x in user_input.split(',')]
            remove_paths = {all_contracts[i]['file_path'] for i in remove_indices if i < len(all_contracts)}
            updated_paths = [p for p in current if p not in remove_paths]
            
            self.db.update_scope_contracts(scope['id'], updated_paths)
            scope['selected_contracts'] = updated_paths
            scope['total_selected'] = len(updated_paths)
            scope['total_pending'] = len(updated_paths) - scope['total_audited']
            
            self.console.print(f"\n[green]✓ Removed {len(remove_paths)} contracts. Total: {len(updated_paths)}[/green]")
            return scope
        except (ValueError, IndexError):
            self.console.print("[red]Invalid input[/red]")
            return None
    
    def handle_reaudit(self, scope: Dict[str, Any]) -> Dict[str, Any]:
        """Reset scope for fresh re-analysis."""
        self.db.reset_scope_for_reaudit(scope['id'])
        scope['total_audited'] = 0
        scope['total_pending'] = scope['total_selected']
        scope['last_audited_contract_id'] = None
        self.console.print(f"\n[green]✓ Scope reset for re-audit. {scope['total_selected']} contracts ready.[/green]")
        return scope

