"""
Tests for Textual TUI modal dialogs.

Tests ConfirmDialog, SelectDialog, TextInputDialog, CheckboxDialog,
and PathDialog using Textual's run_test() + Pilot API.
"""

import unittest
from unittest import IsolatedAsyncioTestCase

from textual.app import App, ComposeResult
from textual.widgets import Static


# ── Minimal host app for dialog testing ─────────────────────────


class DialogTestApp(App):
    """Minimal app that hosts a dialog for testing."""

    def __init__(self, dialog, **kwargs):
        super().__init__(**kwargs)
        self._dialog = dialog
        self.dialog_result = "NOT_SET"

    def compose(self) -> ComposeResult:
        yield Static("Dialog Test Host")

    def on_mount(self) -> None:
        def _capture(result):
            self.dialog_result = result

        self.push_screen(self._dialog, callback=_capture)


# ── ConfirmDialog Tests ─────────────────────────────────────────


class TestConfirmDialog(IsolatedAsyncioTestCase):
    """Test ConfirmDialog returns True/False based on user action."""

    async def test_confirm_yes_button(self):
        """Clicking Yes button should return True."""
        from cli.tui.dialogs.confirm import ConfirmDialog

        dialog = ConfirmDialog("Do you want to proceed?")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            # Click the Yes button
            await pilot.click("#yes")
            await pilot.pause()
            self.assertTrue(app.dialog_result)

    async def test_confirm_no_button(self):
        """Clicking No button should return False."""
        from cli.tui.dialogs.confirm import ConfirmDialog

        dialog = ConfirmDialog("Do you want to proceed?")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.click("#no")
            await pilot.pause()
            self.assertFalse(app.dialog_result)

    async def test_confirm_y_key(self):
        """Pressing 'y' key should return True."""
        from cli.tui.dialogs.confirm import ConfirmDialog

        dialog = ConfirmDialog("Proceed?")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("y")
            await pilot.pause()
            self.assertTrue(app.dialog_result)

    async def test_confirm_n_key(self):
        """Pressing 'n' key should return False."""
        from cli.tui.dialogs.confirm import ConfirmDialog

        dialog = ConfirmDialog("Proceed?")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            self.assertFalse(app.dialog_result)

    async def test_confirm_escape_returns_false(self):
        """Pressing escape should return False."""
        from cli.tui.dialogs.confirm import ConfirmDialog

        dialog = ConfirmDialog("Proceed?")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            self.assertFalse(app.dialog_result)

    async def test_confirm_displays_message(self):
        """ConfirmDialog should display the message text."""
        from cli.tui.dialogs.confirm import ConfirmDialog

        dialog = ConfirmDialog("Are you sure about this?")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            msg_widget = app.screen.query_one("#message", Static)
            self.assertIn("Are you sure about this?", str(msg_widget.content))
            # Clean up
            await pilot.press("n")
            await pilot.pause()


# ── SelectDialog Tests ──────────────────────────────────────────


class TestSelectDialog(IsolatedAsyncioTestCase):
    """Test SelectDialog returns the selected choice or None on cancel."""

    async def test_select_first_item_via_enter(self):
        """Pressing Enter on the highlighted (first) item returns its value."""
        from cli.tui.dialogs.select import SelectDialog

        dialog = SelectDialog("Pick one", ["Option A", "Option B", "Option C"])
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            # First item is highlighted by default; press Enter
            await pilot.press("enter")
            await pilot.pause()
            self.assertEqual(app.dialog_result, "Option A")

    async def test_select_second_item_via_arrow_enter(self):
        """Pressing Down then Enter selects the second item."""
        from cli.tui.dialogs.select import SelectDialog

        dialog = SelectDialog("Pick one", ["Alpha", "Beta", "Gamma"])
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("down")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            self.assertEqual(app.dialog_result, "Beta")

    async def test_select_cancel_via_escape(self):
        """Pressing Escape should return None."""
        from cli.tui.dialogs.select import SelectDialog

        dialog = SelectDialog("Pick one", ["A", "B"])
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            self.assertIsNone(app.dialog_result)

    async def test_select_displays_prompt(self):
        """SelectDialog should show the prompt text."""
        from cli.tui.dialogs.select import SelectDialog

        dialog = SelectDialog("Choose wisely", ["X", "Y"])
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            prompt = app.screen.query_one("#prompt", Static)
            self.assertIn("Choose wisely", str(prompt.content))
            await pilot.press("escape")
            await pilot.pause()


# ── TextInputDialog Tests ───────────────────────────────────────


class TestTextInputDialog(IsolatedAsyncioTestCase):
    """Test TextInputDialog returns user input or None on cancel."""

    async def test_submit_default_value(self):
        """Pressing Enter without typing should return the default value."""
        from cli.tui.dialogs.text_input import TextInputDialog
        from textual.widgets import Input

        dialog = TextInputDialog("Enter path:", default="/tmp/test")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            # Press Enter to submit the default value
            await pilot.press("enter")
            await pilot.pause()
            self.assertEqual(app.dialog_result, "/tmp/test")

    async def test_submit_typed_value(self):
        """Typing text and pressing Enter should return the typed value."""
        from cli.tui.dialogs.text_input import TextInputDialog
        from textual.widgets import Input

        dialog = TextInputDialog("Name:", default="")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            # Type into the input
            input_widget = app.screen.query_one("#text-input", Input)
            input_widget.value = "my-contract"
            await pilot.pause()
            # Click OK button
            await pilot.click("#ok")
            await pilot.pause()
            self.assertEqual(app.dialog_result, "my-contract")

    async def test_cancel_returns_none(self):
        """Pressing Escape should return None."""
        from cli.tui.dialogs.text_input import TextInputDialog

        dialog = TextInputDialog("Enter:", default="test")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            self.assertIsNone(app.dialog_result)

    async def test_cancel_button_returns_none(self):
        """Clicking Cancel button should return None."""
        from cli.tui.dialogs.text_input import TextInputDialog

        dialog = TextInputDialog("Enter:", default="test")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.click("#cancel")
            await pilot.pause()
            self.assertIsNone(app.dialog_result)

    async def test_displays_prompt(self):
        """TextInputDialog should show the prompt text."""
        from cli.tui.dialogs.text_input import TextInputDialog

        dialog = TextInputDialog("Enter your API key:", default="")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            prompt = app.screen.query_one("#prompt", Static)
            self.assertIn("Enter your API key:", str(prompt.content))
            await pilot.press("escape")
            await pilot.pause()


# ── CheckboxDialog Tests ────────────────────────────────────────


class TestCheckboxDialog(IsolatedAsyncioTestCase):
    """Test CheckboxDialog returns selected values or None."""

    async def test_ok_returns_initially_selected(self):
        """Clicking OK should return values that were initially checked."""
        from cli.tui.dialogs.checkbox import CheckboxDialog

        choices = [
            ("Feature A", "feat_a", True),
            ("Feature B", "feat_b", False),
            ("Feature C", "feat_c", True),
        ]
        dialog = CheckboxDialog("Select features", choices)
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.click("#ok")
            await pilot.pause()
            # Should return the initially checked values
            result = app.dialog_result
            self.assertIsInstance(result, list)
            self.assertIn("feat_a", result)
            self.assertIn("feat_c", result)
            self.assertNotIn("feat_b", result)

    async def test_cancel_returns_none(self):
        """Pressing Escape should return None."""
        from cli.tui.dialogs.checkbox import CheckboxDialog

        choices = [
            ("A", "a", True),
            ("B", "b", False),
        ]
        dialog = CheckboxDialog("Select", choices)
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            self.assertIsNone(app.dialog_result)

    async def test_cancel_button_returns_none(self):
        """Clicking Cancel button should return None."""
        from cli.tui.dialogs.checkbox import CheckboxDialog

        choices = [
            ("X", "x", True),
        ]
        dialog = CheckboxDialog("Select", choices)
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.click("#cancel")
            await pilot.pause()
            self.assertIsNone(app.dialog_result)

    async def test_empty_selection_returns_empty_list(self):
        """If no items are checked, OK should return an empty list."""
        from cli.tui.dialogs.checkbox import CheckboxDialog

        choices = [
            ("A", "a", False),
            ("B", "b", False),
        ]
        dialog = CheckboxDialog("Select", choices)
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.click("#ok")
            await pilot.pause()
            self.assertEqual(app.dialog_result, [])


# ── PathDialog Tests ────────────────────────────────────────────


class TestPathDialog(IsolatedAsyncioTestCase):
    """Test PathDialog returns path or None."""

    async def test_ok_returns_input_value(self):
        """Clicking OK should return the current input value."""
        from cli.tui.dialogs.path_picker import PathDialog
        from textual.widgets import Input

        dialog = PathDialog("Select path:", default="/tmp")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            # Set a value in the path input
            input_widget = app.screen.query_one("#path-input", Input)
            input_widget.value = "/tmp/my-contracts"
            await pilot.pause()
            await pilot.click("#ok")
            await pilot.pause()
            self.assertEqual(app.dialog_result, "/tmp/my-contracts")

    async def test_cancel_returns_none(self):
        """Pressing Escape should return None."""
        from cli.tui.dialogs.path_picker import PathDialog

        dialog = PathDialog("Select path:")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            self.assertIsNone(app.dialog_result)

    async def test_cancel_button_returns_none(self):
        """Clicking Cancel button should return None."""
        from cli.tui.dialogs.path_picker import PathDialog

        dialog = PathDialog("Select path:", default="/tmp")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.click("#cancel")
            await pilot.pause()
            self.assertIsNone(app.dialog_result)

    async def test_submit_via_enter_in_input(self):
        """Pressing Enter in the input field should submit."""
        from cli.tui.dialogs.path_picker import PathDialog
        from textual.widgets import Input

        dialog = PathDialog("Select path:", default="/tmp/test-path")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            # Focus the input and press Enter
            input_widget = app.screen.query_one("#path-input", Input)
            input_widget.focus()
            await pilot.pause()
            input_widget.value = "/tmp/submitted-path"
            await pilot.pause()
            # Simulate Enter key on input which triggers on_input_submitted
            await pilot.press("enter")
            await pilot.pause()
            self.assertEqual(app.dialog_result, "/tmp/submitted-path")

    async def test_displays_prompt(self):
        """PathDialog should show the prompt text."""
        from cli.tui.dialogs.path_picker import PathDialog

        dialog = PathDialog("Choose a directory:", default="/tmp")
        app = DialogTestApp(dialog)

        async with app.run_test() as pilot:
            await pilot.pause()
            prompt = app.screen.query_one("#prompt", Static)
            self.assertIn("Choose a directory:", str(prompt.content))
            await pilot.press("escape")
            await pilot.pause()


if __name__ == "__main__":
    unittest.main()
