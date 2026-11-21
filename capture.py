"""Renode capture sequence for Cipher Workshop (not yet run).

Run from xous-dev-toolkit:
    python3 scripts/renode_capture.py --app cipher-workshop --script ../precursor-cipher/capture.py

Contract: run(ctl, outdir) -> number of failed steps. The app is already launched.
"""
import os


def run(ctl, outdir) -> int:
    failures = 0

    def shot(name):
        nonlocal failures
        if not ctl.try_screenshot(os.path.join(outdir, name)):
            failures += 1

    shot("01_select.png")
    for _ in range(3):                 # Caesar -> ROT13 -> Atbash -> Vigenere
        ctl.timed_key("Down", after=1.0)
    shot("02_vigenere_selected.png")
    ctl.inject_line("")                # Enter: input screen
    ctl.sleep(1.0)
    ctl.inject_string("ATTACKATDAWN")
    shot("03_input.png")
    ctl.inject_line("")                # Enter: key screen
    ctl.sleep(1.0)
    ctl.inject_string("LEMON")
    shot("04_key.png")
    ctl.inject_line("")                # Enter: run -> LXFOPVEFRNHR
    ctl.sleep(1.0)
    shot("05_output.png")
    ctl.inject_key("f")
    ctl.sleep(1.0)
    shot("06_frequency.png")
    ctl.timed_key("BackSpace", after=1.0)
    ctl.inject_key("s")                # save
    ctl.sleep(1.5)
    shot("07_saved_status.png")
    ctl.timed_key("BackSpace", after=1.0)   # back to cipher list
    ctl.inject_key("s")                # saved list
    ctl.sleep(1.0)
    shot("08_saved_list.png")
    ctl.inject_line("")                # view
    ctl.sleep(1.0)
    shot("09_view.png")
    ctl.timed_key("F4", after=1.0)
    ctl.timed_key("F4", after=1.0)
    shot("10_back_to_select.png")
    return failures
