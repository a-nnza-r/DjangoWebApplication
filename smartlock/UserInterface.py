#!/usr/bin/env python3

import sys
import asyncio
from enum import Enum
from BLEClient import BLEClient
from nicegui import app, run, ui  # GUI Library


DEVICE_NAME = "Smart Lock [Group 4]"

AUTH = [0x00]  # 9 Bytes
OPEN = [0x01]  # 1 Byte
CLOSE = [0x02]  # 1 Byte
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Correct PASSCODE


class LockState(Enum):
    DISCONNECTED = (0,)
    OPENED = (1,)
    CLOSED = 2


ui_lock_state = LockState.DISCONNECTED
ble = BLEClient()


async def ui_connect(device_name, stepper=None):
    spinner = ui.spinner(size="lg")
    res = await ble.connect(device_name)
    spinner.delete()

    if res is None:
        ui.notify(
            f"Error: Cannot connect to {device_name}",
            type="negative",
        )
        return False

    if stepper:
        stepper.next()

    ui.notify("Connected!", type="positive")

    return True


async def ui_authenticate(passcode_value, stepper=None):
    spinner = ui.spinner(size="lg")
    passcode_value_array = [ord(c) - 0x30 for c in passcode_value]

    res = await ble.write_command(AUTH + passcode_value_array)
    if res[0] != 0:
        ui.notify(
            "Error: Wrong Passcode. Try again!", type="negative", close_button=True
        )
        spinner.delete()
        return False

    await asyncio.sleep(0.5)
    spinner.delete()
    ui.notify("Authenticated!", type="positive")

    if stepper:
        stepper.next()

    return True


async def ui_open():
    global ui_lock_state
    if ui_lock_state == LockState.OPENED:
        return
    ui_lock_state = LockState.OPENED
    spinner = ui.spinner(size="lg")
    await ble.write_command(OPEN)
    await asyncio.sleep(1)
    spinner.delete()


async def ui_close():
    global ui_lock_state
    if ui_lock_state == LockState.CLOSED:
        return
    ui_lock_state = LockState.CLOSED
    spinner = ui.spinner(size="lg")
    await ble.write_command(CLOSE)
    await asyncio.sleep(1)
    spinner.delete()


async def ui_disconnect(stepper=None):
    global ui_lock_state
    spinner = ui.spinner(size="lg")
    await ble.disconnect()
    spinner.delete()

    ui.notify("Disconnected", type="warning")
    ui_lock_state = LockState.DISCONNECTED

    if stepper:
        return stepper.run_method("goTo", "Connect")


def ui_update_step_connect(device_name, code):
    code.set_content(
        f"""
from BLEClient import BLEClient
ble = BLEClient()
ble.connect("{device_name}") # <---
"""
    )


def ui_update_step_authenticate(device_name, passcode, code):
    passcode_array = [ord(c) - 0x30 for c in passcode]
    code.set_content(
        f"""
from BLEClient import BLEClient
ble = BLEClient()
ble.connect("{device_name}")
ble.write_command({passcode_array}) # <---
"""
    )


async def user_interface() -> None:
    device_name = None  # type: ui.input
    passcode = None  # type: ui.input

    with ui.row().classes("flex-center justify-center w-full"):
        ui.markdown("# 🔒 Wireless Smart Lock")

    with ui.row().classes("items-start justify-center w-full"):
        with ui.card().classes("col-xs-11 col-md-auto"):
            ui.chip("Quick Start", color="primary", icon="rocket_launch").props(
                'outline size="1.5em"'
            ).classes("w-full").style("margin-top: -5px")
            with ui.stepper().props("horizontal flat") as stepper:
                with ui.step("Connect"):
                    ui.label("Connect to the SmartLock")

                    ui.mermaid(
                        """
                    sequenceDiagram
                        Client->>SmartLock 🔒: BLE Connect
                    """,
                        config={
                            "mirrorActors": False,
                            "boxMargin": 2,
                            "noteMargin": 5,
                            "height": 20,
                            "showSequenceNumbers": True,
                        },
                    ).classes("w-full")

                    code_step_connect = ui.code(
                        f"""
                        from BLEClient import BLEClient
                        ble = BLEClient()
                        ble.connect("{DEVICE_NAME}") # <---
                        """
                    ).classes("w-full")

                    device_name = ui.input(
                        "Name of device",
                        value=DEVICE_NAME,
                        on_change=lambda evt: ui_update_step_connect(
                            evt.value, code_step_connect
                        ),
                    ).classes("w-full")
                    with ui.stepper_navigation():
                        ui.button(
                            "Connect",
                            on_click=lambda: ui_connect(device_name.value, stepper),
                            icon="bluetooth",
                        ).props("push glossy")

                with ui.step("Authenticate"):
                    ui.label(
                        "Insert the correct passcode to authenticate with the smartlock"
                    )

                    ui.mermaid(
                        """
                    sequenceDiagram
                        Client->>SmartLock 🔒: BLE Connect
                        Client->>SmartLock 🔒: Authenticate (0x00 + 6 Bytes)
                    """,
                        config={
                            "mirrorActors": False,
                            "boxMargin": 2,
                            "noteMargin": 5,
                            "height": 20,
                            "showSequenceNumbers": True,
                        },
                    ).classes("w-full")

                    code_step_authenticate = ui.code(
                        f"""
                        from BLEClient import BLEClient
                        ble = BLEClient()
                        ble.connect("{device_name.value}")
                        ble.write_command({PASSCODE}) # <---
                    """
                    ).classes("w-full")
                    passcode = ui.input(
                        "Passcode",
                        value="".join([chr(b + 0x30) for b in PASSCODE]),
                        password_toggle_button=True,
                        on_change=lambda evt: ui_update_step_authenticate(
                            device_name.value, evt.value, code_step_authenticate
                        ),
                    ).classes("w-full")
                    with ui.stepper_navigation():
                        ui.button(
                            "Authenticate",
                            on_click=lambda: ui_authenticate(passcode.value, stepper),
                            icon="key",
                        ).props("push glossy")
                        ui.button(
                            "Disconnect",
                            on_click=lambda: ui_disconnect(stepper),
                            icon="bluetooth_disabled",
                        ).props("flat")

                with ui.step("Send Commands"):
                    ui.label(
                        "Control the SmartLock. You can open (unlock) or close (lock) the door!"
                    )

                    ui.mermaid(
                        """
                    sequenceDiagram
                        Client->>SmartLock 🔒: BLE Connect
                        Client->>SmartLock 🔒: Authenticate (0x00 + 6 Bytes)
                        Client->>SmartLock 🔒: Open (0x01)
                        Client->>SmartLock 🔒: Close (0x02)
                    """,
                        config={
                            "mirrorActors": False,
                            "boxMargin": 2,
                            "noteMargin": 5,
                            "height": 20,
                            "showSequenceNumbers": True,
                        },
                    ).classes("w-full")

                    updated_passcode = [ord(c) - 0x30 for c in passcode.value]
                    ui.code(
                        f"""
                        from BLEClient import BLEClient
                        ble = BLEClient()
                        ble.connect("{device_name.value}")
                        ble.write_command({updated_passcode})
                        ble.write_command({OPEN}) # <---
                        ### ----- OR ------ ###
                        ble.write_command({CLOSE}) # <---
                    """
                    ).classes("w-full")
                    with ui.stepper_navigation():
                        # with ui.button_group():
                        ui.button("Open", on_click=ui_open, icon="lock_open").props(
                            "push outline"
                        )
                        ui.button("Close", on_click=ui_close, icon="lock").props(
                            "push outline"
                        )
                        ui.button(
                            "Disconnect",
                            on_click=lambda: ui_disconnect(stepper),
                            icon="bluetooth_disabled",
                        ).props("flat")

        with ui.card().classes("col-xs-11 col-md-6 col-lg-5"):
            ui.chip("Logs", color="primary", icon="content_paste_search").props(
                'outline size="1.5em"'
            ).classes("w-full").style("margin-top: -5px")
            log = ui.log().style("height: 450px")

    # Show logs from Serial port
    port = ble.open_serialport()
    while not app.is_stopped:
        try:
            line = await run.io_bound(port.readline)
            if line:
                print(f'<-- {line.decode().strip('\r\n')}')
                log.push(line.decode())
        except Exception:
            if port:
                port.close()
                port = None
            print("[!] Serial Port disconnected!")
            while port == None:
                await asyncio.sleep(0.1)
                port = ble.open_serialport()


def ShowUserInterface():
    app.on_startup(user_interface)
    app.on_disconnect(ble.disconnect)
    app.on_shutdown(ble.disconnect)
    app.on_shutdown(ble.close_serialport)
    ui.run(title="Smart Lock Control", favicon="icon.png", reload=False)
