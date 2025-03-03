import serial  # Serial port library
import serial.tools.list_ports  # Serial port library
import asyncio
from bleak import BleakScanner, BleakClient  # BLE library
from nicegui import run
from signal import SIGINT, SIGTERM


class BLEClient:

    client = None  # type: BleakClient
    device_name = None  # type: str
    COMMAND_ADDR = "2B39"  # type: str
    serialport = None  # type: serial.Serial
    serialport_logs = []  # type: list[str]
    task_logs = None  # type: asyncio.Task

    async def connect(self, device_name):
        device = await BleakScanner.find_device_by_name(
            device_name, cb=dict(use_bdaddr=True)
        )

        if device is None:
            print(f'[X] Failure: Device "{device_name}" not found!')
            return None

        self.device_name = device_name
        self.client = BleakClient(device)

        return await self.client.connect()

    async def disconnect(self):
        if self.client:
            return await self.client.disconnect()
        return True

    async def write_command(self, command_data):
        print(f"[!] --> Command:  {command_data}")
        await self.client.write_gatt_char(
            self.COMMAND_ADDR, bytearray(command_data), response=False
        )
        res = await self.read_command()
        print(f"[!] <-- Response: {res}")
        return res

    async def read_command(self):
        res = await self.client.read_gatt_char(self.COMMAND_ADDR)
        return list(res)  # From bytearray to list

    def open_serialport(self):
        ports = list(serial.tools.list_ports.comports())
        for port in ports:
            if port.vid == 0x303A and port.pid == 0x1001:
                print(f"[!] Serial Port: {port.name}")
                self.serialport = serial.Serial(
                    port.device,
                    baudrate=115200,
                    timeout=0.01,
                    dsrdtr=False,
                    rtscts=True,
                )
                return self.serialport
        return None

    def close_serialport(self):
        if self.serialport:
            print("[!] Serial Port Closed")
            self.serialport.close()
            return True
        return False

    async def _serialport_task(self):
        # Show logs from Serial port
        port = self.open_serialport()

        while True:
            try:
                try:
                    line = await run.io_bound(port.readline)
                except KeyboardInterrupt:
                    return
                if line:
                    self.serialport_logs.append(line.decode().strip("\r\n"))
            except Exception:
                if port:
                    port.close()
                    port = None
                print("[!] Serial Port disconnected!")
                while port is None:
                    await asyncio.sleep(0.1)
                    port = self.open_serialport()
            await asyncio.sleep(0.1)

    def init_logs(self):
        self.task_logs = asyncio.create_task(self._serialport_task())

    def read_logs(self):
        return self.serialport_logs
