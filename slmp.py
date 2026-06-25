import socket
import struct
import os
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox

# SLMP 通訊與簡單 GUI 工具
# 支援 CC-Link IE FB 物件讀取 / 寫入，並將寫入操作記錄到 log 檔案
class SLMPClient:
    def __init__(self, ip, port=5010, module_io=b'\xFF\x03', timeout=3.0):
        # 初始化 SLMP Client
        self.ip = ip
        self.port = port
        self.module_io = module_io
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        # 寫入日誌檔案路徑，預設為 None 表示不記錄
        self.log_file = None
        print(f"[系統] 目標 IP: {self.ip}:{self.port}")

    def enable_write_log(self, file_path: str):
        """啟用寫入日誌功能，日誌會附加到指定檔案。"""
        self.log_file = file_path

    def _log_write(self, index, sub_index, current_value, new_value, success, end_code, data_size, signed):
        # 若未啟用日誌，直接跳過
        if not self.log_file:
            return
        try:
            need_header = not os.path.exists(self.log_file) or os.path.getsize(self.log_file) == 0
            with open(self.log_file, 'a', encoding='utf-8') as f:
                if need_header:
                    f.write('timestamp,device_ip,index,subindex,data_size,signed,current_value,new_value,success,end_code\n')
                ts = datetime.now().isoformat()
                # 記錄寫入行為的詳細資料
                line = (
                    f"{ts},{self.ip},0x{index:04X},0x{sub_index:02X},{data_size},{int(bool(signed))},"
                    f"{current_value},{new_value},{int(bool(success))},0x{end_code:04X}\n"
                )
                f.write(line)
        except Exception as e:
            print(f"[警告] 無法寫入 log: {e}")

    def _build_header(self, request_data):
        # 組合 SLMP 標頭
        # Subheader(2) + Network(1) + Station(1) + Module IO(2) + Multidrop(1) + DataLen(2) + Timer(2)
        subheader = b'\x50\x00'
        network_no = b'\x00'
        station_no = b'\xFF'
        module_io = self.module_io
        multidrop_no = b'\x00'
        timer = b'\x0A\x00'
        # DataLen = Timer + request_data length
        data_len = struct.pack('<H', len(timer) + len(request_data))

        return subheader + network_no + station_no + module_io + multidrop_no + data_len + timer + request_data

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def write_object(self, index, sub_index, value, data_size=4, signed=False, write_command=b'\x20\x40', subcommand=b'\x02\x00'):
        """寫入物件值。

        Parameters:
        - index: 16-bit object index (e.g., 0x6085)
        - sub_index: 8-bit sub-index
        - value: integer value to write
        - data_size: bytes (1, 2, 4, or 8)
        - signed: whether to treat value as signed
        - write_command: two-byte command for write (little-endian bytes)
        - subcommand: two-byte subcommand
        """
        command = write_command
        subcommand = subcommand
        index_bytes = struct.pack('<H', index)
        sub_index_bytes = struct.pack('B', sub_index)
        reserved = b'\x00'
        # 設定寫入資料長度（以 byte 為單位）
        number_of_data = struct.pack('<H', data_size)

        # 嘗試讀取目前值以便寫入時記錄 log（若失敗則忽略）
        current_value = None
        try:
            current_value = self.read_object(index, sub_index, data_size=data_size, signed=signed)
        except Exception:
            current_value = None

        # 將要寫入的值轉換為對應的 byte 數據
        try:
            if data_size == 1:
                fmt = '<b' if signed else '<B'
                data_bytes = struct.pack(fmt, int(value))
            elif data_size == 2:
                fmt = '<h' if signed else '<H'
                data_bytes = struct.pack(fmt, int(value))
            elif data_size == 4:
                fmt = '<i' if signed else '<I'
                data_bytes = struct.pack(fmt, int(value))
            elif data_size == 8:
                fmt = '<q' if signed else '<Q'
                data_bytes = struct.pack(fmt, int(value))
            else:
                # fallback: convert integer to little-endian bytes
                data_bytes = int(value).to_bytes(data_size, 'little', signed=signed)
        except Exception as e:
            print(f"[錯誤] 打包寫入值失敗: {e}")
            return False

        request = command + subcommand + index_bytes + sub_index_bytes + reserved + number_of_data + data_bytes
        packet = self._build_header(request)
        print(f"[除錯] 發送(寫入): {packet.hex().upper()}")

        # 傳送寫入請求至設備
        try:
            self.sock.sendto(packet, (self.ip, self.port))
            data, _ = self.sock.recvfrom(1024)
            print(f"[除錯] 接收(寫入): {data.hex().upper()}")

            if len(data) < 11:
                print(f"[錯誤] 回應資料長度不足: {len(data)} bytes")
                return False

            try:
                end_code = struct.unpack('<H', data[9:11])[0]
            except struct.error as e:
                print(f"[錯誤] 無法解析 End Code: {e}")
                return False

            if end_code == 0:
                print("[成功] 寫入完成，End Code = 0")
                # log the write
                try:
                    self._log_write(index, sub_index, current_value, int(value), True, end_code, data_size, signed)
                except Exception:
                    pass
                return True
            else:
                print(f"[錯誤] 寫入失敗，End Code = {hex(end_code)}")
                try:
                    self._log_write(index, sub_index, current_value, int(value), False, end_code, data_size, signed)
                except Exception:
                    pass
                return False

        except socket.timeout:
            print("[錯誤] Timeout！請確認網路連線與驅動器 IP。")
            return False
        except Exception as e:
            print(f"[例外] 寫入時發生錯誤: {e}")
            return False

    def read_object(self, index, sub_index, data_size=2, signed=False):
        # 讀取物件值
        # 透過 SLMP 讀取命令構造 request packet
        command = b'\x20\x40'
        subcommand = b'\x01\x00'
        index_bytes = struct.pack('<H', index)
        sub_index_bytes = struct.pack('B', sub_index)
        reserved = b'\x00'
        number_of_data = b'\x00\x00'
        
        request = command + subcommand + index_bytes + sub_index_bytes + reserved + number_of_data
        packet = self._build_header(request)
        
        print(f"[除錯] 發送: {packet.hex().upper()}")
        
        try:
            self.sock.sendto(packet, (self.ip, self.port))
            data, _ = self.sock.recvfrom(1024)
            print(f"[除錯] 接收: {data.hex().upper()}")

            # --- 解析回傳資料 ---
            # 回應結構: Subheader(2) + Network(1) + Station(1) + ModuleIO(2) + Multi(1) + DataLen(2) + EndCode(2) + Data...
            # 最小長度檢查，避免短封包解析失敗
            if len(data) < 11:
                print(f"[錯誤] 回應資料長度不足: {len(data)} bytes")
                return None

            try:
                end_code = struct.unpack('<H', data[9:11])[0]
            except struct.error as e:
                print(f"[錯誤] 無法解析 End Code: {e}")
                return None

            if end_code == 0:
                # 讀取指定長度的數值（支援 2 或 4 bytes）
                payload = data[11:]
                # 回應中通常包含 index/subindex/reserved/count，實際資料在後面
                if len(payload) >= 6 and payload[:2] == index_bytes:
                    payload = payload[6:]

                expected_len = data_size
                if len(payload) < expected_len:
                    print(f"[錯誤] 回應缺少資料欄位，長度: {len(payload)}，期待至少: {expected_len}")
                    return None

                raw_value = payload[:data_size]
                try:
                    if data_size == 1:
                        fmt = '<b' if signed else '<B'
                        value = struct.unpack(fmt, raw_value)[0]
                    elif data_size == 2:
                        fmt = '<h' if signed else '<H'
                        value = struct.unpack(fmt, raw_value)[0]
                    elif data_size == 4:
                        fmt = '<i' if signed else '<I'
                        value = struct.unpack(fmt, raw_value)[0]
                    elif data_size == 8:
                        fmt = '<q' if signed else '<Q'
                        value = struct.unpack(fmt, raw_value)[0]
                    else:
                        # 非標準長度，回傳 raw bytes
                        print(f"[資訊] 回傳 raw bytes: {raw_value.hex().upper()}")
                        return raw_value
                except struct.error as e:
                    print(f"[錯誤] 無法解析回傳值: {e}")
                    return None

                print(f"[成功] End Code: 0, 讀取值: {value} (Hex: {hex(value)})")
                return value
            else:
                print(f"[錯誤] End Code 為: {hex(end_code)}，請參考手冊錯誤碼表。")
                return None

        except socket.timeout:
            print("[錯誤] Timeout！請確認網路連線與驅動器 IP。")
            return None
        except Exception as e:
            print(f"[例外] 讀取時發生錯誤: {e}")
            return None

class SLMPApp:
    # GUI 介面管理類別
    def __init__(self, root):
        self.root = root
        self.root.title('士林電機 SDC-F CC-Link IEFB Tools')
        self.root.geometry('760x520')
        self.root.resizable(False, False)
        self.client = None

        self.ip_var = tk.StringVar(value='192.168.3.1')
        self.port_var = tk.StringVar(value='5010')
        self.index_var = tk.StringVar(value='6085')
        self.subindex_var = tk.StringVar(value='00')
        self.data_size_var = tk.StringVar(value='4')
        self.signed_var = tk.BooleanVar(value=False)
        self.write_value_hex_var = tk.BooleanVar(value=False)
        self.read_value_hex_var = tk.BooleanVar(value=False)
        self.auto_readback_var = tk.BooleanVar(value=True)
        self.value_var = tk.StringVar(value='200')
        self.log_path_var = tk.StringVar(value='slmp_writes.log')
        self.read_value_var = tk.StringVar(value='')

        self._build_ui()
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)

    def _build_ui(self):
        # 建立主要 UI 控制項
        outer = tk.Frame(self.root, padx=12, pady=12)
        outer.pack(fill=tk.BOTH, expand=True)

        top_frame = tk.Frame(outer)
        top_frame.pack(fill=tk.X, pady=(0, 10))

        left_panel = tk.LabelFrame(top_frame, text='連線設定', padx=10, pady=10)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        left_panel.grid_columnconfigure(1, weight=1)

        right_panel = tk.LabelFrame(top_frame, text='物件設定', padx=10, pady=10)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right_panel.grid_columnconfigure(1, weight=1)

        tk.Label(left_panel, text='IP 地址:').grid(row=0, column=0, sticky='e', pady=4)
        tk.Entry(left_panel, textvariable=self.ip_var, width=24).grid(row=0, column=1, sticky='we', pady=4, columnspan=2)
        tk.Label(left_panel, text='Port:').grid(row=1, column=0, sticky='e', pady=4)
        tk.Entry(left_panel, textvariable=self.port_var, width=12).grid(row=1, column=1, sticky='w', pady=4)

        tk.Label(left_panel, text='Log File:').grid(row=2, column=0, sticky='e', pady=4)
        tk.Entry(left_panel, textvariable=self.log_path_var, width=36).grid(row=2, column=1, sticky='we', pady=4)
        tk.Button(left_panel, text='Browse...', width=10, command=self._browse_log).grid(row=2, column=2, sticky='w', padx=(8, 0), pady=4)

        tk.Label(right_panel, text='Object Index (hex):').grid(row=0, column=0, sticky='e', pady=4)
        tk.Entry(right_panel, textvariable=self.index_var, width=22).grid(row=0, column=1, sticky='we', pady=4, columnspan=2)
        tk.Label(right_panel, text='Sub-index (hex):').grid(row=1, column=0, sticky='e', pady=4)
        tk.Entry(right_panel, textvariable=self.subindex_var, width=12).grid(row=1, column=1, sticky='w', pady=4)

        tk.Label(right_panel, text='Data Size:').grid(row=2, column=0, sticky='e', pady=4)
        tk.OptionMenu(right_panel, self.data_size_var, '1', '2', '4', '8').grid(row=2, column=1, sticky='w', pady=4)
        tk.Checkbutton(right_panel, text='Signed', variable=self.signed_var).grid(row=2, column=2, sticky='w', padx=(10, 0))

        tk.Label(right_panel, text='Write Value:').grid(row=3, column=0, sticky='e', pady=4)
        tk.Entry(right_panel, textvariable=self.value_var, width=22).grid(row=3, column=1, sticky='we', pady=4)
        tk.Checkbutton(right_panel, text='Write Hex', variable=self.write_value_hex_var).grid(row=3, column=2, sticky='w', padx=(10, 0))

        tk.Checkbutton(right_panel, text='Read Hex', variable=self.read_value_hex_var).grid(row=4, column=0, sticky='w', pady=4)
        tk.Checkbutton(right_panel, text='寫入後自動讀回', variable=self.auto_readback_var).grid(row=4, column=1, columnspan=2, sticky='w', pady=4)

        tk.Label(right_panel, text='最新讀取值:').grid(row=5, column=0, sticky='e', pady=4)
        tk.Entry(right_panel, textvariable=self.read_value_var, width=22, state='readonly').grid(row=5, column=1, sticky='we', pady=4)

        button_frame = tk.Frame(outer)
        button_frame.pack(fill=tk.X, pady=(0, 8))
        tk.Button(button_frame, text='讀取值', width=14, command=self.read_value).pack(side=tk.LEFT, padx=6)
        tk.Button(button_frame, text='寫入值', width=14, command=self.write_value).pack(side=tk.LEFT, padx=6)
        tk.Button(button_frame, text='清除輸出', width=14, command=self._clear_output).pack(side=tk.LEFT, padx=6)

        output_frame = tk.LabelFrame(outer, text='執行結果', padx=10, pady=10)
        output_frame.pack(fill=tk.BOTH, expand=True)
        output_frame.grid_rowconfigure(0, weight=1)
        output_frame.grid_columnconfigure(0, weight=1)

        self.output_text = tk.Text(output_frame, wrap='word', state='disabled')
        self.output_text.grid(row=0, column=0, sticky='nsew')
        scrollbar = tk.Scrollbar(output_frame, command=self.output_text.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.output_text.configure(yscrollcommand=scrollbar.set)

    def _append_output(self, message):
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, f'{message}\n')
        self.output_text.see(tk.END)
        self.output_text.configure(state='disabled')

    def _clear_output(self):
        self.output_text.configure(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.configure(state='disabled')

    def _browse_log(self):
        path = filedialog.asksaveasfilename(
            title='選擇 Log 檔案',
            defaultextension='.log',
            filetypes=[('Log Files', '*.log'), ('All Files', '*.*')]
        )
        if path:
            self.log_path_var.set(path)

    def _create_client(self):
        try:
            ip = self.ip_var.get().strip()
            port = int(self.port_var.get().strip())
            self.client = SLMPClient(ip, port)
            log_path = self.log_path_var.get().strip()
            if log_path:
                self.client.enable_write_log(log_path)
            return self.client
        except ValueError:
            messagebox.showerror('輸入錯誤', 'Port 必須為數字。')
            return None

    def _parse_int(self, text, name):
        try:
            return int(text.strip(), 0)
        except ValueError:
            messagebox.showerror('輸入錯誤', f'{name} 必須是十進位或 0x 十六進位數值。')
            return None

    def _parse_hex(self, text, name):
        try:
            value = text.strip().lower()
            if value.startswith('0x'):
                value = value[2:]
            return int(value, 16)
        except ValueError:
            messagebox.showerror('輸入錯誤', f'{name} 必須是 16 進位數值。')
            return None

    def read_value(self):
        client = self._create_client()
        if not client:
            return

        index = self._parse_hex(self.index_var.get(), 'Object Index')
        subindex = self._parse_hex(self.subindex_var.get(), 'Sub-index')
        data_size = self._parse_int(self.data_size_var.get(), 'Data Size')
        signed = self.signed_var.get()
        if index is None or subindex is None or data_size is None:
            client.close()
            return

        self._append_output('開始讀取...')
        try:
            result = client.read_object(index, subindex, data_size=data_size, signed=signed)
            if result is None:
                self._append_output('讀取失敗，請檢查訊息。')
                self.read_value_var.set('')
            else:
                display = f'0x{result:X}' if self.read_value_hex_var.get() else str(result)
                self._append_output(f'讀取成功: Object 0x{index:04X}[0x{subindex:02X}] = {display}')
                self.read_value_var.set(display)
        finally:
            client.close()

    def write_value(self):
        client = self._create_client()
        if not client:
            return

        index = self._parse_hex(self.index_var.get(), 'Object Index')
        subindex = self._parse_hex(self.subindex_var.get(), 'Sub-index')
        data_size = self._parse_int(self.data_size_var.get(), 'Data Size')
        signed = self.signed_var.get()
        try:
            value_text = self.value_var.get().strip()
            if self.write_value_hex_var.get():
                if value_text.lower().startswith('0x'):
                    value_text = value_text[2:]
                value = int(value_text, 16)
            else:
                value = int(value_text, 0)
        except ValueError:
            messagebox.showerror('輸入錯誤', 'Write Value 必須是整數或 16 進位數值。')
            client.close()
            return

        self._append_output('開始寫入...')
        try:
            success = client.write_object(index, subindex, value, data_size=data_size, signed=signed)
            self._append_output(f'寫入結果: {success}')
            if success and self.auto_readback_var.get():
                self._append_output('寫入成功，開始讀回...')
                result = client.read_object(index, subindex, data_size=data_size, signed=signed)
                if result is None:
                    self._append_output('讀回失敗，請檢查訊息。')
                    self.read_value_var.set('')
                else:
                    display = f'0x{result:X}' if self.read_value_hex_var.get() else str(result)
                    self._append_output(f'讀回結果: Object 0x{index:04X}[0x{subindex:02X}] = {display}')
                    self.read_value_var.set(display)
        finally:
            client.close()

    def on_close(self):
        if self.client:
            self.client.close()
        self.root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = SLMPApp(root)
    root.mainloop()