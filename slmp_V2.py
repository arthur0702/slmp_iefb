import socket
import struct
import os
from datetime import datetime

class SLMPClient:
    def __init__(self, ip, port=5010, module_io=b'\xFF\x03', timeout=3.0):
        self.ip = ip
        self.port = port
        self.module_io = module_io
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        # logging file for write operations (optional)
        self.log_file = None
        print(f"[系統] 目標 IP: {self.ip}:{self.port}")

    def enable_write_log(self, file_path: str):
        """Enable write logging to the given file path."""
        self.log_file = file_path

    def _log_write(self, index, sub_index, current_value, new_value, success, end_code, data_size, signed):
        if not self.log_file:
            return
        try:
            need_header = not os.path.exists(self.log_file) or os.path.getsize(self.log_file) == 0
            with open(self.log_file, 'a', encoding='utf-8') as f:
                if need_header:
                    f.write('timestamp,device_ip,index,subindex,data_size,signed,current_value,new_value,success,end_code\n')
                ts = datetime.now().isoformat()
                line = (
                    f"{ts},{self.ip},0x{index:04X},0x{sub_index:02X},{data_size},{int(bool(signed))},"
                    f"{current_value},{new_value},{int(bool(success))},0x{end_code:04X}\n"
                )
                f.write(line)
        except Exception as e:
            print(f"[警告] 無法寫入 log: {e}")

    def _build_header(self, request_data):
        # 建立 SLMP 標頭
        subheader = b'\x50\x00'
        network_no = b'\x00'
        station_no = b'\xFF'
        module_io = self.module_io
        multidrop_no = b'\x00'
        timer = b'\x0A\x00'
        # Data length 應包含後續的 Timer 與實際的 request data
        data_len = struct.pack('<H', len(timer) + len(request_data))

        return subheader + network_no + station_no + module_io + multidrop_no + data_len + timer + request_data

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def write_object(self, index, sub_index, value, data_size=4, signed=False, write_command=b'\x20\x40', subcommand=b'\x02\x00'):
        """Write a value to an object/register.

        Parameters:
        - index: 16-bit object index (e.g., 0x6085)
        - sub_index: 8-bit sub-index
        - value: integer value to write
        - data_size: bytes (2 or 4; UDINT uses 4)
        - signed: whether to treat value as signed
        - write_command: two-byte command for write (little-endian bytes)
        - subcommand: two-byte subcommand
        """
        command = write_command
        subcommand = subcommand
        index_bytes = struct.pack('<H', index)
        sub_index_bytes = struct.pack('B', sub_index)
        reserved = b'\x00'
        # 設定寫入資料長度（以 byte 為單位），UDINT 為 4
        number_of_data = struct.pack('<H', data_size)

        # read current value (best-effort) for logging
        current_value = None
        try:
            current_value = self.read_object(index, sub_index, data_size=data_size, signed=signed)
        except Exception:
            current_value = None

        # pack value according to size and sign
        try:
            if data_size == 2:
                fmt = '<h' if signed else '<H'
                data_bytes = struct.pack(fmt, int(value))
            elif data_size == 4:
                fmt = '<i' if signed else '<I'
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
        except socket.timeout:
            print("[錯誤] Timeout！請確認網路連線與驅動器 IP。")
            return False
        except Exception as e:
            print(f"[例外] 寫入時發生錯誤: {e}")
            return False

    def read_object(self, index, sub_index, data_size=2, signed=False):
        # 組合請求封包
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
            # 最小長度檢查
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
                    if data_size == 2:
                        fmt = '<h' if signed else '<H'
                        value = struct.unpack(fmt, raw_value)[0]
                    elif data_size == 4:
                        fmt = '<i' if signed else '<I'
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

# --- 執行測試 ---
if __name__ == '__main__':
    client = SLMPClient("192.168.3.1")
    # 啟用寫入日誌
    client.enable_write_log('slmp_writes.log')
    # 讀取 6085h 的範例
    try:
        val = client.read_object(0x6085, 0x00)
        # 寫入測試範例：UDINT 寫入值 200 到 0x6085 subindex 0x00
        success = client.write_object(0x6085, 0x00, 200, data_size=4, signed=False)
        print(f"[測試] 寫入結果: {success}")
        # 讀回確認（選擇性）
        val_after = client.read_object(0x6085, 0x00, data_size=4, signed=False)
        print(f"[測試] 寫回讀值: {val_after}")
    finally:
        client.close()