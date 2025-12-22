# data_exporter.py
# IDA Pro 9.0 数据导出插件 - 兼容版
# 使用 IDA 9.0 官方公开 API

import ida_kernwin
import ida_idaapi
import ida_bytes
import ida_lines
import struct
from typing import Optional, List, Tuple
import ida_ua  # 指令解码相关库
from ida_ua import insn_t  # 导入insn_t结构体

class DataExporterPlugin(ida_idaapi.plugin_t):
    """数据导出插件"""
    
    # flags = ida_idaapi.PLUGIN_PROC
    flags = ida_idaapi.PLUGIN_HIDE
    comment = "数据导出工具 - 导出指定地址范围的数据"
    help = "右键设置起始/结束地址，导出数据到Output窗口"
    wanted_name = "Data Exporter"
    wanted_hotkey = ""  # 仅保留插件主快捷键（显示菜单）
    
    def __init__(self):
        super().__init__()
        self.start_addr = ida_idaapi.BADADDR
        self.end_addr = ida_idaapi.BADADDR
        self.ui_hooks = None
        self._actions_registered = False
    
    def init(self):
        """初始化插件"""
        print(f"[Data Exporter] 插件已加载")
        
        # 仅当Action未注册时，执行注册逻辑
        if not self._actions_registered:
            self.register_actions()
            # 注册完成后，标记为已注册
            self._actions_registered = True
        
        # 仅当UI钩子未创建时，创建并挂载钩子
        if self.ui_hooks is None:
            self.ui_hooks = DataExporterContextMenu(self)
            self.ui_hooks.hook()
        
        return ida_idaapi.PLUGIN_OK
    
    def register_actions(self):
        """注册所有动作（取消导出功能快捷键）"""
        # 封装注册函数，增加校验（可选，便于调试）
        def reg_action(desc):
            if ida_kernwin.register_action(desc):
                print(f"[Data Exporter] 注册Action成功: {desc.name}")
            else:
                print(f"[Data Exporter] 注册Action失败: {desc.name}")
        
        # 设置起始地址
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:set_start",
            "设置起始地址",
            SetStartAddrAction(self),
            "Ctrl+Shift+S", 
            "将当前地址设置为起始地址",
            0
        )
        reg_action(action_desc)
        
        # 设置结束地址
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:set_end",
            "设置结束地址",
            SetEndAddrAction(self),
            "Ctrl+Shift+E", 
            "将当前地址设置为结束地址",
            0
        )
        reg_action(action_desc)
        
        # 导出数据 - 单字节（取消快捷键）
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:export_bytes",
            "导出为单字节格式",
            ExportBytesAction(self),
            None,
            "导出为单字节格式",
            0
        )
        reg_action(action_desc)
        
        # 导出数据 - 双字节（取消快捷键）
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:export_words",
            "导出为双字节格式",
            ExportWordsAction(self),
            None,
            "导出为双字节格式",
            0
        )
        reg_action(action_desc)
        
        # 导出数据 - 四字节（取消快捷键）
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:export_dwords",
            "导出为四字节格式",
            ExportDwordsAction(self),
            None,
            "导出为四字节格式",
            0
        )
        reg_action(action_desc)
        
        # 导出数据 - 十六进制字符串（取消快捷键）
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:export_hex",
            "导出为十六进制字符串",
            ExportHexAction(self),
            "Ctrl+Shift+X",
            "导出为十六进制字符串",
            0
        )
        reg_action(action_desc)

        # 导出指令后1字节
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:export_insn_last1",
            "导出指令后1字节",
            ExportInsnLastBytesAction(self),
            None,
            "导出每条指令机器码的最后1字节",
            0
        )
        reg_action(action_desc)

        # 导出指令后4字节
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:export_insn_last4",
            "导出指令后4字节",
            ExportInsnLast4BytesAction(self),
            None,
            "导出每条指令机器码的最后4字节（不足补0）",
            0
        )
        reg_action(action_desc)
        
        # 导出指令后8字节
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:export_insn_last8",
            "导出指令后8字节",
            ExportInsnLast8BytesAction(self),
            None,
            "导出每条指令机器码的最后8字节（不足补0）",
            0
        )
        reg_action(action_desc)
        
        # 显示信息
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:info",
            "显示当前设置",
            InfoAction(self),
            None,
            "显示当前设置的起始和结束地址",
            0
        )
        reg_action(action_desc)
        
        # 清除设置
        action_desc = ida_kernwin.action_desc_t(
            "data_exporter:clear",
            "清除地址设置",
            ClearAction(self),
            None,
            "清除已设置的起始和结束地址",
            0
        )
        reg_action(action_desc)
    
    def run(self, arg):
        print("[Data Exporter] 请通过右键菜单「Data Exporter」执行相关操作")
    
    def term(self):
        """终止插件"""
        return
    
    def set_start_addr(self, ctx=None):
        """设置起始地址"""
        ea = ida_kernwin.get_screen_ea()
        if ea == ida_idaapi.BADADDR:
            print("[Data Exporter] 错误: 当前地址无效！")
            return 0
        self.start_addr = ea
        print(f"[Data Exporter] 起始地址设置为: 0x{ea:08X}")
        return 1
    
    def set_end_addr(self, ctx=None):
        """设置结束地址"""
        ea = ida_kernwin.get_screen_ea()
        if ea == ida_idaapi.BADADDR:
            print("[Data Exporter] 错误: 当前地址无效！")
            return 0
        self.end_addr = ea
        print(f"[Data Exporter] 结束地址设置为: 0x{ea:08X}")
        return 1
    
    def show_addr_info(self):
        """显示当前设置的地址信息"""
        if self.start_addr == ida_idaapi.BADADDR:
            print("[Data Exporter] 起始地址: 未设置")
        else:
            print(f"[Data Exporter] 起始地址: 0x{self.start_addr:08X}")
            
        if self.end_addr == ida_idaapi.BADADDR:
            print("[Data Exporter] 结束地址: 未设置")
        else:
            print(f"[Data Exporter] 结束地址: 0x{self.end_addr:08X}")
            
        if self.start_addr != ida_idaapi.BADADDR and self.end_addr != ida_idaapi.BADADDR:
            size = abs(self.end_addr - self.start_addr) + 1
            print(f"[Data Exporter] 数据大小: {size} 字节")
        return 1
    
    def clear_addresses(self):
        """清除设置的地址"""
        self.start_addr = ida_idaapi.BADADDR
        self.end_addr = ida_idaapi.BADADDR
        print("[Data Exporter] 已清除地址设置")
        return 1
    
    def validate_address_range(self) -> Tuple[bool, int, int, int]:
        """验证地址范围并返回有效范围"""
        if self.start_addr == ida_idaapi.BADADDR or self.end_addr == ida_idaapi.BADADDR:
            print("[Data Exporter] 错误: 请先设置起始地址和结束地址")
            return False, 0, 0, 0
        
        start = min(self.start_addr, self.end_addr)
        end = max(self.start_addr, self.end_addr)
        size = end - start + 1
        
        if size <= 0:
            print("[Data Exporter] 错误: 无效的地址范围")
            return False, 0, 0, 0
            
        return True, start, end, size
    
    def export_as_bytes(self):
        """导出为单字节格式"""
        valid, start, end, size = self.validate_address_range()
        if not valid:
            return 1
        
        print(f"\n[Data Exporter] 单字节格式导出 (0x{start:08X} - 0x{end:08X}):")
        print("=" * 80)
        
        line_data = []
        for i in range(size):
            ea = start + i
            byte_val = ida_bytes.get_byte(ea)
            line_data.append(f"0x{byte_val:02X}")
            
            # 每16字节输出一行
            if len(line_data) == 16 or i == size - 1:
                addr = ea - len(line_data) + 1
                # print(f"0x{addr:08X}: {', '.join(line_data)}")
                print(f"{', '.join(line_data)},")
                line_data = []
        
        # print(f"{'-' * 80}")
        print(f"总计: {size} 字节")
        print("=" * 80)
        return 1
    
    def export_as_words(self):
        """导出为双字节（字）格式"""
        valid, start, end, size = self.validate_address_range()
        if not valid:
            return 1
        
        # 确保地址对齐到2字节边界
        if start % 2 != 0:
            print(f"[Data Exporter] 警告: 起始地址 0x{start:08X} 未对齐到字边界，已自动对齐")
            start = start + 1
        
        word_count = (end - start + 1) // 2
        if word_count <= 0:
            print("[Data Exporter] 错误: 地址范围太小，无法导出字数据")
            return 1
        
        print(f"\n[Data Exporter] 双字节格式导出 (0x{start:08X} - 0x{end:08X}):")
        print("=" * 80)
        
        line_data = []
        for i in range(word_count):
            ea = start + i * 2
            if ea + 1 > end:
                break
                
            # 读取两个字节并组合成字（小端序）
            byte1 = ida_bytes.get_byte(ea)
            byte2 = ida_bytes.get_byte(ea + 1)
            word_val = (byte2 << 8) | byte1
            line_data.append(f"0x{word_val:04X}")
            
            # 每8个字输出一行
            if len(line_data) == 8 or i == word_count - 1:
                addr = ea - len(line_data) * 2 + 2
                # print(f"0x{addr:08X}: {', '.join(line_data)}")
                print(f"{', '.join(line_data)},")
                line_data = []
        
        # print(f"{'-' * 80}")
        print(f"总计: {word_count} 个字 ({word_count * 2} 字节)")
        print("=" * 80)
        return 1
    
    def export_as_dwords(self):
        """导出为四字节（双字）格式"""
        valid, start, end, size = self.validate_address_range()
        if not valid:
            return 1
        
        # 确保地址对齐到4字节边界
        if start % 4 != 0:
            print(f"[Data Exporter] 警告: 起始地址 0x{start:08X} 未对齐到双字边界，已自动对齐")
            start = start + (4 - (start % 4))
        
        dword_count = (end - start + 1) // 4
        if dword_count <= 0:
            print("[Data Exporter] 错误: 地址范围太小，无法导出双字数据")
            return 1
        
        print(f"\n[Data Exporter] 四字节格式导出 (0x{start:08X} - 0x{end:08X}):")
        print("=" * 80)
        
        line_data = []
        for i in range(dword_count):
            ea = start + i * 4
            if ea + 3 > end:
                break
                
            # 读取四个字节并组合成双字（小端序）
            byte1 = ida_bytes.get_byte(ea)
            byte2 = ida_bytes.get_byte(ea + 1)
            byte3 = ida_bytes.get_byte(ea + 2)
            byte4 = ida_bytes.get_byte(ea + 3)
            dword_val = (byte4 << 24) | (byte3 << 16) | (byte2 << 8) | byte1
            line_data.append(f"0x{dword_val:08X}")
            
            # 每4个双字输出一行
            if len(line_data) == 4 or i == dword_count - 1:
                addr = ea - len(line_data) * 4 + 4
                # print(f"0x{addr:08X}: {', '.join(line_data)}")
                print(f"{', '.join(line_data)},")
                line_data = []
        
        # print(f"{'-' * 80}")
        print(f"总计: {dword_count} 个双字 ({dword_count * 4} 字节)")
        print("=" * 80)
        return 1
    
    def export_as_hex_string(self):
        """导出为十六进制字符串"""
        valid, start, end, size = self.validate_address_range()
        if not valid:
            return 1
        
        print(f"\n[Data Exporter] 十六进制字符串导出 (0x{start:08X} - 0x{end:08X})[{size} 字节]:")
        print("=" * 80)
        
        # 构建十六进制字符串
        hex_str = ""
        hex_str_none = ""
        hex_str_0x = ""
        for i in range(size):
            ea = start + i
            byte_val = ida_bytes.get_byte(ea)
            hex_str += f"{byte_val:02X}"
            hex_str_0x += f"0x{byte_val:02X}"
            hex_str_none += f"{byte_val:02X}"
            
            # 每32字节添加换行（优化可读性）
            if i != size - 1:
                hex_str += " "
                hex_str_0x += ","
        
        print("十六进制数据:")
        print(hex_str)
        print(hex_str_none)
        print(hex_str_0x)
        
        # 同时显示C/C++格式的数组
        print(f"\n{'-' * 80}")
        print("C/C++ 数组格式:")
        print(f"unsigned char data[{size}] = {{")
        
        line_data = []
        for i in range(size):
            ea = start + i
            byte_val = ida_bytes.get_byte(ea)
            line_data.append(f"0x{byte_val:02X}")
            
            # 每16字节一行
            if len(line_data) == 16 or i == size - 1:
                print(f"    {', '.join(line_data)}{',' if i != size - 1 else ''}")
                line_data = []
        
        print("};")
        # 同时显示python格式的数组
        print(f"\n{'-' * 80}")
        print("python 数组格式:")
        print(f"data = [")
        
        line_data = []
        for i in range(size):
            ea = start + i
            byte_val = ida_bytes.get_byte(ea)
            line_data.append(f"0x{byte_val:02X}")
            
            # 每16字节一行
            if len(line_data) == 16 or i == size - 1:
                print(f"    {', '.join(line_data)}{',' if i != size - 1 else ''}")
                line_data = []
        
        print("]")

        print("=" * 80)
        return 1
    
    def export_insn_last_4bytes(self):
        """导出每条指令机器码的最后4字节（不足补0）"""
        valid, start, end, _ = self.validate_address_range()
        if not valid:
            return 1
        
        print(f"\n[Data Exporter] 指令后4字节导出 (0x{start:08X} - 0x{end:08X}):")
        print("=" * 80)
        
        ea = start
        insn_count = 0
        line_data = []
        insn = insn_t()
        
        while ea <= end:
            # 传入insn对象和ea地址进行指令解码
            if not ida_ua.decode_insn(insn, ea):
                print(f"[Data Exporter] 警告: 地址 0x{ea:08X} 无法解码为指令，跳过")
                ea += 1
                continue
            
            # 通过insn.size获取指令长度
            insn_len = insn.size
            insn_bytes = [ida_bytes.get_byte(ea + i) for i in range(insn_len)]
            
            # 取最后4字节，不足则前面补0（凑够4字节）
            last_4bytes = [0] * 4
            start_idx = max(0, len(insn_bytes) - 4)
            last_4bytes[4 - (len(insn_bytes) - start_idx):] = insn_bytes[start_idx:]
            
            byte_str_list = [f"0x{b:02X}" for b in last_4bytes]
            print(f"{', '.join(byte_str_list)},")
            insn_count += 1
            
            # 移动到下一条指令
            ea += insn_len
        
        # print(f"{'-' * 80}")
        print(f"总计: {insn_count} 条指令")
        print("=" * 80)
        return 1

    def export_insn_last_bytes(self):
        """导出每条指令机器码的最后1字节"""
        valid, start, end, _ = self.validate_address_range()
        if not valid:
            return 1
        
        print(f"\n[Data Exporter] 指令后1字节导出 (0x{start:08X} - 0x{end:08X}):")
        print("=" * 80)
        
        ea = start
        insn_count = 0
        line_data = []
        insn = insn_t()
        byte_str_list = []
        while ea <= end:
            # 传入insn对象和ea地址进行指令解码
            if not ida_ua.decode_insn(insn, ea):
                print(f"[Data Exporter] 警告: 地址 0x{ea:08X} 无法解码为指令，跳过")
                ea += 1
                continue
            
            # 通过insn.size获取指令长度
            insn_len = insn.size
            insn_bytes = [ida_bytes.get_byte(ea + i) for i in range(insn_len)]
            
            # 取最后1字节
            last_bytes = 0
            start_idx = max(0, len(insn_bytes) - 1)
            last_bytes = insn_bytes[start_idx:][0]
            
            byte_str_list.append(f"0x{last_bytes:02X}")
            insn_count += 1
            
            # 移动到下一条指令
            ea += insn_len
        
        print(f"{', '.join(byte_str_list)}",end='')
        # print(f"{'-' * 80}")
        print(f"\n总计: {insn_count} 条指令")
        print("=" * 80)
        return 1

    # 导出指令后8字节
    def export_insn_last_8bytes(self):
        """导出每条指令机器码的最后8字节（不足补0）"""
        valid, start, end, _ = self.validate_address_range()
        if not valid:
            return 1
        
        print(f"\n[Data Exporter] 指令后8字节导出 (0x{start:08X} - 0x{end:08X}):")
        print("=" * 80)
        
        ea = start
        insn_count = 0
        line_data = []
        insn = insn_t()  # 创建insn_t对象
        
        while ea <= end:
            # 传入insn对象和ea地址进行指令解码
            if not ida_ua.decode_insn(insn, ea):
                print(f"[Data Exporter] 警告: 地址 0x{ea:08X} 无法解码为指令，跳过")
                ea += 1
                continue
            
            # 通过insn.size获取指令长度
            insn_len = insn.size
            insn_bytes = [ida_bytes.get_byte(ea + i) for i in range(insn_len)]
            
            # 取最后8字节，不足则前面补0（凑够8字节）
            last_8bytes = [0] * 8
            start_idx = max(0, len(insn_bytes) - 8)
            last_8bytes[8 - (len(insn_bytes) - start_idx):] = insn_bytes[start_idx:]
            
            byte_str_list = [f"0x{b:02X}" for b in last_8bytes]
            print(f"{', '.join(byte_str_list)},")
            insn_count += 1
            
            # 移动到下一条指令
            ea += insn_len
        
        print(f"总计: {insn_count} 条指令")
        print("=" * 80)
        return 1

# 右键菜单处理器
class DataExporterContextMenu(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def finish_populating_widget_popup(self, widget, popup):
        """在右键菜单中添加选项（按需显示导出功能组）"""
        # 统一子菜单路径：Data Exporter/
        submenu = "Data Exporter/"
        
        # 1. 地址设置组（始终显示，无论地址是否设置）
        ida_kernwin.attach_action_to_popup(
            widget, popup, "data_exporter:set_start", submenu, ida_kernwin.SETMENU_APP
        )
        ida_kernwin.attach_action_to_popup(
            widget, popup, "data_exporter:set_end", submenu, ida_kernwin.SETMENU_APP
        )
        
        # 2. 判断：仅当起始地址和结束地址均有效时，才显示导出功能组
        addr_is_valid = (self.plugin.start_addr != ida_idaapi.BADADDR) and (self.plugin.end_addr != ida_idaapi.BADADDR)
        if addr_is_valid:
            # 导出功能组前的分隔符
            ida_kernwin.attach_action_to_popup(
                widget, popup, "-", submenu, ida_kernwin.SETMENU_APP
            )
            
            # 3. 导出功能组（仅地址有效时显示）
            ida_kernwin.attach_action_to_popup(
                widget, popup, "data_exporter:export_bytes", submenu, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_popup(
                widget, popup, "data_exporter:export_words", submenu, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_popup(
                widget, popup, "data_exporter:export_dwords", submenu, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_popup(
                widget, popup, "data_exporter:export_hex", submenu, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_popup(
                widget, popup, "data_exporter:export_insn_last1", submenu, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_popup(
                widget, popup, "data_exporter:export_insn_last4", submenu, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_popup(
                widget, popup, "data_exporter:export_insn_last8", submenu, ida_kernwin.SETMENU_APP
            )
        
        # 4. 辅助功能组前的分隔符（始终显示，与导出功能组隔离）
        ida_kernwin.attach_action_to_popup(
            widget, popup, "-", submenu, ida_kernwin.SETMENU_APP
        )
        
        # 5. 辅助功能组（始终显示，无论地址是否设置）
        ida_kernwin.attach_action_to_popup(
            widget, popup, "data_exporter:info", submenu, ida_kernwin.SETMENU_APP
        )
        ida_kernwin.attach_action_to_popup(
            widget, popup, "data_exporter:clear", submenu, ida_kernwin.SETMENU_APP
        )

# 动作处理类
class SetStartAddrAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.set_start_addr(ctx)
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class SetEndAddrAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.set_end_addr(ctx)
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExportBytesAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.export_as_bytes()
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExportWordsAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.export_as_words()
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExportDwordsAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.export_as_dwords()
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExportHexAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.export_as_hex_string()
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExportInsnLastBytesAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.export_insn_last_bytes()
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExportInsnLast4BytesAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.export_insn_last_4bytes()
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExportInsnLast8BytesAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.export_insn_last_8bytes()
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class InfoAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.show_addr_info()
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ClearAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
    
    def activate(self, ctx):
        return self.plugin.clear_addresses()
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# 插件入口
def PLUGIN_ENTRY():
    """插件入口函数，IDA会自动调用"""
    return DataExporterPlugin()