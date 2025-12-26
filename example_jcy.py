import logging
import posixpath
import sys
import os
from unicorn import *
from unicorn.arm64_const import *

from androidemu.const import emu_const
from androidemu.emulator import Emulator
from androidemu.java.classes.string import String
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
import androidemu.utils.debug_utils
from androidemu.utils.chain_log import ChainLogger

import capstone
import traceback

g_cfd = ChainLogger(sys.stdout, "./ins-jni.txt")
# Add debugging.
def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        if (not emu.memory.check_addr(address, UC_PROT_EXEC)):
            logger.error("addr 0x%08X out of range"%(address,))
            sys.exit(-1)
        offset = address - 0xcbbcb000
        # print(f'{hex(offset)}')
        if (offset == 0x309A68):
            logger.debug("hook_code: 0x%08X"%(address,))
            androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd)
            #androidemu.utils.debug_utils.dump_stack(emu, g_cfd)
            androidemu.utils.debug_utils.dump_registers(emu, g_cfd)

        #androidemu.utils.debug_utils.dump_registers(mu, sys.stdout)
        # global lib_module
        # if address >= lib_module.base  and address < lib_module.base + lib_module.size:
        #     androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd)
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)
    #
#

def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    
    if (address == 0xCBC80640):
        logger.debug("read mutex")
        data = uc.mem_read(address, size)
        v = int.from_bytes(data, byteorder='little', signed=False)
        logger.debug(">>> Memory READ at 0x%08X, data size = %u,  data value = 0x%08X, pc: 0x%08X," % (address, size, v, pc))
    #
#

def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    if (address == 0xCBC80640):
        logger.debug("write mutex")
        logger.debug(">>> Memory WRITE at 0x%08X, data size = %u, data value = 0x%08X, pc: 0x%08X" % (address, size, value, pc))
    #
#

class MainActivity(metaclass=JavaClassDef, jvm_name='local/myapp/testnativeapp/MainActivity'):

    def __init__(self):
        pass

    @java_method_def(name='stringFromJNI', signature='()Ljava/lang/String;', native=True)
    def string_from_jni(self, mu):
        pass

    def test(self):
        pass

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)


def print_callstack(emu,lib_module_base=0, max_depth=32):
    """打印基于帧指针 (FP/x29) 的调用堆栈。
    通过读取寄存器 PC/FP/LR，然后遍历帧链：在每个 FP 地址读取 16 字节，
    前 8 字节为上一个 FP，后 8 字节为保存的 LR（返回地址）。
    """
    mu = emu.mu
    log = logging.getLogger(__name__)
    try:
        pc = mu.reg_read(UC_ARM64_REG_PC)
        fp = mu.reg_read(UC_ARM64_REG_FP)  # x29
        lr = mu.reg_read(UC_ARM64_REG_LR)  # x30
    except Exception:
        log.exception("无法读取寄存器以生成调用堆栈")
        return

    log.info("Callstack (PC=0x%016X, FP=0x%016X, LR=0x%016X):" % (pc, fp, lr))

    # 首条为当前 PC 和 LR
    try:
        log.info("  [0] PC : 0x%016X" % (pc-lib_module_base))
        log.info("  [1] LR : 0x%016X" % (lr-lib_module_base))
    except Exception:
        pass

    depth = 0
    addr = fp
    # 遍历帧链
    while addr and depth < max_depth:
        try:
            data = mu.mem_read(addr, 16)
            prev_fp = int.from_bytes(data[0:8], byteorder='little', signed=False)
            saved_lr = int.from_bytes(data[8:16], byteorder='little', signed=False)
            log.info("  [%2d] FP : 0x%016X" % (depth + 2, addr-lib_module_base))
        except Exception:
            log.debug("无法从内存读取 FP 链条: 0x%016X" % addr)
            break

        # 如果 saved_lr 为 0 则停止
        if saved_lr == 0:
            break

        log.info("  [%2d] LR@FP(0x%016X) = 0x%016X" % (depth + 2, addr-lib_module_base, saved_lr-lib_module_base))
        addr = prev_fp
        depth += 1

    log.info("Callstack unwind finished, depth=%d" % (depth + 2))

# Initialize emulator
emulator = Emulator(
    arch=emu_const.ARCH_ARM64,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Load all libraries.
lib_module = emulator.load_library(r"D:\crack\jiongciyuan\最新so\libcore.so")

with open('libcore.bin','wb') as f:
    data =emulator.mu.mem_read(lib_module.base,lib_module.size)
    f.seek(0)
    f.write(data)

#androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

# Show loaded modules.
logger.info("Loaded modules:")

# Register Java class.
# emulator.java_classloader.add_class(MainActivity)
emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)

emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    arg1="8Z6U5XgDhiCax7WkwvG35Hutqjt37uV0ESmREsyp3ryPg5oYPfeTZSzu0OEHENK2RHDLk5I9JyYSDL+unH9vTSsTbOt99JkzoN7WXQtMhT8NIfBnLBslMru0AG4v04AP3XJfjCLlJrr33D+FXzNNn2bwa5rH37TrIBYA08wz/LPXRAcixYb6km780shST+glI1AUlldt7tw8zKEhFqP4ULrHvV+ZWYB8k+s6lK8QGCuHbG8vQc7M7Q6CSC/U0cwKKOFQlzLtT1UQW2YqIyqH5jGsQuPnvqdMQz+Al+CV2oRsDqEyck9Y3HGWde5oU44BI75SPZojobN+GWQR7x2jObEknCQjRUJlnknp3w6DJrtNfhxjWU8XnaiU7ufO8zQqPo/wfnwqSfWfNI0Uib/Z4VfCWgz867pl7SUi0gkYx88wFXsq2N0iYtRncLR3/gXkWvv/GIWkBjhk2iGYgeskIEInfn7uukH3vRCQ9v5nT6C+UDxtnIm6deoMzDeHCfyHwjV55aGRSISZv7giIwlA/wqBvgSzr5KbpTL67dzURx93jQPAcokMcK6C4rJ65pUp".encode('utf-8')
    # 映射一个连续的大内存块来覆盖所有需要的地址
    emulator.mu.mem_map(0x80000000, 0x4000000, UC_PROT_ALL)
    emulator.mu.mem_write(0x80000000, arg1)
    lib_module.symbol_lookup["__memset_chk"]

    emulator.call_symbol(lib_module, 'call', 0x80000000)

    # Do native stuff.
    # main_activity = MainActivity()
    # logger.info("Response from JNI call: %s" % main_activity.string_from_jni(emulator))

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

except UcError as e:
    address = emulator.mu.reg_read(UC_ARM64_REG_PC)
    print("Exit at ",hex(address-lib_module.base))
    androidemu.utils.debug_utils.dump_code(emulator, address, 4, g_cfd)
    androidemu.utils.debug_utils.dump_registers(emulator, g_cfd)

    # print unicorn traceback

    try:
        print_callstack(emulator,lib_module.base)
    except Exception:
        logger.exception("打印调用堆栈时出错")

        raise
    finally:
        logger.exception("Unicorn error: %s" % str(e))

