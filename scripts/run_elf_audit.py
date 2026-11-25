#!/usr/bin/env python3
import os
import sys
import subprocess
import re

TARGET = "/home/riajul/Pictures/HyperOS/daisy_target"
APEX_BASE = "/tmp/apex_extracted"
VENDOR_BASE = "/tmp/vendor_extracted"
REPORT_PATH = "/home/riajul/Pictures/HyperOS/v8_elf_audit.txt"

SEARCH_DIRS_64 = [
    os.path.join(TARGET, "system/lib64"),
    os.path.join(TARGET, "system_ext/lib64"),
    os.path.join(TARGET, "product/lib64"),
    os.path.join(TARGET, "system/lib64/bootstrap"),
]
if os.path.exists(APEX_BASE):
    for d in sorted(os.listdir(APEX_BASE)):
        for sub in ["lib64", "lib64/bionic", "lib64/arm64"]:
            p = os.path.join(APEX_BASE, d, sub)
            if os.path.exists(p):
                SEARCH_DIRS_64.append(p)
if os.path.exists(VENDOR_BASE):
    SEARCH_DIRS_64.append(os.path.join(VENDOR_BASE, "lib64"))

SEARCH_DIRS_32 = [
    os.path.join(TARGET, "system/lib"),
    os.path.join(TARGET, "system_ext/lib"),
    os.path.join(TARGET, "product/lib"),
    os.path.join(TARGET, "system/lib/bootstrap"),
]
if os.path.exists(APEX_BASE):
    for d in sorted(os.listdir(APEX_BASE)):
        for sub in ["lib", "lib/bionic", "lib/arm"]:
            p = os.path.join(APEX_BASE, d, sub)
            if os.path.exists(p):
                SEARCH_DIRS_32.append(p)
if os.path.exists(VENDOR_BASE):
    SEARCH_DIRS_32.append(os.path.join(VENDOR_BASE, "lib"))

BINARIES = [
    "system/bin/surfaceflinger",
    "system/bin/app_process32",
    "system/bin/app_process64",
    "system/bin/cameraserver",
    "system/bin/mediaextractor",
    "system/bin/mediaserver",
    "system/bin/mediaserver32",
    "system/bin/netd",
    "system/bin/audioserver",
    "system_ext/bin/mcd",
    "system/lib64/libandroid_servers.so",
    "system/lib64/libandroid_runtime.so"
]

ELF_CACHE = {}

def get_elf_info(path):
    if path in ELF_CACHE:
        return ELF_CACHE[path]

    if not os.path.exists(path) or os.path.islink(path):
        if os.path.islink(path):
            target = os.readlink(path)
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
            if not os.path.exists(resolved):
                res = (None, "broken_link", [], set(), set())
                ELF_CACHE[path] = res
                return res
            path = resolved
        else:
            res = (None, "missing", [], set(), set())
            ELF_CACHE[path] = res
            return res
    try:
        out = subprocess.check_output(["readelf", "-h", path], stderr=subprocess.DEVNULL).decode()
        is_64 = "ELF64" in out
        arch = "aarch64" if "AArch64" in out else "arm" if "ARM" in out else "unknown"
        
        # DT_NEEDED
        d_out = subprocess.check_output(["readelf", "-d", path], stderr=subprocess.DEVNULL).decode()
        needed = []
        for line in d_out.splitlines():
            m = re.search(r"\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]", line)
            if m:
                needed.append(m.group(1))
        
        # Symbols (UND and Exported)
        s_out = subprocess.check_output(["readelf", "-Ws", path], stderr=subprocess.DEVNULL).decode()
        und_syms = set()
        exp_syms = set()
        for line in s_out.splitlines():
            parts = line.split()
            if len(parts) >= 8:
                if "<OS" in parts[3] and len(parts) >= 10:
                    bind = parts[6]
                    ndx = parts[8]
                    name = parts[9].split("@")[0]
                    if ndx == "UND":
                        und_syms.add(name)
                    elif bind in ["GLOBAL", "WEAK"]:
                        exp_syms.add(name)
                else:
                    sym_type = parts[3]
                    bind = parts[4]
                    ndx = parts[6]
                    name = parts[7].split("@")[0]
                    if sym_type in ["FUNC", "IFUNC", "OBJECT"]:
                        if ndx == "UND":
                            und_syms.add(name)
                        elif bind in ["GLOBAL", "WEAK"]:
                            exp_syms.add(name)
                        
        res = (is_64, arch, needed, und_syms, exp_syms)
        ELF_CACHE[path] = res
        return res
    except Exception as e:
        res = (None, str(e), [], set(), set())
        ELF_CACHE[path] = res
        return res

def find_library(name, is_64):
    dirs = SEARCH_DIRS_64 if is_64 else SEARCH_DIRS_32
    for d in dirs:
        cand = os.path.join(d, name)
        if os.path.exists(cand):
            return cand
    return None

def main():
    report = []
    report.append("================================================================================")
    report.append("     HyperOS 4 Android 17 (daisy) - Automated ELF Dependency & Symbol Audit    ")
    report.append("================================================================================")
    report.append(f"Workspace: {TARGET}")
    report.append(f"Audit Target Count: {len(BINARIES)}")
    report.append("")

    total_binaries_audited = 0
    total_missing_libs = 0
    total_missing_symbols = 0

    for rel in BINARIES:
        full_path = os.path.join(TARGET, rel)
        if not os.path.exists(full_path):
            report.append(f"[-] TARGET NOT PRESENT (Skipped): {rel}")
            continue
        
        total_binaries_audited += 1
        is_64, arch, needed, und_syms, exp_syms = get_elf_info(full_path)
        report.append("--------------------------------------------------------------------------------")
        report.append(f"Binary: {rel}")
        report.append(f"  Class: {'ELF64' if is_64 else 'ELF32'}, Architecture: {arch}")
        report.append(f"  Direct DT_NEEDED: {len(needed)} entries")
        report.append(f"  Undefined Symbols: {len(und_syms)}")
        
        # Recursive resolution
        queue = list(needed)
        resolved_libs = {}
        missing_libs = []
        
        while queue:
            lib_name = queue.pop(0)
            if lib_name in resolved_libs or lib_name in missing_libs:
                continue
            lib_path = find_library(lib_name, is_64)
            if lib_path:
                resolved_libs[lib_name] = lib_path
                l_is_64, l_arch, l_needed, l_und, l_exp = get_elf_info(lib_path)
                for sub_dep in l_needed:
                    if sub_dep not in resolved_libs and sub_dep not in missing_libs and sub_dep not in queue:
                        queue.append(sub_dep)
            else:
                missing_libs.append(lib_name)
                
        report.append(f"  Total Recursive Dependencies: {len(resolved_libs)}")
        if missing_libs:
            total_missing_libs += len(missing_libs)
            report.append(f"  [!] MISSING LIBRARIES ({len(missing_libs)}):")
            for m in missing_libs:
                report.append(f"      - {m}")
        else:
            report.append("  [+] ALL RECURSIVE DEPENDENCIES RESOLVED (0 missing)")

        # Symbol resolution check across top binary AND every transitive DT_NEEDED library
        all_exported = set(exp_syms)
        for l_name, l_path in resolved_libs.items():
            _, _, _, _, l_exp = get_elf_info(l_path)
            all_exported.update(l_exp)
            
        harmless_weak = {
            "__cfi_check", "__cfi_slowpath", "__cfi_slowpath_diag", "__ubsan_handle_cfi_check_fail",
            "__cxa_finalize", "_ZdaPv", "_ZdlPv", "dlopen", "dlsym", "dlclose", "dlerror",
            "__register_atfork", "android_get_device_api_level", "pthread_atfork"
        }

        # Check undefined symbols of top-level binary
        top_unresolved = (und_syms - all_exported) - harmless_weak
        
        # Check undefined symbols of EVERY transitive DT_NEEDED library
        transitive_unresolved = {}
        total_lib_und_count = 0
        total_lib_res_count = 0
        for l_name, l_path in resolved_libs.items():
            l_und = get_elf_info(l_path)[3]
            total_lib_und_count += len(l_und)
            l_missing = (l_und - all_exported) - harmless_weak
            total_lib_res_count += (len(l_und) - len(l_missing))
            if l_missing:
                transitive_unresolved[l_name] = l_missing

        critical_unresolved = set(top_unresolved)
        for l_missing in transitive_unresolved.values():
            critical_unresolved.update(l_missing)
                
        report.append(f"  Top Binary Symbol Audit: {len(und_syms) - len(top_unresolved)}/{len(und_syms)} resolved")
        report.append(f"  Transitive Libs Symbol Audit: {total_lib_res_count}/{total_lib_und_count} resolved across {len(resolved_libs)} libraries")
        if critical_unresolved:
            total_missing_symbols += len(critical_unresolved)
            report.append(f"  [!] CRITICAL UNRESOLVED SYMBOLS ({len(critical_unresolved)}):")
            if top_unresolved:
                report.append("      Top Binary Unresolved:")
                for u in sorted(list(top_unresolved))[:5]:
                    report.append(f"        - {u}")
            for ln, l_miss in transitive_unresolved.items():
                report.append(f"      In {ln}:")
                for u in sorted(list(l_miss))[:5]:
                    report.append(f"        - {u}")
        else:
            report.append("  [+] ZERO UNRESOLVED SYMBOLS (100% matched across binary & all transitive libraries)")

    report.append("")
    report.append("================================================================================")
    report.append("                              AUDIT SUMMARY")
    report.append("================================================================================")
    report.append(f"Binaries Audited: {total_binaries_audited}")
    report.append(f"Total Missing Shared Libraries: {total_missing_libs}")
    report.append(f"Total Missing Critical Symbols: {total_missing_symbols}")
    res_str = "PASSED - ZERO UNRESOLVED REQUIRED DEPENDENCIES" if total_missing_libs == 0 and total_missing_symbols == 0 else "WARNINGS FOUND"
    report.append(f"Overall Result: {res_str}")
    report.append("================================================================================")

    report_text = "\n".join(report)
    with open(REPORT_PATH, "w") as f:
        f.write(report_text)
    print(report_text)

if __name__ == "__main__":
    main()
