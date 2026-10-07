#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""task17（差分密码分析 / 简化 SPN）判分脚本。

规则：
1. 交付 solve.py，运行后调用 ./oracle 恢复 32 位主密钥，密钥打到标准输出，
   并在本目录生成 report.md。
2. 判分脚本先冒烟测试 oracle，再跑 `python3 solve.py`（限时 10 分钟），
   从输出里提取恢复的密钥，跟隐藏主密钥 0x47ce57e9 逐半字节比对。
3. 检查 report.md 存在且包含差分分布表、差分特征及概率、候选密钥命中统计，
   缺一样判不过，证明不是穷举出来的。

用法：
  python3 grade.py
  python3 grade.py --solver path/to/solve.py
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.path.join(HERE, "oracle")
EXPECTED_KEY = 0x47CE57E9
EXPECTED_HEX = "%08x" % EXPECTED_KEY

# oracle 冒烟测试向量：明文 0x0000 -> 密文 0x92a6
SMOKE_PT = "0000"
SMOKE_CT = "92a6"

TIMEOUT = 600  # 10 分钟


def oracle_smoke():
    if not os.path.exists(ORACLE):
        return False, "找不到 oracle（%s）" % ORACLE
    r = subprocess.run([ORACLE], input=SMOKE_PT + "\n",
                       capture_output=True, text=True, cwd=HERE)
    got = r.stdout.strip().split()
    if r.returncode != 0 or not got:
        return False, "oracle 运行失败：%s" % r.stderr[-200:]
    if got[0] != SMOKE_CT:
        return False, "oracle 自检不一致：明文 %s 期望 %s 得到 %s" % (SMOKE_PT, SMOKE_CT, got[0])
    return True, ""


def run_solver(solver):
    if not os.path.exists(solver):
        return None, "找不到 solve.py（%s）" % solver, "", 0
    try:
        r = subprocess.run([sys.executable, solver], cwd=HERE,
                           capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, "solve.py 超过 %d 秒未完成" % TIMEOUT, "", TIMEOUT
    return r.returncode, r.stderr, r.stdout, r.returncode


def extract_key(stdout):
    """从标准输出里找 8 个十六进制字符的密钥候选。"""
    text = stdout
    # 优先看带 key 的行
    for line in text.splitlines():
        if "key" in line.lower():
            m = re.search(r"(?:0x)?([0-9a-fA-F]{8})", line)
            if m:
                return m.group(1).lower()
    # 兜底：全输出里最后出现的 8 个十六进制字符
    cands = re.findall(r"\b[0-9a-fA-F]{8}\b", text)
    if cands:
        return cands[-1].lower()
    return None


def check_report():
    path = os.path.join(HERE, "report.md")
    if not os.path.exists(path):
        return False, "缺少 report.md"
    try:
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
    except Exception as e:
        return False, "report.md 读取失败：%s" % e
    if len(content) < 500:
        return False, "report.md 内容过短，疑似没有认真写差分分析"
    low = content.lower()
    has_ddt = ("ddt" in low) or ("差分分布" in content)
    has_char = ("特征" in content) or ("characteristic" in low) or ("differential" in low)
    has_hits = ("命中" in content) or ("计数" in content) or ("hit" in low) or ("count" in low)
    missing = []
    if not has_ddt:
        missing.append("差分分布表")
    if not has_char:
        missing.append("差分特征及概率")
    if not has_hits:
        missing.append("候选密钥命中统计")
    if missing:
        return False, "report.md 缺：%s" % "、".join(missing)
    return True, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--solver", default=os.path.join(HERE, "solve.py"))
    args = ap.parse_args()

    print("=" * 60)
    print("判分开始")

    ok, msg = oracle_smoke()
    if not ok:
        print("[FAIL] " + msg)
        print("=" * 60)
        print("总结论：FAIL")
        sys.exit(1)
    print("[OK] oracle 冒烟测试通过（明文 %s -> 密文 %s）" % (SMOKE_PT, SMOKE_CT))

    rc, err, out, _ = run_solver(args.solver)
    if rc is None:
        print("[FAIL] " + err)
        print("=" * 60)
        print("总结论：FAIL")
        sys.exit(1)
    if rc != 0:
        print("[FAIL] solve.py 退出码非 0：%s" % err[-300:])
        print("=" * 60)
        print("总结论：FAIL")
        sys.exit(1)

    key = extract_key(out)
    if key is None:
        print("[FAIL] 从 solve.py 输出里没找到 8 位十六进制密钥")
        print("stdout 末尾：%r" % out[-300:])
        print("=" * 60)
        print("总结论：FAIL")
        sys.exit(1)

    if key == EXPECTED_HEX:
        print("[OK] 恢复密钥 0x%s 与隐藏主密钥一致" % key)
    else:
        print("[FAIL] 恢复密钥 0x%s，期望 0x%s" % (key, EXPECTED_HEX))
        print("=" * 60)
        print("总结论：FAIL")
        sys.exit(1)

    rok, rmsg = check_report()
    if not rok:
        print("[FAIL] " + rmsg)
        print("=" * 60)
        print("总结论：FAIL")
        sys.exit(1)
    print("[OK] report.md 包含差分分布表、差分特征及概率、候选密钥命中统计")

    print("=" * 60)
    print("总结论：PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
