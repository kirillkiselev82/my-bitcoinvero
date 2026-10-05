from __future__ import annotations
import os,sys
ANSI={"BLUE":"\033[94m","GREEN":"\033[92m","YELLOW":"\033[93m","RED":"\033[91m","RESET":"\033[0m"}
def enabled():
    mode=os.environ.get('UTXO_COLOR','auto').lower()
    return False if mode=='never' else True if mode=='always' else bool(sys.stdout.isatty())
def paint(s,c): return f"{ANSI[c]}{s}{ANSI['RESET']}" if enabled() else s
def event(color,symbol,title,lines=()): return '\n'.join([paint(f"{symbol} {title}",color)]+[f"  {x}" for x in lines])
