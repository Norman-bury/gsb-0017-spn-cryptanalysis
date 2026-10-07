#!/usr/bin/env python3
import subprocess,os,itertools,math
HERE=os.path.dirname(os.path.abspath(__file__))
SB=[0xE,0x4,0xD,0x1,0x2,0xF,0xB,0x8,0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7]
INV=[0]*16
for i,x in enumerate(SB):INV[x]=i
N=1<<16
DDT=[[0]*16 for _ in range(16)]
for x in range(16):
 for y in range(16):DDT[x^y][SB[x]^SB[y]]+=1
def nib(x):return [(x>>12)&15,(x>>8)&15,(x>>4)&15,x&15]
def P(x):
 n=nib(x);o=0
 for j in range(4):
  z=0
  for k in range(4):z=(z<<1)|((n[k]>>(3-j))&1)
  o=(o<<4)|z
 return o
def oracle_groups(configs):
 lines=[]
 for pos,a,b in configs:
  d=a<<(12-4*pos)
  lines += [f'{x:04x}' for x in range(N)]
  lines += [f'{x^d:04x}' for x in range(N)]
 p=subprocess.run([os.path.join(HERE,'oracle')],input='\n'.join(lines)+'\n',text=True,capture_output=True,check=True,cwd=HERE)
 v=[int(x,16) for x in p.stdout.split()]
 groups=[];off=0
 for _ in configs:
  groups.append(list(zip(v[off:off+N],v[off+N:off+2*N])));off+=2*N
 return groups
# Search two-round characteristics with first S 7/3 -> f and exactly two
# active final nibbles. These are fixed differentials, and each score is a
# 256-entry local 8-bit round-key table.
def build_features():
 out=[]
 for pos in range(4):
  a=7;b=15;mid=P(b<<(12-4*pos));act=tuple(i for i in range(4) if (mid>>(12-4*i))&15)
  for vals in itertools.product(range(1,16),repeat=len(act)):
   pr=DDT[a][b]
   x2=0
   for j,q in enumerate(act):
    pr*=DDT[(mid>>(12-4*q))&15][vals[j]];x2|=vals[j]<<(12-4*q)
   if not pr:continue
   x3=P(x2);fa=tuple(i for i in range(4) if (x3>>(12-4*i))&15)
   if len(fa)==2:out.append((pos,a,b,x3,fa,pr/(16**3),act,vals))
 return out
FEATURES=build_features()
# Empirically strongest fixed paths (verified from DDT-derived joint-score
# ranking); keep a broad set so overlap determines every K3 nibble.
SELECT=[]
# Strong fixed two-round paths selected from the DDT enumeration and validated
# by joint hit counts.  They overlap as follows:
# F7 -> nibbles 0,1; F0/FA -> 0,2/0,3; 70 -> 1,3; A0 -> 2,3.
selected_paths=[
 (1,7,0xf100),(2,7,0xf200),(2,7,0xf005),(2,7,0xf0f0),
 (3,7,0x70c),(3,7,0xfb00),(0,7,0x00ad)
]
for pos,a,x3 in selected_paths:
 b=15
 mid=P(b<<(12-4*pos));act=tuple(i for i in range(4) if (mid>>(12-4*i))&15)
 # recover pre-P values by applying involution P; split on active second S boxes
 x2=P(x3);vals=tuple((x2>>(12-4*q))&15 for q in act)
 pr=DDT[a][b]
 for j,q in enumerate(act):pr*=DDT[(mid>>(12-4*q))&15][vals[j]]
 fa=tuple(i for i in range(4) if (x3>>(12-4*i))&15)
 SELECT.append((pos,a,b,x3,fa,pr/(16**3),act,vals))
def joint_table(pairs,x3,fa):
 sh=[12-4*q for q in fa];tv=[(x3>>s)&15 for s in sh]
 good=[]
 for j in range(2):good.append([tuple(k for k in range(16) if SB[INV[k^d]]==tv[j]) for d in range(16)])
 cnt=[0]*256
 for c,e in pairs:
  d=c^e
  g0=good[0][(d>>sh[0])&15];g1=good[1][(d>>sh[1])&15]
  for k0 in g0:
   base=k0*16
   for k1 in g1:cnt[base+k1]+=1
 return sorted(enumerate(cnt),key=lambda z:z[1],reverse=True)
def recover_k3():
 groups=oracle_groups([(p,a,b) for p,a,b,_,_,_,_,_ in SELECT])
 tables=[]
 for f,pairs in zip(SELECT,groups):
  top=joint_table(pairs,f[3],f[4]);tables.append((f,top))
 # Vote for complete K3 by combining the best local rows; search only top
 # rows of overlapping 8-bit tables, never 2^32 master keys.
 best=None
 # choose tables that collectively cover all four positions; recursive combine
 def combine(i,assign,score):
  nonlocal best
  if i==len(tables):
   if len(assign)==4 and (best is None or score>best[0]):best=(score,tuple(assign[q] for q in range(4)))
   return
  f,top=tables[i];fa=f[4]
  for rank,(kv,n) in enumerate(top[:8]):
   k0,k1=kv>>4,kv&15
   if assign[fa[0]] not in (None,k0) or assign[fa[1]] not in (None,k1):continue
   old=[assign[fa[0]],assign[fa[1]]]
   assign[fa[0]],assign[fa[1]]=k0,k1
   combine(i+1,assign,score+n/(rank+1))
   assign[fa[0]],assign[fa[1]]=old
 combine(0,[None]*4,0)
 k3n=best[1];k3=sum(k3n[i]<<(12-4*i) for i in range(4))
 return k3,k3n,tables
def recover_k2(k3):
 # Peel K3 and the last S/P from ciphertexts, then use one-round differentials
 # on the resulting two-round cipher. Since the resulting output is x3, attack
 # K2 by requiring inverse P then inverse S to follow a single-S transition.
 configs=[]
 for p in range(4):configs.append((p,0xB,0x2))
 groups=oracle_groups(configs)
 k2=[None]*4;stats=[]
 for p,pairs in zip(range(4),groups):
  # transition B->2 after K1; after first P two second-round S boxes are
  # active. Score pairs of K2 nibbles using the same joint attack on reduced
  # outputs x3 = P(S(... xor K2)).
  # Transform C xor K3 through inverse S and P for each pair.
  reduced=[]
  for c,e in pairs:
   u=c^k3;v=e^k3;z0=0;z1=0
   for q in range(4):
    sh=12-4*q
    z0|=INV[(u>>sh)&15]<<sh
    z1|=INV[(v>>sh)&15]<<sh
   # z is the x3 difference.  P is an involution, so applying P gives the
   # second-round S-box output difference x2.
   reduced.append((P(z0),P(z1)))
  # target is selected fixed two-nibble x2 differential; aggregate strongest
  # DDT transitions at both active second-round S boxes.
  besttab=None
  # Try every useful first-round transition; reduced pairs are differences at
  # the second S output, so fixed x2 targets are scored directly.
  for a0 in range(1,16):
   for b0 in range(1,16):
    if not DDT[a0][b0]:continue
    x1=P(b0<<(12-4*p));act=tuple(q for q in range(4) if (x1>>(12-4*q))&15)
    if len(act)>3:continue
    for vals in itertools.product(range(1,16),repeat=len(act)):
     pr=DDT[a0][b0];x2=0
     for j,q in enumerate(act):pr*=DDT[(x1>>(12-4*q))&15][vals[j]];x2|=vals[j]<<(12-4*q)
     if not pr:continue
     fa=tuple(q for q in range(4) if (x2>>(12-4*q))&15)
     if len(fa)==2:
      tab=joint_table(reduced,x2,fa)
      if besttab is None or tab[0][1]>besttab[0][0][1]:besttab=(tab,x2,fa,pr)
  tab,x3,fa,pr=besttab;stats.append((p,hex(x3),fa,tab[:8]))
  # assignment via overlap is handled by choosing all four p and taking best
  # consistent combination; here each observed table is recorded.
  yield p,fa,tab
 # The generator above is consumed in main to combine K2.
def main():
 k3,k3n,t3=recover_k3()
 # recover and combine K2 tables
 rgen=recover_k2(k3)
 tabs=list(rgen)
 best=None
 def comb(i,a,s):
  nonlocal best
  if i==len(tabs):
   if all(x is not None for x in a) and (best is None or s>best[0]):best=(s,tuple(a))
   return
  p,fa,tab=tabs[i]
  for rank,(kv,n) in enumerate(tab[:64]):
   x,y=kv>>4,kv&15
   if a[fa[0]] not in (None,x) or a[fa[1]] not in (None,y):continue
   old=(a[fa[0]],a[fa[1]]);a[fa[0]],a[fa[1]]=x,y
   comb(i+1,a,s+n/(rank+1));a[fa[0]],a[fa[1]]=old
 comb(0,[None]*4,0)
 k2n=best[1];k2=sum(k2n[i]<<(12-4*i) for i in range(4))
 lo=(k3-k2)&0xffff;hi=(k2-lo)&0xffff;key=(hi<<16)|lo
 print(f'key {key:08x}')
 ddt='|in\\out|'+'|'.join(f'{x:X}' for x in range(16))+'|\n|'+'---|'*17+'\n'
 for i,row in enumerate(DDT):ddt+=f'|{i:X}|'+'|'.join(map(str,row))+'|\n'
 md=['# 3轮简化SPN差分密码分析报告\n','## 差分分布表（DDT）\n',ddt,'\n## 差分特征及概率\n']
 md.append('末轮恢复固定两圈特征的第一轮为单 nibble `7 -> F`，概率 8/16；随后沿 P 扩散到四个第二轮 S 盒，程序从 DDT 自动枚举第二轮固定输出，只保留末轮仅两个活动 nibble 的路径。表中概率列为三轮 S 盒转移数 / 16^3。剥末轮后用 `B -> 2`（8/16）构造第二轮恢复特征。所有候选均为 4/8 位局部轮密钥，不穷举 32 位主密钥。\n\n')
 md.append('|输入位置|第一轮|固定 x3 差分|末轮活动 nibble|概率|\n|---:|---:|---:|---:|---:|\n')
 for f,tab in t3:md.append(f'|{f[0]}|{f[1]:X}->{f[2]:X}|{f[3]:04x}|{f[4]}|{f[5]:.8f}|\n')
 md.append('\n## 候选密钥命中统计\n### K3 8位局部候选\n')
 for f,tab in t3:
  md.append(f'\n输入位置 {f[0]}，目标 x3={f[3]:04x}，nibble={f[4]}\n\n|rank|candidate|hits|\n|---:|---:|---:|\n')
  for i,(kv,n) in enumerate(tab[:8],1):md.append(f'|{i}|{kv>>4:X},{kv&15:X}|{n}|\n')
 md.append('\n### K2 8位局部候选\n')
 for p,x3,fa,rows in [(x[0],x[1],x[2],x[3]) for x in []]:pass
 # stats are unavailable after generator; tabs retain top tables
 for p,fa,tab in tabs:
  md.append(f'\n特征组 {p}，nibble={fa}\n\n|rank|candidate|hits|\n|---:|---:|---:|\n')
  for i,(kv,n) in enumerate(tab[:8],1):md.append(f'|{i}|{kv>>4:X},{kv&15:X}|{n}|\n')
 md.append(f'\n恢复 `K3={k3:04x}`，`K2={k2:04x}`；由密钥调度 `lo=K3-K2={lo:04x}`，`hi=K2-lo={hi:04x}`。\n')
 open(os.path.join(HERE,'report.md'),'w',encoding='utf-8').write(''.join(md))
if __name__=='__main__':main()
