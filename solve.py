#!/usr/bin/env python3
import itertools, math, os, subprocess
SBOX=[0xE,0x4,0xD,0x1,0x2,0xF,0xB,0x8,0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7]
SINV=[0]*16
for i,v in enumerate(SBOX):SINV[v]=i
HERE=os.path.dirname(os.path.abspath(__file__))
def P(x):
 n=[(x>>12)&15,(x>>8)&15,(x>>4)&15,x&15];y=0
 for j in range(4):
  t=0
  for k in range(4):t=(t<<1)|((n[k]>>(3-j))&1)
  y=(y<<4)|t
 return y
def Sl(x):return (SBOX[(x>>12)&15]<<12)|(SBOX[(x>>8)&15]<<8)|(SBOX[(x>>4)&15]<<4)|SBOX[x&15]
def enc(p,hi,lo,k2,k3):
 x=p
 for k in (hi,lo,k2):x=P(Sl(x^k))
 return x^k3
def ddt():
 d=[[0]*16 for _ in range(16)]
 for a in range(16):
  for x in range(16):d[a][SBOX[x]^SBOX[x^a]]+=1
 return d
DDT=ddt()
def tr(a):return [(b,DDT[a][b]) for b in range(16) if DDT[a][b]]
def query():
 data=''.join('%04x\n'%p for p in range(65536)).encode()
 out=subprocess.run([os.path.join(HERE,'oracle')],input=data,stdout=subprocess.PIPE,check=True).stdout.split()
 return [int(x,16) for x in out]
def characteristics():
 out=[]
 for pos in range(4):
  for a in range(1,16):
   for b,c0 in tr(a):
    d1=P(b<<(4*(3-pos)));dn=[(d1>>12)&15,(d1>>8)&15,(d1>>4)&15,d1&15]
    for es in itertools.product(*[tr(v) if v else [(0,16)] for v in dn]):
     eta=sum(v<<(4*(3-i)) for i,(v,c) in enumerate(es));delta=P(eta)
     nn=[(delta>>12)&15,(delta>>8)&15,(delta>>4)&15,delta&15];act=tuple(i for i,v in enumerate(nn) if v)
     prob=c0/16*math.prod(c/16 for v,c in es)
     if len(act)==2:
      out.append((prob,a<<(4*(3-pos)),delta,act,tuple(nn[i] for i in act),pos,b,eta,c0,es))
 return sorted(out,reverse=True)
def trail_table(ct, z):
 # Returns counts[k3pair][K1 nibble] using pair frequency tables.
 prob,alpha,delta,act,vals,k1pos,b,eta,c0,es=z
 sh=[4*(3-i) for i in act]; k1sh=4*(3-k1pos)
 # freq[last nibble pair 0][last nibble pair 1][plaintext active nibble pair]
 freq={}
 for p in range(65536):
  q=p^alpha
  if q<p:continue
  key=((((ct[p]>>sh[0])&15)<<4)|((ct[q]>>sh[0])&15),(((ct[p]>>sh[1])&15)<<4)|((ct[q]>>sh[1])&15),(((p>>k1sh)&15)<<4)|(((q>>k1sh)&15)&15))
  freq[key]=freq.get(key,0)+1
 # key3 valid sets for each final active nibble and observed ct pair.
 valid=[]
 for idx in range(2):
  mp={}
  for cd in range(256):
   c=cd>>4;d=cd&15
   mp[cd]=tuple(k for k in range(16) if SINV[c^k]^SINV[d^k]==vals[idx])
  valid.append(mp)
 # k1 valid sets for plaintext pair and first transition b.
 k1valid={cd:tuple(k for k in range(16) if SBOX[(cd>>4)^k]^SBOX[(cd&15)^k]==b) for cd in range(256)}
 counts=[[0]*16 for _ in range(256)]
 for (cd0,cd1,pd),n in freq.items():
  for k0 in valid[0][cd0]:
   for k1 in valid[1][cd1]:
    row=counts[k0|(k1<<4)]
    for k in k1valid[pd]:row[k]+=n
 return counts
def recover(ct,chars):
 # one best trail per K1 nibble
 trails=[]
 for pos in range(4):
  trails.append(next(z for z in chars if z[5]==pos and len(z[3])==2))
 tables=[]
 for z in trails:tables.append(trail_table(ct,z))
 # For each K3 nibble, collect possible rank/value from every pair table involving it.
 # Search all K3 pairs from a trail first (256 choices), choose K1 for that pos; combine trails by trying top candidates.
 candidate_lists=[]
 report_counts=[]
 for pos,z,tab in zip(range(4),trails,tables):
  # marginalize over unknown other K3 nibble: sum counts, preserves K1 signal for correct K3 component but use combos later
  marg=[[0]*16 for _ in range(16)]
  for pair in range(256):
   for order,k in [(0,pair&15),(1,pair>>4)]:
    pass
  # Determine which component corresponds to this K1 pos from z active list
  comp=z[3].index(pos) if pos in z[3] else None
  if comp is None:
   # for K1 pos 2/3 trails active pairs may not contain that final nibble; still K1 signal independent of pair, rank all pairs.
   comp=0
  for pair in range(256):
   kn=(pair&15) if comp==0 else (pair>>4)
   for k1 in range(16):marg[kn][k1]+=tab[pair][k1]
  # score k3n by best contrast of DDT high hit classes
  scored=[]
  for k3n in range(16):
   cnt=marg[k3n]; top=max(cnt); med=sorted(cnt)[len(cnt)//2]
   scored.append((top-med,k3n,cnt))
  scored.sort(reverse=True)
  candidate_lists.append([k for _,k,_ in scored[:8]])
  report_counts.append((z,scored))
 # Try combinations of top K3 nibbles; for each, use exact trail table pair to select K1 nibble.
 for picks in itertools.product(range(8),repeat=4):
  k3n=[candidate_lists[i][picks[i]] for i in range(4)]
  k3=sum(k3n[i]<<(4*(3-i)) for i in range(4));lo_n=[0]*4
  ok=True
  for i,z in enumerate(trails):
   act=z[3]; pair=(k3n[act[0]])|(k3n[act[1]]<<4)
   cnt=z  # tables[i][pair]
   vals=tables[i][pair]
   # choose highest K1 candidate; ties resolved through schedule validation later if needed
   lo_n[i]=max(range(16),key=lambda k:vals[k])
  lo=sum(lo_n[i]<<(4*(3-i)) for i in range(4));hi=(k3-2*lo)&0xffff;k2=(hi+lo)&0xffff
  if enc(0,hi,lo,k2,k3)==ct[0] and enc(0x1234,hi,lo,k2,k3)==ct[0x1234]:
   return (k3,lo,hi,k2),trails,tables,report_counts,candidate_lists
 return None,trails,tables,report_counts,candidate_lists
def report(res,trails,tables,repstats,cands):
 (k3,lo,hi,k2)=res
 L=['# Differential cryptanalysis report','',
    '## S-box DDT','','DDT[a][b] counts pairs x with S[x] xor S[x xor a]=b.','',
    '| a\\\\b | '+' | '.join('%X'%b for b in range(16))+' |','|'+'---|'*17]
 for a,row in enumerate(DDT):L.append('| **%X** | '%a+' | '.join(map(str,row))+' |')
 L += ['','Strong entries include `11->2` count 8 (1/2), and `2->5`, `4->6`, `10->8`, `12->13` count 6 (3/8).','',
       '## Differential characteristics and probabilities','',
       '| plaintext diff | first transition | delta before final S | active final nibbles | K1 nibble | probability |','|---|---:|---:|---|---:|---:|']
 for z in trails:
  prob,alpha,delta,act,vals,pos,b,eta,c0,es=z;a=(alpha>>(4*(3-pos)))&15
  L.append('| `%04x` | `%X->%X` | `%04x` | %s | %d | %.4f |'%(alpha,a,b,delta,act,pos,prob))
 L += ['','The attack filters canonical pairs after inverting the hypothesized final S-box, requiring delta shown above; it then counts only 16 hypotheses for the corresponding K1 nibble using the first-round transition. Four rotated trails recover all nibbles of `K1=lo`; the linear schedule gives `hi=K3-2lo` and `K2=hi+lo`.','',
       '## Candidate hit statistics','','Recovered K3=`%04x`, K1/lo=`%04x`, K2=`%04x`, K0/hi=`%04x`.'%(k3,lo,k2,hi),'']
 for pos,(z,scored) in enumerate(repstats):
  true_lo=(lo>>(4*(3-pos)))&15;true_k3=(k3>>(4*(3-pos)))&15
  # exact counts under true neighboring key from corresponding table
  tab=tables[pos];act=z[3];pair=((k3>>(4*(3-act[0])))&15)|(((k3>>(4*(3-act[1])))&15)<<4);cnt=tab[pair]
  order=sorted(enumerate(cnt),key=lambda x:x[1],reverse=True);alt=order[0][0] if order[0][0]!=true_lo else order[1][0]
  L += ['### K1 nibble %d (true `%X`)'%(pos,true_lo),'','True candidate hits=%d; highest alternate nibble `%X` hits=%d. K3 nibble true value `%X` was in the differential shortlist %s.'%(cnt[true_lo],alt,cnt[alt],true_k3,cands[pos]),'','| K1 candidate | hits |','|---:|---:|']
  for k,v in order:L.append('| `%X` | %d |'%(k,v))
  L.append('')
 L += ['The solver issues 2^16 chosen plaintexts once, counts nibble hypotheses only, and uses linear schedule inversion; it never enumerates the 2^32 master-key space.','']
 open(os.path.join(HERE,'report.md'),'w',encoding='utf-8').write('\n'.join(L))
def main():
 ct=query();chars=characteristics();res,trails,tables,repstats,cands=recover(ct,chars)
 if not res:raise SystemExit('no consistent key')
 report(res,trails,tables,repstats,cands)
 print('recovered key: %08x'%((res[2]<<16)|res[1]))
if __name__=='__main__':main()
