import json, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm
from matplotlib.colors import LinearSegmentedColormap
for s in ("Regular","Italic","Bold"): fm.fontManager.addfont(f"/usr/share/fonts/truetype/liberation/LiberationSerif-{s}.ttf")
plt.rcParams.update({"font.family":"Liberation Serif","font.size":7.5,"axes.linewidth":0.5,"figure.dpi":300,"savefig.dpi":300})
INK,INK2,GRID,BLUE,ORANGE="#0b0b0b","#52514e","#e3e2de","#2a78d6","#eb6834"
d=json.load(open("results.json")); e1,e2=d["exp1"],d["exp2"]
GATES=["G1","G2","G3","G4","G5","G6"]

# ---------- Fig 4: gate outcomes per demo scenario (first attempt) ----------
fig,ax=plt.subplots(figsize=(3.5,2.35))
cols=GATES+["G7"]
L=3.1; ax.set_xlim(0,L+7+2.6); ax.set_ylim(len(e1)+0.1,-0.9); ax.axis("off")
for j,c in enumerate(cols): ax.text(L+j+0.5,-0.5,c,ha="center",va="center",fontsize=7.2,color=INK2,fontweight="bold")
ax.text(L+7.15,-0.5,"Final",ha="left",va="center",fontsize=7.2,color=INK2,fontweight="bold")
for i,s in enumerate(e1):
    ax.text(0,i,s["name"].replace(" (retry fixes)","").replace(" (persistent)","").replace("Embedded instruction","Injected text"),ha="left",va="center",fontsize=6.3,color=INK)
    for j,g in enumerate(GATES):
        st=(s["first_gates"] or {}).get(g)
        fc,t,tc=("#eceae6","–",INK2) if st is None else (("#cfe0f7","P",INK) if st=="PASS" else (ORANGE,"F","#ffffff"))
        ax.add_patch(plt.Rectangle((L+j+0.04,i-0.4),0.92,0.8,fc=fc,ec="none"))
        ax.text(L+j+0.5,i,t,ha="center",va="center",fontsize=7,color=tc,fontweight="bold")
    fc,t,tc=("#cfe0f7","A",INK) if s["reviewed"] else ("#eceae6","–",INK2)
    ax.add_patch(plt.Rectangle((L+6+0.04,i-0.4),0.92,0.8,fc=fc,ec="none")); ax.text(L+6.5,i,t,ha="center",va="center",fontsize=7,color=tc,fontweight="bold")
    lab={"APPROVED":"Approved","REJECT":"Rejected","CLARIFY":"Clarify"}[s["status"]]
    extra=f" ({s['attempts']} tries)" if s["attempts"]>1 else ""
    ax.text(L+7.15,i,lab+extra,ha="left",va="center",fontsize=6.2,color=INK,fontweight="bold")
ax.text(0,len(e1)-0.1,"P pass, F critical fail (first attempt), A reviewer approved, – not evaluated or not reached",fontsize=5.4,color=INK2,ha="left",va="top")
plt.subplots_adjust(left=0.01,right=0.995,top=0.99,bottom=0.02)
fig.savefig("fig4_gates.png",facecolor="white"); plt.close(fig)

# ---------- Fig 5: unsafe drafts accepted, A vs B ----------
modes=["overbroad","wildcard","missing_sod","hallucinated","conflict","omit_rule"]
lab=["Over-\nbroad","Wild-\ncard","Missing\nSoD","Halluc.\nresource","Conflict","Omitted\nrule"]
A=[e2[m]["A_accept_unsafe"] for m in modes]; B=[e2[m]["B_accept_unsafe"] for m in modes]
fig,ax=plt.subplots(figsize=(3.5,2.1))
w=0.36
for i,(a,b) in enumerate(zip(A,B)):
    ax.bar(i-w/2-0.01,a,w,color=BLUE,label="A: no validation" if i==0 else None,zorder=3)
    bb=ax.bar(i+w/2+0.01,b,w,color=ORANGE,label="B: gates G1–G6" if i==0 else None,zorder=3)
    ax.text(i-w/2-0.01,a+0.15,str(a),ha="center",va="bottom",fontsize=7,color=INK)
    ax.text(i+w/2+0.01,b+0.15,str(b),ha="center",va="bottom",fontsize=7,color=INK)
ax.set_xticks(range(6)); ax.set_xticklabels(lab,fontsize=6.4,color=INK2)
ax.set_ylim(0,8.6); ax.set_yticks([0,2,4,6]); ax.tick_params(axis="y",labelsize=6.5,colors=INK2,length=0); ax.tick_params(axis="x",length=0)
ax.set_ylabel("Unsafe drafts accepted (of 7 cases)",fontsize=6.8,color=INK2)
ax.grid(axis="y",color=GRID,lw=0.5,zorder=0)
for s in ("top","right","left"): ax.spines[s].set_visible(False)
ax.spines["bottom"].set_color("#bdbbb4")
ax.legend(frameon=False,fontsize=6.6,loc="upper right",ncol=2,handlelength=1,columnspacing=1.0,bbox_to_anchor=(1.0,1.04))
plt.subplots_adjust(left=0.13,right=0.99,top=0.93,bottom=0.2)
fig.savefig("fig5_accepted.png",facecolor="white"); plt.close(fig)

# ---------- Fig 6: which gate raised a critical finding (drafts out of 7) ----------
rows=["none","overbroad","wildcard","missing_sod","hallucinated","conflict","omit_rule"]
rl=["No fault (control)","Over-broad","Wildcard","Missing SoD","Hallucinated","Conflict","Omitted rule"]
M=[[e2[r]["gates_hit"][g] for g in GATES] for r in rows]
cm=LinearSegmentedColormap.from_list("b",["#f6f9fd","#2a78d6","#1b4f93"])
fig,ax=plt.subplots(figsize=(3.5,2.25))
ax.imshow(M,cmap=cm,vmin=0,vmax=7,aspect="auto")
for i,r in enumerate(M):
    for j,v in enumerate(r):
        ax.text(j,i,str(v),ha="center",va="center",fontsize=7,color="#ffffff" if v>=3 else INK)
ax.set_xticks(range(6)); ax.set_xticklabels(GATES,fontsize=7,color=INK2)
ax.set_yticks(range(7)); ax.set_yticklabels(rl,fontsize=6.8,color=INK)
ax.xaxis.tick_top(); ax.tick_params(length=0)
for s in ax.spines.values(): s.set_visible(False)
ax.set_xticks([x-0.5 for x in range(7)],minor=True); ax.set_yticks([y-0.5 for y in range(8)],minor=True)
ax.grid(which="minor",color="white",lw=1.2); ax.tick_params(which="minor",length=0)
plt.subplots_adjust(left=0.27,right=0.99,top=0.9,bottom=0.01)
fig.savefig("fig6_gate_hits.png",facecolor="white"); plt.close(fig)
