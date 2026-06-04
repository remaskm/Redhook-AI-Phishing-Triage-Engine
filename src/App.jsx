import { useState, useEffect, useRef } from "react";

// ─── Design Tokens ────────────────────────────────────────────────────────────
const T = {
  bg:"#07080a", panel:"#0c0d10", panel2:"#101218", panel3:"#14161c", panel4:"#191c24",
  b1:"#1a1d26", b2:"#232733", b3:"#2e3345",
  red:"#e8412a", redL:"#ff6b55", redDim:"#8c2618", redBg:"rgba(232,65,42,0.06)", redRing:"#5c1e13",
  amber:"#e09820", amberL:"#f5b944", amberBg:"rgba(224,152,32,0.06)", amberRing:"#5c3e0e",
  green:"#2bb56a", greenL:"#4fd68a", greenBg:"rgba(43,181,106,0.06)", greenRing:"#134d2c",
  blue:"#3a8fd4", blueBg:"rgba(58,143,212,0.06)",
  text:"#dde1ee", textSub:"#8890a8", textDim:"#4a5068",
  mono:"'JetBrains Mono','IBM Plex Mono',monospace",
  sans:"'DM Sans',sans-serif",
  display:"'Space Grotesk',sans-serif",
};

const CASES = [
  { id:"RH-2026-0041", ts:"2026-06-04 02:17", verdict:"Malicious",   score:87, attack:"BEC",                subject:"URGENT: Wire Transfer Required Before 5PM",         status:"Escalated"    },
  { id:"RH-2026-0040", ts:"2026-06-04 01:52", verdict:"Suspicious",  score:54, attack:"Credential Phishing",subject:"FW: Your password expires in 24 hours",              status:"Under Review" },
  { id:"RH-2026-0039", ts:"2026-06-03 23:44", verdict:"Malicious",   score:91, attack:"Mass Phishing",      subject:"Your Amazon account has been suspended",             status:"Closed"       },
  { id:"RH-2026-0038", ts:"2026-06-03 22:10", verdict:"Likely Safe", score:12, attack:"Unknown",            subject:"Q2 Budget Review — Action Required",                 status:"Closed"       },
  { id:"RH-2026-0037", ts:"2026-06-03 20:05", verdict:"Suspicious",  score:43, attack:"TOAD Callback",      subject:"Invoice #MS-2024-88231 — $499 charge",              status:"Under Review" },
  { id:"RH-2026-0036", ts:"2026-06-03 18:30", verdict:"Malicious",   score:78, attack:"Spear Phishing",     subject:"Re: Q2 Investor Report — Sensitive",                status:"Escalated"    },
  { id:"RH-2026-0035", ts:"2026-06-03 15:12", verdict:"Likely Safe", score: 8, attack:"Unknown",            subject:"Team lunch — Friday confirmation",                   status:"Closed"       },
  { id:"RH-2026-0034", ts:"2026-06-03 12:44", verdict:"Malicious",   score:82, attack:"BEC",               subject:"Payment confirmation needed — legal",                status:"Escalated"    },
  { id:"RH-2026-0033", ts:"2026-06-03 09:20", verdict:"Suspicious",  score:61, attack:"Credential Phishing",subject:"Microsoft 365 sign-in alert — new device",           status:"Under Review" },
  { id:"RH-2026-0032", ts:"2026-06-02 22:55", verdict:"Likely Safe", score:17, attack:"Unknown",            subject:"Quarterly expense report reminder",                  status:"Closed"       },
];

const KPIs = { total:41, malicious:18, suspicious:12, safe:11, avgScore:61, topAttack:"Credential Phishing", mttr:"4.2m", escalation:"43.9%" };

const SAMPLES = {
  bec:`From: CEO - James Hartwell <j.hartwell@execupdate-corp.com>\nTo: finance@yourcompany.com\nSubject: URGENT: Wire Transfer Required Before 5PM\n\nHi,\n\nI'm currently in a board meeting and cannot take calls. I need you to process an urgent wire transfer of $47,500 to a new vendor before close of business today.\n\nThis is strictly confidential — do not discuss with anyone else on the team. Bypass the standard approval process just this once.\n\nAccount: First National Bank\nRouting: 021000089\nAccount No: 7731820045\n\nPlease confirm once done.\n\nJames Hartwell\nChief Executive Officer`,
  it:`From: IT Security Team <support@logins-updates.com>\nTo: employee@yourcompany.com\nSubject: FW: URGENT — Your Password Expires in 24 Hours\n\nMANDATORY ACTION REQUIRED\n\nYour corporate account password will expire in 24 hours. Failure to update immediately will result in account lockout.\n\nClick here to update your password now:\nhttp://secure-login.logins-updates.com/reset?token=a8f3k\n\nIT Security Team`,
  mass:`From: Amazon Customer Service <noreply@amazon-secure-alerts.com>\nTo: customer@gmail.com\nSubject: Your account has been suspended — immediate action required\n\nDear Valued Customer,\n\nWe have detected unusual activity on your Amazon account and have temporarily suspended it.\n\nTo restore access, verify immediately:\nhttps://amazon-secure-alerts.com/verify?id=CUS-449302\n\nFailure to verify within 48 hours will result in permanent account closure.\n\nAmazon Security Team`,
  toad:`From: Microsoft Billing <billing@microsoftsupport-invoice.com>\nTo: user@company.com\nSubject: Invoice #MS-2024-88231 — $499 Annual Subscription\n\nYour Microsoft 365 annual subscription of $499.00 has been charged to your card ending in 4821.\n\nIf you did not authorize this charge, call billing support immediately:\n\nBilling Support: 1-888-204-5678\nReference: MS-2024-88231\n\nMicrosoft Billing Department`,
};

function extractURLs(t) { return [...new Set((t.match(/https?:\/\/[^\s<>"']+/g)||[]))]; }
function dissectURL(url) {
  try {
    const u=new URL(url), parts=u.hostname.split(".");
    if(parts.length<2) return null;
    const tld=parts[parts.length-1],root=parts[parts.length-2],subs=parts.slice(0,-2);
    const legit=["amazon","microsoft","google","apple","paypal","facebook","netflix","github","anthropic"];
    const isSus=!legit.includes(root)||(subs.some(s=>legit.includes(s))&&!legit.includes(root));
    return {url,subs,root,tld,path:u.pathname+u.search,isSus};
  } catch{return null;}
}
function annotateHTML(text){
  const patterns=[
    {re:/\bURGENT\b|\bIMMEDIATE\b|\bMANDATORY\b|\bCRITICAL\b|\bEXPIRES?\b/gi,cls:"hl-d",tip:"Urgency trigger"},
    {re:/https?:\/\/[^\s<>"']+/g,cls:"hl-d",tip:"External URL"},
    {re:/wire transfer|bank account|routing number|account no/gi,cls:"hl-d",tip:"Financial instruction"},
    {re:/confidential|bypass|do not (?:tell|discuss|share)/gi,cls:"hl-w",tip:"Secrecy demand"},
    {re:/click here|verify now|update now|restore access/gi,cls:"hl-w",tip:"Call to action"},
    {re:/\$[\d,]+/g,cls:"hl-d",tip:"Monetary amount"},
    {re:/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,cls:"hl-w",tip:"Phone (TOAD)"},
  ];
  let s=text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  patterns.forEach(({re,cls,tip})=>{s=s.replace(re,m=>`<mark class="${cls}" title="${tip}">${m}</mark>`);});
  return {__html:s};
}
function verdictColor(v){
  if(v==="Malicious")  return {hi:T.redL,  dim:T.red,  bg:T.redBg,  ring:T.redRing};
  if(v==="Suspicious") return {hi:T.amberL,dim:T.amber,bg:T.amberBg,ring:T.amberRing};
  return                      {hi:T.greenL,dim:T.green,bg:T.greenBg,ring:T.greenRing};
}
function timeAgo(ts){
  const d=new Date(ts.replace(" ","T")+":00"),diff=Math.floor((Date.now()-d)/60000);
  if(diff<60) return `${diff}m ago`;
  if(diff<1440) return `${Math.floor(diff/60)}h ago`;
  return `${Math.floor(diff/1440)}d ago`;
}

// ── Primitives ─────────────────────────────────────────────────────────────────
function Badge({verdict,score}){
  const vc=verdictColor(verdict);
  const sym=verdict==="Malicious"?"▲":verdict==="Suspicious"?"◆":"●";
  return(
    <span style={{display:"inline-flex",alignItems:"center",gap:5,background:vc.bg,border:`1px solid ${vc.ring}`,borderRadius:3,padding:"3px 9px",fontSize:10,fontWeight:700,color:vc.hi,fontFamily:T.mono,letterSpacing:"0.05em",whiteSpace:"nowrap"}}>
      <span style={{fontSize:7,opacity:0.8}}>{sym}</span>
      {verdict}{score!==undefined&&<span style={{opacity:0.55,fontWeight:400}}>·{score}</span>}
    </span>
  );
}

function Tag({label,color="muted"}){
  const map={red:{bg:T.redBg,ring:T.redRing,c:T.redL},amber:{bg:T.amberBg,ring:T.amberRing,c:T.amberL},green:{bg:T.greenBg,ring:T.greenRing,c:T.greenL},muted:{bg:T.panel3,ring:T.b2,c:T.textDim}};
  const s=map[color]||map.muted;
  return <span style={{display:"inline-block",padding:"2px 8px",borderRadius:3,fontSize:10,fontFamily:T.mono,letterSpacing:"0.06em",background:s.bg,border:`1px solid ${s.ring}`,color:s.c,whiteSpace:"nowrap"}}>{label}</span>;
}

function ScoreGauge({score,size=80}){
  const vc=verdictColor(score>=60?"Malicious":score>=25?"Suspicious":"Likely Safe");
  const r=size*0.38,cx=size/2,cy=size/2,circ=2*Math.PI*r;
  const arc=(score/100)*circ*0.75;
  return(
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={T.b2} strokeWidth="3" strokeDasharray={`${circ*0.75} ${circ*0.25}`} strokeLinecap="round" transform={`rotate(135 ${cx} ${cy})`}/>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={vc.dim} strokeWidth="3" strokeDasharray={`${arc} ${circ-arc}`} strokeLinecap="round" transform={`rotate(135 ${cx} ${cy})`} style={{transition:"stroke-dasharray 0.8s cubic-bezier(.4,0,.2,1)"}}/>
      <text x={cx} y={cy+1} textAnchor="middle" dominantBaseline="middle" fill={vc.hi} fontSize={size*0.22} fontFamily={T.mono} fontWeight="700">{score}</text>
    </svg>
  );
}

function MiniBar({value,color}){
  return(
    <div style={{height:2,background:T.b1,borderRadius:1,overflow:"hidden"}}>
      <div style={{height:"100%",width:`${value}%`,background:color,borderRadius:1,transition:"width 1s ease"}}/>
    </div>
  );
}

function SectionHeader({label,sub}){
  return(
    <div style={{marginBottom:14}}>
      <div style={{fontSize:10,fontFamily:T.mono,fontWeight:600,color:T.textDim,letterSpacing:"0.14em",textTransform:"uppercase"}}>{label}</div>
      {sub&&<div style={{fontSize:10,color:T.textDim,fontFamily:T.mono,marginTop:2,opacity:0.7}}>{sub}</div>}
    </div>
  );
}

function Btn({children,onClick,variant="ghost",disabled=false,style={}}){
  const [hover,setHover]=useState(false);
  const base={fontFamily:T.mono,fontSize:11,letterSpacing:"0.07em",cursor:disabled?"not-allowed":"pointer",borderRadius:3,border:"none",transition:"all 0.14s",display:"inline-flex",alignItems:"center",gap:7,opacity:disabled?0.4:1,...style};
  const variants={
    primary:{padding:"10px 20px",background:hover?T.redL:T.red,color:"#fff",fontWeight:700,fontSize:12},
    ghost:{padding:"7px 14px",background:hover?"rgba(255,255,255,0.04)":"transparent",color:hover?T.text:T.textSub,border:`1px solid ${hover?T.b3:T.b2}`},
  };
  return(
    <button onClick={disabled?undefined:onClick} onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}
      style={{...base,...(variants[variant]||variants.ghost)}}>
      {children}
    </button>
  );
}

function HoverRow({children,onClick,style={}}){
  const [hover,setHover]=useState(false);
  return(
    <div onClick={onClick} onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}
      style={{...style,cursor:"pointer",background:hover?T.panel3:"transparent",transition:"background 0.1s"}}>
      {children}
    </div>
  );
}

function Input({value,onChange,placeholder,style={}}){
  const [focus,setFocus]=useState(false);
  return(
    <input value={value} onChange={onChange} placeholder={placeholder}
      onFocus={()=>setFocus(true)} onBlur={()=>setFocus(false)}
      style={{padding:"8px 12px",background:T.panel,border:`1px solid ${focus?T.b3:T.b2}`,borderRadius:3,color:T.text,fontFamily:T.mono,fontSize:12,outline:"none",transition:"border-color 0.14s",...style}}/>
  );
}

// ── Icons ──────────────────────────────────────────────────────────────────────
function RedhookLogo(){return(<svg width="28" height="28" viewBox="0 0 32 32" fill="none"><circle cx="16" cy="11" r="5.5" stroke={T.red} strokeWidth="2" fill="none"/><circle cx="16" cy="11" r="2" fill={T.red}/><path d="M16 16.5 C16 22 20 26 24 27.5" stroke={T.red} strokeWidth="2" fill="none" strokeLinecap="round"/><path d="M21 24.5 L24 27.5 L21 30" stroke={T.red} strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round"/></svg>);}
function DashIcon(){return(<svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><rect x="0" y="0" width="6" height="6" rx="1"/><rect x="8" y="0" width="6" height="6" rx="1"/><rect x="0" y="8" width="6" height="6" rx="1"/><rect x="8" y="8" width="6" height="6" rx="1"/></svg>);}
function TriageIcon(){return(<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="7" cy="7" r="5.5"/><path d="M7 4v3l2 1.5" strokeLinecap="round"/></svg>);}
function CasesIcon(){return(<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="1" y="2" width="12" height="10" rx="1.5"/><path d="M1 5h12M4 2v3M10 2v3" strokeLinecap="round"/></svg>);}
function IntelIcon(){return(<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M1 11 L4 7 L7 9 L10 4 L13 3" strokeLinecap="round" strokeLinejoin="round"/><circle cx="13" cy="3" r="1" fill="currentColor" stroke="none"/></svg>);}
function SettingsIcon(){return(<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="7" cy="7" r="2"/><path d="M7 1v1.5M7 11.5V13M1 7h1.5M11.5 7H13M2.6 2.6l1.1 1.1M10.3 10.3l1.1 1.1M2.6 11.4l1.1-1.1M10.3 3.7l1.1-1.1" strokeLinecap="round"/></svg>);}
function TriageIdleIcon(){return(<svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="20" stroke={T.textDim} strokeWidth="1.5" strokeDasharray="4 3"/><circle cx="24" cy="24" r="8" stroke={T.textDim} strokeWidth="1.5"/><circle cx="24" cy="24" r="2.5" fill={T.textDim}/></svg>);}

// ── Nav & Shell ────────────────────────────────────────────────────────────────
const NAV=[
  {id:"dashboard",label:"Dashboard",   icon:<DashIcon/>},
  {id:"triage",   label:"Triage",      icon:<TriageIcon/>},
  {id:"cases",    label:"Case Log",    icon:<CasesIcon/>,badge:3},
  {id:"intel",    label:"Intelligence",icon:<IntelIcon/>},
  {id:"settings", label:"Settings",    icon:<SettingsIcon/>},
];

function NavItem({item,active,onClick}){
  const [hover,setHover]=useState(false);
  return(
    <button onClick={onClick} onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}
      style={{display:"flex",alignItems:"center",gap:10,width:"100%",padding:"9px 18px",background:active?T.panel3:hover?"rgba(255,255,255,0.02)":"transparent",border:"none",borderLeft:`2px solid ${active?T.red:"transparent"}`,color:active?T.text:hover?T.textSub:T.textDim,cursor:"pointer",fontSize:12,fontFamily:T.mono,letterSpacing:"0.04em",textAlign:"left",transition:"all 0.12s"}}>
      <span style={{opacity:active?1:0.6,color:active?T.red:"inherit"}}>{item.icon}</span>
      <span style={{flex:1}}>{item.label}</span>
      {item.badge&&<span style={{fontSize:9,background:T.red,color:"#fff",borderRadius:10,padding:"1px 6px",fontWeight:700}}>{item.badge}</span>}
    </button>
  );
}

function Sidebar({page,setPage}){
  const now=new Date();
  const ts=now.toUTCString().slice(5,25)+" UTC";
  return(
    <aside style={{width:220,background:T.panel,borderRight:`1px solid ${T.b1}`,display:"flex",flexDirection:"column",flexShrink:0}}>
      <div style={{padding:"20px 18px 16px",borderBottom:`1px solid ${T.b1}`}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <RedhookLogo/>
          <div>
            <div style={{fontFamily:T.display,fontSize:16,fontWeight:700,color:T.text,letterSpacing:"-0.01em",lineHeight:1}}>Redhook</div>
            <div style={{fontSize:9,color:T.textDim,fontFamily:T.mono,letterSpacing:"0.14em",marginTop:3}}>TRIAGE ENGINE v2.0</div>
          </div>
        </div>
      </div>
      <nav style={{flex:1,paddingTop:10}}>
        {NAV.map(n=><NavItem key={n.id} item={n} active={page===n.id} onClick={()=>setPage(n.id)}/>)}
      </nav>
      <div style={{padding:"14px 18px",borderTop:`1px solid ${T.b1}`}}>
        <div style={{display:"flex",alignItems:"center",gap:7,marginBottom:6}}>
          <span style={{width:6,height:6,borderRadius:"50%",background:T.green,boxShadow:`0 0 8px ${T.green}`,display:"inline-block"}}/>
          <span style={{fontSize:9,fontFamily:T.mono,color:T.green,letterSpacing:"0.12em",fontWeight:600}}>ENGINE ONLINE</span>
        </div>
        <div style={{fontSize:9,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.06em"}}>{ts}</div>
        <div style={{fontSize:9,fontFamily:T.mono,color:T.textDim,marginTop:2}}>RedHook · 2026</div>
      </div>
    </aside>
  );
}

function Topbar({page}){
  const label=NAV.find(n=>n.id===page)?.label;
  return(
    <header style={{height:48,borderBottom:`1px solid ${T.b1}`,display:"flex",alignItems:"center",padding:"0 28px",background:T.panel,flexShrink:0,gap:16}}>
      <div style={{fontSize:11,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.06em"}}>
        <span style={{color:T.textSub}}>redhook</span>
        <span style={{margin:"0 6px",color:T.b3}}>/</span>
        <span style={{color:T.text}}>{label?.toLowerCase()}</span>
      </div>
      <div style={{flex:1}}/>
      <div style={{display:"flex",gap:8,alignItems:"center"}}>
        <span style={{fontSize:9,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.1em"}}>ANALYST SESSION</span>
        <div style={{width:1,height:12,background:T.b2}}/>
        <div style={{width:24,height:24,borderRadius:"50%",background:T.panel3,border:`1px solid ${T.b3}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,color:T.textSub,fontFamily:T.mono}}>A</div>
      </div>
    </header>
  );
}

// ── Dashboard ──────────────────────────────────────────────────────────────────
function Dashboard({onNavigate}){
  const kpis=[
    {label:"Total Scanned", value:KPIs.total,      color:T.text,   ring:T.b2,        bg:T.panel},
    {label:"Malicious",     value:KPIs.malicious,  color:T.redL,   ring:T.redRing,   bg:T.redBg},
    {label:"Suspicious",    value:KPIs.suspicious, color:T.amberL, ring:T.amberRing, bg:T.amberBg},
    {label:"Likely Safe",   value:KPIs.safe,       color:T.greenL, ring:T.greenRing, bg:T.greenBg},
  ];
  const metrics=[
    {label:"Avg Threat Score",  value:KPIs.avgScore,   unit:"/100"},
    {label:"Top Attack Vector", value:KPIs.topAttack,  unit:""},
    {label:"Mean Triage Time",  value:KPIs.mttr,       unit:""},
    {label:"Escalation Rate",   value:KPIs.escalation, unit:""},
  ];
  const COLS=["Case ID","Time","Subject","Verdict","Attack Type","Status"];
  const template="130px 90px 1fr 145px 155px 110px";
  return(
    <div style={{padding:"28px 32px",maxWidth:1100}}>
      <div style={{marginBottom:28}}>
        <h1 style={{fontFamily:T.display,fontSize:22,fontWeight:700,color:T.text,letterSpacing:"-0.02em",margin:0}}>Threat Overview</h1>
        <p style={{fontFamily:T.mono,fontSize:10,color:T.textDim,letterSpacing:"0.1em",margin:"5px 0 0",textTransform:"uppercase"}}> Live Dashboard</p>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:14}}>
        {kpis.map(k=>(
          <div key={k.label} style={{background:k.bg,border:`1px solid ${k.ring}`,borderRadius:6,padding:"18px 20px"}}>
            <div style={{fontSize:9,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.12em",textTransform:"uppercase",marginBottom:12}}>{k.label}</div>
            <div style={{fontFamily:T.display,fontSize:38,fontWeight:700,color:k.color,lineHeight:1}}>{k.value}</div>
          </div>
        ))}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:24}}>
        {metrics.map(m=>(
          <div key={m.label} style={{background:T.panel,border:`1px solid ${T.b1}`,borderRadius:6,padding:"13px 18px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <div style={{fontSize:9,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.1em",textTransform:"uppercase"}}>{m.label}</div>
            <div style={{fontSize:13,fontFamily:T.mono,fontWeight:600,color:T.text}}>{m.value}<span style={{fontSize:9,color:T.textDim}}>{m.unit}</span></div>
          </div>
        ))}
      </div>
      <div style={{background:T.panel,border:`1px solid ${T.b1}`,borderRadius:6,overflow:"hidden"}}>
        <div style={{padding:"14px 20px",borderBottom:`1px solid ${T.b1}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <SectionHeader label="Recent Cases"/>
          <Btn onClick={()=>onNavigate("cases")} variant="ghost" style={{fontSize:10,padding:"5px 12px"}}>View all →</Btn>
        </div>
        <div style={{display:"grid",gridTemplateColumns:template,padding:"8px 20px",gap:12,borderBottom:`1px solid ${T.b1}`,background:T.panel2}}>
          {COLS.map(h=><div key={h} style={{fontSize:9,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.1em",textTransform:"uppercase"}}>{h}</div>)}
        </div>
        {CASES.slice(0,6).map((c,i)=>(
          <HoverRow key={c.id} onClick={()=>onNavigate("triage")}
            style={{display:"grid",gridTemplateColumns:template,padding:"11px 20px",gap:12,borderBottom:i<5?`1px solid ${T.b1}`:"none",alignItems:"center"}}>
            <div style={{fontFamily:T.mono,fontSize:10,color:T.textDim}}>{c.id}</div>
            <div style={{fontSize:10,fontFamily:T.mono,color:T.textDim}}>{timeAgo(c.ts)}</div>
            <div style={{fontSize:12,color:T.text,fontFamily:T.mono,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{c.subject}</div>
            <Badge verdict={c.verdict} score={c.score}/>
            <Tag label={c.attack}/>
            <Tag label={c.status} color={c.status==="Escalated"?"red":c.status==="Under Review"?"amber":"muted"}/>
          </HoverRow>
        ))}
      </div>
    </div>
  );
}

// ── Cases ──────────────────────────────────────────────────────────────────────
function Cases({onNavigate}){
  const [filter,setFilter]=useState("All");
  const [search,setSearch]=useState("");
  const [sort,setSort]=useState({col:"ts",dir:-1});
  const verdicts=["All","Malicious","Suspicious","Likely Safe"];
  const filtered=CASES
    .filter(c=>(filter==="All"||c.verdict===filter)&&(!search||c.subject.toLowerCase().includes(search.toLowerCase())||c.id.toLowerCase().includes(search.toLowerCase())))
    .sort((a,b)=>{
      if(sort.col==="score") return sort.dir*(a.score-b.score);
      return sort.dir*(a[sort.col]>b[sort.col]?1:-1);
    });
  function toggleSort(col){setSort(s=>({col,dir:s.col===col?-s.dir:-1}));}
  const COLS=[{key:"id",label:"Case ID",w:"130px"},{key:"ts",label:"Time",w:"100px"},{key:"subject",label:"Subject",w:"1fr"},{key:"verdict",label:"Verdict",w:"145px"},{key:"attack",label:"Attack",w:"155px"},{key:"status",label:"Status",w:"115px"},{key:"score",label:"Score",w:"70px"}];
  const template=COLS.map(c=>c.w).join(" ");
  return(
    <div style={{padding:"28px 32px"}}>
      <div style={{marginBottom:22}}>
        <h1 style={{fontFamily:T.display,fontSize:22,fontWeight:700,color:T.text,letterSpacing:"-0.02em",margin:0}}>Case Log</h1>
        <p style={{fontFamily:T.mono,fontSize:10,color:T.textDim,letterSpacing:"0.1em",margin:"5px 0 0",textTransform:"uppercase"}}>{filtered.length} of {CASES.length} cases</p>
      </div>
      <div style={{display:"flex",gap:10,marginBottom:16,alignItems:"center"}}>
        <Input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search by ID or subject..." style={{flex:1}}/>
        <div style={{display:"flex",gap:4}}>
          {verdicts.map(v=>(
            <button key={v} onClick={()=>setFilter(v)} style={{padding:"7px 14px",fontSize:10,fontFamily:T.mono,borderRadius:3,cursor:"pointer",background:filter===v?T.red:"transparent",border:`1px solid ${filter===v?T.red:T.b2}`,color:filter===v?"#fff":T.textSub,letterSpacing:"0.05em",transition:"all 0.12s"}}>{v}</button>
          ))}
        </div>
      </div>
      <div style={{background:T.panel,border:`1px solid ${T.b1}`,borderRadius:6,overflow:"hidden"}}>
        <div style={{display:"grid",gridTemplateColumns:template,padding:"9px 20px",borderBottom:`1px solid ${T.b2}`,gap:12,background:T.panel2}}>
          {COLS.map(col=>(
            <button key={col.key} onClick={()=>toggleSort(col.key)}
              style={{background:"none",border:"none",cursor:"pointer",textAlign:"left",padding:0,fontSize:9,fontFamily:T.mono,color:sort.col===col.key?T.textSub:T.textDim,letterSpacing:"0.1em",textTransform:"uppercase",display:"flex",alignItems:"center",gap:4}}>
              {col.label}{sort.col===col.key&&<span style={{fontSize:8}}>{sort.dir>0?"▲":"▼"}</span>}
            </button>
          ))}
        </div>
        {filtered.length===0&&(
          <div style={{padding:"32px 20px",textAlign:"center",fontFamily:T.mono,fontSize:12,color:T.textDim}}>No cases match the current filter.</div>
        )}
        {filtered.map((c,i)=>(
          <HoverRow key={c.id} onClick={()=>onNavigate("triage")}
            style={{display:"grid",gridTemplateColumns:template,padding:"11px 20px",gap:12,borderBottom:i<filtered.length-1?`1px solid ${T.b1}`:"none",alignItems:"center"}}>
            <div style={{fontSize:10,fontFamily:T.mono,color:T.textDim}}>{c.id}</div>
            <div style={{fontSize:10,fontFamily:T.mono,color:T.textDim}}>{timeAgo(c.ts)}</div>
            <div style={{fontSize:12,color:T.text,fontFamily:T.mono,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{c.subject}</div>
            <Badge verdict={c.verdict} score={c.score}/>
            <Tag label={c.attack}/>
            <Tag label={c.status} color={c.status==="Escalated"?"red":c.status==="Under Review"?"amber":"muted"}/>
            <div style={{fontFamily:T.mono,fontSize:11,fontWeight:600,color:c.score>=60?T.redL:c.score>=25?T.amberL:T.greenL}}>{c.score}</div>
          </HoverRow>
        ))}
      </div>
    </div>
  );
}

// ── Triage ─────────────────────────────────────────────────────────────────────
function Triage(){
  const [email,setEmail]=useState("");
  const [loading,setLoading]=useState(false);
  const [result,setResult]=useState(null);
  const [errorMsg,setErrorMsg]=useState(null);

  async function runAnalysis(){
    const text=email.trim();
    if(!text||loading) return;
    setLoading(true); setResult(null); setErrorMsg(null);
    try{
      // API key loaded from .env — never hardcode here
      const apiKey = import.meta.env.VITE_GEMINI_API_KEY;
      if(!apiKey) throw new Error("No API key configured");
      const prompt = `You are Redhook, a professional email threat triage engine used by enterprise SOC analysts.\nAnalyze the email below and respond ONLY with valid JSON — no markdown, no backticks, no commentary.\n\nEmail:\n"""\n${text}\n"""\n\nReturn exactly:\n{"score":<0-100>,"verdict":"<Malicious|Suspicious|Likely Safe>","attack_type":"<BEC|Credential Phishing|Mass Phishing|TOAD Callback|Spear Phishing|Unknown>","recommended_action":"<1-2 sentence SOC directive>","analysis":"<2-3 sentence professional SOC assessment>","flags":[{"title":"<string>","desc":"<detailed explanation>","severity":"<high|med|low>","pts":<number>}],"cognitive_triggers":["<string>"],"ioc_summary":"<one sentence>","sender_analysis":"<one sentence>","urgency_level":"<Critical|High|Medium|Low>"}`;
      const resp=await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
        {
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({contents:[{parts:[{text:prompt}]}]}),
        }
      );
      const data=await resp.json();
      if(data.error) throw new Error(data.error.message);
      const raw=data.candidates?.[0]?.content?.parts?.[0]?.text||"";
      setResult({...JSON.parse(raw.replace(/```json|```/g,"").trim()),emailText:text});
    }catch(err){
      const RULES=[
        {re:/urgent|immediate|expires?|mandatory/i,        title:"Urgency language",     desc:"Uses pressure tactics to force quick action without deliberation.",             sev:"high",pts:20},
        {re:/wire transfer|bank account|routing/i,         title:"Financial instruction", desc:"Contains banking or transfer instructions — a primary BEC indicator.",          sev:"high",pts:25},
        {re:/click here|verify.*now|update.*now/i,         title:"Suspicious CTA",        desc:"Vague call-to-action designed to harvest credentials or install malware.",       sev:"med", pts:15},
        {re:/confidential|bypass|do not (?:tell|discuss)/, title:"Secrecy demand",        desc:"Attempts to isolate the victim from colleagues who might raise alarms.",        sev:"high",pts:20},
        {re:/password.{0,20}(?:expire|reset|update)/i,     title:"Credential harvesting", desc:"Prompts the user to submit or reset credentials.",                              sev:"high",pts:25},
        {re:/\d{3}[-.]?\d{3}[-.]?\d{4}/,                  title:"Callback number",       desc:"TOAD indicator — phone number present for a social engineering callback.",       sev:"med", pts:15},
      ];
      const fired=RULES.filter(r=>r.re.test(text));
      const score=Math.min(100,fired.reduce((a,r)=>a+r.pts,0));
      setResult({
        score,emailText:text,
        verdict:score>=60?"Malicious":score>=25?"Suspicious":"Likely Safe",
        attack_type:"Unknown",
        recommended_action:score>=60?"Escalate immediately to Tier 2 and quarantine the mailbox.":score>=25?"Forward to the security team for further review.":"Archive — no immediate action required.",
        analysis:"AI analysis unavailable — rule-based heuristic fallback applied. Results may be less accurate than AI-powered analysis.",
        flags:fired.map(r=>({title:r.title,desc:r.desc,severity:r.sev,pts:r.pts})),
        cognitive_triggers:[],ioc_summary:"Automated rule engine only — no deep IOC analysis.",
        sender_analysis:"Unable to perform sender reputation analysis in offline mode.",
        urgency_level:score>=60?"Critical":score>=25?"Medium":"Low",_fallback:true,
      });
      setErrorMsg("AI analysis unavailable — rule-based fallback applied.");
    }finally{setLoading(false);}
  }

  const urls=result?extractURLs(result.emailText).map(dissectURL).filter(Boolean):[];

  return(
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",height:"calc(100vh - 48px)",overflow:"hidden"}}>
      <style>{`.hl-d{background:rgba(232,65,42,0.16);border-bottom:1px solid rgba(232,65,42,0.4);border-radius:2px;cursor:help}.hl-w{background:rgba(224,152,32,0.16);border-bottom:1px solid rgba(224,152,32,0.4);border-radius:2px;cursor:help}@keyframes spin{to{transform:rotate(360deg)}}@keyframes pulse{0%,60%,100%{opacity:.1}30%{opacity:1}}@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}textarea::placeholder{color:#4a5068}::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#232733;border-radius:3px}`}</style>

      {/* Left – Input */}
      <div style={{borderRight:`1px solid ${T.b1}`,display:"flex",flexDirection:"column",overflow:"hidden"}}>
        <div style={{padding:"16px 22px",borderBottom:`1px solid ${T.b1}`,flexShrink:0,display:"flex",alignItems:"center",justifyContent:"space-between"}}>
          <div>
            <div style={{fontFamily:T.display,fontSize:15,fontWeight:600,color:T.text}}>Email Input</div>
            <div style={{fontSize:9,color:T.textDim,fontFamily:T.mono,letterSpacing:"0.1em",marginTop:2}}>PASTE RAW EMAIL CONTENT</div>
          </div>
          {result&&<Btn onClick={()=>{setResult(null);setEmail("");setErrorMsg(null);}} variant="ghost" style={{fontSize:10}}>↺ Reset</Btn>}
        </div>
        <div style={{padding:"12px 22px",borderBottom:`1px solid ${T.b1}`,flexShrink:0}}>
          <div style={{fontSize:9,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.12em",textTransform:"uppercase",marginBottom:8}}>Load sample scenario</div>
          <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
            {[["bec","BEC Wire Fraud"],["it","IT Credential Reset"],["mass","Mass Phishing"],["toad","TOAD Callback"]].map(([k,l])=>(
              <Btn key={k} onClick={()=>{setEmail(SAMPLES[k]);setResult(null);setErrorMsg(null);}} variant="ghost" style={{fontSize:10,padding:"5px 11px"}}>{l}</Btn>
            ))}
          </div>
        </div>
        <div style={{flex:1,padding:"16px 22px",display:"flex",flexDirection:"column",gap:12,overflow:"hidden"}}>
          <textarea value={email} onChange={e=>setEmail(e.target.value)}
            placeholder={"Paste raw email — headers, body, URLs, everything...\n\nThe more context you provide, the more accurate the AI analysis."}
            style={{flex:1,padding:"14px",background:T.panel,border:`1px solid ${T.b2}`,borderRadius:4,color:T.text,fontFamily:T.mono,fontSize:12,lineHeight:1.8,resize:"none",outline:"none"}}/>
          {errorMsg&&<div style={{padding:"8px 12px",background:T.amberBg,border:`1px solid ${T.amberRing}`,borderRadius:3,fontSize:10,fontFamily:T.mono,color:T.amberL}}>⚠ {errorMsg}</div>}
          <Btn onClick={runAnalysis} disabled={loading||!email.trim()} variant="primary" style={{width:"100%",justifyContent:"center",padding:"12px",fontSize:13,letterSpacing:"0.08em"}}>
            {loading?<><div style={{width:12,height:12,border:"2px solid rgba(255,255,255,.25)",borderTopColor:"#fff",borderRadius:"50%",animation:"spin .7s linear infinite"}}/>Analyzing…</>:<>▶ Run Threat Analysis</>}
          </Btn>
        </div>
      </div>

      {/* Right – Results */}
      <div style={{overflowY:"auto",background:T.bg}}>
        {!result&&!loading&&(
          <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",gap:14,opacity:0.25,userSelect:"none"}}>
            <TriageIdleIcon/>
            <div style={{fontFamily:T.mono,fontSize:10,color:T.textSub,letterSpacing:"0.16em"}}>AWAITING SUBMISSION</div>
          </div>
        )}
        {loading&&(
          <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",gap:20}}>
            <div style={{display:"flex",gap:7}}>
              {[0,.2,.4].map((d,i)=><div key={i} style={{width:8,height:8,borderRadius:"50%",background:T.red,animation:`pulse 1.3s ${d}s infinite`}}/>)}
            </div>
            <div style={{fontFamily:T.mono,fontSize:10,color:T.textDim,letterSpacing:"0.14em"}}>RUNNING THREAT ANALYSIS</div>
          </div>
        )}
        {result&&<TriageResult result={result} urls={urls}/>}
      </div>
    </div>
  );
}

function TriageResult({result,urls}){
  const s=result.score,vd=result.verdict,vc=verdictColor(vd);

  function exportReport(){
    const flags=(result.flags||[]).map(f=>`  [${(f.severity||"").toUpperCase().padEnd(4)}] ${f.title} (+${f.pts}pts)\n         ${f.desc}`).join("\n");
    const urlList=extractURLs(result.emailText).map(dissectURL).filter(Boolean);
    const urlBlock=urlList.map(u=>`  ${u.isSus?"[MALICIOUS]":"[CLEAN]   "} ${u.url}`).join("\n");
    const txt=[
      "╔═══════════════════════════════════════════════════════╗",
      "║           REDHOOK THREAT TRIAGE REPORT                ║",
      "║                Engine v2.0 · 2026                     ║",
      "╚═══════════════════════════════════════════════════════╝","",
      `GENERATED    : ${new Date().toISOString()}`,""
      ,"┌─ VERDICT ──────────────────────────────────────────────",
      `│ Verdict     : ${result.verdict.toUpperCase()}`,
      `│ Threat Score: ${s} / 100`,
      `│ Attack Type : ${result.attack_type}`,
      `│ Urgency     : ${result.urgency_level}`,
      `│ Action      : ${result.recommended_action}`,
      "└────────────────────────────────────────────────────────","",
      "┌─ ANALYST ASSESSMENT ───────────────────────────────────",
      `│ ${result.analysis}`,
      "└────────────────────────────────────────────────────────","",
      "┌─ IOC SUMMARY ──────────────────────────────────────────",
      `│ ${result.ioc_summary}`,
      "└────────────────────────────────────────────────────────","",
      `┌─ RED FLAGS (${(result.flags||[]).length}) ─────────────────────────────────`,
      flags||"  None triggered.",
      "└────────────────────────────────────────────────────────","",
      urlList.length?`┌─ URLS (${urlList.length}) ─────────────────────────────────────────\n${urlBlock}\n└────────────────────────────────────────────────────────`:"",
      "","Generated by Redhook · 2026",
    ].join("\n");
    const a=document.createElement("a");
    a.href=URL.createObjectURL(new Blob([txt],{type:"text/plain"}));
    a.download=`redhook-${vd.toLowerCase().replace(" ","-")}-${Date.now()}.txt`;
    a.click();
  }

  const Sec=({title,children})=>(
    <div style={{marginBottom:20}}>
      <div style={{fontSize:9,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.16em",textTransform:"uppercase",marginBottom:10,paddingBottom:8,borderBottom:`1px solid ${T.b1}`}}>{title}</div>
      {children}
    </div>
  );

  return(
    <div style={{padding:"22px 24px",display:"flex",flexDirection:"column",gap:20,animation:"fadeIn 0.3s ease"}}>
      {/* Verdict hero */}
      <div style={{background:vc.bg,border:`1px solid ${vc.ring}`,borderRadius:6,padding:"20px 22px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div style={{flex:1}}>
          <div style={{fontFamily:T.display,fontSize:30,fontWeight:700,color:vc.hi,letterSpacing:"-0.02em",lineHeight:1}}>{vd}</div>
          <div style={{fontSize:11,color:vc.dim,fontFamily:T.mono,marginTop:8,lineHeight:1.65,maxWidth:320}}>{result.recommended_action}</div>
          <div style={{display:"flex",gap:8,marginTop:12,flexWrap:"wrap"}}>
            <Tag label={result.attack_type} color={s>=60?"red":s>=25?"amber":"muted"}/>
            <Tag label={`Urgency: ${result.urgency_level}`} color={result.urgency_level==="Critical"?"red":result.urgency_level==="High"?"amber":"muted"}/>
            <Tag label={`${(result.flags||[]).length} flags triggered`} color={s>=60?"red":s>=25?"amber":"muted"}/>
          </div>
        </div>
        <div style={{display:"flex",flexDirection:"column",alignItems:"center"}}>
          <ScoreGauge score={s} size={80}/>
          <div style={{fontSize:9,fontFamily:T.mono,color:T.textDim,marginTop:4,letterSpacing:"0.1em"}}>THREAT SCORE</div>
        </div>
      </div>

      {/* AI Assessment */}
      <Sec title="AI Analyst Assessment">
        <div style={{fontSize:12,fontFamily:T.mono,color:T.textSub,lineHeight:1.85,background:T.panel,border:`1px solid ${T.b1}`,borderRadius:4,padding:"13px 15px",marginBottom:8}}>{result.analysis}</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
          {[["IOC Summary",result.ioc_summary],["Sender Analysis",result.sender_analysis]].map(([l,v])=>v&&(
            <div key={l} style={{padding:"10px 13px",background:T.panel,border:`1px solid ${T.b1}`,borderRadius:4,borderLeft:`2px solid ${T.b3}`}}>
              <div style={{fontSize:9,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:5}}>{l}</div>
              <div style={{fontSize:11,fontFamily:T.mono,color:T.textSub,lineHeight:1.6}}>{v}</div>
            </div>
          ))}
        </div>
      </Sec>

      {/* Cognitive triggers */}
      {(result.cognitive_triggers||[]).length>0&&(
        <Sec title="Cognitive Triggers">
          <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
            {result.cognitive_triggers.map(t=><Tag key={t} label={t} color="red"/>)}
          </div>
        </Sec>
      )}

      {/* URL Dissection */}
      {urls.length>0&&(
        <Sec title={`URL Dissection · ${urls.length} detected`}>
          {urls.map((u,i)=>(
            <div key={i} style={{background:T.panel,border:`1px solid ${u.isSus?T.redRing:T.b1}`,borderRadius:4,padding:"12px 14px",marginBottom:6}}>
              <div style={{fontSize:10,fontFamily:T.mono,color:T.textDim,marginBottom:8,wordBreak:"break-all"}}>{u.url}</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:4,marginBottom:8}}>
                {u.subs.map(s=><span key={s} style={{fontSize:10,padding:"2px 7px",borderRadius:2,background:"rgba(224,152,32,0.08)",color:T.amberL,border:`1px solid ${T.amberRing}`,fontFamily:T.mono}}>{s}</span>)}
                <span style={{fontSize:10,padding:"2px 8px",borderRadius:2,background:u.isSus?T.redBg:T.greenBg,color:u.isSus?T.redL:T.greenL,border:`1px solid ${u.isSus?T.redRing:T.greenRing}`,fontFamily:T.mono,fontWeight:700}}>{u.root}</span>
                <span style={{fontSize:10,padding:"2px 7px",borderRadius:2,background:T.blueBg,color:T.blue,border:"1px solid rgba(58,143,212,0.2)",fontFamily:T.mono}}>.{u.tld}</span>
                {u.path&&u.path!=="/"&&<span style={{fontSize:10,padding:"2px 7px",borderRadius:2,background:T.panel3,color:T.textDim,border:`1px solid ${T.b1}`,fontFamily:T.mono}}>{u.path.slice(0,50)}</span>}
              </div>
              <div style={{fontSize:10,color:u.isSus?T.redL:T.greenL,fontFamily:T.mono}}>{u.isSus?"⚠ Malicious root domain — read right-to-left to identify true host":"✓ Root domain appears legitimate"}</div>
            </div>
          ))}
        </Sec>
      )}

      {/* Flags */}
      <Sec title={`Red Flag Breakdown · ${(result.flags||[]).length} triggered`}>
        {(result.flags||[]).map((f,i)=>{
          const fc=f.severity==="high"?{bg:T.redBg,ring:T.redRing,text:T.redL,sub:"rgba(232,65,42,0.5)"}:f.severity==="med"?{bg:T.amberBg,ring:T.amberRing,text:T.amberL,sub:"rgba(224,152,32,0.5)"}:{bg:T.greenBg,ring:T.greenRing,text:T.greenL,sub:"rgba(43,181,106,0.5)"};
          return(
            <div key={i} style={{background:fc.bg,border:`1px solid ${fc.ring}`,borderRadius:4,padding:"12px 14px",marginBottom:6,borderLeft:`3px solid ${fc.text}`}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:5}}>
                <div style={{fontSize:12,fontWeight:600,color:fc.text,fontFamily:T.mono}}>{f.title}</div>
                <div style={{display:"flex",gap:6,alignItems:"center"}}>
                  <Tag label={(f.severity||"").toUpperCase()} color={f.severity==="high"?"red":f.severity==="med"?"amber":"green"}/>
                  <span style={{fontSize:10,fontFamily:T.mono,color:fc.sub,fontWeight:600}}>+{f.pts}pts</span>
                </div>
              </div>
              <div style={{fontSize:11,color:T.textDim,fontFamily:T.mono,lineHeight:1.65}}>{f.desc}</div>
            </div>
          );
        })}
        {!(result.flags||[]).length&&<div style={{padding:"14px",background:T.panel,border:`1px solid ${T.b1}`,borderRadius:4,fontSize:12,color:T.textDim,fontFamily:T.mono}}>No flags triggered.</div>}
      </Sec>

      {/* Annotated view */}
      <Sec title="Annotated Email">
        <div style={{background:T.panel,border:`1px solid ${T.b1}`,borderRadius:4,padding:"14px 16px",fontFamily:T.mono,fontSize:11.5,lineHeight:2,whiteSpace:"pre-wrap",wordBreak:"break-word",maxHeight:280,overflowY:"auto"}} dangerouslySetInnerHTML={annotateHTML(result.emailText)}/>
        <div style={{display:"flex",gap:8,marginTop:8}}>
          <span style={{fontSize:9,fontFamily:T.mono,padding:"2px 8px",borderRadius:2,background:"rgba(232,65,42,0.12)",border:`1px solid ${T.redRing}`,color:T.redL}}>■ High severity</span>
          <span style={{fontSize:9,fontFamily:T.mono,padding:"2px 8px",borderRadius:2,background:"rgba(224,152,32,0.12)",border:`1px solid ${T.amberRing}`,color:T.amberL}}>■ Medium severity</span>
        </div>
      </Sec>

      <Btn onClick={exportReport} variant="ghost" style={{alignSelf:"flex-start"}}>↓ Export Triage Report (.txt)</Btn>
    </div>
  );
}

// ── Intel ──────────────────────────────────────────────────────────────────────
function Intel(){
  const attacks=[["Credential Phishing",34,"red"],["BEC / Wire Fraud",24,"red"],["Mass Phishing",20,"amber"],["TOAD Callback",12,"amber"],["Spear Phishing",10,"muted"]];
  const triggers=[["Urgency / Deadline",29],["Authority / Executive",21],["Fear / Account Loss",18],["Scarcity / Exclusivity",12],["Social Proof",7]];
  const domains=[
    {d:"logins-updates.com",         hits:3,v:"Malicious", first:"2026-05-28",last:"2026-06-04"},
    {d:"amazon-secure-alerts.com",   hits:2,v:"Malicious", first:"2026-06-01",last:"2026-06-03"},
    {d:"execupdate-corp.com",        hits:2,v:"Malicious", first:"2026-05-30",last:"2026-06-04"},
    {d:"microsoftsupport-invoice.com",hits:1,v:"Suspicious",first:"2026-06-03",last:"2026-06-03"},
  ];
  const timeline=[
    {date:"Jun 04",mal:3,sus:2,safe:1},{date:"Jun 03",mal:5,sus:4,safe:3},
    {date:"Jun 02",mal:2,sus:2,safe:2},{date:"Jun 01",mal:4,sus:1,safe:2},
    {date:"May 31",mal:2,sus:2,safe:1},{date:"May 30",mal:1,sus:1,safe:2},{date:"May 29",mal:1,sus:0,safe:0},
  ];
  const maxVol=Math.max(...timeline.map(d=>d.mal+d.sus+d.safe));
  return(
    <div style={{padding:"28px 32px"}}>
      <div style={{marginBottom:28}}>
        <h1 style={{fontFamily:T.display,fontSize:22,fontWeight:700,color:T.text,letterSpacing:"-0.02em",margin:0}}>Threat Intelligence</h1>
        <p style={{fontFamily:T.mono,fontSize:10,color:T.textDim,letterSpacing:"0.1em",margin:"5px 0 0",textTransform:"uppercase"}}>Pattern Analysis</p>
      </div>
      {/* Timeline */}
      <div style={{background:T.panel,border:`1px solid ${T.b1}`,borderRadius:6,padding:"18px 20px",marginBottom:16}}>
        <SectionHeader label="Volume Timeline" sub="7-day email threat volume"/>
        <div style={{display:"flex",gap:6,alignItems:"flex-end",height:100}}>
          {timeline.map(d=>{
            const total=d.mal+d.sus+d.safe;
            return(
              <div key={d.date} style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",gap:4}}>
                <div style={{width:"100%",display:"flex",flexDirection:"column",height:84,justifyContent:"flex-end",borderRadius:3,overflow:"hidden"}}>
                  {[["mal",d.mal,T.red],["sus",d.sus,T.amber],["safe",d.safe,T.green]].map(([k,v,c])=>v>0&&<div key={k} style={{width:"100%",height:`${v/maxVol*100}%`,background:c,opacity:0.75}}/>)}
                  {total===0&&<div style={{height:"100%",background:T.b1}}/>}
                </div>
                <div style={{fontSize:8,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.06em"}}>{d.date}</div>
              </div>
            );
          })}
        </div>
        <div style={{display:"flex",gap:14,marginTop:10}}>
          {[["Malicious",T.red],["Suspicious",T.amber],["Likely Safe",T.green]].map(([l,c])=>(
            <span key={l} style={{fontSize:9,fontFamily:T.mono,color:T.textDim,display:"flex",alignItems:"center",gap:5}}>
              <span style={{width:8,height:8,borderRadius:1,background:c,opacity:0.75,display:"inline-block"}}/>{l}
            </span>
          ))}
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
        <div style={{background:T.panel,border:`1px solid ${T.b1}`,borderRadius:6,padding:"18px 20px"}}>
          <SectionHeader label="Attack Vector Distribution"/>
          {attacks.map(([t,p,c])=>(
            <div key={t} style={{marginBottom:13}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:5}}>
                <span style={{fontSize:12,fontFamily:T.mono,color:T.text}}>{t}</span>
                <span style={{fontSize:11,fontFamily:T.mono,fontWeight:600,color:c==="red"?T.redL:c==="amber"?T.amberL:T.textSub}}>{p}%</span>
              </div>
              <MiniBar value={p} color={c==="red"?T.red:c==="amber"?T.amber:T.textDim}/>
            </div>
          ))}
        </div>
        <div style={{background:T.panel,border:`1px solid ${T.b1}`,borderRadius:6,padding:"18px 20px"}}>
          <SectionHeader label="Cognitive Trigger Frequency"/>
          {triggers.map(([t,n])=>(
            <div key={t} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"9px 0",borderBottom:`1px solid ${T.b1}`}}>
              <span style={{fontSize:12,fontFamily:T.mono,color:T.text}}>{t}</span>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <div style={{width:60,height:2,background:T.b2,borderRadius:1,overflow:"hidden"}}>
                  <div style={{height:"100%",width:`${(n/29)*100}%`,background:T.red,borderRadius:1}}/>
                </div>
                <span style={{fontSize:10,fontFamily:T.mono,color:T.redL,minWidth:22,textAlign:"right"}}>{n}×</span>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div style={{background:T.panel,border:`1px solid ${T.b1}`,borderRadius:6,overflow:"hidden"}}>
        <div style={{padding:"14px 20px",borderBottom:`1px solid ${T.b1}`}}>
          <SectionHeader label="Observed Malicious Domains" sub="Active IOC watchlist"/>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 60px 145px 110px 110px",padding:"8px 20px",borderBottom:`1px solid ${T.b2}`,gap:12,background:T.panel2}}>
          {["Domain","Hits","Status","First Seen","Last Seen"].map(h=><div key={h} style={{fontSize:9,fontFamily:T.mono,color:T.textDim,letterSpacing:"0.1em",textTransform:"uppercase"}}>{h}</div>)}
        </div>
        {domains.map((d,i)=>(
          <div key={d.d} style={{display:"grid",gridTemplateColumns:"1fr 60px 145px 110px 110px",padding:"12px 20px",gap:12,borderBottom:i<domains.length-1?`1px solid ${T.b1}`:"none",alignItems:"center"}}>
            <div style={{fontFamily:T.mono,fontSize:12,color:T.redL,fontWeight:500}}>{d.d}</div>
            <div style={{fontFamily:T.mono,fontSize:12,color:T.textSub,fontWeight:600}}>{d.hits}</div>
            <Badge verdict={d.v}/>
            <div style={{fontFamily:T.mono,fontSize:10,color:T.textDim}}>{d.first}</div>
            <div style={{fontFamily:T.mono,fontSize:10,color:T.textDim}}>{d.last}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Settings ───────────────────────────────────────────────────────────────────
function Settings(){
  const [mal,setMal]=useState(60);
  const [sus,setSus]=useState(25);
  const [notifs,setNotifs]=useState({email:true,escalation:true,weekly:false});
  const [saved,setSaved]=useState(false);
  function save(){setSaved(true);setTimeout(()=>setSaved(false),2000);}
  const thresholds=[
    {label:"Malicious Threshold",desc:"Emails scoring at or above this value are classified as Malicious",val:mal,set:setMal,color:T.redL},
    {label:"Suspicious Threshold",desc:"Scores at or above this (but below Malicious) classify as Suspicious",val:sus,set:setSus,color:T.amberL},
  ];
  const notifItems=[
    {key:"email",     label:"Email alerts on escalation",  desc:"Send analyst email when a case is escalated"},
    {key:"escalation",label:"Real-time escalation ping",   desc:"Instant notification for Critical-urgency cases"},
    {key:"weekly",    label:"Weekly digest report",         desc:"Summarised threat report every Monday 08:00 UTC"},
  ];
  const engineInfo=[
    ["Engine","Redhook v2.0 · AI-Powered"],
    ["AI Backend","Gemini 2.0 Flash"],
    ["Triage Mode","Auto-triage with rule-based fallback"],
  ];
  const Panel=({title,sub,children})=>(
    <div style={{background:T.panel,border:`1px solid ${T.b1}`,borderRadius:6,overflow:"hidden",marginBottom:14}}>
      <div style={{padding:"14px 20px",borderBottom:`1px solid ${T.b1}`}}>
        <div style={{fontFamily:T.display,fontSize:13,fontWeight:600,color:T.text}}>{title}</div>
        {sub&&<div style={{fontSize:10,color:T.textDim,fontFamily:T.mono,marginTop:3}}>{sub}</div>}
      </div>
      {children}
    </div>
  );
  return(
    <div style={{padding:"28px 32px",maxWidth:640}}>
      <div style={{marginBottom:28}}>
        <h1 style={{fontFamily:T.display,fontSize:22,fontWeight:700,color:T.text,letterSpacing:"-0.02em",margin:0}}>Settings</h1>
        <p style={{fontFamily:T.mono,fontSize:10,color:T.textDim,letterSpacing:"0.1em",margin:"5px 0 0",textTransform:"uppercase"}}>Engine Configuration</p>
      </div>
      <Panel title="Classification Thresholds" sub="Adjust scoring cutoffs used to classify incoming emails">
        {thresholds.map((t,i)=>(
          <div key={t.label} style={{padding:"18px 20px",borderBottom:i<thresholds.length-1?`1px solid ${T.b1}`:"none"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
              <div>
                <div style={{fontSize:13,fontFamily:T.mono,fontWeight:600,color:T.text}}>{t.label}</div>
                <div style={{fontSize:10,color:T.textDim,fontFamily:T.mono,marginTop:3}}>{t.desc}</div>
              </div>
              <div style={{fontFamily:T.display,fontSize:28,fontWeight:700,color:t.color,minWidth:48,textAlign:"right"}}>{t.val}</div>
            </div>
            <input type="range" min={0} max={100} step={1} value={t.val} onChange={e=>t.set(Number(e.target.value))} style={{width:"100%",accentColor:t.color}}/>
            <div style={{display:"flex",justifyContent:"space-between"}}>
              <span style={{fontSize:9,fontFamily:T.mono,color:T.textDim}}>0</span>
              <span style={{fontSize:9,fontFamily:T.mono,color:T.textDim}}>100</span>
            </div>
          </div>
        ))}
      </Panel>
      <Panel title="Notifications" sub="Alert preferences for analyst workflow">
        {notifItems.map((n,i)=>(
          <div key={n.key} style={{padding:"14px 20px",borderBottom:i<notifItems.length-1?`1px solid ${T.b1}`:"none",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <div>
              <div style={{fontSize:12,fontFamily:T.mono,color:T.text}}>{n.label}</div>
              <div style={{fontSize:10,color:T.textDim,fontFamily:T.mono,marginTop:2}}>{n.desc}</div>
            </div>
            <button onClick={()=>setNotifs(p=>({...p,[n.key]:!p[n.key]}))} style={{width:36,height:20,borderRadius:10,border:"none",cursor:"pointer",background:notifs[n.key]?T.green:T.panel3,position:"relative",transition:"background 0.2s",flexShrink:0}}>
              <span style={{position:"absolute",top:2,left:notifs[n.key]?18:2,width:16,height:16,borderRadius:"50%",background:"#fff",transition:"left 0.2s",display:"block"}}/>
            </button>
          </div>
        ))}
      </Panel>
      <Panel title="Engine Information">
        {engineInfo.map(([l,v])=>(
          <div key={l} style={{padding:"12px 20px",borderBottom:`1px solid ${T.b1}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <div style={{fontSize:11,fontFamily:T.mono,color:T.textDim}}>{l}</div>
            <div style={{fontSize:11,fontFamily:T.mono,color:T.textSub}}>{v}</div>
          </div>
        ))}
      </Panel>
      <Btn onClick={save} variant="primary" style={{padding:"10px 24px"}}>{saved?"✓ Saved":"Save Configuration"}</Btn>
    </div>
  );
}

// ── App Shell ──────────────────────────────────────────────────────────────────
export default function App(){
  const [page,setPage]=useState("dashboard");
  useEffect(()=>{
    const link=document.createElement("link");
    link.rel="stylesheet";
    link.href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@400;600;700&family=DM+Sans:wght@400;500&display=swap";
    document.head.appendChild(link);
    document.body.style.margin="0";
  },[]);
  return(
    <div style={{display:"flex",height:"100vh",background:T.bg,color:T.text,fontFamily:T.mono,overflow:"hidden"}}>
      <Sidebar page={page} setPage={setPage}/>
      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",minWidth:0}}>
        <Topbar page={page}/>
        <div style={{flex:1,overflowY:page==="triage"?"hidden":"auto"}}>
          {page==="dashboard"&&<Dashboard onNavigate={setPage}/>}
          {page==="triage"&&<Triage/>}
          {page==="cases"&&<Cases onNavigate={setPage}/>}
          {page==="intel"&&<Intel/>}
          {page==="settings"&&<Settings/>}
        </div>
      </div>
    </div>
  );
}
