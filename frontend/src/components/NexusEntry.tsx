import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { useLive } from "../live/LiveContext";

export function NexusEntry({ className = "", children = "Enter the Nexus" }: { className?: string; children?: React.ReactNode }) {
  const navigate=useNavigate();
  const {authNeeded}=useLive();
  const [entering,setEntering]=useState(false);
  const timer=useRef<number|undefined>(undefined);
  useEffect(()=>()=>window.clearTimeout(timer.current),[]);
  const enter=()=>{
    let seen=false;
    try {seen=sessionStorage.getItem('dsn.interface-intro')==='seen';} catch { /* unavailable storage */ }
    const destination=authNeeded?'/access':'/overview';
    if(seen||window.matchMedia('(prefers-reduced-motion: reduce)').matches){navigate(destination);return;}
    try {sessionStorage.setItem('dsn.interface-intro','seen');} catch { /* unavailable storage */ }
    setEntering(true);
    timer.current=window.setTimeout(()=>navigate(destination),600);
  };
  return <><button className={`nexus-entry ${className}`} onClick={enter} disabled={entering}>{children}<span aria-hidden="true">&#8599;</span></button>{entering&&<div className="nexus-entry-transition" role="status" aria-live="polite"><span className="entry-symbol" aria-hidden="true">◇</span><strong>ENTERING THE NEXUS</strong><p>Opening the intelligence workspace</p><span className="entry-progress" /></div>}</>;
}
