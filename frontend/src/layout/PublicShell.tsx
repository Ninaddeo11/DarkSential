import { Link, NavLink, Outlet, useLocation } from "react-router";
import { useEffect, useRef } from "react";
import { Brand } from "../components/Brand";
import { PageTransition } from "../components/PageTransition";
import { NexusEntry } from "../components/NexusEntry";

export function PublicShell() {
  const box=useRef<HTMLElement>(null);
  const {pathname}=useLocation();
  useEffect(()=>{box.current?.scrollTo({top:0,behavior:'instant'});},[pathname]);
  useEffect(()=>{
    const glyphs=[...document.querySelectorAll<HTMLElement>('.evidence-glyph')];
    const visible=new Set<Element>();
    const update=()=>glyphs.forEach(el=>{el.style.animationPlayState=!document.hidden&&visible.has(el)?'running':'paused';});
    const observer=new IntersectionObserver(entries=>{entries.forEach(entry=>entry.isIntersecting?visible.add(entry.target):visible.delete(entry.target));update();});
    glyphs.forEach(el=>observer.observe(el));
    document.addEventListener('visibilitychange',update);
    return ()=>{observer.disconnect();document.removeEventListener('visibilitychange',update);};
  },[pathname]);
  return <div className="public-shell"><a className="skip-link" href="#public-main">Skip to content</a><header className="public-header"><Brand /><nav aria-label="Public navigation"><NavLink to="/" end>Platform</NavLink><NavLink to="/intelligence">Intelligence</NavLink><NavLink to="/about">About</NavLink></nav><NexusEntry className="entry-small" /></header><main ref={box} id="public-main" className="public-main scroll-thin"><PageTransition id={pathname} className="public-route"><Outlet /></PageTransition><footer className="public-footer"><Brand /><p>Evidence before attribution.<br />Intelligence before action.</p><nav aria-label="Footer navigation"><Link to="/intelligence">Research scope</Link><Link to="/about">Mission briefing</Link><Link to="/overview">Operations</Link></nav><span>MONITORING / ANALYSIS / DEFENSE</span></footer></main></div>;
}
