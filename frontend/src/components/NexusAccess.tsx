import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router';
import { useLive } from '../live/LiveContext';

/** Same token/OIDC authentication as the operational header, in a dedicated entry surface. */
export function NexusAccess({embedded=false}:{embedded?:boolean}){
  const {login,me,health}=useLive();
  const navigate=useNavigate();
  const [secret,setSecret]=useState('');
  const [error,setError]=useState<string|null>(null);
  const [pending,setPending]=useState(false);
  const authenticated=me&&me.source!=='anonymous';
  const disabled=me?.login_enabled===false;
  const submit=async(e:FormEvent)=>{
    e.preventDefault();if(pending)return;
    setPending(true);setError(null);
    try{await login(secret);setSecret('');if(!embedded)navigate('/overview');}
    catch(err){setError(err instanceof Error?err.message:String(err));}
    finally{setPending(false);}
  };
  return <section className={`nexus-access ${embedded?'access-embedded':''}`} aria-labelledby={embedded?'embedded-access-title':'access-title'}>
    <svg className="access-insignia" width="48" height="48" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2l9 5v10l-9 5-9-5V7zM12 7v10M7 10l5-3 5 3M7 14l5 3 5-3" fill="none" stroke="currentColor" strokeWidth=".9" /></svg>
    <p className="section-eyebrow">IDENTITY / VERIFICATION / ACCESS</p>
    <h1 id={embedded?'embedded-access-title':'access-title'}>Nexus access<span className="hero-mark">.</span></h1>
    <p className="access-state">{authenticated?'SESSION VERIFIED':disabled?'READ-ONLY ACCESS':'AUTHENTICATION REQUIRED'}</p>
    <p className="access-description">{authenticated?'Your authenticated intelligence workspace is ready.':disabled?'This deployment provides a read-only workspace. Authentication is not configured.':'Enter your viewer, operator, or OIDC access token to open the intelligence workspace.'}</p>
    {authenticated||disabled?<Link className="nexus-entry" to="/overview">Enter the workspace <span aria-hidden="true">↗</span></Link>:<form onSubmit={submit}><label htmlFor={embedded?'embedded-token':'access-token'}>ACCESS TOKEN</label><input id={embedded?'embedded-token':'access-token'} type="password" autoComplete="current-password" className="input" placeholder="Your access token" value={secret} onChange={e=>setSecret(e.target.value)} required disabled={pending} aria-describedby={error?'access-error':undefined} /><button className="nexus-entry" type="submit" disabled={pending||!secret.trim()}>{pending?'Verifying access':'Authenticate'}<span aria-hidden="true">↗</span></button>{error&&<p id="access-error" className="access-error" role="alert">{error}</p>}</form>}
    <div className="access-footnote"><span className="status-dot" /><span>{health?'SYSTEM REACHABLE':'CONNECTION NOT VERIFIED'} / SESSION-BASED ACCESS</span></div>
  </section>;
}
