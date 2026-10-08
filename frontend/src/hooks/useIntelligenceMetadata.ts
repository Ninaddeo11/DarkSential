import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { FeedsStatus } from "../api/types";

/** Read-only graph metadata used by both public briefings and analyst workspaces. */
export function useIntelligenceMetadata() {
  const [counts,setCounts]=useState<Record<string,number>|null>(null);
  const [feeds,setFeeds]=useState<FeedsStatus|null>(null);
  const [error,setError]=useState<string|null>(null);
  useEffect(()=>{
    let cancelled=false;
    api.graphCounts().then(v=>{if(!cancelled)setCounts(v);}).catch(e=>{if(!cancelled)setError(e instanceof Error?e.message:String(e));});
    api.feeds().then(v=>{if(!cancelled)setFeeds(v);}).catch(()=>undefined);
    return()=>{cancelled=true;};
  },[]);
  return {counts,feeds,error};
}
