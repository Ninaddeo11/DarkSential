import { motion, useReducedMotion } from 'framer-motion';
import type { ReactNode } from 'react';

/** Animate presentation on updates without interpolating or inventing measured values. */
export function AnimatedValue({value}:{value:ReactNode}){
  const reduced=useReducedMotion();
  return <motion.span key={String(value)} style={{display:'inline-block',fontVariantNumeric:'tabular-nums'}} initial={reduced?false:{opacity:.45,y:3}} animate={{opacity:1,y:0}} transition={{duration:reduced?0:.25}}>{value}</motion.span>;
}
