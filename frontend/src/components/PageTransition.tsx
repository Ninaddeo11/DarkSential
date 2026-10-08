import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import type { ReactNode } from 'react';

export function PageTransition({id,children,className=''}:{id:string;children:ReactNode;className?:string}){
  const reduced=useReducedMotion();
  return <AnimatePresence mode="wait" initial={false}><motion.div key={id} className={className} initial={reduced?false:{opacity:0,y:7,filter:'blur(2px)'}} animate={{opacity:1,y:0,filter:'blur(0px)'}} exit={reduced?{opacity:1}:{opacity:0,y:-4,filter:'blur(1px)'}} transition={{duration:reduced?0:.22,ease:'easeOut'}}>{children}</motion.div></AnimatePresence>;
}
