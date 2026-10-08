import { describe, expect, it } from 'vitest';
import { graphFromPaths } from './model';
import type { PathStep } from '../api/types';
const a: PathStep = {node_id:'indicator-1', label:'Indicator', name:'Observed indicator', via:null};
const b: PathStep = {node_id:'malware-1', label:'Malware', name:'Sample family', via:'INDICATES'};
const c: PathStep = {node_id:'actor-1', label:'IntrusionSet', name:'Sample actor', via:'USES'};
describe('evidence graph projection', () => {
  it('preserves backend identities and relationship labels while deduplicating paths', () => {
    const graph = graphFromPaths([[a,b,c],[a,b]]);
    expect(graph.nodes.map(n=>n.id)).toEqual(['indicator-1','malware-1','actor-1']);
    expect(graph.edges).toEqual([{source:a.node_id,target:b.node_id,label:'INDICATES'},{source:b.node_id,target:c.node_id,label:'USES'}]);
  });
  it('caps visible objects without creating dangling or inferred relationships', () => {
    const graph = graphFromPaths([[a,b,c]],2);
    expect(graph.nodes).toHaveLength(2);
    expect(graph.edges).toEqual([{source:a.node_id,target:b.node_id,label:'INDICATES'}]);
    expect(graphFromPaths([[a],[c]]).edges).toEqual([]);
    expect(graphFromPaths([])).toEqual({nodes:[],edges:[]});
  });
});
