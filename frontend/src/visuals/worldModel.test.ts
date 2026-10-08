import { describe, expect, it } from 'vitest';
import { WORLD_ARTIFACTS, visibleArtifacts, worldLayer } from './worldModel';

describe('persistent world configuration',()=>{
  it('keeps stable artifact identities and valid bounded procedural motion',()=>{
    expect(new Set(WORLD_ARTIFACTS.map(a=>a.id)).size).toBe(WORLD_ARTIFACTS.length);
    for(const a of WORLD_ARTIFACTS){
      expect([...a.position,...a.rotation,...a.velocity,a.scale,a.amplitude,a.frequency,a.opacity].every(Number.isFinite)).toBe(true);
      expect(a.scale).toBeGreaterThan(0);expect(a.opacity).toBeGreaterThan(0);expect(a.opacity).toBeLessThanOrEqual(1);
      expect(a.amplitude).toBeLessThan(.3);expect(a.frequency).toBeLessThan(.3);
    }
    expect(new Set(WORLD_ARTIFACTS.map(a=>a.position[2])).size).toBeGreaterThan(5);
  });
  it('reduces density while retaining core research subjects and existing object identities',()=>{
    const mobile=visibleArtifacts('mobile'),tablet=visibleArtifacts('tablet'),desktop=visibleArtifacts('desktop');
    expect(mobile.length).toBeLessThan(tablet.length);expect(tablet.length).toBeLessThan(desktop.length);
    for(const category of ['weapons','narcotics','trafficking','infrastructure','crypto','malware'])expect(mobile.some(a=>a.category===category)).toBe(true);
    mobile.forEach(a=>expect(desktop.includes(a)).toBe(true));
  });
  it('maps entry and public aliases while keeping operational routes in the same world',()=>{
    expect(worldLayer('/')).toBe(worldLayer('/landing'));
    expect(worldLayer('/access')).toBe(worldLayer('/login'));
    for(const route of ['/dashboard','/overview','/devices','/devices/test-node','/events','/response','/evaluation','/dark-web','/intel'])expect(worldLayer(route)).toBe('operations');
  });
});
