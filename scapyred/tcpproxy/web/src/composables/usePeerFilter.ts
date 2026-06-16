import { reactive, ref } from 'vue'

// Module-level singleton — shared between PeersPanel and EventsPanel
const enabledPeers = reactive(new Set<string>())
const knownPeers = new Set<string>()
const onlinePeers = reactive(new Set<string>())
const peerRefreshTick = ref(0)

export function usePeerFilter() {
  function registerPeer(ip: string): void {
    if (!knownPeers.has(ip)) {
      knownPeers.add(ip)
      enabledPeers.add(ip)  // enabled by default on first sight only
    }
  }

  function togglePeer(ip: string, enabled: boolean): void {
    if (enabled) enabledPeers.add(ip)
    else enabledPeers.delete(ip)
  }

  function isPeerEnabled(ip: string): boolean {
    return enabledPeers.has(ip)
  }

  function isPeerKnown(ip: string): boolean {
    return knownPeers.has(ip)
  }

  function setPeerOnline(ip: string): void {
    onlinePeers.add(ip)
  }

  function setPeerOffline(ip: string): void {
    onlinePeers.delete(ip)
  }

  function isPeerOnline(ip: string): boolean {
    return onlinePeers.has(ip)
  }

  function selectAll(): void {
    knownPeers.forEach(ip => enabledPeers.add(ip))
  }

  function deselectAll(): void {
    enabledPeers.clear()
  }

  function triggerRefresh(): void {
    peerRefreshTick.value++
  }

  return { enabledPeers, registerPeer, togglePeer, isPeerEnabled, isPeerKnown, isPeerOnline, setPeerOnline, setPeerOffline, selectAll, deselectAll, peerRefreshTick, triggerRefresh }
}
