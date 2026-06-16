<template>
    <v-card color="surface-variant" rounded="lg" variant="tonal" class="d-flex flex-column fill-height">
        <v-card-title class="d-flex align-center pa-4 pb-2">
            <span class="text-h6 font-weight-bold">Peers</span>
            <v-spacer />
            <v-btn icon="mdi-checkbox-multiple-marked" size="small" variant="text" title="Select all"
                @click="selectAll" />
            <v-btn icon="mdi-checkbox-multiple-blank-outline" size="small" variant="text" title="Deselect all"
                @click="deselectAll" />
        </v-card-title>

        <v-divider />

        <v-card-text class="flex-grow-1 overflow-y-auto pa-3">
            <div v-if="Object.keys(peers).length === 0" class="text-center text-medium-emphasis py-8">
                <v-icon icon="mdi-lan-disconnect" size="48" class="mb-2 d-block mx-auto" />
                No peers connected
            </div>

            <v-card v-for="(peer, ip) in peers" :key="ip" class="mb-3 position-relative" variant="outlined" rounded="lg">
                <v-icon
                    :icon="isPeerOnline(String(ip)) ? 'mdi-circle' : 'mdi-circle-outline'"
                    :color="isPeerOnline(String(ip)) ? 'success' : 'error'"
                    :title="isPeerOnline(String(ip)) ? 'Online' : 'Offline'"
                    size="10"
                    class="peer-status-dot"
                />
                <v-card-item>
                    <template #title>
                        <span class="font-weight-bold font-mono">{{ ip }}</span>
                    </template>
                    <template #append>
                        <v-checkbox :model-value="isPeerEnabled(String(ip))" hide-details density="compact"
                            color="primary" title="Include in event log"
                            @update:model-value="(val) => togglePeer(String(ip), !!val)" />
                    </template>
                    <template #subtitle>
                        <div class="d-flex align-center flex-wrap gap-2 mt-1">
                            <v-chip size="small" :color="stateColor(peer.state)" :prepend-icon="stateIcon(peer.state)"
                                label>
                                {{ stateName(peer.state) }}
                            </v-chip>
                            <span v-if="peer.state !== PeerState.FORWARD && peer.redirection.host"
                                class="text-caption font-mono text-medium-emphasis">
                                → {{ peer.redirection.host }}:{{ peer.redirection.port }}
                            </span>
                        </div>
                    </template>
                </v-card-item>

                <v-card-actions class="px-3 pt-0 pb-3 flex-wrap gap-1">
                    <v-btn size="small" color="success" variant="tonal" prepend-icon="mdi-arrow-right"
                        :disabled="peer.state === PeerState.FORWARD" @click="setForward(String(ip))">
                        Forward
                    </v-btn>
                    <v-btn size="small" color="warning" variant="tonal" prepend-icon="mdi-swap-horizontal"
                        @click="openRedirectDialog(String(ip), PeerState.REDIRECT_PERMANENT)">
                        Permanent Redirect
                    </v-btn>
                    <v-btn size="small" color="info" variant="tonal" prepend-icon="mdi-package-variant"
                        @click="openRedirectDialog(String(ip), PeerState.REDIRECT_ONCE)">
                        Temporary Redirect
                    </v-btn>
                </v-card-actions>
            </v-card>
        </v-card-text>
    </v-card>

    <!-- Redirect configuration dialog -->
    <v-dialog v-model="dialogOpen" max-width="420" :persistent="true">
        <v-card rounded="lg">
            <v-card-title class="pa-4 pb-2">
                <v-icon icon="mdi-swap-horizontal" class="mr-2" />
                Set Redirection
            </v-card-title>
            <v-card-subtitle class="px-4 pb-2">
                <v-chip size="small" color="primary" label class="mr-1">{{ dialogIp }}</v-chip>
                <v-chip size="small" :color="stateColor(dialogState)" label>{{ stateName(dialogState) }}</v-chip>
            </v-card-subtitle>
            <div class="px-4 pb-1 text-caption text-medium-emphasis">
                {{ dialogState === PeerState.REDIRECT_ONCE
                    ? 'This temporary redirect resets at the end of the next TCP session.'
                    : 'This permanent redirect stays active until you change it.' }}
            </div>

            <v-card-text class="pa-4">
                <v-text-field v-model="redirectHost" label="Host" placeholder="192.168.1.100"
                    prepend-inner-icon="mdi-server" variant="outlined" density="compact" class="mb-2" autofocus
                    @keyup.enter="redirectPort !== 0 && confirmRedirect()" />
                <v-text-field v-model.number="redirectPort" label="Port" placeholder="4444"
                    prepend-inner-icon="mdi-pound" variant="outlined" density="compact" type="number" :min="1"
                    :max="65535" @keyup.enter="redirectHost && confirmRedirect()" />
            </v-card-text>

            <v-card-actions class="pa-4 pt-0">
                <v-spacer />
                <v-btn variant="text" @click="dialogOpen = false">Cancel</v-btn>
                <v-btn color="primary" variant="tonal" :disabled="!redirectHost || !redirectPort"
                    @click="confirmRedirect">
                    Apply
                </v-btn>
            </v-card-actions>
        </v-card>
    </v-dialog>
</template>

<script lang="ts" setup>
import { ref, watch, onMounted, onUnmounted } from 'vue'
import { usePeerFilter } from '@/composables/usePeerFilter'

const API_BASE = 'http://127.0.0.1:8888'

const { registerPeer, togglePeer, isPeerEnabled, isPeerOnline, selectAll, deselectAll, peerRefreshTick } = usePeerFilter()

enum PeerState {
    FORWARD = 1,
    REDIRECT_PERMANENT = 2,
    REDIRECT_ONCE = 3,
}

interface PeerInfo {
    state: PeerState
    redirection: {
        host: string
        port: number
    }
}

const peers = ref<Record<string, PeerInfo>>({})

// Dialog state
const dialogOpen = ref(false)
const dialogIp = ref('')
const dialogState = ref<PeerState>(PeerState.REDIRECT_PERMANENT)
const redirectHost = ref('')
const redirectPort = ref<number>(0)

function stateColor(state: PeerState): string {
    switch (state) {
        case PeerState.FORWARD: return 'success'
        case PeerState.REDIRECT_PERMANENT: return 'warning'
        case PeerState.REDIRECT_ONCE: return 'info'
        default: return 'default'
    }
}

function stateIcon(state: PeerState): string {
    switch (state) {
        case PeerState.FORWARD: return 'mdi-arrow-right-circle'
        case PeerState.REDIRECT_PERMANENT: return 'mdi-link-lock'
        case PeerState.REDIRECT_ONCE: return 'mdi-link-variant-minus'
        default: return 'mdi-help-circle'
    }
}

function stateName(state: PeerState): string {
    switch (state) {
        case PeerState.FORWARD: return 'Forward'
        case PeerState.REDIRECT_PERMANENT: return 'Permanent Redirect'
        case PeerState.REDIRECT_ONCE: return 'Temporary Redirect'
        default: return 'Unknown'
    }
}

async function fetchPeers(): Promise<void> {
    try {
        const res = await fetch(`${API_BASE}/getpeers`)
        if (res.ok) {
            peers.value = await res.json()
            Object.keys(peers.value).forEach(registerPeer)
        }
    } catch {
        // Backend may not be reachable yet; silently retry on next event
    }
}

async function setPeerStatus(
    ip: string,
    state: PeerState,
    host?: string,
    port?: number,
): Promise<void> {
    const body: Record<string, unknown> = { peer: ip, state }
    if (host !== undefined && port !== undefined) {
        body.redirection = { host, port }
    }
    try {
        await fetch(`${API_BASE}/setpeerstatus`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        })
    } catch {
        // ignore
    }
    await fetchPeers()
}

async function setForward(ip: string): Promise<void> {
    await setPeerStatus(ip, PeerState.FORWARD)
}

function openRedirectDialog(ip: string, state: PeerState): void {
    dialogIp.value = ip
    dialogState.value = state
    const peer = peers.value[ip]
    redirectHost.value = peer?.redirection.host ?? ''
    redirectPort.value = peer?.redirection.port ?? 0
    dialogOpen.value = true
}

async function confirmRedirect(): Promise<void> {
    dialogOpen.value = false
    await setPeerStatus(
        dialogIp.value,
        dialogState.value,
        redirectHost.value,
        Number(redirectPort.value),
    )
}

onMounted(() => {
    fetchPeers()
    watch(peerRefreshTick, fetchPeers)
})

onUnmounted(() => {
})
</script>

<style scoped>
.font-mono {
    font-family: monospace;
}

.peer-status-dot {
    position: absolute;
    top: 8px;
    right: 8px;
}
</style>
