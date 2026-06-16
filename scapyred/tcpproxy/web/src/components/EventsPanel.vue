<template>
    <v-card color="surface-variant" rounded="lg" variant="tonal" class="d-flex flex-column fill-height">
        <v-card-title class="d-flex align-center pa-4 pb-2">
            <span class="text-h6 font-weight-bold">Events</span>
            <v-spacer />
            <v-chip size="small" :color="connected ? 'success' : 'error'"
                :prepend-icon="connected ? 'mdi-circle' : 'mdi-circle-off-outline'" label class="mr-2">
                {{ connected ? 'Live' : 'Disconnected' }}
            </v-chip>
            <v-btn icon="mdi-delete-sweep" size="small" variant="text" title="Clear events" @click="events = []" />
        </v-card-title>

        <v-divider />

        <v-card-text ref="scrollContainer" class="flex-grow-1 overflow-y-auto pa-3 fill-height">
            <div v-if="filteredEvents.length === 0" class="text-center text-medium-emphasis py-8">
                <v-icon icon="mdi-broadcast-off" size="48" class="mb-2 d-block mx-auto" />
                Waiting for events…
            </div>

            <div v-for="(evt, i) in filteredEvents" :key="i" class="event-row d-flex align-start">
                <span class="event-time text-caption text-medium-emphasis font-mono mr-3 flex-shrink-0 pt-px">
                    {{ evt.time }}
                </span>
                <span :class="['event-text', 'text-body-2', 'font-mono', evt.type ? `text-${evt.type}` : '']">
                    {{ evt.text }}
                </span>
            </div>
        </v-card-text>
    </v-card>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { usePeerFilter } from '@/composables/usePeerFilter'

const API_BASE = 'http://127.0.0.1:8888'

const { isPeerEnabled, isPeerKnown, triggerRefresh, setPeerOnline, setPeerOffline } = usePeerFilter()

interface EventEntry {
    text: string
    type: 'client' | 'server' | 'special' | 'error' | ''
    peer: string
    time: string
}

const events = ref<EventEntry[]>([])
const filteredEvents = computed(() =>
    events.value.filter(evt => !evt.peer || isPeerEnabled(evt.peer))
)
const connected = ref(false)
const scrollContainer = ref<{ $el: HTMLElement } | null>(null)

let running = false
let abortController: AbortController | null = null

function formatTime(d: Date): string {
    return d.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    })
}

async function scrollToBottom(): Promise<void> {
    await nextTick()
    const el = scrollContainer.value?.$el ?? (scrollContainer.value as unknown as HTMLElement | null)
    if (el) {
        el.scrollTop = el.scrollHeight
    }
}

async function pollLoop(): Promise<void> {
    running = true
    while (running) {
        abortController = new AbortController()
        try {
            const res = await fetch(`${API_BASE}/event`, { signal: abortController.signal })
            connected.value = res.ok
            if (res.ok) {
                const event: { type: string; text?: string; peer: string } | null = await res.json()
                if (event !== null) {
                    if (event.type === 'newpeer') {
                        setPeerOnline(event.peer)
                        triggerRefresh()
                        continue
                    }
                    if (event.type === 'deadpeer') {
                        setPeerOffline(event.peer)
                        continue
                    }
                    if (event.peer && !isPeerKnown(event.peer)) {
                        triggerRefresh()
                    }
                    events.value.push({
                        text: event.text ?? '',
                        type: event.type as EventEntry['type'],
                        peer: event.peer ?? '',
                        time: formatTime(new Date()),
                    })
                    await scrollToBottom()
                    // event received – loop immediately for next one
                    continue
                }
            }
        } catch (err: unknown) {
            if ((err as Error).name === 'AbortError') break
            connected.value = false
            // Wait before retrying so we don't spam the console when the backend is down
            await new Promise<void>((resolve) => setTimeout(resolve, 2000))
        }
    }
}

onMounted(() => {
    pollLoop()
})

onUnmounted(() => {
    running = false
    abortController?.abort()
})
</script>

<style scoped>
.font-mono {
    font-family: monospace;
}

.event-row {
    padding: 3px 0;
    border-bottom: 1px solid rgba(128, 128, 128, 0.08);
    line-height: 1.5;
}

.event-row:last-child {
    border-bottom: none;
}

.event-time {
    min-width: 7ch;
    user-select: none;
}

/* Direction colouring – uses CSS custom properties so it works across light/dark themes */
.text-client {
    color: rgb(var(--v-theme-info));
}

.text-server {
    color: rgb(var(--v-theme-success));
}

.text-special {
    color: rgb(var(--v-theme-secondary));
}

.text-error {
    color: rgb(var(--v-theme-error));
}
</style>
