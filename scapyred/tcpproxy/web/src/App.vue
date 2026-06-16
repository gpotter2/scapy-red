<template>
  <v-app>
    <v-main>
      <v-container fluid class="fill-height pa-4" style="max-width: 2000px;">
        <v-row class="fill-height" style="max-height: 95vh;">
          <v-col cols="12" md="4" class="d-flex flex-column fill-height">
            <PeersPanel class="flex-grow-1" />
          </v-col>
          <v-col cols="12" md="8" class="d-flex flex-column fill-height">
            <EventsPanel class="flex-grow-1" />
          </v-col>
        </v-row>
      </v-container>
    </v-main>

    <v-btn
      class="ma-2"
      icon="mdi-theme-light-dark"
      location="bottom right"
      position="absolute"
      @click="$vuetify.theme.cycle()"
    />
  </v-app>
</template>

<script lang="ts" setup>
import PeersPanel from './components/PeersPanel.vue'
import EventsPanel from './components/EventsPanel.vue'
</script>
