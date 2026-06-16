<template>
  <v-app>
    <v-main>
      <v-container class="fill-height d-flex flex-column justify-center" max-width="2000">
        <div>
          <v-row>
            <v-col cols="4">
              <v-card class="py-4" color="surface-variant" rounded="lg" variant="tonal">
                <template #title>
                  <div class="text-headline-medium font-weight-bold">Peers</div>
                </template>

              </v-card>
            </v-col>
            <v-col cols="8">
              <v-card class="py-4" color="surface-variant" rounded="lg" variant="tonal">
                <template #title>
                  <div class="text-headline-medium font-weight-bold">Trafic</div>
                </template>

                <template #subtitle>
                  <div class="text-body-large">
                    Change this page by updating <v-kbd>{{ `
                      <HelloWorld />` }}
                    </v-kbd> in <v-kbd>components/HelloWorld.vue</v-kbd>.
                  </div>
                </template>
              </v-card>
            </v-col>
          </v-row>
        </div>
      </v-container>
    </v-main>
    <v-btn class="ma-2" icon="mdi-theme-light-dark" location="top right" position="absolute"
      @click="$vuetify.theme.cycle()" />
  </v-app>
</template>

<script lang="ts" setup>
</script>
