<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'

/**
 * "By the numbers" strip for the landing page. Values count up once the
 * strip scrolls into view — measured claims, presented like instrument
 * readouts.
 */

interface Stat {
  value: number
  format: (n: number) => string
  label: string
  detail: string
}

const STATS: Stat[] = [
  {
    value: 100_000,
    format: (n) => `${Math.round(n / 1000)}k`,
    label: 'concurrent connections',
    detail: 'on one 8-core node',
  },
  {
    value: 13.8,
    format: (n) => n.toFixed(1),
    label: 'KB per connection',
    detail: 'resident, at full load',
  },
  {
    value: 29,
    format: (n) => `${Math.round(n)}`,
    label: 'IRCv3 capabilities',
    detail: 'negotiable via CAP',
  },
  {
    value: 0,
    format: () => '0',
    label: 'lines of unsafe',
    detail: 'forbidden workspace-wide',
  },
]

const shown = ref(STATS.map(() => 0))
const host = ref<HTMLElement | null>(null)
let raf = 0

function animate() {
  const t0 = performance.now()
  const DURATION = 1400
  const tick = (t: number) => {
    const p = Math.min((t - t0) / DURATION, 1)
    const ease = 1 - Math.pow(1 - p, 3)
    shown.value = STATS.map((s) => s.value * ease)
    if (p < 1) raf = requestAnimationFrame(tick)
  }
  raf = requestAnimationFrame(tick)
}

onMounted(() => {
  if (typeof IntersectionObserver === 'undefined') {
    shown.value = STATS.map((s) => s.value)
    return
  }
  const io = new IntersectionObserver(
    (entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        io.disconnect()
        animate()
      }
    },
    { threshold: 0.4 },
  )
  if (host.value) io.observe(host.value)
})

onUnmounted(() => cancelAnimationFrame(raf))
</script>

<template>
  <div ref="host" class="fx-stats">
    <div v-for="(s, i) in STATS" :key="s.label" class="fx-stat">
      <div class="fx-stat-value">{{ s.format(shown[i]) }}</div>
      <div class="fx-stat-label">{{ s.label }}</div>
      <div class="fx-stat-detail">{{ s.detail }}</div>
    </div>
  </div>
</template>

<style scoped>
.fx-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1px;
  max-width: 960px;
  margin: 3rem auto 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  overflow: hidden;
  background: var(--vp-c-divider);
}

.fx-stat {
  background: var(--vp-c-bg-soft);
  padding: 22px 20px 18px;
  text-align: center;
}

.fx-stat-value {
  font-family: var(--vp-font-family-mono);
  font-size: 34px;
  font-weight: 700;
  line-height: 1.1;
  letter-spacing: -0.03em;
  color: var(--vp-c-brand-1);
  font-variant-numeric: tabular-nums;
}

.fx-stat-label {
  margin-top: 6px;
  font-size: 13px;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.fx-stat-detail {
  margin-top: 2px;
  font-size: 12px;
  color: var(--vp-c-text-3);
  font-family: var(--vp-font-family-mono);
}

@media (max-width: 720px) {
  .fx-stats {
    grid-template-columns: repeat(2, 1fr);
  }
  .fx-stat-value {
    font-size: 28px;
  }
}
</style>
