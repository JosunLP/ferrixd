<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'

/**
 * An animated capture of a real ferrixd session: TLS connect, CAP
 * negotiation, SASL SCRAM, join, chathistory. Lines "arrive" one by one,
 * client-sent lines are typed out.
 */

interface Line {
  dir: 'in' | 'out' | 'sys'
  text: string
}

const SCRIPT: Line[] = [
  { dir: 'sys', text: '$ openssl s_client -connect irc.example.test:6697 -quiet' },
  { dir: 'out', text: 'CAP LS 302' },
  { dir: 'in', text: ':irc.example.test CAP * LS :sasl=PLAIN,EXTERNAL,SCRAM-SHA-256 message-tags server-time batch draft/chathistory labeled-response …' },
  { dir: 'out', text: 'CAP REQ :sasl server-time message-tags batch draft/chathistory' },
  { dir: 'in', text: ':irc.example.test CAP * ACK :sasl server-time message-tags batch draft/chathistory' },
  { dir: 'out', text: 'AUTHENTICATE SCRAM-SHA-256' },
  { dir: 'in', text: 'AUTHENTICATE +' },
  { dir: 'out', text: 'AUTHENTICATE biwsbj1hbGljZSxyPXJPcHJOR2Z3RWJlUldnYnRSbmlhdXc9PQ==' },
  { dir: 'in', text: ':irc.example.test 900 alice alice!alice@alice.ferrixnet alice :You are now logged in as alice' },
  { dir: 'in', text: ':irc.example.test 903 alice :SASL authentication successful' },
  { dir: 'out', text: 'NICK alice' },
  { dir: 'out', text: 'USER alice 0 * :Alice' },
  { dir: 'in', text: ':irc.example.test 001 alice :Welcome to the ferrixnet Network, alice' },
  { dir: 'out', text: 'JOIN #forge' },
  { dir: 'in', text: '@msgid=00000000000004d2;time=2026-07-13T20:15:07.000Z :alice!alice@alice.ferrixnet JOIN #forge' },
  { dir: 'out', text: 'CHATHISTORY LATEST #forge * 3' },
  { dir: 'in', text: ':irc.example.test BATCH +f1x chathistory #forge' },
  { dir: 'in', text: '@batch=f1x;msgid=00000000000004cf :bob!bob@bob.ferrixnet PRIVMSG #forge :the mesh relinked in 30s, zero desync' },
  { dir: 'in', text: ':irc.example.test BATCH -f1x' },
]

const shown = ref<Line[]>([])
const typing = ref('')
const typingDir = ref<'in' | 'out' | 'sys'>('out')
const done = ref(false)
const host = ref<HTMLElement | null>(null)

let timers: ReturnType<typeof setTimeout>[] = []

function later(fn: () => void, ms: number) {
  timers.push(setTimeout(fn, ms))
}

function play(i: number) {
  if (i >= SCRIPT.length) {
    done.value = true
    return
  }
  const line = SCRIPT[i]
  if (line.dir === 'in') {
    // server lines arrive whole
    shown.value = [...shown.value, line]
    scroll()
    later(() => play(i + 1), 260 + Math.min(line.text.length * 2, 340))
  } else {
    // client/system lines get typed
    typingDir.value = line.dir
    let pos = 0
    const step = () => {
      pos = Math.min(pos + 2 + Math.floor(pos / 18), line.text.length)
      typing.value = line.text.slice(0, pos)
      scroll()
      if (pos < line.text.length) {
        later(step, 24)
      } else {
        later(() => {
          shown.value = [...shown.value, line]
          typing.value = ''
          scroll()
          play(i + 1)
        }, 180)
      }
    }
    step()
  }
}

function scroll() {
  const el = host.value
  if (el) el.scrollTop = el.scrollHeight
}

onMounted(() => {
  const start = () => later(() => play(0), 600)
  if (typeof IntersectionObserver === 'undefined') {
    start()
    return
  }
  const io = new IntersectionObserver(
    (entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        io.disconnect()
        start()
      }
    },
    { threshold: 0.25 },
  )
  if (host.value) io.observe(host.value)
})

onUnmounted(() => timers.forEach(clearTimeout))
</script>

<template>
  <div class="fx-term">
    <div class="fx-term-bar">
      <span class="fx-dot" /><span class="fx-dot" /><span class="fx-dot" />
      <span class="fx-term-title">irc.example.test:6697 — TLS 1.3</span>
      <span class="fx-term-badge">SASL ✓</span>
    </div>
    <div ref="host" class="fx-term-body" aria-hidden="true">
      <div v-for="(l, i) in shown" :key="i" :class="['fx-line', `fx-${l.dir}`]">
        <span class="fx-gutter">{{ l.dir === 'in' ? '«' : l.dir === 'out' ? '»' : ' ' }}</span>
        <span class="fx-text">{{ l.text }}</span>
      </div>
      <div v-if="typing" :class="['fx-line', `fx-${typingDir}`]">
        <span class="fx-gutter">{{ typingDir === 'in' ? '«' : typingDir === 'out' ? '»' : ' ' }}</span>
        <span class="fx-text">{{ typing }}<span class="fx-cursor" /></span>
      </div>
      <div v-if="done" class="fx-line fx-sys">
        <span class="fx-gutter"> </span>
        <span class="fx-text">— live session, 0 allocations parsing hostile input, 0 lines of unsafe —<span class="fx-cursor" /></span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.fx-term {
  margin: 2.5rem auto 0;
  max-width: 960px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  overflow: hidden;
  background: #14110e;
  box-shadow: 0 18px 60px rgba(0, 0, 0, 0.35), 0 0 0 1px rgba(212, 88, 30, 0.12);
  font-family: var(--vp-font-family-mono);
}

.fx-term-bar {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 10px 14px;
  background: #1e1a16;
  border-bottom: 1px solid rgba(212, 88, 30, 0.2);
}

.fx-dot {
  width: 11px;
  height: 11px;
  border-radius: 50%;
  background: #3a332c;
}

.fx-dot:first-child { background: #d4581e; }

.fx-term-title {
  margin-left: 10px;
  font-size: 12px;
  color: #8d8478;
}

.fx-term-badge {
  margin-left: auto;
  font-size: 11px;
  color: #f59e6c;
  border: 1px solid rgba(245, 158, 108, 0.35);
  border-radius: 99px;
  padding: 1px 9px;
}

.fx-term-body {
  height: 340px;
  overflow-y: auto;
  padding: 14px 16px 18px;
  font-size: 12.5px;
  line-height: 1.75;
  scrollbar-width: thin;
}

.fx-line {
  display: flex;
  gap: 10px;
  white-space: pre-wrap;
  word-break: break-all;
}

.fx-gutter {
  flex: none;
  width: 1ch;
  opacity: 0.55;
  user-select: none;
}

.fx-in .fx-text { color: #b8ada0; }
.fx-in .fx-gutter { color: #f59e6c; }
.fx-out .fx-text { color: #ffd9c2; }
.fx-out .fx-gutter { color: #e8763b; }
.fx-sys .fx-text { color: #6f675c; font-style: italic; }

.fx-cursor {
  display: inline-block;
  width: 7px;
  height: 14px;
  margin-left: 2px;
  vertical-align: -2px;
  background: #e8763b;
  animation: fx-blink 1s steps(1) infinite;
}

@keyframes fx-blink {
  50% { opacity: 0; }
}

@media (max-width: 640px) {
  .fx-term-body { height: 280px; font-size: 11px; }
}
</style>
