<script setup lang="ts">
import { withBase } from 'vitepress'

/**
 * IRC-flavoured 404: the server numeric for "no such nick/channel" is 401,
 * which is close enough to be the joke.
 */
</script>

<template>
  <div class="fx-nf">
    <pre class="fx-nf-wire" aria-hidden="true">
» WHOIS this-page
« :irc.example.test 401 you this-page :No such nick/channel</pre>
    <h1 class="fx-nf-title">404 — no such nick/channel</h1>
    <p class="fx-nf-text">
      The page you asked for isn't connected to this network. It may have been
      renamed, netsplit, or K-lined during a docs restructure.
    </p>
    <div class="fx-nf-actions">
      <a class="fx-nf-btn brand" :href="withBase('/')">/join home</a>
      <a class="fx-nf-btn" :href="withBase('/guide/what-is-ferrixd')">/topic guide</a>
      <a class="fx-nf-btn" :href="withBase('/reference/cli')">/list reference</a>
    </div>
  </div>
</template>

<style scoped>
.fx-nf {
  max-width: 720px;
  margin: 0 auto;
  padding: 96px 24px 120px;
  text-align: center;
}

.fx-nf-wire {
  display: inline-block;
  margin: 0 auto 28px;
  padding: 16px 22px;
  text-align: left;
  font-family: var(--vp-font-family-mono);
  font-size: 13px;
  line-height: 1.8;
  color: var(--vp-c-text-2);
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  border-radius: 10px;
  overflow-x: auto;
  max-width: 100%;
}

.fx-nf-title {
  font-family: var(--vp-font-family-mono);
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--vp-c-brand-1);
}

.fx-nf-text {
  margin: 14px auto 32px;
  max-width: 44em;
  color: var(--vp-c-text-2);
  line-height: 1.7;
}

.fx-nf-actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  flex-wrap: wrap;
}

.fx-nf-btn {
  font-family: var(--vp-font-family-mono);
  font-size: 14px;
  font-weight: 600;
  padding: 8px 18px;
  border-radius: 20px;
  border: 1px solid var(--vp-c-divider);
  color: var(--vp-c-text-1);
  transition: border-color 0.25s, color 0.25s, background-color 0.25s;
}

.fx-nf-btn:hover {
  border-color: var(--vp-c-brand-1);
  color: var(--vp-c-brand-1);
}

.fx-nf-btn.brand {
  background: var(--vp-c-brand-3);
  border-color: var(--vp-c-brand-3);
  color: #fff;
}

.fx-nf-btn.brand:hover {
  background: var(--vp-c-brand-2);
  border-color: var(--vp-c-brand-2);
  color: #fff;
}
</style>
