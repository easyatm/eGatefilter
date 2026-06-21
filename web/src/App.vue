<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

type CaptureRecord = {
  id: number
  created_at: string
  protocol: string
  method: string
  scheme: string
  host: string
  port: number
  url: string
  path: string
  status_code: number
  rule_name: string
  action: string
  client_addr: string
  server_addr: string
  process_pid: number
  process_name: string
  process_path: string
  request_size: number
  response_size: number
  duration_ms: number
  note: string
}

type CaptureBody = {
  path: string
  size: number
  offset: number
  limit: number
  next_offset: number
  text: string
  hex: string
  truncated: boolean
}

const bodyTabs = [
  { value: 'requestHeader', label: '请求头' },
  { value: 'requestBody', label: '请求体 / TCP上行' },
  { value: 'responseHeader', label: '响应头' },
  { value: 'responseBody', label: '响应体 / TCP下行' }
]

const records = ref<CaptureRecord[]>([])
const keyword = ref('')
const selected = ref<CaptureRecord | null>(null)
const bodyPart = ref('responseBody')
const bodyText = ref('')
const bodyInfo = ref<CaptureBody | null>(null)
const bodyLoading = ref(false)
const wsState = ref('连接中')
const errorMessage = ref('')
const apiBase = import.meta.env.DEV ? 'http://127.0.0.1:8090' : ''
const wsBase = import.meta.env.DEV ? 'ws://127.0.0.1:8090' : `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`
const bodyChunkSize = 1024 * 1024
const sidebarWidth = ref(Number(localStorage.getItem('captureSidebarWidth') || '460'))
const resizing = ref(false)

const filteredRecords = computed(() => records.value)

async function fetchJSON<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(url, { headers: { Accept: 'application/json' } })
    const contentType = res.headers.get('content-type') || ''
    if (!res.ok) throw new Error(`请求失败: ${res.status} ${res.statusText}`)
    if (!contentType.includes('application/json')) throw new Error('后端 API 未启动或 Vite 代理未生效')
    return await res.json()
  } catch (err) {
    errorMessage.value = err instanceof Error ? err.message : String(err)
    return null
  }
}

async function loadRecords() {
  const params = new URLSearchParams({ limit: '500', q: keyword.value })
  const data = await fetchJSON<{ items?: CaptureRecord[] }>(`${apiBase}/api/captures?${params}`)
  if (!data) return
  errorMessage.value = ''
  records.value = data.items || []
  if (!selected.value && records.value.length > 0) await selectRecord(records.value[0])
}

async function loadBodyChunk(reset = false) {
  if (!selected.value || bodyLoading.value) return
  const offset = reset ? 0 : (bodyInfo.value?.next_offset || 0)
  if (!reset && bodyInfo.value && !bodyInfo.value.truncated) return
  bodyLoading.value = true
  const params = new URLSearchParams({ offset: String(offset), limit: String(bodyChunkSize) })
  const data = await fetchJSON<CaptureBody>(`${apiBase}/api/captures/${selected.value.id}/body/${bodyPart.value}?${params}`)
  bodyLoading.value = false
  if (!data) return
  bodyInfo.value = data
  bodyText.value = reset ? data.text : `${bodyText.value}${data.text}`
}

async function selectRecord(record: CaptureRecord) {
  selected.value = record
  bodyText.value = ''
  bodyInfo.value = null
  await loadBodyChunk(true)
}

async function switchBodyPart(part: string) {
  bodyPart.value = part
  bodyText.value = ''
  bodyInfo.value = null
  await loadBodyChunk(true)
}

function connectWs() {
  const ws = new WebSocket(`${wsBase}/ws/captures`)
  ws.onopen = () => { wsState.value = '实时连接已建立' }
  ws.onclose = () => {
    wsState.value = '连接断开，正在重连'
    setTimeout(connectWs, 1500)
  }
  ws.onerror = () => { wsState.value = '连接异常' }
  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data)
      if (msg.type === 'capture') {
        records.value = [msg.data, ...records.value.filter((item) => item.id !== msg.data.id)].slice(0, 500)
      }
    } catch (err) {
      errorMessage.value = err instanceof Error ? err.message : 'WebSocket 消息解析失败'
    }
  }
}

function onBodyScroll(event: Event) {
  const el = event.target as HTMLElement
  if (el.scrollTop + el.clientHeight >= el.scrollHeight - 80) loadBodyChunk(false)
}

function formatSize(value: number) {
  if (value > 1024 * 1024) return `${(value / 1024 / 1024).toFixed(2)} MB`
  if (value > 1024) return `${(value / 1024).toFixed(2)} KB`
  return `${value || 0} B`
}

function formatTime(value: string) {
  if (!value) return '-'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function startResize(event: MouseEvent) {
  resizing.value = true
  const startX = event.clientX
  const startWidth = sidebarWidth.value
  const onMove = (moveEvent: MouseEvent) => {
    const nextWidth = Math.min(Math.max(startWidth + moveEvent.clientX - startX, 320), Math.floor(window.innerWidth * 0.65))
    sidebarWidth.value = nextWidth
    localStorage.setItem('captureSidebarWidth', String(nextWidth))
  }
  const onUp = () => {
    resizing.value = false
    window.removeEventListener('mousemove', onMove)
    window.removeEventListener('mouseup', onUp)
  }
  window.addEventListener('mousemove', onMove)
  window.addEventListener('mouseup', onUp)
}

onMounted(() => {
  loadRecords()
  connectWs()
})
</script>

<template>
  <main class="shell">
    <section class="hero">
      <div>
        <p class="eyebrow">eGatefilter Capture GUI</p>
        <h1>TCP / HTTP / HTTPS 实时抓包</h1>
        <p>元数据写入 SQLite，包文保存为本地文件，实时记录通过 WebSocket 推送。</p>
      </div>
      <div class="status">{{ wsState }}</div>
    </section>

    <section class="toolbar">
      <input v-model="keyword" placeholder="搜索协议、域名、URL" @keyup.enter="loadRecords" />
      <button @click="loadRecords">查询</button>
    </section>

    <section v-if="errorMessage" class="errorBanner">{{ errorMessage }}</section>

    <section :class="['workspace', resizing ? 'resizing' : '']">
      <aside class="list sidebar" :style="{ width: `${sidebarWidth}px` }">
        <article
          v-for="item in filteredRecords"
          :key="item.id"
          :class="['row', selected?.id === item.id ? 'active' : '']"
          @click="selectRecord(item)"
        >
          <div class="rowTop">
            <b>{{ (item.protocol || '').toUpperCase() }}</b>
            <span>{{ item.status_code || '-' }}</span>
            <small>{{ formatTime(item.created_at) }}</small>
            <small>{{ item.duration_ms }}ms</small>
          </div>
          <h3>{{ item.method || 'CONNECT' }} {{ item.host }}{{ item.port ? ':' + item.port : '' }}</h3>
          <div class="meta">
            <span>{{ formatSize(item.request_size) }} ↑</span>
            <span>{{ formatSize(item.response_size) }} ↓</span>
            <span>{{ item.action || 'passthrough' }}</span>
            <span v-if="item.process_name">{{ item.process_name }}#{{ item.process_pid || '-' }}</span>
            <span v-if="item.rule_name">{{ item.rule_name }}</span>
          </div>
        </article>
      </aside>

      <div class="resizeHandle" @mousedown="startResize" />

      <section v-if="selected" class="detail">
        <div class="card">
          <h2>#{{ selected.id }} {{ selected.method || 'TCP' }} {{ selected.host }}</h2>
          <p class="url">{{ selected.url || selected.path || selected.host }}</p>
          <dl>
            <div><dt>时间</dt><dd>{{ formatTime(selected.created_at) }}</dd></div>
            <div><dt>协议</dt><dd>{{ selected.protocol }}</dd></div>
            <div><dt>规则</dt><dd>{{ selected.rule_name || '-' }}</dd></div>
            <div><dt>客户端</dt><dd>{{ selected.client_addr }}</dd></div>
            <div><dt>目标</dt><dd>{{ selected.server_addr }}</dd></div>
            <div><dt>进程</dt><dd>{{ selected.process_name || '-' }} <template v-if="selected.process_pid">#{{ selected.process_pid }}</template></dd></div>
            <div><dt>进程路径</dt><dd>{{ selected.process_path || '-' }}</dd></div>
            <div><dt>耗时</dt><dd>{{ selected.duration_ms }}ms</dd></div>
          </dl>
        </div>

        <div class="card bodyCard">
          <div class="bodyTabs">
            <button
              v-for="tab in bodyTabs"
              :key="tab.value"
              :class="['tabButton', bodyPart === tab.value ? 'active' : '']"
              @click="switchBodyPart(tab.value)"
            >
              {{ tab.label }}
            </button>
          </div>
          <div class="bodyInfo">
            <template v-if="bodyInfo?.path">
              {{ bodyInfo.path }} · {{ formatSize(bodyInfo.size) }} · 已加载 {{ formatSize(bodyInfo.next_offset || 0) }}
            </template>
            <template v-else>暂无包文内容</template>
          </div>
          <pre @scroll="onBodyScroll">{{ bodyText || '暂无包文内容' }}</pre>
          <p v-if="bodyInfo?.truncated" class="hint">
            {{ bodyLoading ? '正在继续加载...' : '滚动到底部自动继续加载，每次最多加载 1MB。' }}
          </p>
        </div>
      </section>

      <section v-else class="detail">
        <div class="card">暂无抓包记录，保持代理运行后访问网页即可实时显示。</div>
      </section>
    </section>
  </main>
</template>
