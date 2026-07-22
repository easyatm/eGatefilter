<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch, nextTick } from 'vue'
import GeminiView from './components/GeminiView.vue'
import OpenaiView from './components/OpenaiView.vue'

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
  { value: 'info', label: '信息' },
  { value: 'requestHeader', label: '请求头' },
  { value: 'requestBody', label: '请求体 / TCP上行' },
  { value: 'responseHeader', label: '响应头' },
  { value: 'responseBody', label: '响应体 / TCP下行' }
]

const records = ref<CaptureRecord[]>([])
const keyword = ref(localStorage.getItem('captureKeyword') || '')
watch(keyword, (newVal) => {
  localStorage.setItem('captureKeyword', newVal)
})
const selected = ref<CaptureRecord | null>(null)
const bodyPart = ref('info')
const bodyText = ref('')
const bodyInfo = ref<CaptureBody | null>(null)
const bodyLoading = ref(false)
const clearing = ref(false)
const wsState = ref('连接中')
const errorMessage = ref('')
const configuredApiBase = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '')
const pageWsBase = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`
const serverBase = ref(normalizeServerBase(localStorage.getItem('captureServerBase') ?? localStorage.getItem('captureApiBase') ?? configuredApiBase))
const serverBaseDraft = ref(serverBase.value)
const showServerConfig = ref(false)
const bodyChunkSize = 1024 * 1024
const sidebarWidth = ref(Number(localStorage.getItem('captureSidebarWidth') || '460'))
const resizing = ref(false)
let activeWs: WebSocket | null = null
let reconnectTimer: number | undefined

const viewMode = ref<'raw' | 'interactive'>('interactive')

const detectedFormat = computed(() => {
  if (!bodyText.value) return null
  
  if (bodyPart.value === 'requestBody') {
    try {
      const data = JSON.parse(bodyText.value)
      const reqObj = data.request || data
      if (reqObj && Array.isArray(reqObj.contents)) {
        return 'gemini'
      }
      if (Array.isArray(data.messages)) {
        return 'openai'
      }
    } catch (e) {
      // 忽略
    }
  } else if (bodyPart.value === 'responseBody') {
    if (bodyText.value.includes('data:')) {
      if (bodyText.value.includes('"candidates"') || bodyText.value.includes('"usageMetadata"')) {
        return 'gemini'
      }
      if (bodyText.value.includes('"choices"') || bodyText.value.includes('"delta"') || bodyText.value.includes('"tool_calls"')) {
        return 'openai'
      }
    }
  }
  return null
})

const interactiveViewLabel = computed(() => {
  if (detectedFormat.value === 'gemini') return 'Gemini协议'
  if (detectedFormat.value === 'openai') return 'OpenAI协议'
  return '交互视图'
})

const showRawEditor = computed(() => {
  if (bodyPart.value === 'info') return true
  if (bodyPart.value.endsWith('Header')) return true
  if (!detectedFormat.value) return true
  return viewMode.value === 'raw'
})

watch(showRawEditor, (newVal) => {
  if (newVal) {
    nextTick(() => {
      if (editorInstance) {
        editorInstance.layout()
      }
    })
  }
})

const filteredRecords = computed(() => {
  const text = keyword.value.trim().toLowerCase()
  if (!text) return records.value
  return records.value.filter((item) => {
    const searchable = [
      item.protocol,
      item.method,
      item.scheme,
      item.host,
      String(item.port || ''),
      item.url,
      item.path,
      String(item.status_code || ''),
      item.rule_name,
      item.action,
      item.client_addr,
      item.server_addr,
      item.process_name,
      item.process_path,
      item.note
    ].join(' ').toLowerCase()
    return searchable.includes(text)
  })
})

function normalizeServerBase(value: string) {
  const trimmed = value.trim().replace(/\/$/, '')
  if (!trimmed) return ''
  if (/^https?:\/\//i.test(trimmed)) return trimmed
  if (/^wss?:\/\//i.test(trimmed)) return trimmed.replace(/^ws/i, 'http')
  return `http://${trimmed}`
}

function effectiveApiBase() {
  return serverBase.value
}

function effectiveWsBase() {
  if (serverBase.value) return serverBase.value.replace(/^http/i, 'ws')
  return pageWsBase
}

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
  const params = new URLSearchParams({ limit: '500' })
  const data = await fetchJSON<{ items?: CaptureRecord[] }>(`${effectiveApiBase()}/api/captures?${params}`)
  if (!data) return
  errorMessage.value = ''
  records.value = data.items || []
  if (!selected.value && records.value.length > 0) await selectRecord(records.value[0])
}

async function saveServerConfig() {
  serverBase.value = normalizeServerBase(serverBaseDraft.value)
  serverBaseDraft.value = serverBase.value
  if (serverBase.value) localStorage.setItem('captureServerBase', serverBase.value)
  else localStorage.removeItem('captureServerBase')
  localStorage.removeItem('captureApiBase')
  localStorage.removeItem('captureWsBase')
  showServerConfig.value = false
  records.value = []
  selected.value = null
  bodyText.value = ''
  bodyInfo.value = null
  connectWs()
  await loadRecords()
}

async function clearRecords() {
  if (clearing.value || !confirm('确定要清空全部抓包历史记录和本地包文文件吗？')) return
  clearing.value = true
  try {
    const res = await fetch(`${effectiveApiBase()}/api/captures`, { method: 'DELETE', headers: { Accept: 'application/json' } })
    if (!res.ok) throw new Error(`清空失败: ${res.status} ${res.statusText}`)
    records.value = []
    selected.value = null
    bodyText.value = ''
    bodyInfo.value = null
    errorMessage.value = ''
  } catch (err) {
    errorMessage.value = err instanceof Error ? err.message : String(err)
  } finally {
    clearing.value = false
  }
}

let editorInstance: any = null
let isEditorInitializing = false

function getEditorLanguage() {
  if (bodyPart.value === 'info') {
    return 'plaintext'
  }
  if (bodyPart.value.endsWith('Header')) {
    return 'http'
  }
  const record = selected.value
  if (!record) return 'plaintext'
  if (record.protocol === 'tcp') return 'plaintext'
  
  const path = (record.path || '').toLowerCase()
  if (path.endsWith('.json')) return 'json'
  if (path.endsWith('.html') || path.endsWith('.htm')) return 'html'
  if (path.endsWith('.js') || path.endsWith('.ts')) return 'javascript'
  if (path.endsWith('.css')) return 'css'
  if (path.endsWith('.xml')) return 'xml'
  
  const text = (bodyText.value || '').trim()
  if (text.startsWith('{') || text.startsWith('[')) {
    return 'json'
  }
  
  return 'plaintext'
}

function createRawEditor(container: HTMLElement) {
  const editor = (window as any).monaco.editor.create(container, {
    value: '',
    language: getEditorLanguage(),
    readOnly: true,
    theme: 'vs-dark',
    domReadOnly: true,
    wordWrap: 'off',
    unicodeHighlight: {
      ambiguousCharacters: false,
      invisibleCharacters: false,
      nonBasicASCIICharacters: false
    },
    minimap: { enabled: true },
    scrollBeyondLastLine: false,
    automaticLayout: true
  })
  return editor
}

function initEditor(id: string, lang: string) {
  const actualLang = (lang && lang.toLowerCase().startsWith('zh')) ? 'zh-cn': 'en';
  const locales: Record<string, Record<string, string>> = {
    'zh-cn': {
      loading: '正在加载编辑器...',
      failed: '编辑器加载失败',
      retry: '重新加载'
    },
    en: {
      loading: 'Loading editor...',
      failed: 'Failed to load editor',
      retry: 'Retry'
    }
  };
  const text = locales[actualLang];
  const container = document.getElementById(id);
  if (!container) return Promise.reject(new Error('Container not found'));
  if (window.getComputedStyle(container).position === 'static') container.style.position = 'relative';
  let overlay = container.querySelector('.editor-loading-overlay') as HTMLElement | null;
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.className = 'editor-loading-overlay';
    container.appendChild(overlay)
  }
  const showLoadingOverlay = () => {
    if (overlay) {
      overlay.style.display = 'flex';
      overlay.innerHTML = `<div style="font-size:16px;">${text.loading}</div>`;
    }
  };
  const hideOverlay = () => { if (overlay) overlay.style.display = 'none' };
  return new Promise<any>((resolve, reject) => {
    const tryLoadAndCreate = () => {
      if ((window as any).monaco) { hideOverlay(); return resolve(createRawEditor(container)) }
      showLoadingOverlay();
      const baseUrl = actualLang === 'zh-cn' ? 'https://registry.npmmirror.com/monaco-editor/0.52.0/files/min/vs' : 'https://cdn.jsdelivr.net/npm/monaco-editor@0.52.0/min/vs';
      if (!(window as any).__monacoLoading) {
        (window as any).__monacoLoading = new Promise<void>((res, rej) => {
          const scriptId = 'monaco-loader-script';
          let script = document.getElementById(scriptId) as HTMLScriptElement | null;
          if (!script) {
            script = document.createElement('script');
            script.id = scriptId;
            script.src = `${baseUrl}/loader.js`;
            document.head.appendChild(script)
          }
          script.onload = () => {
            const config: Record<string, any> = { paths: { vs: baseUrl } };
            if (actualLang === 'zh-cn') config['vs/nls'] = { availableLanguages: { '*': 'zh-cn' } };
            (window as any).require.config(config);
            (window as any).require(['vs/editor/editor.main'], () => res());
          };
          script.onerror = () => {
            if (script && script.parentNode) script.parentNode.removeChild(script);
            rej(new Error('Monaco加载失败'))
          };
        });
      }
      (window as any).__monacoLoading.then(() => { hideOverlay(); resolve(createRawEditor(container)) }).catch((err: any) => { 
        (window as any).__monacoLoading = null; 
        if (overlay) {
          overlay.style.display = 'flex'; 
          overlay.innerHTML = `<div style="font-size:16px;margin-bottom:15px;color:#f48771;">${text.failed}</div><button class="retry-btn" style="padding:8px 16px;background-color:#007acc;color:white;border:none;border-radius:4px;cursor:pointer;font-size:14px;">${text.retry}</button>`; 
          const retryBtn = overlay.querySelector('.retry-btn') as HTMLElement | null; 
          if (retryBtn) retryBtn.onclick = () => tryLoadAndCreate();
        }
        reject(err) 
      });
    };
    tryLoadAndCreate();
  });
}

async function ensureEditor() {
  const containerId = 'editor-container'
  const container = document.getElementById(containerId)
  if (!container) {
    if (editorInstance) {
      editorInstance.dispose()
      editorInstance = null
    }
    return null
  }
  
  if (editorInstance) {
    if (editorInstance.getDomNode() === container) {
      return editorInstance
    } else {
      editorInstance.dispose()
      editorInstance = null
    }
  }
  
  if (isEditorInitializing) return null
  isEditorInitializing = true
  try {
    const lang = navigator.language || 'zh-CN'
    editorInstance = await initEditor(containerId, lang)
    
    editorInstance.onDidScrollChange((e: any) => {
      const layoutInfo = editorInstance.getLayoutInfo()
      if (layoutInfo && e.scrollTop + layoutInfo.height >= editorInstance.getContentHeight() - 80) {
        loadBodyChunk(false)
      }
    })
    
    isEditorInitializing = false
    return editorInstance
  } catch (err) {
    isEditorInitializing = false
    console.error(err)
    return null
  }
}

async function loadBodyChunk(reset = false) {
  if (!selected.value) return
  if (bodyPart.value === 'info') {
    bodyLoading.value = false
    const lines = [
      `序号        : ${selected.value.id}`,
      `时间        : ${formatTime(selected.value.created_at)}`,
      `协议        : ${selected.value.protocol || '-'}`,
      `方法        : ${selected.value.method || 'TCP'}`,
      `域名/主机   : ${selected.value.host || '-'}`,
      `端口        : ${selected.value.port || '-'}`,
      `网址/路径   : ${selected.value.url || selected.value.path || selected.value.host}`,
      `状态码      : ${selected.value.status_code || '-'}`,
      `规则名称    : ${selected.value.rule_name || '-'}`,
      `匹配动作    : ${selected.value.action || 'passthrough'}`,
      `客户端地址  : ${selected.value.client_addr || '-'}`,
      `服务器地址  : ${selected.value.server_addr || '-'}`,
      `进程名称    : ${selected.value.process_name || '-'}`,
      `进程PID     : ${selected.value.process_pid || '-'}`,
      `进程路径    : ${selected.value.process_path || '-'}`,
      `请求流量    : ${formatSize(selected.value.request_size)}`,
      `响应流量    : ${formatSize(selected.value.response_size)}`,
      `耗时        : ${selected.value.duration_ms}ms`
    ]
    bodyText.value = lines.join('\n')
    bodyInfo.value = {
      path: 'Metadata',
      size: bodyText.value.length,
      offset: 0,
      limit: bodyText.value.length,
      next_offset: bodyText.value.length,
      text: bodyText.value,
      hex: '',
      truncated: false
    }
    nextTick(async () => {
      const editor = await ensureEditor()
      if (editor) {
        editor.setValue(bodyText.value)
        const model = editor.getModel()
        if (model) {
          ;(window as any).monaco.editor.setModelLanguage(model, 'plaintext')
        }
      }
    })
    return
  }

  if (bodyLoading.value) return
  const offset = reset ? 0 : (bodyInfo.value?.next_offset || 0)
  if (!reset && bodyInfo.value && !bodyInfo.value.truncated) return
  bodyLoading.value = true
  const params = new URLSearchParams({ offset: String(offset), limit: String(bodyChunkSize) })
  const data = await fetchJSON<CaptureBody>(`${effectiveApiBase()}/api/captures/${selected.value.id}/body/${bodyPart.value}?${params}`)
  bodyLoading.value = false
  if (!data) return
  bodyInfo.value = data
  bodyText.value = reset ? data.text : `${bodyText.value}${data.text}`

  nextTick(async () => {
    const editor = await ensureEditor()
    if (editor) {
      const scrollPosition = editor.getScrollTop()
      
      let displayText = bodyText.value || '暂无包文内容'
      const lang = getEditorLanguage()
      if (lang === 'json' && bodyText.value) {
        try {
          const parsed = JSON.parse(bodyText.value)
          displayText = JSON.stringify(parsed, null, 2)
        } catch (e) {
          // 如果流式截断或者格式不完整，保持原样
        }
      }
      
      editor.setValue(displayText)
      const model = editor.getModel()
      if (model) {
        ;(window as any).monaco.editor.setModelLanguage(model, lang)
      }
      if (!reset) {
        editor.setScrollTop(scrollPosition)
      }
    }
  })
}

async function selectRecord(record: CaptureRecord) {
  selected.value = record
  bodyText.value = ''
  bodyInfo.value = null
  viewMode.value = 'interactive'
  await loadBodyChunk(true)
}

async function switchBodyPart(part: string) {
  bodyPart.value = part
  bodyText.value = ''
  bodyInfo.value = null
  viewMode.value = 'interactive'
  await loadBodyChunk(true)
}

function connectWs() {
  if (reconnectTimer) window.clearTimeout(reconnectTimer)
  if (activeWs) activeWs.close()
  const ws = new WebSocket(`${effectiveWsBase()}/ws/captures`)
  activeWs = ws
  ws.onopen = () => { wsState.value = '实时连接已建立' }
  ws.onclose = () => {
    if (activeWs !== ws) return
    wsState.value = '连接断开，正在重连'
    reconnectTimer = window.setTimeout(connectWs, 1500)
  }
  ws.onerror = () => { wsState.value = '连接异常' }
  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data)
      if (msg.type === 'capture') {
        records.value = [msg.data, ...records.value.filter((item) => item.id !== msg.data.id)].slice(0, 500)
      } else if (msg.type === 'clear') {
        records.value = []
        selected.value = null
        bodyText.value = ''
        bodyInfo.value = null
      }
    } catch (err) {
      errorMessage.value = err instanceof Error ? err.message : 'WebSocket 消息解析失败'
    }
  }
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

onUnmounted(() => {
  if (editorInstance) {
    editorInstance.dispose()
    editorInstance = null
  }
})
</script>

<template>
  <main class="shell">
    <section class="hero">
      <div class="hero-left">
        <h1>eGatefilter</h1>
        <p>TCP / HTTP / HTTPS 抓包工具 · 数据已写入 SQLite，包文保存为本地文件</p>
      </div>
      <div class="hero-actions">
        <div class="status">{{ wsState }}</div>
        <button class="configButton" @click="showServerConfig = !showServerConfig">配置</button>
      </div>
    </section>

    <section class="toolbar">
      <input v-model="keyword" placeholder="实时过滤协议、域名、URL、进程、状态码" />
      <button @click="loadRecords">刷新</button>
      <button class="dangerButton" :disabled="clearing || records.length === 0" @click="clearRecords">
        {{ clearing ? '清空中...' : '清空记录' }}
      </button>
    </section>

    <section v-if="showServerConfig" class="serverToolbar">
      <input v-model="serverBaseDraft" placeholder="后端地址，如 127.0.0.1:8081 或 http://127.0.0.1:8081；留空使用当前页面同源" @keyup.enter="saveServerConfig" />
      <button @click="saveServerConfig">保存并重连</button>
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
          
          <div class="bodyInfoAndToggle">
            <div v-if="detectedFormat" class="viewModeToggle">
              <button :class="{ active: viewMode === 'interactive' }" @click="viewMode = 'interactive'">{{ interactiveViewLabel }}</button>
              <button :class="{ active: viewMode === 'raw' }" @click="viewMode = 'raw'">原始代码</button>
            </div>
            <div v-else></div>
            
            <div class="bodyInfo">
              <template v-if="bodyInfo?.path">
                {{ bodyInfo.path }} · {{ formatSize(bodyInfo.size) }} · 已加载 {{ formatSize(bodyInfo.next_offset || 0) }}
              </template>
              <template v-else>暂无包文内容</template>
            </div>
          </div>

          <!-- 原始 Monaco 编辑器视图 -->
          <div id="editor-container" v-show="showRawEditor" class="editor-container"></div>

          <!-- 交互视图组件 -->
          <GeminiView
            v-if="detectedFormat === 'gemini' && viewMode === 'interactive'"
            :bodyPart="bodyPart"
            :bodyText="bodyText"
          />
          <OpenaiView
            v-else-if="detectedFormat === 'openai' && viewMode === 'interactive'"
            :bodyPart="bodyPart"
            :bodyText="bodyText"
          />

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
