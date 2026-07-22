<script setup lang="ts">
import { computed } from 'vue'
import { marked } from 'marked'

marked.setOptions({
  gfm: true,
  breaks: true
})

function renderMarkdown(text: string) {
  if (!text) return ''
  try {
    return marked.parse(text) as string
  } catch (e) {
    return text
  }
}

const props = defineProps<{
  bodyPart: string
  bodyText: string
}>()

function parseGeminiRequest(jsonText: string) {
  if (!jsonText) return null
  try {
    const data = JSON.parse(jsonText)
    const reqObj = data.request || data
    if (reqObj && Array.isArray(reqObj.contents)) {
      const systemInstruction = reqObj.systemInstruction?.parts?.[0]?.text || ''
      const messages = reqObj.contents.map((item: any) => {
        const parts = (item.parts || []).map((p: any) => {
          if (p.text !== undefined) {
            return { type: 'text', text: p.text }
          }
          if (p.functionCall) {
            return {
              type: 'functionCall',
              id: p.functionCall.id || '',
              name: p.functionCall.name || '',
              args: p.functionCall.args || {}
            }
          }
          if (p.functionResponse) {
            const resp = p.functionResponse.response || {}
            let outputStr = ''
            if (resp.output) {
              outputStr = typeof resp.output === 'string' ? resp.output : JSON.stringify(resp.output, null, 2)
            } else {
              outputStr = JSON.stringify(resp, null, 2)
            }
            return {
              type: 'functionResponse',
              id: p.functionResponse.id || '',
              name: p.functionResponse.name || '',
              output: outputStr
            }
          }
          return { type: 'text', text: JSON.stringify(p) }
        })
        return {
          role: item.role || 'user',
          parts
        }
      })
      const tools = reqObj.tools || null
      return {
        systemInstruction,
        messages,
        tools
      }
    }
  } catch (e) {
    // 忽略
  }
  return null
}

function parseGeminiResponse(rawText: string) {
  if (!rawText) return null
  if (!rawText.includes('data:')) return null
  
  const lines = rawText.split('\n')
  let fullText = ''
  let functionCalls: any[] = []
  let usage: any = null
  let modelVersion = ''
  let isGemini = false

  for (let line of lines) {
    line = line.trim()
    if (line.startsWith('data:')) {
      const jsonStr = line.substring(5).trim()
      if (!jsonStr) continue
      try {
        const obj = JSON.parse(jsonStr)
        const geminiCand = obj.response?.candidates || obj.candidates
        if (Array.isArray(geminiCand)) {
          isGemini = true
          for (const cand of geminiCand) {
            const parts = cand.content?.parts
            if (Array.isArray(parts)) {
              for (const part of parts) {
                if (part.text) fullText += part.text
                if (part.functionCall) functionCalls.push(part.functionCall)
              }
            }
          }
        }
        const geminiUsage = obj.response?.usageMetadata || obj.usageMetadata
        if (geminiUsage) usage = geminiUsage
        if (obj.response?.modelVersion) modelVersion = obj.response.modelVersion
      } catch (e) {
        // 忽略单行解析失败
      }
    }
  }

  if (isGemini) {
    return {
      fullText,
      functionCalls,
      usage,
      modelVersion
    }
  }
  return null
}

const parsedRequest = computed(() => {
  if (props.bodyPart !== 'requestBody') return null
  return parseGeminiRequest(props.bodyText)
})

const parsedResponse = computed(() => {
  if (props.bodyPart !== 'responseBody') return null
  return parseGeminiResponse(props.bodyText)
})

const parsedSpecial = computed(() => {
  if (!props.bodyText) return null
  try {
    const data = JSON.parse(props.bodyText)
    if (data.functionCall) {
      return {
        type: 'functionCall',
        id: data.functionCall.id || '',
        name: data.functionCall.name || '',
        args: data.functionCall.args || {},
        thoughtSignature: data.thoughtSignature || ''
      }
    }
    if (data.functionResponse) {
      const resp = data.functionResponse.response || {}
      const keys = Object.keys(resp)
      let outputStr = ''
      if (resp.output) {
        outputStr = typeof resp.output === 'string' ? resp.output : JSON.stringify(resp.output, null, 2)
      } else if (keys.length > 0) {
        outputStr = JSON.stringify(resp, null, 2)
      } else {
        outputStr = JSON.stringify(data.functionResponse)
      }
      return {
        type: 'functionResponse',
        id: data.functionResponse.id || '',
        name: data.functionResponse.name || '',
        output: outputStr
      }
    }
  } catch (e) {
    // 忽略
  }
  return null
})
</script>

<template>
  <div class="interactive-container">
    <!-- 优先渲染特殊的单体工具请求或响应 -->
    <template v-if="parsedSpecial">
      <!-- functionCall (工具调用请求) -->
      <div v-if="parsedSpecial.type === 'functionCall'" class="interactive-card">
        <div class="card-header">⚡ 模型工具调用请求 (Function Call Request)</div>
        <div class="special-body">
          <div><b>调用接口:</b> <code>{{ parsedSpecial.name }}</code></div>
          <div v-if="parsedSpecial.id"><b>调用 ID:</b> <code>{{ parsedSpecial.id }}</code></div>
          <div class="special-args-header">调用参数 (Arguments):</div>
          <pre class="call-args">{{ JSON.stringify(parsedSpecial.args, null, 2) }}</pre>
          <div v-if="parsedSpecial.thoughtSignature" class="special-thought-header">思考签名 (Thought Signature):</div>
          <pre v-if="parsedSpecial.thoughtSignature" class="thought-sig">{{ parsedSpecial.thoughtSignature }}</pre>
        </div>
      </div>

      <!-- functionResponse (工具返回结果) -->
      <div v-else-if="parsedSpecial.type === 'functionResponse'" class="interactive-card">
        <div class="card-header">📋 工具执行结果返回 (Function Response)</div>
        <div class="special-body">
          <div><b>对应接口:</b> <code>{{ parsedSpecial.name }}</code></div>
          <div v-if="parsedSpecial.id"><b>调用 ID:</b> <code>{{ parsedSpecial.id }}</code></div>
          <div class="special-response-header">执行输出 (Output):</div>
          <pre class="call-response">{{ parsedSpecial.output }}</pre>
        </div>
      </div>
    </template>

    <!-- 请求体交互视图 -->
    <template v-else-if="bodyPart === 'requestBody' && parsedRequest">
      <!-- 系统提示词 -->
      <div v-if="parsedRequest.systemInstruction" class="interactive-card system-instruction">
        <div class="card-header">系统提示词 (System Instruction)</div>
        <pre class="instruction-content">{{ parsedRequest.systemInstruction }}</pre>
      </div>
      
      <!-- 消息气泡 -->
      <div class="chat-flow">
        <div v-for="(msg, idx) in parsedRequest.messages" :key="idx" :class="['chat-bubble-row', msg.role === 'user' ? 'align-right' : 'align-left']">
          <div :class="['chat-bubble', msg.role === 'user' ? 'bubble-user' : 'bubble-model']">
            <div class="bubble-role">{{ msg.role === 'user' ? 'User' : 'Assistant' }}</div>
            
            <div v-for="(part, pIdx) in msg.parts" :key="pIdx" class="bubble-part">
              <!-- 文本类型 -->
              <div v-if="part.type === 'text'" class="bubble-markdown-text" v-html="renderMarkdown(part.text)"></div>
              
              <!-- 工具调用类型 -->
              <div v-else-if="part.type === 'functionCall'" class="inner-special-card function-call">
                <div class="inner-card-title">⚡ 工具调用请求 (Call: <code>{{ part.name }}</code>)</div>
                <div v-if="part.id" class="inner-card-id">ID: <code>{{ part.id }}</code></div>
                <pre class="inner-card-pre">{{ JSON.stringify(part.args, null, 2) }}</pre>
              </div>
              
              <!-- 工具执行结果类型 -->
              <div v-else-if="part.type === 'functionResponse'" class="inner-special-card function-response">
                <div class="inner-card-title">📋 工具返回结果 (Response: <code>{{ part.name }}</code>)</div>
                <div v-if="part.id" class="inner-card-id">ID: <code>{{ part.id }}</code></div>
                <pre class="inner-card-pre">{{ part.output }}</pre>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 可用工具 -->
      <div v-if="parsedRequest.tools && parsedRequest.tools.length > 0" class="interactive-card tools-list">
        <div class="card-header">可用工具 (Tools Declared)</div>
        <div v-for="(tool, idx) in parsedRequest.tools" :key="idx" class="tool-item">
          <details v-if="tool.functionDeclarations">
            <summary><b>{{ tool.functionDeclarations.length }} 个函数声明</b></summary>
            <div v-for="(fd, fIdx) in tool.functionDeclarations" :key="fIdx" class="func-dec">
              <code>{{ fd.name }}</code> - {{ fd.description }}
              <pre v-if="fd.parameters" class="func-params">{{ JSON.stringify(fd.parameters, null, 2) }}</pre>
            </div>
          </details>
          <div v-else>{{ JSON.stringify(tool) }}</div>
        </div>
      </div>
    </template>

    <!-- 响应体交互视图 -->
    <template v-else-if="bodyPart === 'responseBody' && parsedResponse">
      <!-- 提示模型与版本 -->
      <div v-if="parsedResponse.modelVersion" class="model-badge">
        模型版本: <span>{{ parsedResponse.modelVersion }}</span>
      </div>

      <!-- 组合后的大模型完整回复 -->
      <div v-if="parsedResponse.fullText" class="chat-flow">
        <div class="chat-bubble-row align-left">
          <div class="chat-bubble bubble-model">
            <div class="bubble-role">Assistant Output (Stream Aggregated)</div>
            <div class="bubble-markdown-text" v-html="renderMarkdown(parsedResponse.fullText)"></div>
          </div>
        </div>
      </div>

      <!-- 工具调用 -->
      <div v-if="parsedResponse.functionCalls && parsedResponse.functionCalls.length > 0" class="interactive-card function-calls">
        <div class="card-header">工具调用 (Function Calls)</div>
        <div v-for="(call, idx) in parsedResponse.functionCalls" :key="idx" class="call-item">
          <div class="call-title">⚡ Call: <code>{{ call.name }}</code> (ID: {{ call.id || '-' }})</div>
          <pre class="call-args">{{ JSON.stringify(call.args, null, 2) }}</pre>
        </div>
      </div>

      <!-- 统计信息 -->
      <div v-if="parsedResponse.usage" class="interactive-card usage-stats">
        <div class="card-header">Token 消耗 (Usage Metadata)</div>
        <dl class="usage-grid">
          <div v-if="parsedResponse.usage.promptTokenCount !== undefined">
            <dt>输入 Token</dt>
            <dd>{{ parsedResponse.usage.promptTokenCount }}</dd>
          </div>
          <div v-if="parsedResponse.usage.candidatesTokenCount !== undefined">
            <dt>输出 Token</dt>
            <dd>{{ parsedResponse.usage.candidatesTokenCount }}</dd>
          </div>
          <div v-if="parsedResponse.usage.thoughtsTokenCount !== undefined">
            <dt>思考 Token</dt>
            <dd>{{ parsedResponse.usage.thoughtsTokenCount }}</dd>
          </div>
          <div v-if="parsedResponse.usage.totalTokenCount !== undefined">
            <dt>总 Token</dt>
            <dd>{{ parsedResponse.usage.totalTokenCount }}</dd>
          </div>
        </dl>
      </div>
    </template>
  </div>
</template>
