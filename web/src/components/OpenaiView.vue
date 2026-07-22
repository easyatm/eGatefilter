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

function parseOpenaiRequest(jsonText: string) {
  if (!jsonText) return null
  try {
    const data = JSON.parse(jsonText)
    if (Array.isArray(data.messages)) {
      const messages = data.messages.map((item: any) => {
        const parts: any[] = []
        
        // 1. 解析 content
        if (typeof item.content === 'string' && item.content) {
          parts.push({ type: 'text', text: item.content })
        } else if (Array.isArray(item.content)) {
          item.content.forEach((c: any) => {
            if (c.text) parts.push({ type: 'text', text: c.text })
            else parts.push({ type: 'text', text: JSON.stringify(c) })
          })
        }
        
        // 2. 解析 tool_calls (工具调用请求)
        if (Array.isArray(item.tool_calls)) {
          item.tool_calls.forEach((tc: any) => {
            if (tc.function) {
              parts.push({
                type: 'functionCall',
                id: tc.id || '',
                name: tc.function.name || '',
                args: tc.function.arguments ? JSON.parse(tc.function.arguments) : {}
              })
            }
          })
        }
        
        // 3. 如果是 tool 角色 (工具返回结果)
        if (item.role === 'tool') {
          parts.push({
            type: 'functionResponse',
            id: item.tool_call_id || '',
            name: item.name || '',
            output: typeof item.content === 'string' ? item.content : JSON.stringify(item.content, null, 2)
          })
        }
        
        return {
          role: item.role || 'user',
          parts
        }
      })
      
      const systemMsg = messages.find(m => m.role === 'system')
      const systemInstruction = systemMsg ? systemMsg.parts.map((p: any) => p.text).join('\n') : ''
      const filteredMessages = messages.filter(m => m.role !== 'system')
      const tools = data.tools || null
      return {
        systemInstruction,
        messages: filteredMessages,
        tools
      }
    }
  } catch (e) {
    // 忽略
  }
  return null
}

function parseOpenaiResponse(rawText: string) {
  if (!rawText) return null
  if (!rawText.includes('data:')) return null
  
  const lines = rawText.split('\n')
  let fullText = ''
  let functionCalls: any[] = []
  let usage: any = null
  let modelVersion = ''
  let isOpenai = false

  for (let line of lines) {
    line = line.trim()
    if (line.startsWith('data:')) {
      const jsonStr = line.substring(5).trim()
      if (!jsonStr) continue
      if (jsonStr === '[DONE]') continue
      try {
        const obj = JSON.parse(jsonStr)
        const choices = obj.choices
        if (Array.isArray(choices)) {
          isOpenai = true
          for (const c of choices) {
            const delta = c.delta
            if (delta) {
              if (delta.content) fullText += delta.content
              if (delta.tool_calls) {
                for (const tc of delta.tool_calls) {
                  if (tc.function) {
                    functionCalls.push({
                      name: tc.function.name || '',
                      args: tc.function.arguments ? JSON.parse(tc.function.arguments) : {},
                      id: tc.id
                    })
                  }
                }
              }
            }
          }
        }
        if (obj.usage) usage = obj.usage
        if (obj.model) modelVersion = obj.model
      } catch (e) {
        // 忽略单行解析失败
      }
    }
  }

  if (isOpenai) {
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
  return parseOpenaiRequest(props.bodyText)
})

const parsedResponse = computed(() => {
  if (props.bodyPart !== 'responseBody') return null
  return parseOpenaiResponse(props.bodyText)
})
</script>

<template>
  <div class="interactive-container">
    <!-- 请求体交互视图 -->
    <template v-if="bodyPart === 'requestBody' && parsedRequest">
      <!-- 系统提示词 -->
      <div v-if="parsedRequest.systemInstruction" class="interactive-card system-instruction">
        <div class="card-header">系统提示词 (System Instruction)</div>
        <pre class="instruction-content">{{ parsedRequest.systemInstruction }}</pre>
      </div>
      
      <!-- 消息气泡 -->
      <div class="chat-flow">
        <div v-for="(msg, idx) in parsedRequest.messages" :key="idx" :class="['chat-bubble-row', msg.role === 'user' || msg.role === 'tool' ? 'align-right' : 'align-left']">
          <div :class="['chat-bubble', msg.role === 'user' || msg.role === 'tool' ? 'bubble-user' : 'bubble-model']">
            <div class="bubble-role">
              <template v-if="msg.role === 'user'">User</template>
              <template v-else-if="msg.role === 'tool'">Tool Response</template>
              <template v-else>Assistant</template>
            </div>
            
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
          <details v-if="tool.function">
            <summary><b>函数: {{ tool.function.name }}</b></summary>
            <div class="func-dec">
              {{ tool.function.description }}
              <pre v-if="tool.function.parameters" class="func-params">{{ JSON.stringify(tool.function.parameters, null, 2) }}</pre>
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
          <div v-if="parsedResponse.usage.prompt_tokens !== undefined">
            <dt>输入 Token</dt>
            <dd>{{ parsedResponse.usage.prompt_tokens }}</dd>
          </div>
          <div v-if="parsedResponse.usage.completion_tokens !== undefined">
            <dt>输出 Token</dt>
            <dd>{{ parsedResponse.usage.completion_tokens }}</dd>
          </div>
          <div v-if="parsedResponse.usage.total_tokens !== undefined">
            <dt>总 Token</dt>
            <dd>{{ parsedResponse.usage.total_tokens }}</dd>
          </div>
        </dl>
      </div>
    </template>
  </div>
</template>
