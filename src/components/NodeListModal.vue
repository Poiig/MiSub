<script setup>
import { ref, computed } from 'vue';

const props = defineProps({
  isOpen: {
    type: Boolean,
    required: true
  },
  subscription: {
    type: Object,
    required: true
  },
  nodes: {
    type: Array,
    default: () => []
  },
  isLoading: {
    type: Boolean,
    default: false
  },
  error: {
    type: String,
    default: ''
  }
});

const emit = defineEmits(['close', 'retry']);

// 解析节点信息
const parseNodeInfo = (nodeUrl) => {
  try {
    // 提取节点名称
    const hashIndex = nodeUrl.lastIndexOf('#');
    const name = hashIndex !== -1 ? decodeURIComponent(nodeUrl.substring(hashIndex + 1)) : '未命名节点';
    
    // 提取协议类型
    const protocolMatch = nodeUrl.match(/^(.*?):/);
    const protocol = protocolMatch ? protocolMatch[1].toUpperCase() : 'UNKNOWN';
    
    // 提取服务器地址
    let server = '';
    let port = '';
    
    if (protocol === 'VMESS') {
      try {
        const base64Part = nodeUrl.substring('vmess://'.length);
        const jsonString = atob(base64Part);
        const config = JSON.parse(jsonString);
        server = config.add || '';
        port = config.port || '';
        return {
          name: config.ps || name,
          protocol,
          server,
          port,
          details: config
        };
      } catch (e) {
        // VMESS解析失败
      }
    } else {
      // 其他协议（ss, trojan, vless等）
      const atIndex = nodeUrl.indexOf('@');
      if (atIndex !== -1) {
        const hashIdx = nodeUrl.indexOf('#');
        const endIndex = hashIdx !== -1 ? hashIdx : nodeUrl.length;
        const serverPart = nodeUrl.substring(atIndex + 1, endIndex);
        const colonIndex = serverPart.indexOf(':');
        if (colonIndex !== -1) {
          server = serverPart.substring(0, colonIndex);
          const portPart = serverPart.substring(colonIndex + 1);
          port = portPart.split('?')[0]; // 去掉查询参数
        }
      }
    }
    
    return {
      name,
      protocol,
      server,
      port,
      rawUrl: nodeUrl
    };
  } catch (e) {
    return {
      name: '解析失败',
      protocol: 'UNKNOWN',
      server: '',
      port: '',
      error: e.message
    };
  }
};

const parsedNodes = computed(() => {
  return props.nodes.map(nodeUrl => parseNodeInfo(nodeUrl));
});

const selectedNode = ref(null);

const showNodeDetails = (node) => {
  selectedNode.value = node;
};

const copyToClipboard = (text) => {
  navigator.clipboard.writeText(text).then(() => {
    // 可以添加一个toast提示
    alert('已复制到剪贴板');
  }).catch(err => {
    console.error('复制失败:', err);
  });
};

const getProtocolColor = (protocol) => {
  const colors = {
    'SS': 'bg-blue-500/20 text-blue-500',
    'SSR': 'bg-cyan-500/20 text-cyan-500',
    'VMESS': 'bg-purple-500/20 text-purple-500',
    'VLESS': 'bg-indigo-500/20 text-indigo-500',
    'TROJAN': 'bg-red-500/20 text-red-500',
    'HYSTERIA': 'bg-pink-500/20 text-pink-500',
    'HYSTERIA2': 'bg-pink-500/20 text-pink-500',
    'HY': 'bg-pink-500/20 text-pink-500',
    'HY2': 'bg-pink-500/20 text-pink-500',
    'TUIC': 'bg-orange-500/20 text-orange-500',
    'SOCKS5': 'bg-gray-500/20 text-gray-500',
  };
  return colors[protocol] || 'bg-gray-500/20 text-gray-500';
};
</script>

<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm" @click.self="emit('close')">
    <div class="bg-white dark:bg-gray-900 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[85vh] flex flex-col">
      <!-- Header -->
      <div class="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
        <div>
          <h2 class="text-2xl font-bold text-gray-800 dark:text-gray-100">节点列表</h2>
          <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">{{ subscription.name }}</p>
        </div>
        <button 
          @click="emit('close')" 
          class="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <!-- Content -->
      <div class="flex-1 overflow-y-auto p-6">
        <!-- Loading State -->
        <div v-if="isLoading" class="flex flex-col items-center justify-center py-12">
          <svg class="animate-spin h-12 w-12 text-indigo-500 mb-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <p class="text-gray-500 dark:text-gray-400">正在获取节点列表...</p>
        </div>

        <!-- Error State -->
        <div v-else-if="error" class="flex flex-col items-center justify-center py-12">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-red-500 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p class="text-red-500 dark:text-red-400 mb-4">{{ error }}</p>
          <button 
            @click="emit('retry')" 
            class="px-4 py-2 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg transition-colors"
          >
            重试
          </button>
        </div>

        <!-- Node List -->
        <div v-else-if="parsedNodes.length > 0" class="space-y-3">
          <div 
            v-for="(node, index) in parsedNodes" 
            :key="index"
            class="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4 hover:shadow-md transition-shadow cursor-pointer"
            @click="showNodeDetails(node)"
          >
            <div class="flex items-start justify-between gap-4">
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 mb-2">
                  <span class="text-xs font-bold px-2 py-1 rounded-full" :class="getProtocolColor(node.protocol)">
                    {{ node.protocol }}
                  </span>
                  <h3 class="font-semibold text-gray-800 dark:text-gray-200 truncate" :title="node.name">
                    {{ node.name }}
                  </h3>
                </div>
                <div class="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                  <div v-if="node.server" class="flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                    </svg>
                    <span class="font-mono">{{ node.server }}</span>
                    <span v-if="node.port" class="text-indigo-500 font-semibold">:{{ node.port }}</span>
                  </div>
                </div>
              </div>
              <button 
                @click.stop="copyToClipboard(node.rawUrl || '')"
                class="p-2 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-500 hover:text-indigo-500 transition-colors shrink-0"
                title="复制节点链接"
              >
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        <!-- Empty State -->
        <div v-else class="flex flex-col items-center justify-center py-12">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-gray-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
          </svg>
          <p class="text-gray-500 dark:text-gray-400">未找到任何节点</p>
        </div>
      </div>

      <!-- Footer -->
      <div class="flex items-center justify-between p-6 border-t border-gray-200 dark:border-gray-700">
        <div class="text-sm text-gray-500 dark:text-gray-400">
          共 <span class="font-semibold text-indigo-500">{{ parsedNodes.length }}</span> 个节点
        </div>
        <button 
          @click="emit('close')" 
          class="px-6 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-800 dark:text-gray-200 rounded-lg transition-colors font-medium"
        >
          关闭
        </button>
      </div>
    </div>
  </div>
</template>

