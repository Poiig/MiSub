<script setup>
import { computed } from 'vue';
import { useI18n } from '@/i18n/index.js';
import Switch from '../ui/Switch.vue';
import { extractHostAndPort } from '../../lib/utils.js';
import { getDaysRemaining, getExpiryStyleClass } from '../../utils/expiry.js';

const props = defineProps({
  node: {
    type: Object,
    required: true
  },
  isSelectionMode: Boolean,
  isSelected: Boolean,
  pingResult: Object,
  isPinging: Boolean
});

const emit = defineEmits(['delete', 'edit', 'toggle-select', 'filter-group', 'ping', 'change', 'renew']);
const { t } = useI18n();

const hostAndPort = computed(() => extractHostAndPort(props.node?.url));

const expiryInfo = computed(() => {
  const days = getDaysRemaining(props.node?.expiresAt);
  if (days === null) return null;
  return {
    text: days < 0
      ? t('subscriptions.expired')
      : (days === 0 ? t('subscriptions.expiresToday') : t('subscriptions.expiresInDays', { count: days })),
    style: getExpiryStyleClass(days)
  };
});

const getProtocol = (url) => {
  try {
    if (!url) return 'unknown';
    const lowerUrl = url.toLowerCase();
    if (lowerUrl.startsWith('anytls://')) return 'anytls';
    if (lowerUrl.startsWith('hysteria2://') || lowerUrl.startsWith('hy2://')) return 'hysteria2';
    if (lowerUrl.startsWith('hysteria://') || lowerUrl.startsWith('hy://')) return 'hysteria';
    if (lowerUrl.startsWith('ssr://')) return 'ssr';
    if (lowerUrl.startsWith('tuic://')) return 'tuic';
    if (lowerUrl.startsWith('ss://')) return 'ss';
    if (lowerUrl.startsWith('vmess://')) return 'vmess';
    if (lowerUrl.startsWith('vless://')) return 'vless';
    if (lowerUrl.startsWith('trojan://')) return 'trojan';
    if (lowerUrl.startsWith('socks5://') || lowerUrl.startsWith('socks://')) return 'socks5';
    if (lowerUrl.startsWith('snell://')) return 'snell';
    if (lowerUrl.startsWith('naive+https://') || lowerUrl.startsWith('naive+http://') || lowerUrl.startsWith('naive+quic://')) return 'naive';
    if (lowerUrl.startsWith('http')) return 'http';
  } catch {
    return 'unknown';
  }
  return 'unknown';
};

const protocol = computed(() => getProtocol(props.node.url));

const protocolStyle = computed(() => {
  const p = protocol.value;
  switch (p) {
    case 'anytls': return { text: 'AnyTLS', style: 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border border-slate-500/20' };
    case 'vless': return { text: 'VLESS', style: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20' };
    case 'hysteria2': return { text: 'HY2', style: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20' };
    case 'hysteria': return { text: 'Hysteria', style: 'bg-fuchsia-500/10 text-fuchsia-600 dark:text-fuchsia-400 border border-fuchsia-500/20' };
    case 'tuic': return { text: 'TUIC', style: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20' };
    case 'trojan': return { text: 'TROJAN', style: 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20' };
    case 'ssr': return { text: 'SSR', style: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20' };
    case 'ss': return { text: 'SS', style: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/20' };
    case 'vmess': return { text: 'VMESS', style: 'bg-teal-500/10 text-teal-600 dark:text-teal-400 border border-teal-500/20' };
    case 'socks5': return { text: 'SOCKS5', style: 'bg-lime-500/10 text-lime-600 dark:text-lime-400 border border-lime-500/20' };
    case 'http': return { text: 'HTTP', style: 'bg-green-500/10 text-green-600 dark:text-green-400 border border-green-500/20' };
    case 'snell': return { text: 'SNELL', style: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20' };
    case 'naive': return { text: 'NAIVE', style: 'bg-pink-500/10 text-pink-600 dark:text-pink-400 border border-pink-500/20' };
    default: return { text: 'LINK', style: 'bg-gray-500/10 text-gray-500 dark:text-gray-400 border border-gray-500/20' };
  }
});

/**
 * 切换启用状态，与机场订阅卡片底部开关一致。
 */
const handleEnabledChange = (enabled) => {
  emit('change', { ...props.node, enabled });
};

/**
 * 请求续期：只抛出当前节点，由上层统一计算新有效期，避免重复 +1 年。
 */
const handleRenew = () => {
  emit('renew', props.node);
};
</script>

<template>
  <div
    class="group relative flex h-full min-h-[200px] flex-col overflow-hidden rounded-xl border border-gray-100 bg-white p-5 shadow-sm transition-all duration-300 hover:-translate-y-0.5 hover:shadow-xl hover:shadow-primary-500/5 dark:border-white/10 dark:bg-gray-900/70"
    :class="{
      'opacity-75 grayscale-[0.8]': !node.enabled && !isSelectionMode,
      'ring-2 ring-primary-500 bg-primary-50 dark:bg-primary-900/10': isSelectionMode && isSelected,
      'cursor-pointer': isSelectionMode
    }"
    @click="isSelectionMode ? emit('toggle-select') : null"
  >
    <div class="relative z-10 flex h-full flex-col">
      <div class="mb-4 flex items-start justify-between gap-3">
        <div class="min-w-0 flex-1">
          <!-- 头部只展示协议与剩余天数，避免分组名挤换行导致两张卡片样式不一致 -->
          <div class="mb-1.5 flex items-center gap-2">
            <div
              v-if="isSelectionMode"
              class="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 transition-colors"
              :class="isSelected ? 'border-primary-500 bg-primary-500' : 'border-gray-300 dark:border-gray-600'"
            >
              <svg v-if="isSelected" xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5 text-white" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" /></svg>
            </div>
            <span class="rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider" :class="protocolStyle.style">
              {{ protocolStyle.text }}
            </span>
            <span
              v-if="expiryInfo"
              class="rounded-full border border-transparent bg-gray-100 px-2 py-0.5 text-[10px] font-medium dark:bg-white/5"
              :class="expiryInfo.style"
            >
              {{ expiryInfo.text }}
            </span>
            <div
              v-if="pingResult"
              class="rounded-full px-2 py-0.5 text-[10px] font-medium"
              :class="{
                'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400': pingResult.status === 'ok' && pingResult.latency < 300,
                'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400': pingResult.status === 'ok' && pingResult.latency >= 300,
                'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400': pingResult.status === 'error' || pingResult.status === 'timeout',
                'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400': pingResult.status === 'loading'
              }"
            >
              <span v-if="pingResult.status === 'loading'">{{ t('manualNodes.pinging') }}</span>
              <span v-else-if="pingResult.status === 'ok'">{{ pingResult.latency }}ms</span>
              <span v-else>{{ t('manualNodes.unreachable') }}</span>
            </div>
          </div>
          <h3 class="truncate text-lg font-semibold leading-tight text-gray-900 dark:text-white" :title="node.name || t('manualNodes.unnamed')">
            {{ node.name || t('manualNodes.unnamed') }}
          </h3>
        </div>

        <div
          v-if="!isSelectionMode"
          class="flex items-center gap-1 opacity-100 transition-opacity duration-200 md:opacity-0 md:group-hover:opacity-100"
        >
          <button
            type="button"
            class="flex min-h-[44px] min-w-[44px] items-center justify-center rounded-full p-2.5 text-gray-400 transition-colors hover:bg-green-500/10 hover:text-green-500 lg:min-h-0 lg:min-w-0"
            :title="t('actions.ping')"
            :disabled="isPinging"
            :class="{ 'animate-pulse text-green-500': isPinging }"
            @click.stop="emit('ping')"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </button>
          <button
            type="button"
            class="flex min-h-[44px] min-w-[44px] items-center justify-center rounded-full p-2.5 text-gray-400 transition-colors hover:bg-primary-50 hover:text-primary-500 dark:hover:bg-white/10 lg:min-h-0 lg:min-w-0"
            :title="t('actions.edit')"
            @click.stop="emit('edit')"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.536L16.732 3.732z" /></svg>
          </button>
          <button
            type="button"
            class="flex min-h-[44px] min-w-[44px] items-center justify-center rounded-full p-2.5 text-gray-400 transition-colors hover:bg-red-50 hover:text-red-500 dark:hover:bg-red-500/20 lg:min-h-0 lg:min-w-0"
            :title="t('actions.delete')"
            @click.stop="emit('delete')"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
          </button>
        </div>
      </div>

      <div class="grid gap-3 rounded-lg border border-gray-100 bg-gray-50/80 p-3 dark:border-white/10 dark:bg-white/5">
        <div class="flex items-center justify-between text-xs">
          <span class="text-gray-500 dark:text-gray-400">{{ t('manualNodes.addressLabel') }}</span>
          <span class="truncate font-mono font-semibold text-gray-700 dark:text-gray-200">
            {{ hostAndPort.host || 'N/A' }}:{{ hostAndPort.port || 'N/A' }}
          </span>
        </div>
        <div class="flex items-center justify-between text-xs">
          <span class="text-gray-500 dark:text-gray-400">{{ t('manualNodes.groupOptional') }}</span>
          <button
            v-if="node.group"
            type="button"
            class="truncate font-semibold text-gray-700 transition-colors hover:text-primary-500 dark:text-gray-200"
            :title="node.group"
            @click.stop="emit('filter-group', node.group)"
          >
            {{ node.group }}
          </button>
          <span v-else class="font-semibold text-gray-700 dark:text-gray-200">
            {{ t('manualNodes.ungrouped') }}
          </span>
        </div>
      </div>

      <div class="mt-auto flex items-center justify-between border-t border-gray-100 pt-3 dark:border-white/10">
        <Switch
          :model-value="node.enabled !== false"
          :disabled="isSelectionMode"
          @update:model-value="handleEnabledChange"
        />
        <button
          type="button"
          class="rounded-md px-2 py-1 text-xs font-medium text-indigo-600 transition-colors hover:bg-indigo-50 dark:text-indigo-300 dark:hover:bg-indigo-500/10"
          :title="t('manualNodes.renewOneYear')"
          :disabled="isSelectionMode"
          @click.stop="handleRenew"
        >
          {{ t('manualNodes.renew') }}
        </button>
      </div>
    </div>
  </div>
</template>
