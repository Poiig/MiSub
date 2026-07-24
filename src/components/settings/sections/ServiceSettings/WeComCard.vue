<script setup>
import { ref } from 'vue';
import { useI18n } from '../../../../i18n/index.js';

const { t } = useI18n();

const props = defineProps({
  settings: {
    type: Object,
    required: true
  }
});

const isTesting = ref(false);
const testResult = ref(null);

/**
 * 调用后端测试企微 Webhook，确认机器人可收消息。
 */
async function testNotification() {
  isTesting.value = true;
  testResult.value = null;

  try {
    const response = await fetch('/api/test_notification', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel: 'wecom',
        weComWebhookUrl: props.settings.WeComWebhookUrl
      })
    });

    const data = await response.json();
    if (data.success) {
      testResult.value = { success: true, message: t('settings.wecomTestSuccess') };
    } else {
      testResult.value = {
        success: false,
        message: data.error || t('settings.wecomTestFailed'),
        detail: data.detail
      };
    }
  } catch (error) {
    testResult.value = {
      success: false,
      message: error.message || t('settings.wecomRequestFailed')
    };
  } finally {
    isTesting.value = false;
  }
}
</script>

<template>
  <section class="bg-white/90 dark:bg-gray-900/70 misub-radius-lg p-6 border border-gray-100/80 dark:border-white/10 shadow-sm space-y-4">
    <div>
      <h3 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('settings.wecomNotifyTitle') }}</h3>
      <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">{{ t('settings.wecomNotifyDesc') }}</p>
    </div>

    <div>
      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{{ t('settings.wecomWebhookLabel') }}</label>
      <input
        v-model="settings.WeComWebhookUrl"
        type="text"
        :placeholder="t('settings.wecomWebhookPlaceholder')"
        class="block w-full px-3 py-2 bg-gray-50 dark:bg-gray-900/50 border border-gray-300 dark:border-gray-600 misub-radius-lg shadow-xs focus:ring-1 focus:ring-blue-500 focus:border-blue-500 sm:text-sm dark:text-white transition-colors"
      >
      <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('settings.wecomWebhookHint') }}</p>
    </div>

    <div class="flex flex-col sm:flex-row sm:items-center gap-3">
      <button
        type="button"
        class="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-medium misub-radius-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
        :disabled="isTesting || !settings.WeComWebhookUrl"
        @click="testNotification"
      >
        <svg v-if="isTesting" class="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
        <span>{{ isTesting ? t('settings.wecomTesting') : t('settings.wecomSendTest') }}</span>
      </button>
      <p v-if="testResult" class="text-sm" :class="testResult.success ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'">
        {{ testResult.message }}
      </p>
    </div>
  </section>
</template>
