<script setup>
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue';
import { t } from '@/i18n/index.js';

const props = defineProps({
  modelValue: {
    type: String,
    default: ''
  },
  groups: {
    type: Array,
    default: () => []
  },
  placeholder: {
    type: String,
    default: () => t('common.groupPlaceholder')
  }
});

const emit = defineEmits(['update:modelValue']);

const isOpen = ref(false);
const inputRef = ref(null);
const containerRef = ref(null);
const dropdownStyle = ref({ top: '0px', left: '0px', width: '0px' });
const isTyping = ref(false);

const normalizeGroup = (value) => String(value || '').trim();
const normalizeGroupForCompare = (value) => normalizeGroup(value).toLowerCase();
const hasExistingGroup = computed(() => {
  const current = normalizeGroupForCompare(props.modelValue);
  if (!current) return false;
  return props.groups.some(group => normalizeGroupForCompare(group) === current);
});

// Filter groups based on actual typing. Opening dropdown should show all groups.
const filteredGroups = computed(() => {
  const groups = props.groups.map(normalizeGroup).filter(Boolean);
  const uniqueGroups = Array.from(new Set(groups));
  const query = isTyping.value ? normalizeGroupForCompare(props.modelValue) : '';
  if (!query) return uniqueGroups;
  return uniqueGroups.filter(group => group.toLowerCase().includes(query));
});

const updatePosition = () => {
  if (inputRef.value) {
    const rect = inputRef.value.getBoundingClientRect();
    dropdownStyle.value = {
      top: `${rect.bottom + window.scrollY + 4}px`,
      left: `${rect.left + window.scrollX}px`,
      width: `${rect.width}px`
    };
  }
};

const handleInput = (e) => {
  isTyping.value = true;
  emit('update:modelValue', e.target.value);
  isOpen.value = true;
};

const handleFocus = () => {
  isTyping.value = false;
  isOpen.value = true;
};

const selectGroup = (group) => {
  emit('update:modelValue', normalizeGroup(group));
  isTyping.value = false;
  isOpen.value = false;
};

/**
 * 清空当前分组：编辑节点时允许从「已选分组」回到未分组。
 */
const clearGroup = () => {
  emit('update:modelValue', '');
  isTyping.value = false;
  isOpen.value = false;
};

const toggleDropdown = () => {
  isTyping.value = false;
  isOpen.value = !isOpen.value;
};

const handleClickOutside = (e) => {
  if (containerRef.value && !containerRef.value.contains(e.target)) {
    // Check if clicking inside the dropdown (which is teleported)
    const dropdownEl = document.getElementById('group-selector-dropdown');
    if (dropdownEl && dropdownEl.contains(e.target)) {
      return;
    }
    isOpen.value = false;
  }
};

const handleScroll = () => {
  if (isOpen.value) {
    updatePosition();
  }
};

watch(isOpen, (val) => {
  if (val) {
    nextTick(() => {
      updatePosition();
      window.addEventListener('scroll', handleScroll, true);
      window.addEventListener('resize', updatePosition);
    });
  } else {
    window.removeEventListener('scroll', handleScroll, true);
    window.removeEventListener('resize', updatePosition);
  }
});

onMounted(() => {
  document.addEventListener('click', handleClickOutside, true);
});

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside, true);
  window.removeEventListener('scroll', handleScroll, true);
  window.removeEventListener('resize', updatePosition);
});
</script>

<template>
  <div ref="containerRef" class="relative group w-full">
    <div class="relative w-full">
      <input
        ref="inputRef"
        :value="modelValue"
        type="text"
        :placeholder="placeholder"
        class="w-full pl-10 py-2 bg-gray-50 dark:bg-black/20 border border-gray-200 dark:border-white/10 misub-radius-lg focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 text-sm transition-all h-[42px] dark:text-white placeholder-gray-400"
        :class="normalizeGroup(modelValue) ? 'pr-16' : 'pr-10'"
        @input="handleInput"
        @focus="handleFocus"
        @keydown.enter="isOpen = false"
        @keydown.escape="isOpen = false"
      />
      <div class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none">
        <slot name="icon">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path d="M4 3a2 2 0 100 4h12a2 2 0 100-4H4z" />
            <path fill-rule="evenodd" d="M3 8h14v7a2 2 0 01-2 2H5a2 2 0 01-2-2V8zm5 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" clip-rule="evenodd" />
          </svg>
        </slot>
      </div>

      <!-- 有值时可一键清除，避免只能逐字删 -->
      <button
        v-if="normalizeGroup(modelValue)"
        type="button"
        data-testid="group-selector-clear"
        class="absolute right-8 top-1/2 -translate-y-1/2 rounded p-0.5 text-gray-400 transition-colors hover:text-gray-600 dark:hover:text-gray-200"
        :title="t('common.clearGroup')"
        :aria-label="t('common.clearGroup')"
        @click.stop="clearGroup"
      >
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
        </svg>
      </button>
      
      <!-- Arrow Icon -->
      <div 
        data-testid="group-selector-toggle"
        class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 cursor-pointer transition-transform duration-200 hover:text-gray-600 dark:hover:text-gray-300" 
        :class="{ 'rotate-180': isOpen }"
        @click.stop="toggleDropdown"
      >
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    </div>

    <!-- Dropdown -->
    <Teleport to="body">
      <Transition
        enter-active-class="transition duration-100 ease-out"
        enter-from-class="transform scale-95 opacity-0"
        enter-to-class="transform scale-100 opacity-100"
        leave-active-class="transition duration-75 ease-in"
        leave-from-class="transform scale-100 opacity-100"
        leave-to-class="transform scale-95 opacity-0"
      >
        <div
          v-if="isOpen"
          id="group-selector-dropdown"
          class="absolute z-[9999] bg-white dark:bg-gray-800 misub-radius-lg shadow-lg border border-gray-100 dark:border-gray-700 max-h-60 overflow-auto py-1 custom-scrollbar"
          :style="dropdownStyle"
        >
          <button
            type="button"
            class="w-full text-left pl-10 pr-4 py-2 text-sm text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700/50 block transition-colors"
            :class="{ 'bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400': !normalizeGroup(modelValue) }"
            @click="clearGroup"
          >
            {{ t('common.noGroup') }}
          </button>
          <button
            v-if="normalizeGroup(modelValue) && !hasExistingGroup"
            type="button"
            class="w-full text-left pl-10 pr-4 py-2 text-sm text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700/50 block transition-colors"
            @click="selectGroup(modelValue)"
          >
            {{ t('common.createGroup', { name: modelValue }) }}
          </button>
          <button
            v-for="group in filteredGroups"
            :key="group"
            type="button"
            class="w-full text-left pl-10 pr-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-indigo-50 dark:hover:bg-indigo-500/10 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors flex items-center justify-between group-item"
            :class="{ 'bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400': modelValue === group }"
            @click="selectGroup(group)"
          >
            <span>{{ group }}</span>
            <svg v-if="modelValue === group" xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 4px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background-color: rgba(156, 163, 175, 0.5);
  border-radius: 2px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background-color: rgba(156, 163, 175, 0.8);
}
</style>
