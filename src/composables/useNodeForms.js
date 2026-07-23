import { ref } from 'vue';
import { useToastStore } from '../stores/toast.js';
import { extractNodeName } from '../lib/utils.js';
import { generateNodeId } from '../utils/id.js';
import { defaultExpiresAtDateInput, dateInputToExpiresAt, toDateInputValue } from '../utils/expiry.js';
import { t } from '../i18n/index.js';

const isDev = import.meta.env.DEV;

export function useNodeForms({ addNode, updateNode }) {
    const { showToast } = useToastStore();
    const showModal = ref(false);
    const isNew = ref(false);
    const editingNode = ref(null);

    const openAdd = () => {
        isNew.value = true;
        editingNode.value = {
            id: generateNodeId(),
            name: '',
            url: '',
            enabled: true,
            colorTag: null,
            // 表单用 YYYY-MM-DD，保存时再转成日末 ISO
            expiresAt: defaultExpiresAtDateInput()
        };
        showModal.value = true;
    };

    const openEdit = (node) => {
        if (!node) {
            console.error('UseNodeForms: openEdit called with null');
            return;
        }
        if (isDev) {
            console.debug('UseNodeForms: openEdit called with', node);
        }
        isNew.value = false;
        editingNode.value = {
            ...node,
            expiresAt: toDateInputValue(node.expiresAt)
        };
        if (isDev) {
            console.debug('UseNodeForms: editingNode set to', editingNode.value);
        }
        showModal.value = true;
    };

    const handleUrlInput = (event) => {
        if (!editingNode.value) return;
        const newUrl = event.target.value;
        if (newUrl && !editingNode.value.name) {
            editingNode.value.name = extractNodeName(newUrl);
        }
    };

    const handleSave = () => {
        if (!editingNode.value || !editingNode.value.url) {
            showToast(t('manualNodes.urlRequired'), 'error');
            return;
        }

        const nodeToSave = {
            ...editingNode.value,
            expiresAt: dateInputToExpiresAt(editingNode.value.expiresAt)
        };

        if (isNew.value) {
            addNode(nodeToSave);
        } else {
            updateNode(nodeToSave);
        }
        showModal.value = false;
    };

    return {
        showModal,
        isNew,
        editingNode,
        openAdd,
        openEdit,
        handleUrlInput,
        handleSave
    };
}
