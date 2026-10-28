<template>
  <div class="proxy-page view-enter-active">
    <div class="proxy-metrics-bar">
      <div class="metric-pill">
        <span class="pulse-healthy"></span>
        <span class="pill-label">健康可用:</span>
        <strong class="pill-val">{{ stats.healthy }}</strong>
      </div>
      <div class="metric-pill">
        <span class="dot-semi"></span>
        <span class="pill-label">半开探测:</span>
        <strong class="pill-val">{{ stats.semi_open }}</strong>
      </div>
      <div class="metric-pill">
        <span class="dot-down"></span>
        <span class="pill-label">熔断异常:</span>
        <strong class="pill-val">{{ stats.unhealthy }}</strong>
      </div>
      <div class="metric-pill">
        <span class="pill-label">平均延迟:</span>
        <strong class="pill-val tabular-nums">{{ stats.avg_latency }}ms</strong>
      </div>
      <div class="flex-spacer"></div>
      <button class="ghost-btn" @click="showImportDrawer = true">+ 批量导入节点</button>
      <button class="primary-btn" @click="showAddDialog = true">+ 新增代理</button>
    </div>

    <div class="table-container">
      <el-table :data="proxyList" v-loading="loading" style="width: 100%">
        <el-table-column prop="name" label="节点名称" min-width="140" />
        <el-table-column prop="protocol" label="协议类型" width="100">
          <template #default="{ row }">
            <span class="proto-tag" :class="row.protocol">{{ row.protocol.toUpperCase() }}</span>
          </template>
        </el-table-column>
        <el-table-column label="服务器地址" min-width="160">
          <template #default="{ row }">
            <span>{{ row.host }}:{{ row.port }}</span>
          </template>
        </el-table-column>
        <el-table-column label="健康状态" width="120">
          <template #default="{ row }">
            <div class="status-cell">
              <span v-if="row.health_status === 'healthy'" class="pulse-healthy"></span>
              <span v-else-if="row.health_status === 'semi-open'" class="dot-semi"></span>
              <span v-else class="dot-down"></span>
              <span class="status-text">{{ row.health_status }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="出口真实 IP" min-width="130">
          <template #default="{ row }">
            <code>{{ row.egress_ip || '未探查' }}</code>
          </template>
        </el-table-column>
        <el-table-column label="延迟" width="100">
          <template #default="{ row }">
            <span class="tabular-nums" :class="row.latency_ms > 1000 ? 'text-warn' : ''">
              {{ row.latency_ms ? `${row.latency_ms}ms` : '-' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="开关" width="80">
          <template #default="{ row }">
            <el-switch v-model="row.status" :active-value="1" :inactive-value="0" @change="toggleStatus(row)" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="160" fixed="right">
          <template #default="{ row }">
            <button class="action-link" :disabled="testingId === row.id" @click="testProxy(row)">
              {{ testingId === row.id ? '探查中...' : '测试出站' }}
            </button>
            <button class="action-link text-danger" @click="deleteProxy(row)">删除</button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 批量导入抽屉 -->
    <el-drawer v-model="showImportDrawer" title="批量录入代理节点" size="480px">
      <div class="drawer-content">
        <p class="drawer-tip">
          支持 <code>ip:port</code> 或 <code>ip:port:user:pass</code> 语法，每行一条。密码将自动 AES-256 加密存库。
        </p>
        <textarea
          v-model="importText"
          class="import-textarea"
          rows="12"
          placeholder="104.28.16.8:8080:proxyuser:secret123&#10;198.51.100.22:1080"
        ></textarea>
        <div class="drawer-footer">
          <button class="primary-btn full-w" :disabled="importing" @click="handleBatchImport">
            {{ importing ? '加密录入中...' : '确认批量导入' }}
          </button>
        </div>
      </div>
    </el-drawer>

    <!-- 新增代理弹窗 -->
    <el-dialog v-model="showAddDialog" title="录入单节点网络代理" width="480px">
      <div class="dialog-form">
        <div class="form-item">
          <label>节点名称</label>
          <input v-model="addForm.name" placeholder="如: 美国-机房01" class="input-custom" />
        </div>
        <div class="form-row">
          <div class="form-item flex-1">
            <label>协议类型</label>
            <select v-model="addForm.protocol" class="select-theme full-w">
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
              <option value="socks5">SOCKS5</option>
              <option value="socks5h">SOCKS5h (远程DNS)</option>
            </select>
          </div>
          <div class="form-item flex-2">
            <label>服务器地址</label>
            <input v-model="addForm.host" placeholder="1.2.3.4" class="input-custom" />
          </div>
          <div class="form-item flex-1">
            <label>端口</label>
            <input v-model.number="addForm.port" type="number" placeholder="1080" class="input-custom" />
          </div>
        </div>
        <div class="form-row">
          <div class="form-item flex-1">
            <label>认证用户名 (可选)</label>
            <input v-model="addForm.auth_user" placeholder="用户名" class="input-custom" />
          </div>
          <div class="form-item flex-1">
            <label>认证密码 (可选)</label>
            <input v-model="addForm.auth_pass" type="password" placeholder="密码" class="input-custom" />
          </div>
        </div>
        <div class="dialog-footer">
          <button class="ghost-btn" @click="showAddDialog = false">取消</button>
          <button class="primary-btn" @click="handleAddSingle">确认保存</button>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'

const loading = ref(false)
const testingId = ref<number | null>(null)
const showImportDrawer = ref(false)
const showAddDialog = ref(false)
const importing = ref(false)
const importText = ref('')

const stats = ref({ healthy: 0, semi_open: 0, unhealthy: 0, avg_latency: 0 })
const proxyList = ref<any[]>([])

const addForm = ref({
  name: '',
  protocol: 'http',
  host: '',
  port: 8080,
  auth_user: '',
  auth_pass: ''
})

const fetchProxies = async () => {
  loading.value = true
  try {
    const [listRes, statsRes] = await Promise.all([
      axios.get('/api/v1/proxies'),
      axios.get('/api/v1/proxy-stats')
    ])
    proxyList.value = listRes.data.data.list
    stats.value = statsRes.data.data
  } catch (err) {
    ElMessage.error('无法拉取代理池列表')
  } finally {
    loading.value = false
  }
}

const testProxy = async (row: any) => {
  testingId.value = row.id
  try {
    const { data } = await axios.post(`/api/v1/proxies/${row.id}/test`)
    ElMessage.success(`✅ 出口 IP: ${data.data.egress_ip} · 延迟: ${data.data.latency_ms}ms`)
    fetchProxies()
  } catch (err: any) {
    ElMessage.error(`❌ 探针失败: ${err.response?.data?.msg || '网络连接超时'}`)
  } finally {
    testingId.value = null
  }
}

const toggleStatus = async (row: any) => {
  try {
    await axios.put(`/api/v1/proxies/${row.id}`, { status: row.status })
    ElMessage.success('状态已同步')
  } catch (e) {
    row.status = row.status === 1 ? 0 : 1
    ElMessage.error('修改失败')
  }
}

const handleAddSingle = async () => {
  if (!addForm.value.name || !addForm.value.host) {
    ElMessage.warning('请填写节点完整地址')
    return
  }
  try {
    await axios.post('/api/v1/proxies', addForm.value)
    ElMessage.success('代理节点录入成功')
    showAddDialog.value = false
    fetchProxies()
  } catch (e: any) {
    ElMessage.error(e.response?.data?.msg || '保存失败')
  }
}

const handleBatchImport = async () => {
  if (!importText.value.trim()) return
  importing.value = true
  try {
    const { data } = await axios.post('/api/v1/proxies/import', { content: importText.value })
    ElMessage.success(data.msg)
    showImportDrawer.value = false
    importText.value = ''
    fetchProxies()
  } catch (err: any) {
    ElMessage.error('导入失败')
  } finally {
    importing.value = false
  }
}

const deleteProxy = (row: any) => {
  ElMessageBox.confirm(`确认删除代理 [${row.name}] 吗？`, '安全警告', {
    type: 'warning'
  }).then(async () => {
    await axios.delete(`/api/v1/proxies/${row.id}`)
    ElMessage.success('已删除')
    fetchProxies()
  })
}

onMounted(() => {
  fetchProxies()
})
</script>

<style scoped>
.proxy-page { display: flex; flex-direction: column; gap: 20px; }
.proxy-metrics-bar {
  display: flex; align-items: center; gap: 16px;
  background: var(--card); padding: 14px 20px;
  border-radius: var(--r-lg); border: 1px solid var(--border);
  box-shadow: var(--shadow-sm); overflow-x: auto;
}
.metric-pill {
  display: flex; align-items: center; gap: 8px; font-size: 13px;
  padding: 4px 12px; background: var(--bg); border-radius: var(--r-full);
}
.pill-label { color: var(--text-2); }
.pill-val { color: var(--text-1); }
.dot-semi { width: 8px; height: 8px; border-radius: 50%; background: var(--warning); }
.dot-down { width: 8px; height: 8px; border-radius: 50%; background: var(--danger); }

.flex-spacer { flex: 1; }
.primary-btn {
  background: var(--grad-brand); color: #fff; border: none;
  padding: 9px 18px; border-radius: var(--r-md); font-size: 13px; font-weight: 500; cursor: pointer;
}
.ghost-btn {
  background: transparent; color: var(--text-2); border: 1px solid var(--border-strong);
  padding: 8px 16px; border-radius: var(--r-md); font-size: 13px; cursor: pointer;
}
.table-container {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--r-lg); padding: 16px; box-shadow: var(--shadow-sm);
}

.proto-tag { font-size: 11px; font-weight: 600; padding: 2px 6px; border-radius: 4px; }
.proto-tag.http { background: #EFF6FF; color: #2563EB; }
.proto-tag.socks5, .proto-tag.socks5h { background: #F0FDF4; color: #16A34A; }
.status-cell { display: flex; align-items: center; gap: 6px; }
.status-text { font-size: 12px; color: var(--text-2); }

.action-link { background: none; border: none; color: var(--brand-600); font-size: 12px; cursor: pointer; margin-right: 12px; }
.action-link.text-danger { color: var(--danger); }
.action-link:disabled { opacity: 0.5; cursor: not-allowed; }

.drawer-content { display: flex; flex-direction: column; gap: 16px; }
.drawer-tip { font-size: 13px; color: var(--text-2); line-height: 1.5; }
.import-textarea {
  width: 100%; box-sizing: border-box; padding: 12px;
  border-radius: var(--r-sm); border: 1px solid var(--border-strong); font-family: monospace; font-size: 13px; outline: none;
}

.dialog-form { display: flex; flex-direction: column; gap: 14px; }
.form-row { display: flex; gap: 12px; }
.flex-1 { flex: 1; }
.flex-2 { flex: 2; }
.input-custom {
  width: 100%; box-sizing: border-box; padding: 9px 12px;
  border-radius: var(--r-sm); border: 1px solid var(--border-strong); outline: none;
}
.select-theme {
  padding: 9px 12px; border-radius: var(--r-sm); border: 1px solid var(--border-strong); outline: none;
}
.dialog-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px; }
.full-w { width: 100%; }
</style>
