<template>
  <div class="domain-page view-enter-active">
    <!-- 顶部操作与搜索 -->
    <div class="action-bar-glass">
      <div class="search-input-group">
        <input 
          v-model="searchKeyword" 
          placeholder="搜索主域名 (如: target.com) 或备注..." 
          class="search-input"
          @keyup.enter="fetchDomains"
        />
        <button class="ghost-btn-search" @click="fetchDomains">检索</button>
      </div>

      <div class="filter-group">
        <select v-model="selectedGroup" class="select-theme" @change="fetchDomains">
          <option value="">全部资产分组</option>
          <option value="SRC核心">SRC核心</option>
          <option value="边界网关">边界网关</option>
          <option value="自有基线">自有基线</option>
        </select>
      </div>

      <div class="flex-spacer"></div>

      <button class="primary-btn" @click="openCreateDrawer">
        <span>+ 新增监控主域名</span>
      </button>
    </div>

    <!-- 桌面表格视图 -->
    <div class="desktop-table-box">
      <el-table :data="domainList" v-loading="loading" style="width: 100%">
        <el-table-column prop="domain" label="主域名" min-width="180">
          <template #default="{ row }">
            <div class="domain-main-cell">
              <span class="domain-name" @click="viewSubdomains(row)">{{ row.domain }}</span>
              <span class="group-pill">{{ row.group_name }}</span>
            </div>
            <div class="remark-sub">{{ row.remark || '暂无说明' }}</div>
          </template>
        </el-table-column>

        <el-table-column label="网络出口策略" min-width="160">
          <template #default="{ row }">
            <span v-if="row.proxy_mode === 'direct'" class="soft-tag info">直连出站</span>
            <span v-else-if="row.proxy_mode === 'proxy_group'" class="soft-tag brand">
              代理: {{ row.proxy_group_name || '已绑定组' }}
            </span>
            <span v-else class="soft-tag neutral">全局自动</span>
          </template>
        </el-table-column>

        <el-table-column label="高阶探针" width="140">
          <template #default="{ row }">
            <div class="feature-tags">
              <span v-if="row.enable_axfr" class="mini-tag warn">AXFR开启</span>
              <span v-if="row.enable_wildcard_filter" class="mini-tag success">泛解析清洗</span>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="存活子域名" width="130">
          <template #default="{ row }">
            <span class="metric-count tabular-nums" @click="viewSubdomains(row)">
              {{ row.subdomain_count }} 条
            </span>
          </template>
        </el-table-column>

        <el-table-column label="监控周期" width="110">
          <template #default="{ row }">
            <span class="interval-badge">{{ row.check_interval }}</span>
          </template>
        </el-table-column>

        <el-table-column label="上次巡检" min-width="150">
          <template #default="{ row }">
            <span class="time-label">{{ row.last_scanned_at || '尚未执行' }}</span>
          </template>
        </el-table-column>

        <el-table-column label="监控开关" width="90">
          <template #default="{ row }">
            <el-switch v-model="row.is_enabled" :active-value="1" :inactive-value="0" @change="toggleEnable(row)" />
          </template>
        </el-table-column>

        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <button class="action-btn" :disabled="scanningId === row.id" @click="triggerScanNow(row)">
              {{ scanningId === row.id ? '扫描中...' : '立即检测' }}
            </button>
            <button class="action-btn" @click="openEditDrawer(row)">策略配置</button>
            <button class="action-btn text-danger" @click="deleteDomain(row)">删除</button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 侧滑主域名配置抽屉 -->
    <el-drawer v-model="drawerVisible" :title="isEdit ? '编辑域名监控策略' : '新增监控主域名'" size="560px">
      <div class="drawer-body">
        <div class="form-section">
          <h4 class="section-title">基础资产信息</h4>
          <div class="form-item">
            <label>主域名 (FQDN)</label>
            <input v-model="form.domain" :disabled="isEdit" placeholder="例如: target-src.com" class="input-custom" />
          </div>
          <div class="form-item">
            <label>资产分组 / SRC 项目</label>
            <input v-model="form.group_name" placeholder="默认分组" class="input-custom" />
          </div>
          <div class="form-item">
            <label>巡检执行周期</label>
            <div class="radio-pill-group">
              <label class="radio-pill" :class="{ active: form.check_interval === '10m' }">
                <input type="radio" v-model="form.check_interval" value="10m" /> 10 分钟
              </label>
              <label class="radio-pill" :class="{ active: form.check_interval === '1h' }">
                <input type="radio" v-model="form.check_interval" value="1h" /> 1 小时
              </label>
              <label class="radio-pill" :class="{ active: form.check_interval === '1d' }">
                <input type="radio" v-model="form.check_interval" value="1d" /> 24 小时
              </label>
            </div>
          </div>
        </div>

        <!-- 高阶弱点与探针策略 (合规约束) -->
        <div class="form-section">
          <h4 class="section-title">高阶探测与合规防线</h4>
          <div class="checkbox-col">
            <label class="check-line">
              <input type="checkbox" v-model="form.enable_wildcard_filter" :true-value="1" :false-value="0" />
              <div>
                <strong>开启泛解析 (Wildcard DNS) 自动识别与清洗</strong>
                <p class="sub-text">通过随机探针探测泛解析特征黑名单，过滤垃圾伪造子域</p>
              </div>
            </label>
            <label class="check-line">
              <input type="checkbox" v-model="form.enable_axfr" :true-value="1" :false-value="0" />
              <div>
                <strong>允许 DNS 区域传送 (AXFR) 弱点探测 (高敏操作)</strong>
                <p class="sub-text">向目标权威 NS 请求 AXFR。仅限已取得正式渗透测试授权的目标开启</p>
              </div>
            </label>
          </div>
        </div>

        <!-- 网络出口配置 -->
        <div class="form-section proxy-section">
          <div class="section-header-flex">
            <h4 class="section-title">网络出口防封策略</h4>
            <span class="compliance-badge">仅用于合规规避限流</span>
          </div>

          <div class="form-item">
            <label>出站路由选择</label>
            <div class="radio-pill-group">
              <label class="radio-pill" :class="{ active: form.proxy_mode === 'auto' }">
                <input type="radio" v-model="form.proxy_mode" value="auto" /> 全局自动策略
              </label>
              <label class="radio-pill" :class="{ active: form.proxy_mode === 'proxy_group' }">
                <input type="radio" v-model="form.proxy_mode" value="proxy_group" /> 指定代理组
              </label>
              <label class="radio-pill" :class="{ active: form.proxy_mode === 'direct' }">
                <input type="radio" v-model="form.proxy_mode" value="direct" /> 服务器直连
              </label>
            </div>
          </div>

          <div v-if="form.proxy_mode === 'proxy_group'" class="proxy-group-picker">
            <div class="form-item">
              <label>绑定出站代理池组</label>
              <select v-model="form.proxy_group_id" class="select-theme full-w">
                <option :value="null">请选择代理组...</option>
                <option v-for="g in proxyGroups" :key="g.id" :value="g.id">
                  {{ g.name }} ({{ g.strategy }})
                </option>
              </select>
            </div>

            <div class="test-egress-bar">
              <button 
                type="button" 
                class="ghost-btn-test" 
                :disabled="testingOutbound || !form.proxy_group_id"
                @click="testDomainEgress"
              >
                {{ testingOutbound ? '出口测试中...' : '测试当前网络出口' }}
              </button>

              <div v-if="egressResult" class="egress-tag" :class="egressResult.status">
                <span>{{ egressResult.status === 'pass' ? '✅ 出口正常' : '❌ 连通失败' }}</span>
                <span>· 节点: {{ egressResult.proxy_used }}</span>
                <span>· 延迟: {{ egressResult.latency_ms }}ms</span>
              </div>
            </div>
          </div>
        </div>

        <div class="drawer-footer">
          <button class="ghost-btn" @click="drawerVisible = false">取消</button>
          <button class="primary-btn" :disabled="saving" @click="saveDomain">
            {{ saving ? '保存中...' : '保存策略' }}
          </button>
        </div>
      </div>
    </el-drawer>

    <!-- 子域名资产清单抽屉 (显示接管风险、发现源、资产名称内联编辑) -->
    <el-drawer v-model="subdomainDrawerVisible" :title="`子域名资产清单 - [${activeDomain?.domain}]`" size="920px">
      <div class="sub-drawer-body">
        <div class="sub-drawer-bar">
          <div class="sub-filter-row">
            <input 
              v-model="subFilterKeyword" 
              placeholder="按子域名 / 资产名称模糊搜索..." 
              class="sub-search-input"
              @keyup.enter="fetchSubdomains"
            />
            <select v-model="subFilterSource" class="select-theme-sm" @change="fetchSubdomains">
              <option value="">全部名称来源</option>
              <option value="alias">自定义别名</option>
              <option value="http_title">网页标题</option>
              <option value="http_server">服务器标识</option>
              <option value="cname">CNAME目标</option>
              <option value="ptr">反查名称</option>
              <option value="hostname">未识别</option>
            </select>
            <button class="ghost-btn-sm" @click="fetchSubdomains">筛选</button>
          </div>

          <div class="flex-spacer"></div>

          <div class="sub-actions-row">
            <button class="ghost-btn-sm" :disabled="batchResolving" @click="handleBatchResolveNames">
              {{ batchResolving ? '批量解析中...' : '🔄 批量重识别名称' }}
            </button>
            <button class="primary-btn-sm" @click="exportSubdomainsCsv">
              📥 导出 CSV
            </button>
          </div>
        </div>

        <el-table :data="subdomainList" v-loading="subLoading" style="width: 100%">
          <el-table-column label="资产名称" min-width="240">
            <template #default="{ row }">
              <div v-if="editingRowId === row.id" class="inline-edit-box">
                <input 
                  :ref="(el) => setInputRef(el, row.id)"
                  v-model="editingAliasText" 
                  class="inline-input"
                  placeholder="输入自定义别名 (回车保存/Esc取消)"
                  @keyup.enter="saveInlineAlias(row)"
                  @keyup.esc="cancelInlineEdit"
                  @blur="saveInlineAlias(row)"
                />
              </div>
              <div v-else class="asset-name-cell" @click="startInlineEdit(row)">
                <div class="title-with-edit">
                  <strong class="asset-main-name">
                    {{ row.asset_name || row.subdomain }}
                  </strong>
                  <span class="edit-pencil-icon" title="点击内联编辑别名">✏️</span>
                </div>
                <div class="subdomain-text">{{ row.subdomain }}</div>
                <div class="source-tag-wrap">
                  <span class="source-soft-tag" :class="row.asset_name_source">
                    {{ formatSourceLabel(row.asset_name_source) }}
                  </span>
                  <!-- 接管风险高亮标记 -->
                  <span v-if="row.takeover_risk" class="takeover-warning-tag" :title="row.takeover_reason">
                    ⚠️ 接管风险
                  </span>
                </div>
              </div>
            </template>
          </el-table-column>

          <el-table-column prop="record_type" label="类型" width="80">
            <template #default="{ row }">
              <span class="type-pill" :class="row.record_type">{{ row.record_type }}</span>
            </template>
          </el-table-column>

          <el-table-column label="解析指向 / 发现源" min-width="220">
            <template #default="{ row }">
              <div class="record-val-text">{{ row.record_value }}</div>
              <div class="sources-list" v-if="parseSources(row).length > 0">
                <span v-for="s in parseSources(row)" :key="s" class="source-bubble">
                  {{ s }}
                </span>
              </div>
            </template>
          </el-table-column>

          <el-table-column label="状态" width="90">
            <template #default="{ row }">
              <span class="soft-tag" :class="row.status === 'active' ? 'pass' : 'fail'">
                {{ row.status === 'active' ? '存活' : '失效' }}
              </span>
            </template>
          </el-table-column>

          <el-table-column label="操作" width="100" fixed="right">
            <template #default="{ row }">
              <button 
                class="action-link-sm" 
                :disabled="singleResolvingId === row.id"
                @click="handleSingleResolveName(row)"
              >
                {{ singleResolvingId === row.id ? '探测中...' : '重识别' }}
              </button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, nextTick } from 'vue'
import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'

const loading = ref(false)
const saving = ref(false)
const scanningId = ref<number | null>(null)
const testingOutbound = ref(false)
const egressResult = ref<any>(null)

const drawerVisible = ref(false)
const isEdit = ref(false)
const searchKeyword = ref('')
const selectedGroup = ref('')

const domainList = ref<any[]>([])
const proxyGroups = ref<any[]>([])

const form = ref<any>({
  id: null,
  domain: '',
  group_name: 'SRC核心',
  remark: '',
  check_interval: '1h',
  proxy_mode: 'auto',
  proxy_group_id: null,
  enable_axfr: 0,
  enable_c_segment: 0,
  enable_wildcard_filter: 1
})

const subdomainDrawerVisible = ref(false)
const activeDomain = ref<any>(null)
const subdomainList = ref<any[]>([])
const subdomainTotal = ref(0)
const subLoading = ref(false)
const subFilterKeyword = ref('')
const subFilterSource = ref('')

const editingRowId = ref<number | null>(null)
const editingAliasText = ref('')
const inputRefs = ref<Record<number, HTMLInputElement>>({})
const singleResolvingId = ref<number | null>(null)
const batchResolving = ref(false)

const setInputRef = (el: any, id: number) => {
  if (el) inputRefs.value[id] = el
}

const formatSourceLabel = (src: string) => {
  const map: Record<string, string> = {
    alias: '自定义',
    http_title: '网页标题',
    http_server: '服务器标识',
    cname: 'CNAME 目标',
    ptr: '反查名称',
    hostname: '未识别'
  }
  return map[src] || '未识别'
}

const parseSources = (row: any) => {
  if (!row.provenance_sources) {
    return row.source ? [row.source] : []
  }
  try {
    const list = JSON.parse(row.provenance_sources)
    return Array.isArray(list) ? list : [row.source]
  } catch (e) {
    return [row.source || 'unknown']
  }
}

const fetchDomains = async () => {
  loading.value = true
  try {
    const { data } = await axios.get('/api/v1/domains', {
      params: { keyword: searchKeyword.value, group_name: selectedGroup.value }
    })
    domainList.value = data.data.list
  } catch (e) {
    ElMessage.error('无法获取主域名列表')
  } finally {
    loading.value = false
  }
}

const fetchProxyGroups = async () => {
  try {
    const { data } = await axios.get('/api/v1/proxy-groups')
    proxyGroups.value = data.data || []
  } catch (e) {}
}

const openCreateDrawer = () => {
  isEdit.value = false
  form.value = {
    domain: '', group_name: 'SRC核心', remark: '',
    check_interval: '1h', proxy_mode: 'auto', proxy_group_id: null,
    enable_axfr: 0, enable_c_segment: 0, enable_wildcard_filter: 1
  }
  egressResult.value = null
  drawerVisible.value = true
}

const openEditDrawer = (row: any) => {
  isEdit.value = true
  form.value = { ...row }
  egressResult.value = null
  drawerVisible.value = true
}

const saveDomain = async () => {
  if (!form.value.domain.trim()) {
    ElMessage.warning('请输入合法的主域名')
    return
  }
  saving.value = true
  try {
    if (isEdit.value) {
      await axios.put(`/api/v1/domains/${form.value.id}`, form.value)
      ElMessage.success('配置已保存')
    } else {
      await axios.post('/api/v1/domains', form.value)
      ElMessage.success('资产域名已纳入监控')
    }
    drawerVisible.value = false
    fetchDomains()
  } catch (err: any) {
    ElMessage.error(err.response?.data?.msg || '保存失败')
  } finally {
    saving.value = false
  }
}

const triggerScanNow = async (row: any) => {
  scanningId.value = row.id
  try {
    const { data } = await axios.post(`/api/v1/domains/${row.id}/scan`)
    ElMessage.success(`全景检测完成: 存活记录 ${data.data.total_active}，发现变动 ${data.data.changes}`)
    fetchDomains()
  } catch (e) {
    ElMessage.error('检测失败')
  } finally {
    scanningId.value = null
  }
}

const testDomainEgress = async () => {
  if (!form.value.id) {
    ElMessage.warning('请先保存域名后再测试')
    return
  }
  testingOutbound.value = true
  try {
    const { data } = await axios.post(`/api/v1/domains/${form.value.id}/proxy-test`, {
      proxy_mode: form.value.proxy_mode,
      proxy_group_id: form.value.proxy_group_id
    })
    egressResult.value = data.data
  } catch (err: any) {
    egressResult.value = { status: 'fail', proxy_used: '无可用节点', latency_ms: 0 }
  } finally {
    testingOutbound.value = false
  }
}

const viewSubdomains = async (row: any) => {
  activeDomain.value = row
  subFilterKeyword.value = ''
  subFilterSource.value = ''
  subdomainDrawerVisible.value = true
  fetchSubdomains()
}

const fetchSubdomains = async () => {
  if (!activeDomain.value) return
  subLoading.value = true
  try {
    const { data } = await axios.get('/api/v1/subdomains', {
      params: {
        domain_id: activeDomain.value.id,
        keyword: subFilterKeyword.value,
        asset_name_source: subFilterSource.value,
        page_size: 100
      }
    })
    subdomainList.value = data.data.list
    subdomainTotal.value = data.data.total
  } catch (e) {
    ElMessage.error('加载子域名失败')
  } finally {
    subLoading.value = false
  }
}

const startInlineEdit = (row: any) => {
  editingRowId.value = row.id
  editingAliasText.value = row.alias_name || row.asset_name || ''
  nextTick(() => {
    inputRefs.value[row.id]?.focus()
  })
}

const cancelInlineEdit = () => {
  editingRowId.value = null
  editingAliasText.value = ''
}

const saveInlineAlias = async (row: any) => {
  if (editingRowId.value !== row.id) return
  const newAlias = editingAliasText.value.trim()
  try {
    const { data } = await axios.put(`/api/v1/subdomains/${row.id}/alias`, {
      alias_name: newAlias
    })
    row.asset_name = data.data.asset_name
    row.alias_name = data.data.alias_name
    row.asset_name_source = data.data.asset_name_source
    ElMessage.success('自定义别名已生效')
  } catch (e: any) {
    ElMessage.error(e.response?.data?.msg || '保存别名失败')
  } finally {
    editingRowId.value = null
  }
}

const handleSingleResolveName = async (row: any) => {
  singleResolvingId.value = row.id
  try {
    const { data } = await axios.post(`/api/v1/subdomains/${row.id}/resolve-name`)
    row.asset_name = data.data.asset_name
    row.asset_name_source = data.data.asset_name_source
    ElMessage.success(`重识别完成: ${data.data.asset_name}`)
  } catch (e) {
    ElMessage.error('名称识别失败')
  } finally {
    singleResolvingId.value = null
  }
}

const handleBatchResolveNames = async () => {
  if (!activeDomain.value) return
  batchResolving.value = true
  try {
    const { data } = await axios.post(`/api/v1/domains/${activeDomain.value.id}/resolve-names`)
    ElMessage.success(data.msg)
    fetchSubdomains()
  } catch (e) {
    ElMessage.error('批量重识别失败')
  } finally {
    batchResolving.value = false
  }
}

const exportSubdomainsCsv = () => {
  if (!activeDomain.value) return
  window.open(`/api/v1/subdomains/export?domain_id=${activeDomain.value.id}`, '_blank')
}

const toggleEnable = async (row: any) => {
  try {
    await axios.put(`/api/v1/domains/${row.id}`, { is_enabled: row.is_enabled })
    ElMessage.success('调度状态已更新')
  } catch (e) {
    row.is_enabled = row.is_enabled === 1 ? 0 : 1
    ElMessage.error('更新失败')
  }
}

const deleteDomain = (row: any) => {
  ElMessageBox.confirm(`确认删除主域名 [${row.domain}] 吗？`, '危险警告', {
    type: 'warning'
  }).then(async () => {
    await axios.delete(`/api/v1/domains/${row.id}`)
    ElMessage.success('已删除')
    fetchDomains()
  })
}

onMounted(() => {
  fetchDomains()
  fetchProxyGroups()
})
</script>

<style scoped>
.domain-page { display: flex; flex-direction: column; gap: 20px; }
.action-bar-glass {
  display: flex; align-items: center; gap: 14px;
  background: var(--card); padding: 14px 20px;
  border-radius: var(--r-lg); border: 1px solid var(--border);
  box-shadow: var(--shadow-sm);
}
.search-input-group { display: flex; align-items: center; gap: 8px; }
.search-input {
  width: 280px; padding: 9px 14px;
  border-radius: var(--r-sm); border: 1px solid var(--border-strong);
  background: var(--bg); color: var(--text-1); outline: none;
}
.search-input:focus { border-color: var(--brand-500); box-shadow: var(--shadow-glow); }
.ghost-btn-search {
  padding: 8px 16px; background: var(--bg-deep);
  border: 1px solid var(--border-strong); border-radius: var(--r-sm);
  color: var(--text-2); cursor: pointer;
}
.select-theme {
  padding: 9px 14px; border-radius: var(--r-sm);
  border: 1px solid var(--border-strong); background: var(--bg);
  color: var(--text-2); outline: none;
}

.desktop-table-box {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--r-lg); padding: 16px; box-shadow: var(--shadow-sm);
}

.domain-main-cell { display: flex; align-items: center; gap: 8px; }
.domain-name { font-weight: 600; color: var(--brand-600); cursor: pointer; }
.domain-name:hover { text-decoration: underline; }
.group-pill {
  font-size: 11px; padding: 2px 8px;
  background: var(--brand-50); color: var(--brand-700);
  border-radius: var(--r-full);
}
.remark-sub { font-size: 12px; color: var(--text-3); margin-top: 2px; }
.metric-count { font-weight: 600; color: var(--text-1); cursor: pointer; }
.interval-badge { font-size: 12px; padding: 2px 6px; background: #F1F5F9; border-radius: 4px; color: var(--text-2); }

.feature-tags { display: flex; flex-direction: column; gap: 4px; }
.mini-tag { font-size: 10px; padding: 1px 4px; border-radius: 3px; font-weight: 500; width: fit-content; }
.mini-tag.warn { background: #FEF3C7; color: #B45309; }
.mini-tag.success { background: #ECFDF5; color: #047857; }

.action-btn {
  background: none; border: none; color: var(--brand-600);
  font-size: 12px; cursor: pointer; margin-right: 12px;
}
.action-btn.text-danger { color: var(--danger); }
.action-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.drawer-body { display: flex; flex-direction: column; gap: 24px; }
.section-title { font-size: 15px; font-weight: 600; color: var(--text-1); margin: 0 0 16px 0; }
.form-section {
  background: rgba(255, 255, 255, 0.6); padding: 16px;
  border-radius: var(--r-md); border: 1px solid var(--border);
}
.checkbox-col { display: flex; flex-direction: column; gap: 12px; }
.check-line {
  display: flex; align-items: flex-start; gap: 10px; cursor: pointer; font-size: 13px;
}
.check-line strong { color: var(--text-1); }
.sub-text { font-size: 12px; color: var(--text-3); margin: 2px 0 0 0; }

.section-header-flex { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.compliance-badge { font-size: 11px; color: var(--brand-600); background: var(--brand-50); padding: 3px 8px; border-radius: 4px; }

.form-item { display: flex; flex-direction: column; gap: 6px; margin-bottom: 14px; }
.form-item label { font-size: 13px; font-weight: 500; color: var(--text-2); }
.input-custom { padding: 10px 14px; border-radius: var(--r-sm); border: 1px solid var(--border-strong); background: #fff; color: var(--text-1); outline: none; }

.radio-pill-group { display: flex; gap: 10px; }
.radio-pill {
  flex: 1; display: flex; align-items: center; justify-content: center;
  gap: 6px; padding: 9px 12px; border: 1px solid var(--border-strong);
  border-radius: var(--r-sm); font-size: 13px; cursor: pointer; background: #fff;
}
.radio-pill.active { border-color: var(--brand-500); background: var(--brand-50); color: var(--brand-600); font-weight: 500; }
.radio-pill input { display: none; }

.proxy-group-picker { margin-top: 12px; padding-top: 12px; border-top: 1px dashed var(--border); }
.ghost-btn-test { padding: 7px 14px; background: #fff; border: 1px solid var(--brand-300); border-radius: var(--r-sm); color: var(--brand-600); font-size: 12px; cursor: pointer; }
.test-egress-bar { display: flex; align-items: center; gap: 12px; margin-top: 10px; }
.egress-tag { font-size: 12px; padding: 4px 10px; border-radius: 4px; }
.egress-tag.pass { background: var(--success-bg); color: var(--success); }
.egress-tag.fail { background: var(--danger-bg); color: var(--danger); }

.sub-drawer-body { display: flex; flex-direction: column; gap: 14px; }
.sub-drawer-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.sub-filter-row { display: flex; align-items: center; gap: 8px; }
.sub-search-input {
  width: 220px; padding: 6px 10px; font-size: 12px;
  border-radius: var(--r-sm); border: 1px solid var(--border-strong); outline: none;
}
.select-theme-sm {
  padding: 6px 10px; font-size: 12px; border-radius: var(--r-sm);
  border: 1px solid var(--border-strong); background: #fff; outline: none;
}
.sub-actions-row { display: flex; gap: 8px; }

.asset-name-cell { cursor: pointer; display: flex; flex-direction: column; gap: 2px; }
.title-with-edit { display: flex; align-items: center; gap: 6px; }
.asset-main-name { font-size: 14px; font-weight: 700; color: var(--text-1); }
.edit-pencil-icon { font-size: 12px; opacity: 0; transition: opacity var(--dur) var(--ease); }
.asset-name-cell:hover .edit-pencil-icon { opacity: 1; }
.subdomain-text { font-size: 12px; color: var(--text-3); font-family: monospace; }
.source-tag-wrap { display: flex; align-items: center; gap: 6px; margin-top: 2px; }
.source-soft-tag { font-size: 10.5px; padding: 1px 6px; border-radius: 4px; font-weight: 500; }
.source-soft-tag.alias { background: #F3E8FF; color: #9333EA; }
.source-soft-tag.http_title { background: #ECFDF5; color: #059669; }
.source-soft-tag.http_server { background: #EFF6FF; color: #2563EB; }
.source-soft-tag.cname { background: #FFFBEB; color: #D97706; }
.source-soft-tag.ptr { background: #F0FDF4; color: #16A34A; }
.source-soft-tag.hostname { background: #F1F5F9; color: #64748B; }

.takeover-warning-tag {
  font-size: 10.5px; padding: 1px 6px; border-radius: 4px;
  background: #FEF2F2; color: #DC2626; border: 1px solid rgba(220, 38, 38, 0.3);
  font-weight: 600;
}

.record-val-text { font-family: monospace; font-size: 12px; color: var(--text-2); }
.sources-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
.source-bubble {
  font-size: 10px; background: #F1F5F9; color: #475569; padding: 1px 5px; border-radius: 3px;
}

.inline-edit-box { width: 100%; }
.inline-input {
  width: 100%; box-sizing: border-box; padding: 6px 10px;
  border-radius: var(--r-sm); border: 1px solid var(--brand-500);
  outline: none; box-shadow: var(--shadow-glow); font-size: 13px; font-weight: 600;
}

.action-link-sm { background: none; border: none; color: var(--brand-600); font-size: 12px; cursor: pointer; }
.action-link-sm:disabled { opacity: 0.5; }
.type-pill { font-size: 11px; font-weight: 600; padding: 2px 6px; border-radius: 4px; }
.type-pill.A { background: #EFF6FF; color: #2563EB; }
.type-pill.CNAME { background: #ECFDF5; color: #059669; }

.flex-spacer { flex: 1; }
.primary-btn {
  background: var(--grad-brand); color: #fff; border: none;
  padding: 10px 20px; border-radius: var(--r-md); font-size: 13px; font-weight: 500; cursor: pointer;
}
.primary-btn-sm {
  background: var(--grad-brand); color: #fff; border: none;
  padding: 6px 14px; border-radius: var(--r-sm); font-size: 12px; font-weight: 500; cursor: pointer;
}
.ghost-btn {
  background: transparent; color: var(--text-2); border: 1px solid var(--border-strong);
  padding: 9px 18px; border-radius: var(--r-md); font-size: 13px; cursor: pointer;
}
.ghost-btn-sm {
  background: #fff; border: 1px solid var(--border-strong); padding: 6px 12px; border-radius: var(--r-sm); font-size: 12px; cursor: pointer;
}
.drawer-footer { display: flex; justify-content: flex-end; gap: 12px; margin-top: 20px; }
.full-w { width: 100%; }

@media (max-width: 768px) {
  .desktop-table-box { display: none; }
}
</style>
