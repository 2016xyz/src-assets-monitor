<template>
  <div class="setting-page view-enter-active">
    <!-- 资产名称与外联探针策略 -->
    <div class="section-card">
      <h3 class="section-title">资产名称与外联探针策略</h3>
      <p class="section-desc">控制是否在子域名解析成功后发起 HTTP(S) 探测抓取网页标题 (HTML &lt;title&gt;) 与 Web 服务器指纹。</p>

      <div class="setting-switch-row">
        <div>
          <strong>开启 HTTP(S) 网页标题探测</strong>
          <p class="sub-tip">关闭后将跳过所有外联 HTTP 请求，仅使用自定义别名、CNAME 目标与 PTR 反查等低成本方式，降低外联暴露风险。</p>
        </div>
        <el-switch 
          v-model="enableHttpProbe" 
          active-value="1" 
          inactive-value="0" 
          @change="saveProbeSwitch" 
        />
      </div>
    </div>

    <!-- 第三方被动源与代码检索 API 密钥管理 -->
    <div class="section-card">
      <h3 class="section-title">第三方数据源与测绘平台 API 凭据</h3>
      <p class="section-desc">配置 GitHub 令牌用于搜索代码泄露子域名，配置 OTX / FOFA 用于扩展被动 DNS 关联源。凭据在数据库中安全持久化。</p>

      <div class="form-grid">
        <div class="form-group col-span-2">
          <label>GitHub Personal Access Token (用于 Dorks 代码泄露检索)</label>
          <input v-model="apiTokens.github_token" type="password" placeholder="ghp_••••••••••••••••••••••••••••••••••••" class="input-custom" />
          <span class="field-hint">只需只读 public_repo 权限，用于规避匿名 60次/小时 速率限制</span>
        </div>

        <div class="form-group">
          <label>AlienVault OTX API Key (被动 DNS 数据源)</label>
          <input v-model="apiTokens.otx_api_key" placeholder="64位十六进制 API 密钥" class="input-custom" />
        </div>

        <div class="form-group">
          <label>SecurityTrails API Key (高精历史 DNS)</label>
          <input v-model="apiTokens.securitytrails_key" placeholder="可选密钥" class="input-custom" />
        </div>
      </div>
      <div class="save-row">
        <button class="primary-btn" @click="saveApiTokens">保存 API 凭据</button>
      </div>
    </div>

    <!-- 内置子域名字典管理 -->
    <div class="section-card">
      <h3 class="section-title">内置子域名爆破字典管理</h3>
      <p class="section-desc">主动枚举阶段探测的高频前缀字典。支持在线新增、移除或一键重置。</p>

      <div class="dict-tags-box">
        <el-tag
          v-for="tag in dictionary"
          :key="tag"
          closable
          class="dict-tag"
          @close="removeDictItem(tag)"
        >
          {{ tag }}
        </el-tag>
      </div>

      <div class="add-tag-row">
        <input v-model="newWord" placeholder="输入新子域名前缀 (如: vpn, oa, git)..." class="input-custom" @keyup.enter="addDictItem" />
        <button class="primary-btn" @click="addDictItem">+ 添加前缀</button>
        <button class="ghost-btn" @click="saveDictionary">保存字典到系统</button>
      </div>
    </div>

    <!-- 全局网络出站代理策略 -->
    <div class="section-card">
      <h3 class="section-title">全局网络出站代理策略</h3>
      <p class="section-desc">配置全局出站并发上限、请求抖动延时与失败策略。</p>

      <div class="form-grid">
        <div class="form-group">
          <label>全局单任务最大并发数</label>
          <input v-model.number="policy.max_concurrency" type="number" class="input-custom" />
        </div>
        <div class="form-group">
          <label>批次间随机抖动 (毫秒)</label>
          <input v-model.number="policy.jitter_ms" type="number" class="input-custom" />
        </div>
      </div>
      <div class="save-row">
        <button class="primary-btn" @click="savePolicy">保存全局网络策略</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'

const enableHttpProbe = ref('1')
const dictionary = ref<string[]>([])
const newWord = ref('')
const policy = ref({ max_concurrency: 10, jitter_ms: 300 })

const apiTokens = ref({
  github_token: '',
  otx_api_key: '',
  securitytrails_key: ''
})

const fetchSettings = async () => {
  try {
    const { data } = await axios.get('/api/v1/settings')
    dictionary.value = data.data.dictionary_subdomains || ['www', 'mail', 'api', 'admin']
    enableHttpProbe.value = String(data.data.enable_asset_name_http_probe ?? '1')
    apiTokens.value.github_token = data.data.github_token || ''
    apiTokens.value.otx_api_key = data.data.otx_api_key || ''
    apiTokens.value.securitytrails_key = data.data.securitytrails_key || ''

    if (data.data.global_proxy_policy) {
      policy.value = data.data.global_proxy_policy
    }
  } catch (e) {
    ElMessage.error('加载系统配置失败')
  }
}

const saveProbeSwitch = async () => {
  try {
    await axios.post('/api/v1/settings', {
      key: 'enable_asset_name_http_probe',
      value: enableHttpProbe.value
    })
    ElMessage.success('资产名称探测策略已同步')
  } catch (e) {
    ElMessage.error('设置失败')
  }
}

const saveApiTokens = async () => {
  try {
    await Promise.all([
      axios.post('/api/v1/settings', { key: 'github_token', value: apiTokens.value.github_token }),
      axios.post('/api/v1/settings', { key: 'otx_api_key', value: apiTokens.value.otx_api_key }),
      axios.post('/api/v1/settings', { key: 'securitytrails_key', value: apiTokens.value.securitytrails_key })
    ])
    ElMessage.success('第三方平台 API 凭据已保存')
  } catch (e) {
    ElMessage.error('保存凭据失败')
  }
}

const addDictItem = () => {
  const w = newWord.value.trim().toLowerCase()
  if (!w) return
  if (!dictionary.value.includes(w)) {
    dictionary.value.push(w)
    newWord.value = ''
  }
}

const removeDictItem = (tag: string) => {
  dictionary.value = dictionary.value.filter(t => t !== tag)
}

const saveDictionary = async () => {
  try {
    await axios.post('/api/v1/settings', {
      key: 'dictionary_subdomains',
      value: dictionary.value
    })
    ElMessage.success('字典已更新')
  } catch (e) {
    ElMessage.error('保存失败')
  }
}

const savePolicy = async () => {
  try {
    await axios.post('/api/v1/settings', {
      key: 'global_proxy_policy',
      value: policy.value
    })
    ElMessage.success('全局策略已更新')
  } catch (e) {
    ElMessage.error('保存失败')
  }
}

onMounted(() => {
  fetchSettings()
})
</script>

<style scoped>
.setting-page { display: flex; flex-direction: column; gap: 24px; }
.section-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--r-lg); padding: 24px; box-shadow: var(--shadow-sm);
}
.section-title { font-size: 16px; font-weight: 600; color: var(--text-1); margin: 0 0 6px 0; }
.section-desc { font-size: 13px; color: var(--text-3); margin: 0 0 18px 0; }

.setting-switch-row {
  display: flex; justify-content: space-between; align-items: center;
  background: var(--bg); padding: 16px 20px; border-radius: var(--r-md);
}
.sub-tip { font-size: 12px; color: var(--text-3); margin: 4px 0 0 0; }

.dict-tags-box {
  display: flex; flex-wrap: wrap; gap: 8px;
  background: var(--bg); padding: 16px; border-radius: var(--r-md);
  margin-bottom: 16px; min-height: 80px;
}
.dict-tag { font-size: 13px; padding: 6px 10px; }

.add-tag-row { display: flex; gap: 12px; }
.input-custom {
  width: 100%; box-sizing: border-box; padding: 9px 14px;
  border-radius: var(--r-sm); border: 1px solid var(--border-strong); outline: none;
}
.field-hint { font-size: 11px; color: var(--text-3); margin-top: 4px; display: block; }

.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
.col-span-2 { grid-column: span 2; }
.form-group label { display: block; font-size: 13px; font-weight: 500; color: var(--text-2); margin-bottom: 6px; }
.save-row { display: flex; justify-content: flex-end; }

.primary-btn {
  background: var(--grad-brand); color: #fff; border: none;
  padding: 9px 18px; border-radius: var(--r-md); font-size: 13px; font-weight: 500; cursor: pointer;
}
.ghost-btn {
  background: transparent; color: var(--text-2); border: 1px solid var(--border-strong);
  padding: 8px 16px; border-radius: var(--r-md); font-size: 13px; cursor: pointer;
}
</style>
