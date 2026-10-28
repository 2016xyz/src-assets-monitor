<template>
  <div class="dashboard-container view-enter-active">
    <!-- 统计指标 5 卡片 -->
    <div class="stats-grid">
      <div v-for="card in statCards" :key="card.title" class="stat-card">
        <div class="card-left">
          <div class="badge-icon" :style="{ background: card.bg }">
            <span class="emoji-icon">{{ card.icon }}</span>
          </div>
          <div>
            <div class="card-label">{{ card.title }}</div>
            <div class="card-value tabular-nums">{{ card.value }}</div>
          </div>
        </div>
        <div class="card-right-sparkline">
          <span class="trend-tag" :class="card.trendUp ? 'up' : 'down'">
            {{ card.trendText }}
          </span>
        </div>
      </div>
    </div>

    <!-- ECharts 核心图表栅格 -->
    <div class="charts-row">
      <div class="chart-box main-trend">
        <div class="chart-header">
          <h4 class="box-title">近 14 天新增子域名解析趋势</h4>
          <span class="box-sub">主动枚举与证书透明度增量</span>
        </div>
        <div ref="trendChartRef" class="echarts-dom"></div>
      </div>

      <div class="chart-box change-pie">
        <div class="chart-header">
          <h4 class="box-title">解析异动类型分布</h4>
          <span class="box-sub">触发告警特征占比</span>
        </div>
        <div ref="pieChartRef" class="echarts-dom"></div>
      </div>
    </div>

    <!-- 底部时间轴流水 (显示 资产名称 + 子域名) -->
    <div class="timeline-box">
      <div class="timeline-header">
        <h4 class="box-title">最新资产变更动态流水</h4>
        <span class="live-tag"><span class="pulse-healthy"></span> 实时同步</span>
      </div>
      <div class="timeline-list">
        <div v-for="item in timelineItems" :key="item.id" class="timeline-row">
          <div class="timeline-indicator" :class="item.change_type"></div>
          <div class="timeline-content">
            <div class="target-title">
              <strong class="timeline-asset-name">{{ item.asset_name || item.subdomain }}</strong>
              <span class="timeline-sub-tag">({{ item.subdomain }})</span>
              <span class="type-tag" :class="item.change_type">{{ formatType(item.change_type) }}</span>
            </div>
            <div class="diff-preview">
              <span class="old-val">{{ item.old_value || '无' }}</span>
              <span class="arrow-diff">➔</span>
              <span class="new-val">{{ item.new_value || 'NXDOMAIN (失效)' }}</span>
            </div>
          </div>
          <div class="timeline-time">{{ item.created_at }}</div>
        </div>
        <div v-if="timelineItems.length === 0" class="empty-timeline">
          暂无解析变更，系统持续监控中...
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import * as echarts from 'echarts'
import axios from 'axios'

const trendChartRef = ref<HTMLDivElement>()
const pieChartRef = ref<HTMLDivElement>()

const statCards = ref([
  { title: '主域名资产数', value: 0, trendText: '监控中', trendUp: true, color: '#3B82F6', bg: 'rgba(59,130,246,0.12)', icon: '🌐' },
  { title: '存活子域名总数', value: 0, trendText: '存活率 100%', trendUp: true, color: '#10B981', bg: 'rgba(16,185,129,0.12)', icon: '⚡' },
  { title: '今日新增解析', value: 0, trendText: '今日入库', trendUp: true, color: '#6366F1', bg: 'rgba(99,102,241,0.12)', icon: '🆕' },
  { title: '今日解析变更', value: 0, trendText: '已告警', trendUp: false, color: '#F59E0B', bg: 'rgba(245,158,11,0.12)', icon: '🔄' },
  { title: '代理池健康度', value: '100%', trendText: '节点可用', trendUp: true, color: '#06B6D4', bg: 'rgba(6,182,212,0.12)', icon: '🛡️' }
])

const timelineItems = ref<any[]>([])

const formatType = (type: string) => {
  const map: Record<string, string> = {
    added: '新增解析',
    changed: '解析变更',
    removed: '解析失效',
    txt_update: '记录变动'
  }
  return map[type] || type
}

const fetchData = async () => {
  try {
    const [statsRes, trendsRes, changesRes, timelineRes] = await Promise.all([
      axios.get('/api/v1/dashboard/stats'),
      axios.get('/api/v1/dashboard/chart/trends'),
      axios.get('/api/v1/dashboard/chart/changes'),
      axios.get('/api/v1/dashboard/timeline?limit=10')
    ])

    const s = statsRes.data.data
    statCards.value[0].value = s.domains_count
    statCards.value[1].value = s.subdomains_count
    statCards.value[2].value = s.today_new
    statCards.value[3].value = s.today_changed
    statCards.value[4].value = s.proxy_health_rate

    timelineItems.value = timelineRes.data.data

    renderTrendChart(trendsRes.data.data)
    renderPieChart(changesRes.data.data)
  } catch (e) {}
}

const renderTrendChart = (data: any) => {
  if (!trendChartRef.value) return
  const chart = echarts.init(trendChartRef.value)
  chart.setOption({
    grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: data.dates || [],
      axisLine: { lineStyle: { color: '#E2E8F0' } }
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: '#F1F5F9' } }
    },
    series: [
      {
        name: '新增子域名',
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 3, color: '#3B82F6' },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(59, 130, 246, 0.35)' },
            { offset: 1, color: 'rgba(59, 130, 246, 0.00)' }
          ])
        },
        data: data.values || []
      }
    ]
  })
  window.addEventListener('resize', () => chart.resize())
}

const renderPieChart = (data: any) => {
  if (!pieChartRef.value) return
  const chart = echarts.init(pieChartRef.value)
  chart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: '0', icon: 'circle' },
    series: [
      {
        name: '变更类型',
        type: 'pie',
        radius: ['50%', '75%'],
        avoidLabelOverlap: false,
        itemStyle: { borderRadius: 8, borderColor: '#fff', borderWidth: 2 },
        label: { show: false },
        data: data || []
      }
    ]
  })
  window.addEventListener('resize', () => chart.resize())
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped>
.dashboard-container { display: flex; flex-direction: column; gap: 24px; }
.stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; }
.stat-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--r-lg); padding: 18px;
  display: flex; align-items: center; justify-content: space-between;
  box-shadow: var(--shadow-sm); transition: all var(--dur) var(--ease);
}
.stat-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); }
.card-left { display: flex; align-items: center; gap: 12px; }
.badge-icon {
  width: 44px; height: 44px; border-radius: var(--r-md);
  display: flex; align-items: center; justify-content: center;
}
.emoji-icon { font-size: 20px; }
.card-label { font-size: 13px; color: var(--text-3); margin-bottom: 4px; }
.card-value { font-size: 22px; font-weight: 700; color: var(--text-1); }
.trend-tag { font-size: 12px; padding: 2px 8px; border-radius: 4px; }
.trend-tag.up { background: var(--success-bg); color: var(--success); }
.trend-tag.down { background: var(--warning-bg); color: var(--warning); }

.charts-row { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
.chart-box {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--r-lg); padding: 20px; box-shadow: var(--shadow-sm);
}
.chart-header { margin-bottom: 16px; }
.box-title { font-size: 16px; font-weight: 600; color: var(--text-1); margin: 0 0 4px 0; }
.box-sub { font-size: 12px; color: var(--text-3); }
.echarts-dom { width: 100%; height: 280px; }

.timeline-box {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--r-lg); padding: 20px; box-shadow: var(--shadow-sm);
}
.timeline-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.live-tag { font-size: 12px; color: var(--success); display: flex; align-items: center; gap: 6px; }
.timeline-list { display: flex; flex-direction: column; gap: 12px; }
.timeline-row {
  display: flex; align-items: center; gap: 16px;
  padding: 12px; border-radius: var(--r-md);
  background: var(--bg); transition: all var(--dur) var(--ease);
}
.timeline-row:hover { background: var(--brand-50); transform: translateX(4px); }
.timeline-indicator { width: 10px; height: 10px; border-radius: 50%; }
.timeline-indicator.added { background: var(--success); }
.timeline-indicator.changed { background: var(--brand-500); }
.timeline-indicator.removed { background: var(--danger); }
.timeline-content { flex: 1; }

.target-title { display: flex; align-items: center; gap: 8px; font-size: 14px; }
.timeline-asset-name { color: var(--text-1); font-weight: 700; }
.timeline-sub-tag { color: var(--text-3); font-size: 12px; font-family: monospace; }
.type-tag { font-size: 11px; padding: 2px 6px; border-radius: 4px; }
.type-tag.added { background: var(--success-bg); color: var(--success); }
.type-tag.changed { background: var(--info-bg); color: var(--brand-600); }
.type-tag.removed { background: var(--danger-bg); color: var(--danger); }
.diff-preview { font-size: 12px; color: var(--text-2); margin-top: 4px; }
.arrow-diff { margin: 0 6px; color: var(--text-3); }
.timeline-time { font-size: 12px; color: var(--text-3); }
.empty-timeline { text-align: center; color: var(--text-3); padding: 20px; font-size: 13px; }

@media (max-width: 1200px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .charts-row { grid-template-columns: 1fr; }
}
@media (max-width: 768px) {
  .stats-grid { grid-template-columns: 1fr; }
}
</style>
