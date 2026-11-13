# CheckQuestion(CZM-Main)

## 项目简介

字谜闯关游戏（CZM-Main）是一个支持**高度自定义题库**的单页答题闯关游戏。本说明重点介绍如何创建与配置自定义题库，并且发布版除早期版本外不含内置题库，只会在Releases中提供示例。

## 自定义题库

题库以 JSON 文件形式存放在 `data/` 目录下，文件名需与 `id` 字段一致（如 `data/mytopic.json` 对应 `"id": "mytopic"`）。服务器启动时会自动扫描并加载所有合法题库，无需改动代码。

### 基本结构

```json
{
  "id": "mytopic",
  "name": "题库显示名",
  "title": "页面标题",
  "logo": "",
  "background": "resource/mybg.jpg",
  "themeColor": "#87CEEB",
  "textColor": "#00008B",
  "promptText": "答案是？",
  "pages": [
    { "key": "cat1", "name": "分类一", "type": "cat1", "icon": "❓" }
  ],
  "levels": {
    "cat1": [
      [
        {
          "q": "题干",
          "answers": ["正确答案1", "正确答案2"],
          "distractors": ["干扰项1", "干扰项2", "干扰项3"]
        }
      ]
    ]
  }
}
```

- `pages` 定义题库的分类标签页，`key` 需与 `levels` 中的键对应
- `levels` 是 `{分类key: [[题目], [题目], ...]}` 结构，每个内层数组是一关
- 每题 `answers` 可含多个正确答案，`distractors` 为干扰选项

### 主题与外观自定义

自定义题库可以完全拥有独立的视觉风格：

- `themeColor`：主题色，影响按钮背景、导航栏、徽章、进度条、PK 按钮等
- `textColor`：字体色，影响标题、按钮文字、分类标题
- `background`：背景，支持**字符串**或**对象**两种写法，不填则使用默认背景
  - 字符串写法：直接写路径或 URL
    - 本地图片：`"resource/mybg.jpg"`
    - 图片 URL：`"https://example.com/bg.jpg"`（自动识别为图片）
    - 网页 URL：`"https://example.com/page"`（自动识别为网页，用 iframe 嵌入作为背景，可交互拖动）
  - 对象写法（可精细控制）：
    ```json
    "background": {
      "src": "resource/mybg.jpg",
      "mode": "cover",
      "overlay": 0.3
    }
    ```
    - `src`/`url`/`image`：图片或网页地址
    - `type`：`"image"` 或 `"webpage"`（显式指定类型，覆盖自动识别）
    - `mode`：图片显示模式，`cover`（默认）/`contain`/`tile`（平铺）/`center`
    - `overlay`：遮罩层透明度，`0~1` 或 `0~100`，用于压暗背景提升文字可读性
- `promptText`：答题区的题干提示文字（默认为"谜底是？"）

未指定时回退到默认红金配色（`#DC143C` + `#FFD700`）。

### 自定义语言包

每个题库可以有自己的语言文件，命名规则为 `lang/{题库id}-{语言}.json`，例如：

- `lang/computer-zh-cn.json`
- `lang/computer-en-us.json`

语言包采用**深度合并**机制：题库语言文件只需覆写需要改变的字段，未覆盖的字段自动回退到基础语言包（`zh-cn.json` / `en-us.json`）。这意味着你只需要写差异部分。

特别地，"关于"页面中的"哈气技巧"（`about.tips` / `about.tipsContent`）**始终使用默认题库内容**，题库语言文件无法覆盖它。

### 成就系统

题库可在 `achievements` 数组中定义成就，每个成就结构如下：

```json
{
  "id": "hello-world",
  "name": "你好世界",
  "desc": "完成第1关",
  "type": "levels",
  "target": 1,
  "scope": "bank",
  "icon": "👋"
}
```

- `type` 支持：`levels`（通关数）、`first`/`second`/`third`（一/二/三等奖次数）、`points`（积分数）、`easter`（触发任意彩蛋）、`vip`（点击 VIP 彩蛋链接）
- `scope`：`global`（全局成就，跨题库统计）或 `bank`（仅本题库）
- `hidden`：设为 `true` 时为隐藏成就，未完成前不会出现在成就列表中，完成后才显示并带 🔒 标识。例外：`id` 为 `superuser` 的成就始终可见，用于测试
- 成就 logo 放在 `resource/achievement-logo/{id}.{png|jpg|svg|webp|gif}`，未提供时回退到 `icon` 字段的 emoji
- 完成成就后弹出领取窗口，奖励积分并持久化

### 商店系统

题库可在 `shop` 数组中定义卖品，所有题库的卖品会在商店页面聚合显示。卖品分两种类型：

**等级商品**（`maxLevel > 0`）：可重复购买升级，每级提升效果。

**一次性商品**（`maxLevel: 0`）：购买后永久拥有。

商品支持以下 `effect` 类型：

| effect | 说明 | 等级商品 |
|---|---|---|
| `glint` | 每级 +10% 概率让正确答案绿色闪烁 | ✅ |
| `time` | 每级 +1 秒答题时间 | ✅ |
| `points` | 每级 +10% 通关获得的积分 | ✅ |
| `ui-glass` | 毛玻璃卡片效果 | ❌ 一次性 |
| `ui-neon` | 霓虹发光效果 | ❌ 一次性 |
| `ui-dark` | 暗黑模式 | ❌ 一次性 |
| `ui-rainbow` | 彩虹主题色循环 | ❌ 一次性 |
| `ui-font` | 手写字体 | ❌ 一次性 |

视觉类商品（`ui-*`）购买后可在商店卡片上点击"已启用 / 已禁用"按钮随时开关，状态持久化。

商品 `tier` 字段显示为卡片上的标签，如"专属""通用"。

## 题库列表缓存

服务器会将题库列表缓存到 `cache/` 目录，玩家进度数据存于 `data/playerdata/{用户名}.json`。

## 运行方式

```bash
node server.js
```

访问 `http://localhost:3000` 即可。
