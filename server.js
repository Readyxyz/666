"use strict";

/**
 * JS-Confuser API 服务
 * --------------------
 * 基于 js-confuser 1.7.3 构建的 Node.js 代码混淆 API。
 *
 * 功能：
 *  - POST /api/obfuscate        单文件混淆（JSON body，直接发送源码）
 *  - POST /api/obfuscate/upload 单文件混淆（multipart 上传 .js 文件）
 *  - POST /api/obfuscate/batch  批量混淆（最多 10 个，并发处理）
 *  - GET  /api/options          获取所有可用混淆选项和预设
 *  - GET  /api/download/:file   下载混淆后的文件
 *  - GET  /                     API 文档页面
 */

const express = require("express");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const JsConfuser = require("./lib/loader");

const app = express();
const PORT = process.env.PORT || 3000;

// ── 中间件 ──────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));

// 静态文件：可访问 /js/ 目录下混淆后的文件
app.use("/js", express.static(path.join(__dirname, "js")));

// multer 配置：内存存储，限制 20MB
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 单文件最大 20MB
});

// ── 常量 ─────────────────────────────────────────────────────
const MAX_BATCH = 10;
const JS_DIR = path.join(__dirname, "js");

// 确保输出目录存在
if (!fs.existsSync(JS_DIR)) {
  fs.mkdirSync(JS_DIR, { recursive: true });
}

// ── 混淆选项定义 ─────────────────────────────────────────────
const OPTION_DEFINITIONS = {
  preset: {
    type: "string",
    values: ["high", "medium", "low"],
    description: "预设等级。high=高混淆(90%性能损耗), medium=中等(50%损耗), low=低(30%损耗)",
  },
  target: {
    type: "string",
    values: ["node", "browser"],
    required: true,
    description: "目标运行环境。node 或 browser",
  },
  compact: {
    type: "boolean",
    default: true,
    description: "移除不必要的空白字符",
  },
  hexadecimalNumbers: {
    type: "boolean",
    default: false,
    description: "将数字转为十六进制表示",
  },
  minify: {
    type: "boolean",
    default: false,
    description: "压缩输出代码",
  },
  es5: {
    type: "boolean",
    default: false,
    description: "输出 ES5 兼容代码",
  },
  renameVariables: {
    type: "boolean",
    default: false,
    description: "重命名变量名",
  },
  renameGlobals: {
    type: "boolean",
    default: true,
    description: "重命名全局变量名",
  },
  identifierGenerator: {
    type: "string",
    values: ["randomized", "hexadecimal", "mangled", "number"],
    default: "randomized",
    description: "标识符生成策略",
  },
  controlFlowFlattening: {
    type: "number",
    range: [0, 1],
    default: 0,
    description: "控制流平坦化强度 (0-1)，值越大混淆越强但性能越差",
  },
  globalConcealing: {
    type: "boolean",
    default: false,
    description: "隐藏全局变量引用",
  },
  stringCompression: {
    type: "boolean",
    default: false,
    description: "压缩字符串（可能导致兼容性问题）",
  },
  stringConcealing: {
    type: "boolean",
    default: false,
    description: "隐藏字符串字面量",
  },
  stringEncoding: {
    type: "boolean",
    default: false,
    description: "编码字符串（高风险，可能损坏文件）",
  },
  stringSplitting: {
    type: "number",
    range: [0, 1],
    default: 0,
    description: "字符串拆分概率 (0-1)",
  },
  duplicateLiteralsRemoval: {
    type: "number",
    range: [0, 1],
    default: 0,
    description: "重复字面量移除比例 (0-1)",
  },
  dispatcher: {
    type: "mixed",
    values: [true, false, 0, 0.25, 0.5, 0.75, 1],
    default: false,
    description: "调度器模式，可设为布尔或 0-1 概率",
  },
  rgf: {
    type: "boolean",
    default: false,
    description: "RGF 模式（高风险，自行承担）",
  },
  objectExtraction: {
    type: "boolean",
    default: false,
    description: "对象提取，将对象属性转为变量",
  },
  flatten: {
    type: "boolean",
    default: false,
    description: "扁平化代码块",
  },
  deadCode: {
    type: "number",
    range: [0, 1],
    default: 0,
    description: "死代码注入比例 (0-1)，会增加文件体积",
  },
  calculator: {
    type: "boolean",
    default: false,
    description: "将算术运算转为计算器函数",
  },
  movedDeclarations: {
    type: "boolean",
    default: false,
    description: "移动变量声明到代码末尾",
  },
  opaquePredicates: {
    type: "number",
    range: [0, 1],
    default: 0,
    description: "不透明谓词强度 (0-1)",
  },
  shuffle: {
    type: "mixed",
    description: "打乱代码顺序，可设为布尔或 { hash: 0-1, true: 0-1 }",
  },
  stack: {
    type: "mixed",
    values: [true, false, 0, 0.5, 1],
    default: false,
    description: "栈混淆，可设为布尔或 0-1 概率",
  },
  lock: {
    type: "object",
    description: "锁定选项，包含 selfDefending, antiDebug, domainLock, osLock, browserLock 等",
    properties: {
      selfDefending: { type: "boolean", description: "自我保护，防止格式化" },
      antiDebug: { type: "boolean", description: "反调试" },
      domainLock: { type: "array", description: "域名锁定，限制在指定域名运行" },
      osLock: { type: "array", values: ["windows", "linux", "osx", "ios", "android"], description: "操作系统锁定" },
      browserLock: { type: "array", values: ["firefox", "chrome", "iexplorer", "edge", "safari", "opera"], description: "浏览器锁定（仅 target=browser）" },
      context: { type: "array", description: "上下文锁定" },
      tamperProtection: { type: "boolean", description: "篡改保护" },
      integrity: { type: "boolean", description: "完整性校验" },
      countermeasures: { type: "boolean", description: "反制措施" },
      startDate: { type: "date", description: "生效开始日期" },
      endDate: { type: "date", description: "生效结束日期" },
    },
  },
};

// ── 工具函数 ─────────────────────────────────────────────────

/**
 * 生成随机 20 位文件名（仅小写字母+数字）
 */
function generateRandomName() {
  return crypto.randomBytes(10).toString("hex"); // 20 hex chars
}

/**
 * 根据 options 构建混淆配置对象
 * 如果提供了 preset，则使用预设并合并用户自定义选项
 */
function buildOptions(userOptions) {
  const opts = { ...userOptions };

  // 必须有 target
  if (!opts.target) {
    opts.target = "node";
  }

  // 如果使用 preset，js-confuser 会自动合并预设
  // 否则需要至少一个混淆选项
  if (!opts.preset) {
    // 没有预设时，确保至少有一个混淆选项
    const obfuscationKeys = Object.keys(opts).filter(
      (k) => k !== "target" && k !== "verbose" && k !== "globalVariables" && k !== "debugComments" && k !== "preserveFunctionLength"
    );
    if (obfuscationKeys.length === 0) {
      // 默认使用 medium 预设
      opts.preset = "medium";
    }
  }

  return opts;
}

/**
 * 验证用户提供的选项
 */
function validateOptions(userOptions) {
  if (!userOptions || typeof userOptions !== "object") {
    return { valid: false, error: "混淆选项不能为空" };
  }

  if (userOptions.target && !["node", "browser"].includes(userOptions.target)) {
    return { valid: false, error: `target 必须是 'node' 或 'browser'，当前值: '${userOptions.target}'` };
  }

  if (userOptions.preset && !["high", "medium", "low"].includes(userOptions.preset)) {
    return { valid: false, error: `preset 必须是 'high'、'medium' 或 'low'，当前值: '${userOptions.preset}'` };
  }

  return { valid: true };
}

/**
 * 执行单个混淆任务
 */
async function doObfuscate(sourceCode, userOptions, label) {
  const startTime = Date.now();

  // 验证选项
  const validation = validateOptions(userOptions);
  if (!validation.valid) {
    throw new Error(`选项验证失败: ${validation.error}`);
  }

  // 构建选项
  const options = buildOptions(userOptions);

  // 执行混淆
  const obfuscated = await JsConfuser.obfuscate(sourceCode, options);

  // 生成随机文件名并保存
  const fileName = generateRandomName() + ".js";
  const filePath = path.join(JS_DIR, fileName);
  fs.writeFileSync(filePath, obfuscated, "utf-8");

  const elapsed = Date.now() - startTime;
  const fileSize = Buffer.byteLength(obfuscated, "utf-8");

  return {
    label: label || "unnamed",
    success: true,
    fileName,
    filePath: `/js/${fileName}`,
    downloadUrl: `/api/download/${fileName}`,
    originalSize: Buffer.byteLength(sourceCode, "utf-8"),
    obfuscatedSize: fileSize,
    elapsedMs: elapsed,
    options: {
      preset: options.preset || "custom",
      target: options.target,
    },
  };
}

// ── 路由 ─────────────────────────────────────────────────────

/**
 * GET / - API 文档页面
 */
app.get("/", (req, res) => {
  res.json({
    name: "JS-Confuser API",
    version: "1.0.0",
    description: "JavaScript 代码混淆 API 服务",
    endpoints: {
      "POST /api/obfuscate": "单文件混淆（JSON body 发送源码）",
      "POST /api/obfuscate/upload": "单文件混淆（上传 .js 文件）",
      "POST /api/obfuscate/batch": "批量混淆（最多 10 个，并发处理）",
      "GET  /api/options": "获取所有可用混淆选项",
      "GET  /api/download/:file": "下载混淆后的文件",
      "GET  /js/:file": "直接访问混淆后的文件",
    },
    quickStart: {
      method: "POST",
      url: "/api/obfuscate",
      body: {
        source: "console.log('hello world');",
        options: { target: "node", preset: "medium" },
      },
    },
  });
});

/**
 * GET /api/options - 获取所有可用混淆选项
 */
app.get("/api/options", (req, res) => {
  res.json({
    presets: {
      low: "低混淆 - 平均 30% 性能损耗",
      medium: "中等混淆 - 平均 50% 性能损耗",
      high: "高混淆 - 平均 90% 性能损耗",
    },
    options: OPTION_DEFINITIONS,
    examples: {
      simple: { target: "node", preset: "medium" },
      custom: {
        target: "node",
        compact: true,
        controlFlowFlattening: 0.5,
        stringConcealing: true,
        renameVariables: true,
        deadCode: 0.1,
      },
      browser: { target: "browser", preset: "high" },
      withLock: {
        target: "node",
        preset: "high",
        lock: {
          selfDefending: true,
          domainLock: ["example.com"],
          osLock: ["linux", "windows"],
        },
      },
    },
  });
});

/**
 * POST /api/obfuscate - 单文件混淆（JSON body）
 *
 * Body:
 *   {
 *     "source": "JS源码字符串",
 *     "options": { "target": "node", "preset": "medium", ... }
 *   }
 *   或
 *   {
 *     "source": "JS源码字符串",
 *     "options": { "target": "node", "compact": true, "stringConcealing": true, ... }
 *   }
 */
app.post("/api/obfuscate", async (req, res) => {
  try {
    const { source, options } = req.body;

    if (!source || typeof source !== "string") {
      return res.status(400).json({
        success: false,
        error: "必须提供 source 字段（JavaScript 源码字符串）",
      });
    }

    if (!options || typeof options !== "object") {
      return res.status(400).json({
        success: false,
        error: "必须提供 options 字段（混淆设置对象）",
      });
    }

    const result = await doObfuscate(source, options, "single");
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/obfuscate/upload - 单文件混淆（文件上传）
 *
 * Multipart form:
 *   file: <.js 文件>
 *   options: <JSON 字符串 或 直接对象>
 *
 * 注意：multer 将 file 存在内存中
 */
app.post("/api/obfuscate/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "必须上传一个 .js 文件 (字段名: file)",
      });
    }

    let options = req.body.options;
    // options 可能是 JSON 字符串
    if (typeof options === "string") {
      try {
        options = JSON.parse(options);
      } catch {
        return res.status(400).json({
          success: false,
          error: "options 不是合法的 JSON",
        });
      }
    }

    if (!options) {
      options = { target: "node", preset: "medium" };
    }

    const source = req.file.buffer.toString("utf-8");
    const result = await doObfuscate(source, options, req.file.originalname || "uploaded");
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/obfuscate/batch - 批量混淆（最多 10 个，并发处理）
 *
 * 方式一：JSON body
 *   {
 *     "items": [
 *       { "source": "JS源码1", "options": { "target": "node", "preset": "high" } },
 *       { "source": "JS源码2", "options": { "target": "node", "preset": "low" } },
 *       ...
 *     ]
 *   }
 *
 * 方式二：multipart 上传多个文件
 *   files: <多个 .js 文件>
 *   options: <JSON 字符串，所有文件共用相同配置>
 */
app.post("/api/obfuscate/batch", upload.array("files", MAX_BATCH), async (req, res) => {
  try {
    let items = [];
    let sharedOptions = null;

    // 方式一：JSON body
    if (req.body.items) {
      let parsedItems = req.body.items;
      if (typeof parsedItems === "string") {
        parsedItems = JSON.parse(parsedItems);
      }
      items = parsedItems;
    }
    // 方式二：multipart 文件上传
    else if (req.files && req.files.length > 0) {
      let options = req.body.options;
      if (typeof options === "string") {
        try {
          options = JSON.parse(options);
        } catch {
          return res.status(400).json({
            success: false,
            error: "options 不是合法的 JSON",
          });
        }
      }
      sharedOptions = options || { target: "node", preset: "medium" };

      items = req.files.map((f) => ({
        source: f.buffer.toString("utf-8"),
        options: sharedOptions,
        label: f.originalname || "uploaded",
      }));
    } else {
      return res.status(400).json({
        success: false,
        error: "请通过 JSON body (items 数组) 或 multipart 上传多个文件 (字段名: files)",
      });
    }

    // 数量校验
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        success: false,
        error: "items 不能为空",
      });
    }

    if (items.length > MAX_BATCH) {
      return res.status(400).json({
        success: false,
        error: `批量混淆最多支持 ${MAX_BATCH} 个文件，当前提交了 ${items.length} 个`,
      });
    }

    // 并发执行所有混淆任务
    const totalStart = Date.now();
    const results = await Promise.allSettled(
      items.map((item, idx) =>
        doObfuscate(item.source, item.options || sharedOptions || { target: "node", preset: "medium" }, item.label || `item-${idx + 1}`)
      )
    );

    const totalElapsed = Date.now() - totalStart;
    const response = {
      success: true,
      total: items.length,
      succeeded: results.filter((r) => r.status === "fulfilled").length,
      failed: results.filter((r) => r.status === "rejected").length,
      totalElapsedMs: totalElapsed,
      results: results.map((r, idx) => {
        if (r.status === "fulfilled") {
          return r.value;
        }
        return {
          label: items[idx].label || `item-${idx + 1}`,
          success: false,
          error: r.reason.message,
        };
      }),
    };

    res.json(response);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/download/:file - 下载混淆后的文件
 */
app.get("/api/download/:file", (req, res) => {
  const fileName = req.params.file;
  const filePath = path.join(JS_DIR, fileName);

  // 防止路径遍历
  if (!filePath.startsWith(JS_DIR)) {
    return res.status(403).json({ error: "非法路径" });
  }

  if (!fs.existsSync(filePath)) {
返回res.status(404).json({error："文件不存在"})；
  }

res.download(filePath，fileName)；
});

/**
*GET/api/文件-列出所有已混淆的文件
 */
app.get("/api/文件"，(req，res)=>{
尝试{
Const files=fs.readdirSync(JS_DIR).filter((f)=>f.endsWith(".js"))；
Const fileList=files.map((f)=>{
常量stat=fs.statSync(路径.join(JS_DIR，f))；
返回{
文件名：f，
size:stat.size，
createdAt:stat.birthtime，
DownloadURL：'/api/download/${f}'，
directUrl：'/js/${f}'，
      };
    });
res.json({success:true，count:fileList.length，files:fileList})；
}catch(err){
res.status(500).json({success:false，error:err.message})；
  }
});

//--错误处理─────────────────────────────────────────────────
app.use((err，req，res，next)=>{
if(multer.MulterError的err实例){
if(err.code==="LIMIT_FILE_SIZE"){
返回res.status(400).json({success:false，错误：“”文件大小超过20MB限制"})；
    }
if(err.code==="LIMIT_FILE_COUNT"){
”返回res.status(400).json({success:false，错误：'批量上传最多${MAX_BATCH}个文件‘})；
    }
返回res.status(400).json({成功：false，错误：err.message})；
  }
console.error("[ERROR]"，err)；
res.status(500).json({成功：假，错误：错误。消息||"服务器内部错误"})；
});

//--启动─────────────────────────────────────────────────────
app.listen(端口，()=>{
console.log("┌─────────────────────────────────────────────┐");
console.log("│JS-Confuser API服务已启动│")；
console.log('│地址：http://localhost:${端口}│')；
console.log('│文档：http://localhost:${PORT}/api/options│')；
console.log("│输出目录：./JS/│")；
console.log("└─────────────────────────────────────────────┘");
});
