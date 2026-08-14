# QualityCI 本地文件导入层（原型）

## 结论

导入层只把本地文件转换为带精确定位的证据项，核心解析器**不执行公式、宏、嵌入对象或PDF动作**，也不会在没有工程师确认时自动将某一列解释为 PFMEA 或控制计划字段。产物具有 QualityCI 合成数据中 `DocumentRevision` 的顶层标识/版本字段，原始证据位于 `fields.evidence`。

这是保守拒绝型原型，不是通用Office/PDF解析器。遇到无法完整定位的结构会拒绝导入，而不是静默声称成功。所有文件名和提取文本仍是不可信数据；展示层必须做HTML/日志转义，Agent层必须把文档内容作为引用数据隔离，不能把它拼接成系统指令或工具指令。

```python
from qualityci.ingestion import ingest_document

document = ingest_document(
    "/safe/uploads/control_plan.xlsx",
    document_id="CP-AXLE-001",
    document_type="CONTROL_PLAN",
    revision="B",
    owner="QUALITY_ENGINEERING",
    root_dir="/safe/uploads",  # 不可信路径必须限制在该根目录
)
```

## 定位粒度

| 格式 | 定位示例 | 说明 |
|---|---|---|
| CSV | `CSV#row-2.cell-B` | 保留逻辑行号和 Excel 式列标；以 `= + - @` 开头的内容仅标记为潜在公式，不执行 |
| XLSX | `'Risk Log'!C12` | 保留 Sheet 名和 Cell；公式仅作文本记录，其已存值显式标记为缓存值 |
| DOCX | `DOCX#paragraph-4` | DOCX 没有稳定的物理页号；支持主文档直属段落及顶层内容控件中的段落 |
| DOCX | `DOCX#table-2.row-3.cell-C` | 保留主文档表格/行/物理单元格；嵌套表格拒绝导入 |
| PDF | `PDF#page-7` | 仅在显式 PDF 页文本适配器返回物理页序列时产生 |

每条证据都重复记录原文件 `source_hash`，同一XLSX中不允许重复Sheet、重复Cell或重复locator。顶层 `source.content_executed=false` 表示QualityCI核心没有主动执行源文档功能；它不构成对第三方PDF适配器的安全证明。

## PDF 适配器约定

Python 标准库没有可靠的 PDF 文本与页面解析器，所以本原型不做“看似成功”的降级。调用方必须显式传入适配器：

```python
def extract_pages(pdf_bytes: bytes) -> list[str]:
    # 由经评审的 PDF 库实现，必须按物理页顺序返回。
    ...

document = ingest_document(
    "report.pdf",
    document_id="VAL-001",
    document_type="VALIDATION_REPORT",
    root_dir=".",
    pdf_page_extractor=extract_pages,
    trusted_pdf_adapter=True,  # 调用方显式承担适配器评审与沙箱责任
)
```

- 未传适配器，或没有显式设置 `trusted_pdf_adapter=True`：拒绝导入。
- 所有页都无文本：按扫描件拒绝，必须另行接入可评审 OCR 适配器。
- 部分页无文本：保留该页定位，并标记 `extractable_text=false`。
- 核心会对可见PDF名称做保守预检，包含加密、JavaScript、Launch、附件、表单动作或不透明对象流等特征时拒绝；同时识别PDF名称中的 `#xx` 转义。
- 该预检不是完整PDF对象图解析，不能证明文件安全。被信任的适配器必须在独立沙箱中再次检查动作、附件、对象流、资源用量和库版本，且不得访问网络或启动外部程序。

## 安全边界

1. **路径**：不可信路径应始终传 `root_dir`；任意 `..` 父级穿越片段直接拒绝，解析后路径也不得越界，且调用方路径中的中间符号链接/重解析点不会在预检时被静默抹去。POSIX 会从已验证根目录逐级使用 `dir_fd + O_NOFOLLOW` 打开。Windows 分支当前仅支持本地固定 NTFS 卷：先核对卷类型、NTFS 文件系统和根目录的卷序列号 + 128-bit FileId，再使用原生 `CreateFileW` 句柄逐级打开；目录句柄在全部路径解析期间不共享写入/删除，每级都使用 `FILE_FLAG_OPEN_REPARSE_POINT` 并检查 `FILE_ATTRIBUTE_REPARSE_POINT`，最后校验句柄返回的路径与根目录包含关系。因此源文件、中间目录的 symlink/junction/其他 reparse point 都按 fail-closed 拒绝。SMB/网络盘、ReFS、FAT/exFAT、可移动盘，以及无法可靠返回卷信息、重解析属性或 128-bit FileId 的驱动/文件系统均保守拒绝；其他不具备 POSIX 或该 Windows 安全打开能力的平台也拒绝不可信根路径导入。
2. **类型**：仅允许 `.csv` / `.xlsx` / `.docx` / `.pdf`，并校验 ZIP/PDF 文件签名。`.xlsm` / `.docm` 等宏格式不在允许列表内。
3. **OOXML ZIP**：检查成员数、单成员和总解压尺寸、压缩比、重名/大小写冲突、路径穿越、加密成员与符号链接；任意 `.bin` 成员按保守策略拒绝。
4. **ContentTypes/关系**：安全解析并验证XLSX/DOCX主内容类型；关系类型必须进入白名单，任何 `TargetMode=External` 外部依赖均显式拒绝，不能静默忽略。
5. **可执行内容**：对XML解码后的ContentType检查宏、ActiveX、OLE和嵌入对象；XLSX公式仅保留公式文本和缓存值，不运算。
6. **XML**：OOXML XML 部件仅接受严格 UTF-8 或 UTF-8 BOM；UTF-16/UTF-32 BOM、非 UTF-8 字节、NUL 以及声明为其他编码的 XML 均在解析前拒绝。入口先解码为文本，再不区分大小写检查 `DOCTYPE` / `ENTITY` 声明，最后才将已检查的字符串交给 ElementTree；不会把可由解析器重新判定编码的原始字节直接传入。
7. **资源限制**：`IngestionLimits` 只接受正整数及有限正压缩比，集中限制源文件、解压大小、证据数、字符数、CSV 行列与 PDF 页数；超限即失败，不静默截断。
8. **格式完整性**：XLSX坐标必须处于 `A1:XFD1048576`；非法共享字符串索引、重复定位、非法Sheet名均拒绝。DOCX支持顶层内容控件，但当前拒绝嵌套表格、页眉页脚、脚注尾注、批注和术语库等未建立稳定locator的文本结构。

## 当前有意不做的事

- 不解析旧版 `.xls` / `.doc`。
- 不运行 Excel 公式，不启动 Office/LibreOffice。
- 不根据内容自动判断文档是 PFMEA 还是控制计划；`document_type` 由上游受控流程提供。
- 不从 DOCX 伪造页号，不把 PDF 字符串粗暴拆分当作页面。
- 不把“通过PDF字节预检”等同于安全证明；PDF适配器必须被单独评审、固定版本并隔离运行。
- 不解析含外部关系、未知二进制部件或当前无法完整定位文本的OOXML；这些文件会明确失败。
- 不直接接收客户原始数据；比赛阶段仍只使用公开资料和显著标注的合成文件。
