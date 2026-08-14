# Case Builder：原始证据表到 Case JSON

`qualityci.case_builder` 是一个最小、显式映射的桥接层。它把团队合成 CSV，或已经由
`ingest_document` 产生的结构化表格证据，转换为现有 `validate_case` / `run_case` 能够消费的
Case JSON。它不使用 LLM 猜测列语义，也不声称理解任意 Office 文档。

## 公开入口

```python
from qualityci.case_builder import build_case_from_pack

# manifest.json与5个相对路径CSV/XLSX/DOCX组成一个pack；Builder内部重新导入
case = build_case_from_pack("pack/manifest.json")
```

`build_case_from_pack` 只接受 manifest 目录内的相对 `.csv` / `.xlsx` / `.docx` 路径，并把路径交给
`ingest_document(..., root_dir=manifest.parent)` 做已有的路径、大小、编码和公式标记检查。
多工作表/多表格必须在 manifest 中用 `table_selector.sheet` 或 `table_selector.table` 唯一选定。
Builder 以实际解析后选中的 sheet/table 生成规范身份，因此单表的隐式选择与显式选择
不会被当成两个表。CSV 没有表选择概念，任何 `table_selector`（包括空对象）都会被拒绝。

普通 Python `dict` 无法自行证明其内容仍与所写 SHA-256 对应；因此 Mapping 级桥接器保持为模块私有
实现，不是来源认证入口。命令行和公开API只使用会重新读取源字节的`build_case_from_pack`。

## Manifest v0.4

`manifest_version` 必须是 `qualityci-case-builder-0.4`。顶层只包含：

- `case`：`case_id`、`title`、`synthetic_for_competition=true` 和可选的 `source_provenance`。
- `event`：现有 Case 事件字段及显式 `affected_links` pair。v0.4 将它们视为经人工复核的 manifest 字面量，不从两个 scope 集合推断笛卡尔关系；可用 `event.provenance` 记录 manifest 定位。
- `documents`：必须恰好包含 `PROCESS_FLOW`、`PFMEA`、`CONTROL_PLAN`、`SOP`、
  `INSPECTION_RECORD` 各一份。

每个 document 声明：

```json
{
  "source_id": "control-plan-table",
  "source_path": "control_plan.csv",
  "document_id": "CP-BUILDER-SYN",
  "document_type": "CONTROL_PLAN",
  "revision": "B",
  "status": "APPROVED",
  "owner": "QUALITY_ENGINEERING",
  "revision_date": "2026-08-03",
  "header_row": 1,
  "columns": {
    "process_step_id": "process_step_id",
    "control_id": "control_id",
    "characteristic_id": "characteristic_id",
    "target": "target",
    "minimum": "minimum",
    "maximum": "maximum",
    "unit": "unit",
    "control_method": "control_method",
    "frequency": "frequency",
    "reaction_plan": "reaction_plan"
  }
}
```

`columns` 左边是固定的标准字段，右边是源表的显式表头。表头比较只做去首尾空白、
合并连续空白和 Unicode `casefold`；不做同义词、缩写、编辑距离或模型匹配。

### 五类表的标准列

| 文档类型 | 必需标准列 | 可选列 | 唯一ID |
|---|---|---|---|
| `PROCESS_FLOW` | `process_step_id` | 无 | `process_step_id` |
| `PFMEA` | `process_step_id`, `failure_mode_id`, `characteristic_id`, `special_characteristic` | `effect` | `failure_mode_id` |
| `CONTROL_PLAN` | `process_step_id`, `control_id`, `characteristic_id`, `target`, `minimum`, `maximum`, `unit`, `control_method`, `frequency`, `reaction_plan` | 无 | `control_id`与`(process_step_id, characteristic_id)` |
| `SOP` | `process_step_id`, `characteristic_id`, `target`, `minimum`, `maximum`, `unit` | 无 | `(process_step_id, characteristic_id)` |
| `INSPECTION_RECORD` | `process_step_id`, `characteristic_id`, `target`, `minimum`, `maximum`, `unit`, `sop_document_id`, `sop_revision`, `control_plan_document_id`, `control_plan_revision` | 无 | `(process_step_id, characteristic_id)` |

`special_characteristic` 只接受明确的 `true` / `false`（不把 `yes`、`1` 猜成布尔值）。
`target` / `minimum` / `maximum` 必须是有限数字。空必需单元格会拒绝整个 build。

## 来源定位与转换结果

输出文档保留 `source_hash`、`source` 和 `mapping_provenance`。每个从单元格转换的值都有一条记录：

```json
{
  "target": "fields.characteristics[0].specification.maximum",
  "value": 0,
  "source": {
    "source_id": "control-plan-table",
    "document_id": "CP-BUILDER-SYN",
    "source_hash": "<sha256>",
    "locator": "CSV#row-2.cell-E",
    "kind": "CELL",
    "column": "maximum",
    "raw_value": "0"
  }
}
```

因此数字/布尔转换后仍能追回原始文本、单元格 locator 和整份文档 SHA-256。
Case 顶层的 `builder_provenance.sources` 列出所有源和实际映射值数量，并保留
`canonical_table_selector` 与 `logical_table_fingerprint`（`sha256:<hex>`），便于审计实际选中表
及规范化指纹。

## Fail-closed 规则

- manifest 少字段、多未知字段、五类文档不齐或源集合不一致：`ManifestError`。
- 五类逻辑文档复用同一 `source_path`，或复用同一 `source_hash + 实际选中表`：拒绝。
- 对实际选中的单元格网格计算规范化内容指纹：去除空白单元格，以非空区域的相对坐标计算，
  并规范 Unicode/换行、字段首尾空白及表头大小写/连续空白。不同编码 BOM、换行符或 CSV 引号方式生成的
  同一规范化表会被拒绝，防止明显的同表自比。
- manifest 指定列不存在，或数据行的必需值为空：`MissingColumnError`。
- 表头规范化后有多个候选、多工作表/多表格未选定、或检验记录中版本引用冲突：
  `AmbiguousMappingError`。
- `failure_mode_id`、特性 ID 或流程步骤 ID 在其唯一作用域重复：
  `DuplicateIdentifierError`。
- 输入 evidence 不是只读/未执行的 ingestion 结果、源哈希不一致、坐标或 locator 重复：
  `CaseBuilderError`。
- 映射表中出现 CSV 公式样文本或 XLSX 公式/缓存值：`CaseBuilderError`；公式缓存值不作为质量证据。
  CSV 中可解析为有限数的带符号字面量（如 `-1.5` 或 `+2`）是数值，不会被误判为公式；
  XLSX 中只要原单元格含公式，即使有数值缓存也仍拒绝。

构建结束时会调用现有 `validate_case`；这仅证明 Case 形状合法。评审规则仍可以对真实冲突返回
`CONTRADICTED` / `UNVERIFIABLE`，桥接器不会为了得到 PASS 改写证据。

## 当前边界

- 仅用于 `synthetic_for_competition=true` 的团队合成数据。
- 不识别图片、合并单元格、自由文本段落、页眉页脚、手写表格或 OCR 结果。
- 不根据文件名或内容猜测文档类型；文档元数据由 manifest 提供，并必须与 EvidenceDocument 完全相等。
- 不自动生成事件风险等级、批准、验证结论或影响范围；这些仍是人工复核的 manifest 输入。
- 规范化内容指纹能识别解析后单元格坐标与内容相同的表，但不是独立来源或作者身份证明。
  故意增删/修改单元格会产生新指纹；该机制是防止明显自比的护栏，不替代文控审批或来源证明。
- 合成五文件 PASS pack 在 `tests/fixtures/case_builder/`；它是可重现的契约测试，不是真实工厂准确率证据。
