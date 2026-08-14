# QualityCI Bench v0.1（合成变异回归基准）

> **强制口径：本基准全部使用显著标注的合成质量文件。** 公开的 NHTSA 资料只用于构造缺陷链背景；PFMEA、控制计划、SOP、检验记录、审批和验证字段均为比赛合成内容。这里得到的指标只证明当前规则引擎能否复现预先声明的变异真值，**不能证明真实工厂中的质量提升、召回率、安全性、ROI或部署成熟度**。

## 1. 目的与边界

QualityCI Bench 用一个合成基线包和30个可重复的 mutation 验证以下能力：

- 7条确定性规则输出完整的 `PASS / CONTRADICTED / UNVERIFIABLE` 状态；
- 单规则故障不会无故污染无关规则；
- 多故障组合可以同时保留多个规则级发现；
- 正常豁免、非特殊特性、中风险事件等边界不被误报；
- 报告的异常发现携带至少一个证据引用。

它不是现场有效性试验，也没有与质量工程师人工审查、通用LLM或商业QMS做独立对照。任何对外材料必须使用“合成变异回归结果”，不能写成“真实制造质量效果”。

## 2. 数据结构

```text
datasets/qualityci-bench/tacoma_24v152/
├── baseline_v04.json       # 当前评测基线，显式 synthetic_for_competition=true
├── mutations/              # M001—M030
└── resolutions/            # 人工审批与复跑的独立工作流样例
```

每个 mutation 都包含：

- 唯一 `mutation_id`；
- 人类可读的 `description`；
- 可重复执行的 `operations`；
- 覆盖全部7条规则的 `expected_rule_statuses` 真值向量。

评测器拒绝缺规则、额外规则、非法状态或重复 mutation ID，防止通过“只标注命中的规则”抬高准确率。

## 3. 30个 mutation 的规则真值

表中未列出的规则均明确为 `PASS`，JSON文件仍保存完整7规则向量。

| Mutation | 主要情形 | 非PASS真值 |
|---|---|---|
| M001 | SOP旧规格、旧日期、引用漂移 | R002=C、R004=C、R005=C |
| M002 | 缺变更验证证据 | R006=U |
| M003 | 特殊特性缺反应计划 | R003=C |
| M004 | 缺质量负责人批准 | R007=C |
| M005 | 检验记录引用旧SOP | R005=C |
| M006 | SOP缺可比较规格 | R002=U |
| M007 | PFMEA漏受影响工序 | R001=C、R003=C |
| M008 | 控制计划漏受影响工序 | R001=C |
| M009 | 事件缺受影响工序范围 | R001=U、R002=U、R003=U |
| M010 | 事件缺受影响特性范围 | R001=U、R002=U、R003=U |
| M011 | SOP单位冲突 | R002=C |
| M012 | 检验上限冲突 | R002=C |
| M013 | 控制计划漏整个特殊特性 | R001=C、R002=U、R003=C |
| M014 | 特殊特性缺控制方法 | R003=C |
| M015 | 特殊特性缺控制频次 | R003=C |
| M016 | 非特殊特性正常边界 | 全PASS |
| M017 | 变更缺批准日期 | R004=U |
| M018 | 旧日期但有绑定文件/事件/角色/有效期/位置的结构化豁免 | 全PASS |
| M019 | 过程流程图旧日期且无豁免 | R004=C |
| M020 | SOP版本号匹配但日期过旧 | R004=C |
| M021 | 检验记录缺版本引用 | R005=U |
| M022 | 检验引用集合含额外旧文件 | R005=C |
| M023 | 验证结果失败 | R006=C |
| M024 | 验证声称通过但无定位锚点 | R006=C |
| M025 | 多项验证中有一项失败 | R006=C |
| M026 | 中风险且无高风险审批 | 全PASS |
| M027 | 高风险无任何审批 | R007=C |
| M028 | 审批对应旧事件版本 | R007=C |
| M029 | 批准日晚于全部文件日期 | R004=C |
| M030 | 工序、规格、控制、验证、审批组合故障 | R001=C、R002=C、R003=C、R006=U、R007=C |

`C` 表示 `CONTRADICTED`，`U` 表示 `UNVERIFIABLE`。R003的缺文档状态被基础Schema阻止；R007按当前规则设计对高风险缺审批直接判为 `CONTRADICTED`，不使用 `UNVERIFIABLE`。

三个边界样例不能被外推为生产控制已完整：M018使用结构化合成豁免记录并校验文件、事件版本、范围、双角色、有效期和定位，但仍没有真实身份与签名；M022把检验引用集合严格相等作为当前策略，真实项目需要先定义哪些额外引用允许存在；M026只验证“高风险专用记录检查不会误伤MEDIUM”，并不证明风险分级本身可信，也不能防止人员恶意降级风险。三者都需要行业专家和身份/策略系统补强。

### 状态覆盖分布

| 规则 | PASS | CONTRADICTED | UNVERIFIABLE |
|---|---:|---:|---:|
| QCI-R001 | 24 | 4 | 2 |
| QCI-R002 | 22 | 4 | 4 |
| QCI-R003 | 22 | 6 | 2 |
| QCI-R004 | 25 | 4 | 1 |
| QCI-R005 | 26 | 3 | 1 |
| QCI-R006 | 25 | 3 | 2 |
| QCI-R007 | 26 | 4 | 0 |

## 4. 指标定义

评测入口为 `qualityci.evaluation.evaluate_benchmark()`。

| 指标 | 定义 | 防止的误导 |
|---|---|---|
| Rule-state accuracy | 210个 mutation×rule 状态中，精确分类正确的比例 | 把C错判为U仍算成功 |
| Mutation pass rate | 一个mutation的7规则完整向量全部正确才算通过 | 只命中一个主规则便宣称案例成功 |
| Finding precision（规则告警口径） | 预测为非PASS的规则中，真值也为非PASS的比例 | 规则误报 |
| Finding recall（规则告警口径） | 真值为非PASS的规则中，被预测为非PASS的比例 | 规则漏报 |
| Finding F1（规则告警口径） | 上述precision与recall的调和平均 | 只优化单侧指标 |
| Evidence-present rate | 预测非PASS发现中，至少含一个 `EvidenceRef` 的比例 | 无证据的结论被当作可审计发现 |

Finding评测预先定义 `expected_status != PASS` 为positive；C/U的精确区分由rule-state accuracy另行约束。这里的统计单位是“mutation中的规则告警”，不是已去重的现实缺陷：同一根因同时触发3条规则会计为3个规则级positive。Evidence-present只验证“存在引用”，不验证引用内容或定位正确；后续仍需独立的缺陷真值、证据定位真值和专家评审。

## 5. 运行方式

```bash
cd QualityCI
PYTHONPATH=src python3 - <<'PY'
from qualityci.evaluation import evaluate_benchmark

report = evaluate_benchmark("datasets/qualityci-bench/tacoma_24v152")
for key, value in report.to_dict().items():
    if key != "mutation_results":
        print(f"{key}: {value}")
PY
```

当前规则版本 `qci-rules-0.6.0` 的回归自测预期为：

```text
mutations_evaluated: 30
rule_states_evaluated: 210
rule_state_accuracy: 1.0
mutation_pass_rate: 1.0
finding_precision: 1.0
finding_recall: 1.0
finding_f1: 1.0
evidence_present_rate: 1.0
```

这些1.0来自“规则实现对照同仓库、共同开发的合成真值”的确定性回归测试，存在设计者泄漏与自证循环，不具备独立性，不能当作产品效果或真实世界准确率。任何规则或真值变更都应经过复核并同步更新开发测试；对外Actual必须来自独立冻结、未参与规则开发的测试集。

## 6. 从回归自测走向正向优化证明

要证明产品产生正向优化，还必须引入当前基准之外的证据：

1. 由未参与规则编写的制造业专家建立或复核盲测真值；
2. 增加不同零部件、不同文件模板和不同术语的独立案例；
3. 同案例比较人工审查、直接LLM、规则基线与QualityCI；
4. 统计证据锚点精确匹配、严重问题漏放行、审查时长和无效建议率；
5. 预注册成功门槛，并如实报告失败案例和适用边界。

在完成这些步骤前，正确表述是“基础闭环通过30个合成变异回归测试”，不是“系统已提升制造业质量”。
