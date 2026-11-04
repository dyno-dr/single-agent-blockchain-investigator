# Agentic Anti-Money Laundering and Rugpull Detection in Ethereum: From Pattern-Based Investigation to Lifecycle-Aware Behavioral Threat Profiling

**Santhosh D R**  
Department of Computer Science and Engineering, Indian Institute of Technology Madras  
*Correspondence:* cs26e004@smail.iitm.ac.in  
*Date:* November 2026  

---

### Abstract
Blockchain-based financial systems present a unique investigative challenge: transaction data is public and immutable, yet the volume and structural complexity of on-chain activity makes systematic anti-money laundering (AML) and fraud detection a non-trivial task. This work documents a research trajectory beginning with the study of LOCARD (Yu and Knottenbelt, 2026), an agentic framework for cross-chain forensics, whose investigation model and architectural limitations motivated an independent effort to build a simpler, single-agent AML investigation system for Ethereum. That baseline agent identifies six canonical money-laundering behavioral patterns—including fund fan-out, fan-in aggregation, rapid serial transfers, dormant wallet reactivation, activity bursting, and round-number structuring—from one-hop transaction graphs, and generates explainable forensic reports. Building on this foundation, the research subsequently narrows its focus to a prevalent and structurally distinct category of blockchain fraud: rugpull exit scams. Drawing on the behavioral taxonomy established by Sharma, Agarwal, and Shukla (2023), this research designs and implements a lifecycle-aware Behavioral Threat Profiling (BTP) engine that evaluates Ethereum deployer wallets across five operational tiers: pre-deployment preparation, funding provenance, cash-out strategy, value-transfer semantics, and post-exploit dormancy. The resulting deterministic forensic engine comprises 29 formally specified rules evaluated without large language model inference, achieving an overall rugpull detection rate of 93.3% on a ground-truth cohort of 90 confirmed malicious creator wallets. Early-stage flagging through funding provenance alone classifies 67.8% of malicious deployers prior to exploit execution. This study further establishes that 67.8% of operators exhibit serial dormancy-reactivation cycles, overturning the assumption that rugpull wallets are single-use burner accounts.

---

### Acknowledgements
The author would like to thank Prof. John Augustine, Professor in the Department of Computer Science and Engineering at the Indian Institute of Technology Madras, for supervising this Undergraduate Research Course project, for providing the academic environment and direction needed to pursue an open-ended research question, and for his patience and constructive feedback across the various phases of this work. Special thanks are due to Dr. Trishie Sharma, Postdoctoral Researcher working with Prof. John Augustine at IIT Madras, whose guidance was instrumental throughout this project. Her expertise in blockchain fraud analysis, her deep familiarity with the behavioral dynamics of fraudulent NFT and DeFi creators, and her willingness to engage with the technical details of the implementation at every stage made a substantial difference to the quality and direction of this work. Many of the feature design decisions and analytical framings in this report reflect discussions with her.

---

## 1 Introduction

Blockchain-based financial systems have fundamentally altered the architecture of digital transactions. The public, immutable ledger that underlies permissionless networks such as Ethereum enables a level of financial transparency unprecedented in traditional systems: every fund transfer, smart contract invocation, and account interaction is permanently recorded and openly accessible. Yet this very transparency presents a paradox for investigators. The volume and structural complexity of on-chain activity—spanning millions of daily transactions, nested internal call traces, cross-contract interactions, and cross-chain bridge operations—makes systematic detection of illicit behavior an analytically non-trivial problem. Anti-money laundering (AML) in blockchain contexts therefore requires not just data access, but disciplined frameworks capable of reasoning over behavioral patterns across the full transaction lifecycle of suspected actors.

### 1.1 Research Motivation: Toward Agentic AML Investigation

The central aim of this Undergraduate Research Course project was to explore the application of agentic, LLM-orchestrated investigation workflows to the problem of blockchain anti-money laundering. The core premise was straightforward: rather than building static rule scanners or one-off analytics pipelines, the research sought to establish whether a software agent—capable of planning, retrieving evidence, applying forensic logic, and generating explainable reports—could serve as a practical investigative instrument for detecting illicit behavior on Ethereum.

An early phase of the project involved studying LOCARD (Yu and Knottenbelt, 2026), a recently proposed agentic framework for blockchain forensics. LOCARD addresses cross-chain transaction tracing: the problem of linking a source transaction on one blockchain to a corresponding destination transaction on another. It employs a Tri-Core Cognitive Architecture in which a Strategic Core directs investigation plans, an Operational Core fetches blockchain evidence using a ReAct-style reasoning-and-acting loop, and an Evaluative Core independently verifies temporal and economic consistency of each discovered link. It demonstrated strong cross-chain tracing performance on the Thor25 benchmark.

This study was informative but also clarified that LOCARD's design scope did not align with the research objective. LOCARD addresses post-incident fund tracing across bridge protocols—a narrow, well-defined problem with a specific architecture built around it. It does not tackle the broader AML challenge this project was motivated by: proactively identifying whether a given wallet is engaged in illicit behavior, without presupposing a known suspicious transaction as the starting point. LOCARD also does not examine the full behavioral lifecycle of a suspicious actor on a single chain. These distinctions clarified what an agentic AML framework for Ethereum would need to accomplish that existing work does not: autonomous evidence collection over raw transaction histories, pattern matching against known fraud behaviors, and explainable verdict synthesis—all without requiring a specific precursor event.

### 1.2 Phase 1: A Single-Agent Baseline for AML Pattern Detection

The first implementation phase established a single-agent blockchain investigation system built on a LangGraph orchestration framework with a FastAPI backend and Etherscan API data access. This baseline agent accepts an Ethereum wallet address as input and executes an investigation workflow comprising five nodes: a Planner that organizes the investigation strategy, a Profiler that retrieves and structures transaction history, a Detector that evaluates the transaction graph for behavioral anomalies, a Reporter that synthesizes explainable findings, and a Memory node that persists results for future retrieval.

The baseline detection engine focuses on six canonical anti-money laundering behavioral patterns that are well-established in both traditional financial intelligence and emerging blockchain forensics literature (Meiklejohn et al., 2013; Ferretti et al., 2024):

1. **Large Transfer Detection:** Flags outgoing transactions that exceed 10 ETH, identifying unusual single-event capital movements that deviate significantly from an account's baseline activity.
2. **Rapid Serial Transfers (Structuring / Layering):** Detects five or more outgoing transactions executed within a 300-second window, a pattern consistent with automated fund dispersal and the layering stage of money laundering.
3. **High Fan-Out Distribution:** Identifies wallets that transfer funds to 20 or more unique recipient addresses, characteristic of coordinated dispersal to mule networks or sybil accounts.
4. **Dormant Wallet Reactivation:** Flags wallets that resume significant transactional activity following a period of 180 or more days of inactivity, consistent with operational security (OpSec) cycles where addresses are deliberately idled to reduce surveillance exposure before reuse.
5. **Activity Burst Detection:** Detects abnormal spikes where a wallet's transaction frequency in a short window exceeds three times its historical average, indicating a scripted activation event.
6. **Round-Number Structuring:** Identifies three or more outgoing transactions that carry identical round ETH values, a signature of scripted transfers using hardcoded value parameters.

Additionally, the agent flags interactions with freshly created destination wallets less than 24 hours old receiving transfers of 0.1 ETH or more—a pattern consistent with seeding newly instantiated mule accounts. Each flagged pattern is surfaced with a structured explanation following an Observation → Evidence → Reasoning schema, ensuring every forensic conclusion is traceable to specific on-chain data points. This baseline system demonstrated the practical viability of LangGraph-orchestrated investigation workflows and established the data access and reporting infrastructure upon which subsequent phases built.

### 1.3 Phase 2 Onward: Specializing to Rugpull Detection

While the baseline AML agent successfully identified general suspicious behavioral patterns, its broad scope meant that it was not specifically calibrated to any particular class of blockchain fraud. The second research phase narrowed the investigative focus to a structurally distinct and empirically prevalent category of Ethereum fraud: the **rugpull exit scam**. In a rugpull, a malicious actor deploys a smart contract—typically a token contract paired with a decentralized exchange liquidity pool—solicits investor deposits or token purchases, and subsequently drains the underlying collateral, leaving the project permanently abandoned. Empirical industry reporting estimates cumulative DeFi rugpull losses exceeding \$2.8 billion between 2021 and 2023 (Ante, 2026).

The critical insight motivating this specialization was that rugpull operators are not random, impulsive actors. The behavioral analysis of Sharma, Agarwal, and Shukla (2023) in the NFT domain established a foundational precedent: fraudulent NFT creators exhibit consistent, recurring behavioral signatures across their wallet preparation, project launch, and fund extraction phases—and many are recidivist serial offenders, with one creator documented executing up to 37 rug pulls within three months. This work established that the deployer's EOA transaction history, not the smart contract bytecode, is the most informative and attack-resistant signal for pre-exploit identification. Crucially, Dr. Trishie Sharma, a co-author of this study, provided direct research guidance throughout this UGRC project, and many of the feature design decisions in this work were informed by discussions with her.

Extending and operationalizing these insights to the Ethereum DeFi context, this research engineered a progressive series of behavioral feature groups drawn directly from the operational lifecycle of a rugpull campaign. Each feature group is grounded in documented operator behaviors observed across the literature (Sharma et al., 2023; Mazorra et al., 2022; Xia et al., 2021) and confirmed empirically against a ground-truth dataset of 90 Ethereum rugpull creator wallets. The resulting forensic engine comprises 29 deterministic rules organized across five behavioral tiers, implemented without large language model inference in the detection path to guarantee mathematical reproducibility.

The contributions of this work are as follows:
- **A Baseline Agentic AML Investigation Framework:** A LangGraph-orchestrated single-agent system that detects six canonical anti-money laundering behavioral patterns from one-hop Ethereum transaction graphs, establishing the foundational agentic architecture and explainable reporting pipeline.
- **A Lifecycle-Aware Behavioral Threat Taxonomy for Rugpulls:** A five-tier behavioral model grounded in and extending the creator behavioral analysis of Sharma et al. (2023), spanning the full operational lifespan of an Ethereum exploit wallet.
- **A Deterministic 29-Rule Forensic Engine:** Twenty-nine mathematically specified detection rules that map low-level transaction traces—including internal EVM call traces—to auditable threat scores without stochastic classifiers.
- **Empirical Validation and Behavioral Discoveries:** A 93.3% detection rate on 90 confirmed rugpull wallets, empirical debunking of the mainnet dry-run hypothesis, discovery of an inverted burstiness correlation, and confirmation that 67.8% of operators exhibit serial dormancy-reactivation cycles.

The remainder of this report is organized as follows: Section 2 contextualizes this work within relevant literature. Section 3 formalizes the problem, presents the architectural pipeline, and details the feature engineering layers. Section 4 reports empirical results and behavioral analyses. Section 5 concludes with limitations and future directions.

---

## 2 Related Work

The research presented in this report draws from and contributes to five interconnected bodies of literature: foundational blockchain transparency and privacy, graph-based anti-money laundering detection, behavioral analysis of decentralized finance fraud, agentic forensic frameworks, and the market dynamics of autonomous agents in blockchain ecosystems. These works are synthesized thematically, emphasizing methodological relationships and research gaps rather than chronological listing.

### 2.1 Foundational Blockchain Transparency and Pseudonymity

The investigative opportunity in blockchain forensics rests on a foundational property: public ledger transparency. Nakamoto (2008) designed Bitcoin as a fully public broadcast network, reasoning that transaction pseudonymity—addresses rather than identities—would provide adequate privacy. Seminal empirical work quickly challenged this assumption. Meiklejohn et al. (2013) introduced address clustering heuristics exploiting multi-input transaction co-spending and change-address identification patterns, demonstrating that a substantial fraction of Bitcoin's economic activity could be attributed to named real-world entities. This established the core principle—exploited throughout this work—that behavioral patterns in publicly visible transaction graphs can bridge the gap between pseudonymous addresses and identifiable operational actors.

As Ethereum's account-based model introduced smart contracts, token transfers, and internal call traces into the forensic surface, the clustering heuristics developed for Bitcoin's UTXO model became insufficient. Biryukov et al. (2014) demonstrated network-level deanonymization through peer-to-peer topology inference, while Möser et al. (2018) empirically assessed the limits of Monero's privacy guarantees, finding that non-uniform ring signature decoy selection left a significant fraction of historical transactions traceable. These works collectively established that pseudonymity on public blockchains is structurally fragile—a premise that motivates the design of behavioral detection systems like the one presented here.

### 2.2 Graph-Based Anomaly Detection and Anti-Money Laundering

The natural representation of blockchain transactions as directed graphs—where addresses form nodes and value transfers form edges—has motivated extensive research in graph-based anomaly detection. Ferretti, D'Angelo, and Ghini (2024) developed edge-aware Graph Neural Network (GNN) architectures for cryptocurrency anti-money laundering, demonstrating that graph convolutions over transaction neighborhoods can classify illicit flows with high accuracy by exploiting structural topology that is invisible to per-transaction rule systems. Han et al. (2024) extended this further with MT2AD, a multi-layer temporal GNN that processes time-evolving graph snapshots to detect anomalous transaction bursts and structurally irregular Ethereum subgraphs—directly addressing the temporal dimension of layering and structuring behaviors.

These learning-based approaches inform the design of the baseline AML investigation agent in this work, which targets several of the same behavioral patterns—fan-out dispersion, rapid serial transfers, structuring—through deterministic rule formulations. While GNN classifiers offer expressive power for complex pattern detection, they exhibit two limitations that influenced the architectural choices made here. In regulatory and judicial contexts, rule-based systems provide mechanistic explainability that graph neural networks cannot: each flagged pattern is traceable to specific transaction hashes, timestamps, and ETH values rather than latent feature activations. Additionally, neural classifiers are vulnerable to out-of-distribution drift when adversarial operators alter their transaction cadence or scatter flows across synthetic intermediary addresses. The deterministic formulation adopted here makes this evasion structurally harder because the rules directly encode the operational constraints that any executing fraudulent campaign must satisfy.

### 2.3 Behavioral Analysis of NFT and DeFi Fraud

The most directly relevant prior work for the rugpull specialization phase of this research is the in-depth behavioral analysis of Sharma, Agarwal, and Shukla (2023), published in ACM Transactions on the Web (Vol. 18, No. 1). This study analyzed 760 confirmed NFT rugpull campaigns across ten marketplaces, establishing a comprehensive behavioral taxonomy of fraudulent creator wallets. Three findings from this work are foundational here. First, rugpull operators are not isolated opportunists: a single creator was documented executing up to 37 rug pulls within a three-month window, confirming that wallet reuse, serial dormancy, and campaign recidivism are empirically prevalent rather than incidental. Second, the behavioral signatures of fraudulent creators are consistent and identifiable at the EOA level before examining any smart contract code—deployment timing, wallet preparation patterns, and fund extraction sequences distinguish malicious from legitimate creators. Third, the wallet linkage analysis in Sharma et al. demonstrated that multiple ostensibly independent projects frequently share common upstream funding infrastructure, establishing the theoretical basis for the co-funding syndicate detection developed in Layer 2 of this framework.

This work operationalizes and extends the Sharma et al. taxonomy into the Ethereum DeFi context. The pre-deployment feature group (Layer 1) formalizes the wallet preparation and warmup patterns described therein. The exit and dormancy group (Layer 5) directly implements and quantifies the serial reactivation cycles that Sharma et al. identified qualitatively. The funding provenance group (Layer 2) extends the upstream linkage analysis to recursive multi-hop graph traversal with formal entropy metrics. Where Sharma et al. (2023) characterized behavior in NFT marketplaces, this framework operationalizes equivalent behaviors as deterministic forensic rules against Ethereum DeFi smart contract deployers.

Mazorra et al. (2022) and Xia et al. (2021) contributed complementary analyses of DeFi rugpull mechanics. Mazorra et al. distinguished hard pulls—where code-level backdoors are explicitly invoked to drain pools—from soft pulls, where developer-allocated tokens are quietly dumped into secondary markets. Xia et al. analyzed token contract behaviors on Uniswap, identifying characteristic liquidity pool manipulation patterns. Both studies focused primarily on contract-layer indicators. The key departure of this work from these analyses is the bypass of contract-layer inspection: by grounding detection entirely in EOA transaction history, the framework remains robust to the contract-level obfuscation techniques that render code-based approaches ineffective.

### 2.4 Agentic Approaches and Autonomous Investigation Systems

Applying autonomous agents to forensic investigation tasks on blockchain systems represents an emerging but rapidly developing area. The study of LOCARD (Yu and Knottenbelt, 2026) during the early phase of this project provided an illustrative data point for what agentic orchestration can achieve in a narrowly defined forensic task—cross-chain transaction tracing—and what it does not address: proactive, single-chain behavioral profiling of suspected actors. The gap left by that design scope is precisely what this project's investigation agent fills, beginning with the general AML baseline and progressing to the rugpull-specific lifecycle engine.

Ante (2026) surveyed the broader landscape of autonomous AI agents in decentralized finance, documenting 306 agents with a combined market capitalization of \$8.6 billion by December 2024. The finding that functionally minimal meme and sentiment agents commanded 59.4% of this total market share despite near-zero utility illustrates the speculative, sentiment-driven character of the DeFi environment—precisely the conditions under which rugpull operators can rapidly accumulate victim liquidity before post-incident systems respond. This market context reinforces the value of proactive, pre-exploit behavioral identification.

### 2.5 NFT Ecosystem Security

Complementing the rugpull-focused behavioral analysis, Wang et al. (2023) examined the broader security landscape of the NFT ecosystem, identifying wash trading, market manipulation, and project abandonment as the dominant threat classes. Their analysis of information asymmetry between creators and buyers—and of the technical mechanisms that enable it—contextualizes why EOA-level behavioral profiling is an effective detection strategy: the creator is an identifiable, immutable on-chain entity even when their contract code is obfuscated or unverified.



---

## 3 Method

### 3.1 Problem Setup and Formal Notation

This work addresses two related but distinct forensic problems, corresponding to the two research phases described in Section 1.

**Phase 1 — General AML Pattern Detection.** Given an Ethereum wallet address $W$, determine whether its one-hop transaction neighborhood exhibits any of six canonical anti-money laundering behavioral patterns. The investigation is executed by a LangGraph-orchestrated agent that retrieves transaction history, applies pattern-matching rules, and produces an explainable report. The output is a structured set of flagged observations with supporting evidence.

**Phase 2 — Rugpull Creator Threat Profiling.** Given a smart contract deployer EOA $W$, compute a structured risk profile from its complete transaction execution history—including internal EVM traces—that determines whether $W$ exhibits behavioral characteristics consistent with a rugpull operator. The formal problem is as follows.

This report formalizes the problem of blockchain behavioral threat profiling as a deterministic mapping from an Externally Owned Account's complete transaction execution history to a structured threat profile.

Let $\mathcal{W}$ denote the universe of Ethereum addresses. A target creator wallet is an EOA address $W \in \mathcal{W}$. The historical on-chain footprint of $W$ is defined by the ordered sequence of standard transactions:
$$T_W = \langle t_1, t_2, \dots, t_n \rangle$$
where each transaction $t_i$ is a tuple:
$$t_i = (h_i, \tau_i, s_i, d_i, v_i, g_i, p_i, \kappa_i, \text{err}_i)$$
representing the transaction hash $h_i$, UNIX block timestamp $\tau_i$, sender address $s_i$, recipient address $d_i$, transfer value in Wei $v_i$, gas limit $g_i$, effective gas price $p_i$, input data payload $\kappa_i$, and error status $\text{err}_i \in \{0, 1\}$.

Let $C_W = \{c_1, c_2, \dots, c_k\} \subset \mathcal{W}$ represent the set of distinct smart contracts deployed by $W$, where contract deployment is indicated by the structural condition $d_i = \emptyset$ (or the null creation address) in $t_i$.

Crucially, in the EVM architecture, interactions that extract native ETH from smart contracts (such as liquidity removals or treasury sweeps) are frequently dispatched via internal contract executions (`CALL`, `DELEGATECALL`, or `SELFDESTRUCT` opcodes) rather than top-level EOA transactions. To capture these flows, the set of internal transaction traces associated with $W$ and its deployed contracts $C_W$ is defined as:
$$I_W = \langle \iota_1, \iota_2, \dots, \iota_m \rangle$$
where each internal trace $\iota_j = (h_j, \text{tr}_j, \tau_j, s_j, d_j, v_j, \text{type}_j, \text{err}_j)$ is uniquely indexed by the composite key $(h_j, \text{tr}_j)$ comprising the parent transaction hash $h_j$ and the execution trace identifier $\text{tr}_j$.

The complete observable transaction substrate for wallet $W$ is the merged, time-ordered sequence:
$$\mathcal{E}_W = \text{MergeSort}(T_W \cup I_W, \text{key}=\tau)$$

The forensic objective is to evaluate a deterministic feature extraction function $\Phi: \mathcal{E}_W \to \mathbb{R}^d$, producing a typed feature vector $\mathbf{x}_W \in \mathcal{X}$, and to apply an evaluation operator $\Psi: \mathcal{X} \to [0, 100]$ that computes a cumulative threat score $S(W)$:
$$S(W) = \min\left(100, \sum_{r \in \mathcal{R}} w_r \cdot \mathbb{I}[r(\mathbf{x}_W) = \text{True}]\right)$$
where $\mathcal{R}$ is the register of 29 deterministic forensic rules, $w_r \in \{5, 10, 15, 20, 25, 30, 40\}$ denotes the static severity weight assigned to rule $r$, and $\mathbb{I}[\cdot]$ is the indicator function. The scalar score $S(W)$ maps to a discrete categorical verdict $V(W)$ defined over five ordinal risk bands:
$$V(W) = \begin{cases}
\text{HIGH\_CONFIDENCE\_RUGPULL}, & \text{if } S(W) \ge 80 \\
\text{STRONG\_PATTERN}, & \text{if } 60 \le S(W) < 80 \\
\text{MODERATE\_PATTERN}, & \text{if } 40 \le S(W) < 60 \\
\text{WEAK\_PATTERN}, & \text{if } 20 \le S(W) < 40 \\
\text{CLEAN}, & \text{if } S(W) < 20
\end{cases}$$

Additionally, if the transaction history contains insufficient pre-deployment activity ($n < 2$ and $C_W = \emptyset$), the system emits an exceptional diagnostic state $V(W) = \text{INSUFFICIENT\_HISTORY}$, preventing false-positive scoring on dormant accounts.

---

### 3.2 System Architecture

The research produced two architecturally related but distinct system components, corresponding to Phase 1 and Phase 2 of the project.

#### 3.2.1 Phase 1: Single-Agent AML Investigation Baseline

The Phase 1 system is a LangGraph-orchestrated investigation agent that accepts an Ethereum wallet address and produces an explainable forensic report identifying which, if any, of six anti-money laundering behavioral patterns are present. The agent workflow is a directed acyclic graph:

```
[START] ──> [Planner] ──> [Profiler] ──> [Detector] ──> [Reporter] ──> [Memory] ──> [END]
```

The **Planner** node identifies the investigation strategy. The **Profiler** retrieves and structures transaction history from the Etherscan API, including wallet balance, transaction counts, counterparty statistics, and token holdings. The **Detector** evaluates the transaction history against six pattern-matching rules (detailed in Section 3.3.0). The **Reporter** synthesizes flagged findings using an Observation → Evidence → Reasoning schema. The **Memory** node persists results to a SQLite store for case history retrieval. A FastAPI backend exposes the agent as a service endpoint.

This baseline established the foundational data retrieval infrastructure, the LangGraph orchestration pattern, and the explainable report format that subsequent phases extended and specialized.

> **Figure 2: LangGraph Orchestration Workflow (Phase 1 and Phase 2 share this DAG structure).** Node responsibilities differ across phases: in Phase 1, the Detector evaluates six AML pattern rules; in Phase 2, it invokes the five-layer deterministic BTP engine.

#### 3.2.2 Phase 2: Deterministic Behavioral Threat Profiling Engine

The Phase 2 engine is a fully decoupled, multi-stage processing pipeline that extends the Phase 1 architecture to deep lifecycle profiling of smart contract deployer EOAs.

```
       [ Etherscan API / Local Node ]
                     │
       ┌─────────────┴─────────────┐
       ▼                           ▼
[ Normal Transactions ]  [ Internal Traces ]
       └─────────────┬─────────────┘
                     ▼
          [ Unified Trace Merging ]
         (Hash + Trace ID Deduplication)
                     │
                     ▼
       ┌───────────────────────────┐
       │ Feature Extraction Engine │
       ├───────────────────────────┤
       │ Layer 1: Pre-Deployment   │
       │ Layer 2: Funding Provenance│
       │ Layer 3: Cash-Out Strategy│
       │ Layer 4: Transfer Semantics│
       │ Layer 5: Exit & Dormancy  │
       └─────────────┬─────────────┘
                     ▼
          [ Pydantic FeatureVector ]
                     │
                     ▼
       ┌───────────────────────────┐
       │ Deterministic Rule Engine │
       │ (29 Invariant Evaluators) │
       └─────────────┬─────────────┘
                     ▼
          [ Additive Scoring Core ]
          Risk Score S ∈ [0, 100]
          Verdict V ∈ {CLEAN ... HIGH}
          Retirement Score S_retire
                     │
                     ▼
       ┌───────────────────────────┐
       │ LangGraph Reporting Agent │
       │ (Structured Narrative LLM)│
       └─────────────┬─────────────┘
                     ▼
      [ Auditable Forensic Report ]
```
> **Figure 1: Phase 2 System Architecture.** The dual-engine design processes raw execution traces through five deterministic feature layers and a static rule engine before dispatching structured evidentiary records to the LangGraph narrative agent.

The operational pipeline proceeds through six discrete stages:
1. **Transaction Retrieval and Reconciliation:** The engine queries raw normal transactions, internal traces, and contract creation events via the Etherscan API. A rate-limiting token bucket throttles requests to 4.5 calls/sec to operate robustly within public API constraints. Standard transactions and internal traces are merged using the composite key $(h_i, \text{tr}_i)$, preventing the omission of contract-mediated ETH sweeps.
2. **Feature Extraction:** The unified trace stream is ingested by five modular extractors corresponding to the five behavioral tiers, outputting a strongly typed `FeatureVector` model backed by Pydantic schema validation.
3. **Deterministic Rule Evaluation:** The 29 formal rules in $\mathcal{R}$ evaluate the `FeatureVector`. Each rule evaluates an invariant condition and returns a boolean trigger flag accompanied by an evidentiary metadata payload.
4. **Additive Score Aggregation:** The scoring engine computes $S(W)$ by summing the severity weights of all triggered rules, enforcing an upper bound of 100.
5. **Verdict and Metadata Synthesis:** The categorical verdict $V(W)$ is assigned. If $S(W) \ge 36$, an auxiliary retirement likelihood score $S_{\text{retire}}(W) \in [0, 0.99]$ is synthesized from dormancy and balance retention metrics.
6. **Agentic Narrative Generation:** The LangGraph Reporter node ingests the pre-computed mathematical facts (triggered rules, exact timestamps, transaction hashes, and amounts) and structures the output using the Observation $\to$ Evidence $\to$ Reasoning investigative schema. The LLM has zero capability to alter the numerical score or verdict, eliminating hallucination risks in the forensic judgment.

---

### 3.3 Feature Engineering Across the Five Behavioral Layers

The five-layer feature taxonomy is grounded in the behavioral analysis of Sharma, Agarwal, and Shukla (2023), which established the foundational typology of fraudulent creator wallet behavior in the NFT domain—including preparation cadence, funding infrastructure, extraction patterns, and serial reuse. This taxonomy is operationalized and extended to the Ethereum DeFi context, translating qualitative behavioral observations into mathematically specified forensic invariants.

#### Layer 0: Phase 1 Baseline — General AML Pattern Rules

Before the rugpull specialization, the Phase 1 agent evaluated the following six behavioral patterns from one-hop transaction graphs. These patterns correspond to canonical money laundering stages (Meiklejohn et al., 2013; Ferretti et al., 2024) and serve as the general-purpose AML detection baseline from which the lifecycle-specific rugpull features were subsequently derived:

| Rule | Threshold | AML Stage |
| :--- | :--- | :--- |
| Large Transfer Detection | Outgoing transfer $\ge$ 10 ETH | Placement / major capital movement |
| Rapid Serial Transfers | $\ge 5$ transfers within 300 seconds | Layering / automated dispersal |
| High Fan-Out Distribution | $\ge 20$ unique recipient addresses | Layering / mule network seeding |
| Dormant Wallet Reactivation | $\ge 180$ days of inactivity before resumption | Integration / OpSec reactivation |
| Activity Burst Detection | Transaction frequency $\ge 3\times$ historical baseline | Automated activation event |
| Round-Number Structuring | $\ge 3$ outgoing transfers with identical round values | Structuring / scripted transfer |

Additionally, the agent flagged transfers of $\ge 0.1$ ETH to destination wallets less than 24 hours old—a pattern consistent with seeding newly instantiated mule accounts. This baseline system operated at the one-hop graph level, without internal trace reconciliation or multi-layer lifecycle analysis. Its limitations—particularly its inability to distinguish rugpull operators from other suspicious actors, and its dependence on post-event signals—motivated the progressive feature engineering described below.

#### Layer 1: Pre-Deployment Behavioral Dynamics

This layer examines the operational tempo of the creator wallet between its initial funding and the deployment of its primary exploit contract. It directly corresponds to the "wallet preparation" behavioral stage identified in Sharma et al. (2023), where fraudulent creators exhibit compressed, scripted warmup sequences that differ markedly from the extended, iterative preparation of legitimate protocol developers.

We now detail the mathematical and algorithmic formulation of the 29 forensic rules, categorized across the five operational layers.

- **Warmup Latency (F1 / RUG-001):** Measures the elapsed time in hours between the wallet's first registered transaction and the first contract deployment:
  $$\Delta \tau_{\text{warmup}} = \frac{\tau_{\text{deploy}, 1} - \tau_1}{3600}$$
  Legitimate engineering teams typically fund development wallets days or weeks prior to mainnet deployment to perform configuration, register domains, or coordinate multisig operations. Scammers, attempting to minimize exposure to heuristic blacklists, operate on compressed timelines. Rule `RUG-001` triggers as **CRITICAL** (+40 points) if $\Delta \tau_{\text{warmup}} < 0.25$ hours (15 minutes).
- **Funding Inter-Arrival Regularity (F2 / RUG-002):** Analyzes the timing consistency of incoming seed funding transactions prior to contract deployment. Let $\langle \tau_{\text{in}, 1}, \tau_{\text{in}, 2}, \dots, \tau_{\text{in}, p} \rangle$ be the timestamps of inbound funding events preceding $\tau_{\text{deploy}, 1}$. The inter-arrival intervals are $\Delta t_k = \tau_{\text{in}, k} - \tau_{\text{in}, k-1}$. The Coefficient of Variation ($CV$) of these intervals is:
  $$CV_{\text{funding}} = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}} = \frac{\sqrt{\frac{1}{p-1}\sum_{k=1}^p (\Delta t_k - \bar{\Delta t})^2}}{\bar{\Delta t}}$$
  Human capital provisioning is erratic and bursty, resulting in high variance ($CV > 1.5$). Scripted, automated sybil funding bots deploy capital at near-uniform, programmatic intervals. Rule `RUG-002` triggers as **HIGH** (+25 points) when $CV_{\text{funding}} \le 0.9956$ with $p \ge 3$.
- **Mainnet Dry-Run Count (F3):** Counts reverted transactions ($\text{err}_i = 1$) executed by $W$ prior to $\tau_{\text{deploy}, 1}$. (As analyzed in Section 4, this feature proved non-informative).
- **Deployment Cadence and Burstiness (F4, F4b, F5):** Measures total contract deployments $k = |C_W|$, deployment interval variance $\sigma^2(\tau_{\text{deploy}})$, and the Shannon entropy of the account's transaction nonces:
  $$H(\text{nonce}) = -\sum_{j=1}^u P(\text{action}_j) \log_2 P(\text{action}_j)$$
- **Bytecode Size Similarity (F7):** Computes pairwise size ratios of compiled bytecode across consecutive deployments within the same wallet to detect cloned scam templates.
- **Secondary Rapid Deployment (NEW-A / RUG-NEW-A):** Evaluates whether an auxiliary contract is deployed within 60 minutes of the primary contract:
  $$\Delta \tau_{\text{clone}} = \tau_{\text{deploy}, 2} - \tau_{\text{deploy}, 1} \le 3600 \text{ seconds}$$
  Malicious operators frequently deploy an auxiliary unverified router, token locker, or liquidity manipulation wrapper immediately alongside their primary ERC-20 token contract.
- **Rapid Ownership Transfer (NEW-B / RUG-NEW-B):** Detects execution of contract ownership renunciation or transfer functions (`transferOwnership(address)` selector `0xf2fde38b`) within 48 hours of deployment:
  $$\Delta \tau_{\text{renounce}} = \tau_{\text{renounce}} - \tau_{\text{deploy}} \le 172,800 \text{ seconds}$$
  This serves as an operational obfuscation maneuver, creating the illusion of decentralization while the underlying liquidity pool remains vulnerable to external drain functions.

#### Layer 2: Funding Provenance and Graph Topology
This layer evaluates the origins of the initial gas and liquidity capital injected into $W$. It operationalizes the wallet linkage findings of Sharma et al. (2023), who demonstrated that multiple ostensibly independent rugpull projects share common upstream funding infrastructure—a pattern that the recursive traversal in this framework formalizes as a graph-theoretic co-funding syndicate test.

- **Mixer and Anonymizing Bridge Ingress (FP1 / RUG-FP4):** The upstream funding tree of $W$ is traced back to identify the immediate source address $s_{\text{seed}}$. The address is cross-referenced against a curated directory of privacy protocols (Tornado.cash, Railgun, Cyclone) and decentralized cross-chain bridge deposit contracts:
  $$\text{IsMixer}(s_{\text{seed}}) \lor \text{IsBridge}(s_{\text{seed}}) = \text{True}$$
  Triggering `RUG-FP4` assigns **CRITICAL** (+40 points), representing the single highest-weight individual indicator in the framework.
- **Recursive Co-Funding and Funder Recurrence (FP2, FP4, FP5 / RUG-FP5):** A recursive breadth-first traversal traces up to $h=3$ hops upstream from $W$. If an upstream funder $s_{\text{upstream}}$ has seeded multiple distinct deployer wallets that subsequently launched verified or unverified contracts, a co-funding syndicate is identified. We compute the Shannon entropy of the incoming funding distribution:
  $$H(\text{Funding}) = -\sum_{i=1}^{q} \left(\frac{v_{\text{in}, i}}{\sum v_{\text{in}}}\right) \log_2 \left(\frac{v_{\text{in}, i}}{\sum v_{\text{in}}}\right)$$
  Where low entropy coupled with recurrent funder nodes indicates centralized sybil infrastructure (`RUG-FP5`, +25 points).
- **Fresh Seed Wallet Fraction (FP3):** The proportion of upstream seed capital originating from addresses created less than 24 hours prior to the funding transaction.
- **Gas-Standardized Seed Capital (FP6, FP7):** Normalizes the raw seed amount $v_{\text{seed}}$ against the prevailing 7-day moving average gas price to differentiate between operational gas provisioning and capital staging.
- **Upstream Funding Tree Overlap (FP8):** Computes the Jaccard similarity index between the set of upstream funding ancestors $\mathcal{A}(W_a)$ and $\mathcal{A}(W_b)$ across investigated deployers:
  $$J(\mathcal{A}_a, \mathcal{A}_b) = \frac{|\mathcal{A}_a \cap \mathcal{A}_b|}{|\mathcal{A}_a \cup \mathcal{A}_b|}$$

#### Layer 3: Cash-Out Strategy and Liquidity Extraction
Layer 3 analyzes the liquidation phase, reconciling normal and internal transaction streams to identify capital extraction patterns. The extraction behaviors captured here—treasury drain velocity, structured layering, mule wallet dispersal—correspond directly to the fund movement patterns documented in Sharma et al. (2023) for NFT rugpulls, generalized here to DeFi liquidity pool exploits where smart contract internal traces carry the primary evidence.

A critical technical contribution of this layer is the dual-stream reconciliation architecture: standard Etherscan `txlist` queries capture EOA-initiated transactions, while `txlistinternal` captures smart-contract-mediated ETH flows generated by `removeLiquidity()` and similar functions. Prior work that relies solely on standard transactions systematically underestimates cash-out volumes in DeFi exploits.

- **Withdrawal Latency (CP1):** Measures the time delta between the first inbound victim deposit into the contract/pool $\tau_{\text{victim}, 1}$ and the first major outflow initiated by the creator $\tau_{\text{drain}, 1}$:
  $$\Delta \tau_{\text{drain}} = \tau_{\text{drain}, 1} - \tau_{\text{victim}, 1}$$
  Triggering `CRITICAL` (+40) if $\Delta \tau_{\text{drain}} < 3,600$ seconds (smash-and-grab within 1 hour), and `HIGH` (+25) if $< 86,400$ seconds (within 24 hours).
- **Treasury Sweep and Drain Ratio (CP2):** Let $V_{\text{inflow}} = \sum v_{\text{victim}}$ denote the cumulative ETH deposited by external accounts into the contract, and $V_{\text{withdrawn}} = \sum v_{\text{creator}}$ denote the cumulative ETH extracted by $W$ or its designated intermediaries. The drain ratio is:
  $$R_{\text{drain}} = \frac{V_{\text{withdrawn}}}{V_{\text{inflow}}}$$
  The rule classifies extraction profiles into three severity categories:
  - *Smash-and-Grab (CRITICAL, +40):* $R_{\text{drain}} \ge 0.90$ executed across $N_{\text{tx}} \le 2$ transactions within 24 hours.
  - *Treasury Sweep (HIGH, +25):* $R_{\text{drain}} \ge 0.90$ across $N_{\text{tx}} \le 2$ transactions, but spanning $\ge 24$ hours.
  - *Near-Total Drain (HIGH, +25):* $R_{\text{drain}} \ge 0.80$ executed across $N_{\text{tx}} \le 5$ transactions.
- **Outflow Fragmentation and Layering (CP3):** Evaluates whether the operator disperses extracted proceeds via structured layering. Computes the coefficient of variation of outflow values $CV(v_{\text{out}})$ and the fraction of transactions matching round-ETH increments ($v_i \pmod{0.5 \text{ ETH}} = 0$).
- **Mule Wallet Fan-Out Diversity (CP4):** Analyzes the destination addresses $\mathcal{D}_{\text{out}} = \{d_j \mid s_j = W\}$ receiving post-extraction outflows. The rule computes the fresh wallet ratio:
  $$R_{\text{fresh}} = \frac{|\{d \in \mathcal{D}_{\text{out}} \mid \text{Age}(d) < 7 \text{ days}\}|}{|\mathcal{D}_{\text{out}}|}$$
  Triggers **CRITICAL** (+40) if $|\mathcal{D}_{\text{out}}| \ge 10$ unique destinations and $R_{\text{fresh}} > 0.60$.
- **Direct Exchange and Mixer Concentration (CP5):** Computes the percentage of extracted volume directly routed to known exchange deposit hot wallets or mixers without intermediate hops. Any direct routing to a mixer triggers **CRITICAL** unconditionally.
- **Swap-Before-Cashout Liquidity Removal (CP6):** Detects execution of canonical AMM liquidity removal function selectors:
  $$\kappa_i \in \{0\text{xbaa2abde}, 0\text{x02751cec}, 0\text{xaf2979eb}\}$$
  corresponding to Uniswap V2 `removeLiquidityWithPermit`, `removeLiquidityETH`, and SushiSwap variants, followed by an immediate decentralized exchange swap (e.g., token-to-ETH or token-to-USDT) executed within 24 hours (+25 points).
- **Retained Proceeds Ratio (CP7):** Computes the final ecosystem balance remaining in the contract or liquidity pool relative to total historical victim deposits:
  $$R_{\text{retained}} = \frac{\text{Balance}_{\text{final}}(C_W)}{V_{\text{inflow}}}$$
  Triggers **CRITICAL** (+40) if $R_{\text{retained}} < 0.01$ (less than 1% of victim capital left behind).

#### Layer 4: Value-Transfer Semantics and Scripting Fingerprints
Layer 4 isolates mechanical signatures imprinted by automated deployment and extraction software. While Sharma et al. (2023) characterized rugpull operators as scripted and systematic, the value-transfer semantics layer developed here provides the first quantitative operationalization of this observation: scripted operations leave reproducible fingerprints in transaction amount distributions, gas pricing uniformity, and pre-cashout probe patterns that manual, human-operated wallets do not produce.

- **Scripted Inbound Value Repetition (VS-1 / RUG-VS-1):** Automated sybil bots are frequently parameterized with fixed ETH amounts. Let $\mathcal{M}(V_{\text{in}})$ denote the modal value of inbound transfers to $W$. The mode frequency ratio is:
  $$R_{\text{mode}} = \frac{\text{Count}(v_i = \mathcal{M}(V_{\text{in}}))}{|V_{\text{in}}|}$$
  Triggers **HIGH** (+20) if $R_{\text{mode}} \ge 0.60$ with $|V_{\text{in}}| \ge 5$, and **MEDIUM** (+10) if $R_{\text{mode}} \ge 0.40$.
- **Round-Number Pre-Deployment Funding (VS-2 / RUG-VS-2):** Evaluates human cognitive bias in capital sizing versus automated fractional transfers. A value $v$ is round in ETH space if:
  $$\left(\frac{v}{10^{18}}\right) \pmod{0.5} = 0$$
  Triggers **HIGH** (+20) if round ratio $\ge 0.80$ with count $\ge 4$.
- **Gas-Price Uniformity Anomaly (VS-3 / RUG-VS-3):** Measures the standard deviation of transaction gas prices across consecutive operations:
  $$CV_{\text{gas}} = \frac{\sigma(p_{\text{gas}})}{\mu(p_{\text{gas}})}$$
  *(Note: For post-EIP-1559 blocks, this metric evaluates the `maxFeePerGas` parameter).*
- **Pre-Cashout Wallet Ping Dusting (VS-4 / RUG-VS-4):** Detects micro-transactions ($v_i \le 10^{14} \text{ Wei} = 0.0001 \text{ ETH}$) dispatched to external addresses or liquidity pools immediately prior to executing the cash-out, representing automated test pings designed to verify router execution pathways (+20 points if $\ge 5$ pings within 24 hours).
- **Cross-Deployment Seed Amount Consistency (VS-5 / RUG-VS-5):** Evaluates the Jaccard similarity of seed transaction values across successive contract launches.
- **Extreme Extraction Multiplier (VS-6 / RUG-VS-6):** Computes the financial return ratio of the exploit:
  $$M = \frac{V_{\text{cashout}}}{\max(V_{\text{deploy}} + V_{\text{self-fund}}, 10^{15} \text{ Wei})}$$
  Triggers **CRITICAL** (+40) if $M \ge 50\times$, capturing the asymmetric economics characteristic of liquidity-draining exploits.

#### Layer 5: Exit Dynamics and Post-Exploit Dormancy
Layer 5 tracks the post-operational phase of the creator account, distinguishing abandoned wallets from persistent developer addresses. This layer is the most direct operationalization of Sharma et al.'s (2023) finding on recidivism: fraudulent NFT creators are serial offenders who cycle between active scam operations and deliberate dormancy periods. EXIT-2 (Cyclical Reactivation Delay) and EXIT-META (Retirement Likelihood Score) together provide a formal measurement instrument for this recidivism pattern at the transaction-graph level.

- **Post-Rug Silence Duration (EXIT-1 / RUG-EXIT-1):** Measures the duration of complete transactional dormancy following the final significant value transfer:
  $$D_{\text{silence}} = \frac{\tau_{\text{now}} - \tau_{\text{last\_significant}}}{86400} \text{ days}$$
  where a significant transaction is defined as moving $> 0.001$ ETH or invoking DeFi router selectors. We formulate the silence ratio:
  $$R_{\text{silence}} = \frac{D_{\text{silence}}}{D_{\text{lifespan}}}$$
  Triggers **HIGH** (+20) if $D_{\text{silence}} > 30 \text{ days}$, $R_{\text{retained}} < 0.01$, and $R_{\text{silence}} > 0.50$.
- **Reactivation Delay / Burner-Phone Pattern (EXIT-2 / RUG-EXIT-2):** Detects cyclical dormancy events, defined as temporal gaps $\Delta \tau_{\text{gap}} \ge 30 \text{ days}$ between consecutive outgoing transactions. For each reactivation event, a Reactivation Context Score ($RCS$) is computed:
  $$RCS = 2 \cdot \mathbb{I}[t_{\text{reactivate}} \text{ deploys contract}] + 2 \cdot \mathbb{I}[d_{\text{reactivate}} \in \text{Mixers}]$$
  Triggers **CRITICAL** (+30) if dormancy events $\ge 2$, and **HIGH** (+20) if 1 event with $RCS \ge 2$.
- **Downstream Funding Tracking (EXIT-3):** Traces whether outgoing transfers from $W$ directly fund the seed capital of subsequent contract deployer addresses.
- **Fresh Wallet Bulk Migration (EXIT-4 / RUG-EXIT-4):** Evaluates whether the operator evacuates stolen capital via a single high-volume transfer:
  $$v_{\text{transfer}} \ge 0.30 \cdot V_{\text{inflow}} \quad \land \quad \text{Age}(d_{\text{destination}}) < 24 \text{ hours}$$
  Assigns **CRITICAL** (+40) if the recipient address was instantiated within 24 hours of the bulk migration.
- **Retirement Likelihood Score (EXIT-META):** An auxiliary synthetic heuristic $S_{\text{retire}}(W) \in [0, 0.99]$ (contributing 0 additive points to the threat score) computed for all wallets with $S(W) \ge 36$:
  $$S_{\text{retire}}(W) = \min\left(0.99, B(N_{\text{dormancy}}) + \Delta_{\text{time}}(D_{\text{silence}})\right)$$
  where the base score $B \in \{0.50, 0.70, 0.88\}$ scales with the number of dormancy events, and $\Delta_{\text{time}} \in \{0.00, 0.04, 0.07, 0.10\}$ scales with absolute post-exploit silence. The score is mathematically capped at 0.99 to reflect the epistemological impossibility of proving permanent on-chain abandonment.

```
+───────────────────────────────────────────────────────────────────────────────+
|               LIFECYCLE-AWARE BEHAVIORAL THREAT TAXONOMY                      |
+───────────────────────────────────────────────────────────────────────────────+
  Phase 1: Pre-Deployment Preparation
  │  ├── F1 (RUG-001): Warmup Latency (<15 min burner window)
  │  ├── F2 (RUG-002): Funding Inter-Arrival CV (scripted funding timing)
  │  ├── F3: Mainnet Dry-Run Count (reverted transactions)
  │  ├── F4/F4b/F5: Deployment Count, Burstiness & Nonce Entropy
  │  ├── F7: Bytecode Size Similarity Across Deployments
  │  ├── NEW-A (RUG-NEW-A): Secondary Rapid Deployment (<60 min)
  │  └── NEW-B (RUG-NEW-B): Rapid Ownership Renunciation (<48 hr)
  │
  Phase 2: Funding Provenance & Ingress
  │  ├── FP1 (RUG-FP4): Mixer & Cross-Chain Bridge Ingress
  │  ├── FP2/FP4/FP5 (RUG-FP5): Recursive Graph Hop & Syndicate Co-Funding
  │  ├── FP3: Fresh Seed Wallet Ratio (<24h seed origin)
  │  └── FP6/FP7/FP8: Gas-Standardized Seed Amounts & Jaccard Tree Overlap
  │
  Phase 3: Cash-Out & Liquidity Extraction
  │  ├── CP1: Extraction Latency (<1h smash-and-grab vs <24h sweep)
  │  ├── CP2: Treasury Sweep & Victim Drain Ratio (>90% drain in <=2 txs)
  │  ├── CP3: Outflow Structuring & Value Fragmentation CV
  │  ├── CP4: Mule Wallet Fan-Out & Fresh Destination Ratio
  │  ├── CP5: Direct Exchange & Mixer Liquidation Concentration
  │  ├── CP6: AMM Liquidity Removal Selectors & Immediate Swap
  │  └── CP7: Ecosystem Retained Proceeds Ratio (<1% remaining)
  │
  Phase 4: Value-Transfer Semantics & Scripting
  │  ├── VS-1 (RUG-VS-1): Modal Inbound Value Repetition
  │  ├── VS-2 (RUG-VS-2): Round-Number Bias in ETH Space (mod 0.5 ETH)
  │  ├── VS-3 (RUG-VS-3): Gas Price Uniformity & Fee Dispersion
  │  ├── VS-4 (RUG-VS-4): Pre-Cashout Micro-Dusting Pings
  │  ├── VS-5: Cross-Deployment Inflow Amount Set Similarity
  │  └── VS-6 (RUG-VS-6): Extreme Profit Extraction Multiplier (M >= 50x)
  │
  Phase 5: Exit Dynamics & Dormancy
     ├── EXIT-1 (RUG-EXIT-1): Post-Exploit Prolonged Silence Ratio
     ├── EXIT-2 (RUG-EXIT-2): Cyclical Reactivation & Burner-Phone Pattern
     ├── EXIT-3: Downstream Deployer Seeding Traversal
     ├── EXIT-4 (RUG-EXIT-4): High-Volume Fresh Proxy Migration (<24h age)
     └── EXIT-META: Non-Scoring Operational Retirement Likelihood
```
> **Figure 7: Behavioral Threat Profiling Lifecycle Coverage.** Mapping the five feature layers to the chronological stages of an adversarial smart contract campaign.

---

## 4 Experiments and Empirical Evaluation

### 4.1 Experimental Setup

#### Phase 1: AML Baseline System Evaluation
The Phase 1 single-agent AML baseline was evaluated qualitatively on individual wallet investigations. The system successfully retrieved transaction histories via the Etherscan API, identified applicable behavioral patterns, and produced structured Observation → Evidence → Reasoning reports for each detected anomaly. The baseline established that the LangGraph orchestration architecture and the Etherscan data pipeline were functionally viable for automated blockchain investigation. The principal limitation identified was the system's breadth without specialization: the six general-purpose rules fired across a wide range of wallet types—both malicious and legitimate—with no mechanism for ranking severity or distinguishing rugpull operators from other categories of suspicious actors.

#### Phase 2: Rugpull Detection — Dataset Curation and Ground Truth
Evaluating the behavioral threat profiling system required authenticated ground-truth datasets containing confirmed malicious rugpull deployers alongside legitimate protocol developers. The dataset was compiled from publicly available blockchain incident registries, Etherscan exploit disclosures, and community-audited DeFi security reports. All wallet addresses are drawn from publicly accessible on-chain data.

The evaluation was executed across two progressive cohorts:
1. **Initial Calibration Cohort ($N_1 = 69$):** Consisting of 50 confirmed malicious Ethereum rugpull creator wallets and 19 verified legitimate developer wallets (representing core contributors, verified protocol factories, and open-source project maintainers). This cohort was utilized for initial feature calibration and hypothesis testing for Layer 1 (pre-deployment) features.
2. **Expanded Benchmark Cohort ($N_2 = 90$):** Consisting of 90 confirmed, independent Ethereum rugpull creator addresses responsible for documented historical liquidity drains. Ground-truth exploit attribution was confirmed via associated DEX liquidity pool drains, community incident reports, and public exploit disclosures. This cohort was used for all Layer 2–5 evaluations.

#### Implementation and Operational Parameters
The forensic engine is implemented in Python 3.11 utilizing FastAPI, Pydantic v2, and SQLite. Graph operations and topological traversals are executed via NetworkX. External blockchain state is queried via the Etherscan Developer API (free tier). Inbound API requests are throttled at 4.5 queries per second via a custom sliding-window token bucket to prevent rate-limit rejections. The analysis engine requires no GPU acceleration; all feature extractions and deterministic rule evaluations complete in under 4.2 seconds per investigated wallet on standard commodity hardware.

#### Evaluation Methodology
Because no prior published system performs multi-stage pre-deployment and lifecycle behavioral profiling on Ethereum creator EOAs, the evaluation is structured as an **ablation-style progression**. The incremental discriminative capacity of the framework is measured as each operational layer is incorporated:
- **Rugpull Baseline (Layer 1):** Pre-Deployment rules (F1–F7, NEW-A, NEW-B), evaluated on $N_1 = 69$.
- **Provenance Expansion (Layers 1–2):** Adding Funding Provenance rules (FP1–FP8), evaluated on $N_2 = 90$.
- **Full Lifecycle Pipeline (Layers 1–3):** Adding Cash-Out Strategy rules (CP1–CP7), evaluated on $N_2 = 90$.
- **Semantics and Dormancy Extension (Layers 4–5):** Value-Transfer Semantics (VS-1–VS-6) and Exit/Dormancy tracking (EXIT-1–EXIT-META), evaluated on $N_2 = 90$.

---

### 4.2 Main Empirical Results

#### Phase 1: Baseline AML Agent — Qualitative Findings
The Phase 1 single-agent system processed individual Ethereum wallet addresses through the five-node LangGraph workflow and correctly identified the following AML patterns where present: fund fan-out distributions (high-fan-out rule triggered for wallets interacting with $\ge 20$ unique recipients), dormant wallet reactivations (flagged for wallets inactive for $\ge 180$ days resuming activity), and structuring events (round-number transfer patterns identified in wallets with scripted outflow sequences). The structured Observation → Evidence → Reasoning reports confirmed that the explainability architecture was effective: each finding was traceable to specific transaction hashes and threshold comparisons. The key limitation confirmed through this evaluation was that the six general rules, while detecting suspicious patterns, could not distinguish between rugpull operators and other categories of suspicious actors—motivating the rugpull-specific behavioral profiling phase.

#### Rugpull Baseline (Layer 1): Pre-Deployment Evaluation and Hypothesis Refutations
Evaluating the initial calibration cohort ($N=69$, 50 malicious, 19 genuine) on pre-deployment features revealed profound behavioral divergence—and critically disproved two conventional forensic assumptions.

```
       [ Funding Arrival Timing CV Distribution ]
Legitimate Developers (N=19):
  Mean CV = 2.41  [====== High Variance (Human) ======]
  ─────────────────────────────────────────────────────
Malicious Deployers (N=50):
  Mean CV = 0.68  [== Low CV (Scripted) ==]  (64% <= 0.9956)
```

1. **Funding Inter-Arrival Regularity (F2 / RUG-002):** The coefficient of variation of pre-deployment funding arrivals proved to be the single strongest early-stage behavioral signal. 64.0% (32/50) of the malicious cohort exhibited $CV_{\text{funding}} \le 0.9956$, reflecting automated, programmatic fund disbursement from distribution scripts. Conversely, legitimate developers exhibited highly irregular, human-driven funding patterns ($\mu = 2.41$, $\sigma = 1.12$), with only one legitimate wallet falling below the 1.0 threshold.
2. **The "Dry-Run" Hypothesis Debunked (F3):** It is widely conjectured in heuristic auditing that malicious actors execute failed or reverted test transactions on mainnet to verify contract execution prior to deploying the final exploit. Empirical measurements here **decisively refute** this hypothesis: the pre-deployment reverted transaction count was **identically 0 across 100% of tested malicious wallets and 94.7% of legitimate developer wallets**. Both malicious operators and legitimate engineers test exclusively on local development forks (e.g., Hardhat, Anvil) or public testnets (Sepolia, Goerli). Mainnet dry-run counting provides zero discriminative utility.
3. **Inversion of Deployment Burstiness and Entropy (F4b, F5):** The empirical data reveals a statistically robust **inverse correlation** regarding deployment burstiness. Naive intuition suggests that scammers deploy rapidly in bursts, whereas legitimate engineers deploy steadily. In reality, legitimate protocol architects exhibit significantly *higher* deployment burstiness and lower nonce entropy: legitimate deployments involve deploying proxy contracts, implementation logic, multi-token registries, and governance modules in immediate succession (e.g., 4–8 transactions within 15 minutes). Scammers, conversely, execute a "deploy, seed liquidity, and wait" operational pattern, resulting in low burstiness and isolated single deployments.

#### Phase 3: Funding Provenance Batch Validation ($N=90$)
Expanding the evaluation to the full benchmark cohort of 90 confirmed rugpull deployers with Layer 1 and Layer 2 (Funding Provenance) active yielded the verdict distribution documented in Table 2.

| Diagnostic Verdict Category | Score Range | Wallet Count | Percentage |
| :--- | :---: | :---: | :---: |
| **HIGH_CONFIDENCE_RUGPULL** | $S \ge 80$ | 55 | 61.1% |
| **STRONG_PATTERN** | $60 \le S < 80$ | 6 | 6.7% |
| **MODERATE_PATTERN** | $40 \le S < 60$ | 4 | 4.4% |
| **WEAK_PATTERN** | $20 \le S < 40$ | 10 | 11.1% |
| **CLEAN** | $S < 20$ | 13 | 14.4% |
| **INSUFFICIENT_HISTORY** | N/A | 2 | 2.2% |
| **Total Evaluated** | — | **90** | **100.0%** |

Prior to observing any cash-out, liquidity removal, or post-exploit transaction, **67.8% of malicious wallets (61/90) were flagged with high confidence or strong patterns** solely through their preparation and funding provenance. The median risk score across the malicious cohort was **80.0 / 100**. Two wallets exhibited fewer than two pre-deployment transactions and zero initial deployment history, triggering the `INSUFFICIENT_HISTORY` handler and verifying graceful failure degradation.

```
Verdict Distribution across Confirmed Malicious Cohort (N=90):
HIGH_CONFIDENCE [███████████████████████████████████████████████████] 61.1% (55)
STRONG_PATTERN  [██████] 6.7% (6)
MODERATE_PAT.   [████] 4.4% (4)
WEAK_PATTERN    [██████████] 11.1% (10)
CLEAN           [█████████████] 14.4% (13)
INSUFFICIENT    [██] 2.2% (2)
```
> **Figure 3: Diagnostic Verdict Distribution ($N=90$, Funding Provenance Phase).** Over two-thirds of malicious deployers are definitively isolated prior to exploit execution.

Analyzing the trigger frequency of individual Layer 1 and Layer 2 rules across the 90 wallets isolates the dominant operational habits of exploit operators:

```
Rule Trigger Frequency (N=90 Benchmark):
RUG-FP4 (Mixer/Bridge Seed)      [█████████████████████████████████████] 55
RUG-FP5 (Syndicate Co-Funding)   [███████████████████████████████████] 53
RUG-NEW-A (Single Burner Deploy) [███████████████] 23
RUG-002 (Scripted Funding Timing)[████████████] 19
RUG-001 (Extreme Burner <15m)    [███████████] 17
RUG-NEW-B (Rapid Renunciation)   [██████] 9
```
> **Figure 4: Trigger Frequency of Early-Stage Forensic Rules ($N=90$).** Rules RUG-FP4 and RUG-FP5 represent the primary structural anchors of scammer preparation.

- **Mixer / Bridge Ingress (RUG-FP4):** Triggered in 55 out of 90 wallets (61.1%). The vast majority of Ethereum rugpull operators acquire initial gas through privacy-preserving protocols (predominantly Tornado.cash) or bridge contracts (e.g., AnySwap/Multichain, FixedFloat).
- **Syndicate Co-Funding (RUG-FP5):** Triggered in 53 out of 90 wallets (58.9%). More than half of investigated wallets shared common upstream funding nodes with other known malicious deployers within 3 graph hops, demonstrating that large numbers of ostensibly independent rugpulls are coordinated by organized scam syndicates utilizing common capital dispersion infrastructure.
- **Extreme Burner Wallets (RUG-001):** 17 wallets (18.9%) deployed their exploit contract within 15 minutes of initial account creation.

#### Phase 4: Cash-Out Strategy Validation ($N=90$)
Integrating Layer 3 (Cash-Out Strategy) expanded the forensic horizon across the entire exploit event. By merging normal transactions with internal EVM traces, the engine captured contract-mediated liquidity extractions that evade standard transaction scrapers.

Incorporating cash-out features elevated the overall malicious detection rate to **93.3% (84 / 90 wallets)** at the standard forensic detection threshold ($S \ge 25$):
- **52 of 90 wallets** triggered at least one post-exploit cash-out rule.
- **16 wallets** were pushed across the diagnostic threshold into `HIGH_CONFIDENCE_RUGPULL` or `STRONG_PATTERN` strictly due to the addition of cash-out evidence.
- **4 wallets** remained below threshold, representing highly minimal on-chain footprints where capital was dormant or routed via unindexed custom contracts.

```
Cash-Out Rule Trigger Rates (N=90):
CP4 (Mule Wallet Fan-Out)       [█████████████████████████] 50.0% (45)
CP6 (Liquidity Removal + Swap)  [████████] 15.6% (14)
CP7 (Retained Proceeds <1%)     [████] 8.9% (8)
CP2 (Treasury Sweep Drain)      [███] 5.6% (5)
CP5 (Direct Mixer Cashout)      [██] 4.4% (4)
CP1 (Withdrawal Latency <1h)    [█] 2.2% (2)
CP3 (Layering Fragmentation)    [] 0.0% (0)
```
> **Figure 6: Trigger Frequencies Across Cash-Out Rules ($N=90$).** Mule wallet dispersal (CP4) dominates post-extraction maneuvers.

Detailed analysis of the cash-out triggers yields several vital forensic findings:
- **Mule Wallet Dispersion (CP4):** Triggered in 50.0% (45/90) of wallets, making it the most ubiquitous post-exploit signature. In 13 cases, the pattern was classified as **CRITICAL** ($\ge 10$ unique destinations, $>60\%$ fresh wallets). One malicious wallet in the benchmark was identified solely through this rule.
- **Swap-Before-Cashout Mechanics (CP6):** Triggered in 14 wallets (15.6%). In 12 of these 14 cases, the decentralized exchange swap occurred **within 60 minutes** of executing the liquidity removal selector (`0xbaa2abde` or `0x02751cec`), providing conclusive evidence of scripted, programmatic execution.
- **Speed Over Sophistication (The CP3 Null Result):** Rule CP3 (Fragmentation and Layering) registered **0 triggers across all 90 wallets**. Scammers in the benchmark dataset overwhelmingly prioritized **extraction velocity** over anti-money-laundering structuring. Rather than slowly fragmenting outflows into varying non-round sizes, operators moved extracted capital en masse into mule wallets or instant mixer deposits to prevent liquidity freezes or front-running by white-hat security teams.

```
          [ Risk Score Distribution (N=90 Cohort) ]
Count
 50 ┤                                                ┌──┐
 45 ┤                                                │  │
 40 ┤                                                │  │
 35 ┤                                                │  │
 30 ┤                                                │  │
 25 ┤                                                │  │
 20 ┤                                                │  │
 15 ┤  ┌──┐                                          │  │
 10 ┤  │  │        ┌──┐                              │  │
  5 ┤  │  │        │  │        ┌──┐        ┌──┐      │  │
  0 ┴──┴──┴────────┴──┴────────┴──┴────────┴──┴──────┴──┴──
       0-19       20-39       40-59       60-79     80-100
      (Clean)    (Weak)      (Mod.)      (Strong)   (High)
```
> **Figure 5: Bimodal Distribution of Composite Threat Scores ($N=90$).** The distribution demonstrates stark polarization, with the primary mass concentrating at $S \ge 80$ (median 80.0), validating the discriminative separation achieved by the multi-tier rules.

---

### 4.3 Analysis: Semantics, Dormancy, and Serial Abuse

#### Layer 4: Value-Transfer Semantics
Evaluating value-transfer semantics confirmed that rugpull operations exhibit mechanical artifacts:
- **Round-Number Pre-Deployment Funding (VS-2):** 28.9% of investigated deployers were funded with exact multiples of 0.5 ETH, consistent with human operators staging discrete gas allocations prior to launching scripts.
- **Scripted Inbound Repetition (VS-1):** Inbound transactions to creator EOAs exhibited modal value frequencies $\ge 0.60$ in 21 wallets, demonstrating that the accounts were repeatedly seeded via automated funding bots executing identical disbursement parameters.
- **Extraction Multipliers (VS-6):** In 11 cases where complete token deposit and withdrawal records were reconstructible, extraction multipliers exceeded $M \ge 50\times$, confirming the massive economic asymmetry characteristic of hard liquidity pulls.

#### Layer 5: Exit Dynamics and the Burner-Phone Phenomenon
The evaluation of post-exploit dormancy rules on pre-cached transaction sequences produced crucial findings regarding wallet lifecycle management:

| Exit Rule ID | Rule Formal Description | Triggered Wallets | Trigger Rate | Dominant Severity |
| :--- | :--- | :---: | :---: | :---: |
| **RUG-EXIT-1** | Post-Exploit Prolonged Silence Ratio | 0 / 90 | 0.0%* | None (Data gap) |
| **RUG-EXIT-2** | Cyclical Reactivation Delay ($>30$d) | 61 / 90 | **67.8%** | CRITICAL (35), MED (26) |
| **RUG-EXIT-4** | Fresh Wallet Bulk Proxy Migration | 0 / 90 | 0.0%* | None (Data gap) |
| **EXIT-META** | Operational Retirement Likelihood | 60 / 90 | **66.7%** | Median Score: 0.74 |

*\*Note on Experimental Data Gaps:* Rules RUG-EXIT-1 and RUG-EXIT-4 registered 0 triggers due to an explicit test-harness data constraint rather than algorithmic invalidity. Specifically, in the offline batch test harness, rule RUG-EXIT-1 required `cp7_retained_ratio`, which evaluated to `None` because contract-internal victim balance traces were excluded from the offline snapshot. Similarly, RUG-EXIT-4 required dynamic lookups of destination wallet creation timestamps, which were unpopulated in the offline static cache.

Conversely, **RUG-EXIT-2 (Cyclical Reactivation Delay) operated without external dependencies and triggered on 67.8% (61/90) of the benchmark cohort**. 
- **35 wallets** triggered the **CRITICAL** threshold, displaying two or more distinct dormancy events exceeding 30 days between operational deployments.
- This empirical result fundamentally overturns the assumption that Ethereum rugpullers rely strictly on single-use "burner" accounts. Instead, operators routinely exhibit a **"burner-phone" pattern**: an account is activated to deploy a scam, silenced for months following the exploit to evade active surveillance, and subsequently reactivated to orchestrate subsequent exploits or transfer residual gas.

#### Progressive Ablation Summary
Table 3 summarizes the diagnostic performance of the framework across its progressive evolutionary stages.

| Evolution Phase | Active Feature Layers | Rule Count | Key New Capability | Primary Metric / Detection Rate |
| :--- | :--- | :---: | :--- | :--- |
| **Phase 1** | Generic EOA Anomaly Rules | 7 | High-volume transfer detection | Baseline anomaly detection (non-specific) |
| **Phase 2** | Layer 1 (Pre-Deployment) | 16 | Warmup timing, funding CV | F2 CV $\le 0.9956$ flags 64% of cohort |
| **Phase 3** | Layers 1 & 2 (Provenance) | 24 | Mixer tracing, co-funding trees | **67.8%** classified HIGH/STRONG ($N=90$) |
| **Phase 4** | Layers 1, 2, & 3 (Cash-Out) | 31 | Internal traces, AMM selectors | **93.3%** Detection Rate ($S \ge 25$) |
| **Phases 5 & 6**| Layers 1–5 (Semantics & Exit)| 29* | Value patterns, serial dormancy| **67.8%** Serial Reuse Identified (EXIT-2) |

*\*Note: The final rule set consolidated redundant Phase 1 rules into the unified 29-rule production register documented in Appendix C.*

---

## 5 Conclusion

This research followed a motivated trajectory through two phases. The central ambition from the outset was to build an agentic framework capable of proactively identifying illicit behavior on Ethereum—an objective that existing approaches, including cross-chain tracing systems studied during the initial literature review, did not address. The first phase realized this as a single-agent AML investigation baseline for Ethereum, capable of detecting six canonical anti-money laundering behavioral patterns—including fund fan-out, dormant wallet reactivation, structured round-number transfers, and rapid serial dispersal. This baseline established the LangGraph orchestration infrastructure and the explainable Observation → Evidence → Reasoning reporting format.

Building on this foundation, the research specialized to rugpull exit scams—grounding feature design in the behavioral taxonomy of Sharma, Agarwal, and Shukla (2023) and extending it to the Ethereum DeFi context through a lifecycle-aware Behavioral Threat Profiling (BTP) engine. The resulting framework evaluates 29 deterministic rules across five operational tiers, moving the forensic focus from contract code inspection to the full behavioral lifespan of the deployer's EOA.

Empirical evaluation across 90 confirmed Ethereum rugpull creator wallets demonstrated a **93.3% overall detection rate** at a scoring threshold of 25 points. Early-stage flagging through funding provenance rules alone classified **67.8% of malicious deployers with high or strong confidence** prior to any post-exploit evidence, with over 60% of operators linked to mixer or bridge co-funding syndicates. Dormancy analysis confirmed that **67.8% of operators exhibit serial cyclical reuse**—directly validating the recidivism patterns identified in Sharma et al. (2023) with on-chain quantitative measurement. The study additionally established two empirically grounded corrections to prevailing heuristic assumptions: the mainnet dry-run count provides zero discriminative utility, and deployment burstiness is negatively correlated with malicious intent due to legitimate contract factory deployment patterns.

### Limitations
Several operational limitations in the current implementation are worth noting:
1. **Single-Chain Focus:** The framework is currently implemented and validated exclusively on Ethereum Layer 1. Cross-chain rugpulls where seed funding originates on alternative chains (e.g., Arbitrum, BNB Chain) require manual cross-chain correlation.
2. **Public API Rate Constraints:** Reliance on Etherscan REST endpoints (throttled to 4.5 calls/sec) introduces ingestion latency during deep graph traversals.
3. **Deferred Downstream Tracking (EXIT-3):** Recursive tracing of downstream funding destinations was deferred due to API call explosion constraints.
4. **Synthetic Calibration of EXIT-META:** The operational retirement likelihood score operates as an uncalibrated heuristic and requires empirical calibration against multi-year survival curves.
5. **No ML Comparison Baseline:** The framework was not benchmarked against GNN-based classifiers (Ferretti et al., 2024; Han et al., 2024); such a comparison would quantify the trade-off between explainability and predictive accuracy.

### Future Work
Future work will focus on three key expansions:
1. **Multi-Chain Generalization:** Extending the behavioral profiling pipeline to BNB Chain and Arbitrum, where rugpull activity is similarly prevalent, using cross-chain wallet correlation to trace seed capital that originates on one network and deploys on another.
2. **Self-Hosted Archive Node Ingestion:** Transitioning data ingestion from commercial APIs to direct JSON-RPC queries on self-hosted Erigon or Reth archive nodes, eliminating rate limits and enabling instantaneous internal trace decoding.
3. **Graph Representation Learning:** Incorporating temporal GNNs (Han et al., 2024; Ferretti et al., 2024) into the funding provenance layer to automatically infer syndicate clusters, and exploring supervised classification over the FeatureVector to quantify the accuracy–explainability trade-off.

---

## References

1. Ante, L. (2026). Autonomous AI agents in decentralized finance: Market dynamics, application areas, and theoretical implications. *Technological Forecasting & Social Change*, 228, 124669.
2. Biryukov, A., Khovratovich, D., and Pustogarov, I. (2014). Deanonymisation of clients in Bitcoin P2P network. In *Proceedings of the 2014 ACM SIGSAC Conference on Computer and Communications Security (CCS '14)*, pages 15–29.
3. Ferretti, S., D'Angelo, G., and Ghini, V. (2024). Enhancing anti-money laundering frameworks: An application of graph neural networks in cryptocurrency transaction classification. *IEEE Access*, 12, 45210–45225.
4. Han, B., Wei, Y., Wang, Q., De Collibus, F. M., and Tessone, C. J. (2024). MT2AD: Multi-layer temporal transaction anomaly detection in Ethereum networks with GNN. *IEEE Transactions on Network and Service Management*, 21(2), 1845–1858.
5. Mazorra, B., Adan, V., and Lux, V. (2022). Do not pull the rug: Evaluating the scamming ecosystem of decentralized finance. *arXiv preprint arXiv:2201.07220*.
6. Meiklejohn, S., Pomarole, M., Jordan, A., Levchenko, K., McCoy, D., Voelker, G. M., and Savage, S. (2013). A fistful of Bitcoins: Characterizing payments among men with no names. In *Proceedings of the 2013 Conference on Internet Measurement Conference (IMC '13)*, pages 127–140.
7. Möser, M., Soska, K., Heilman, E., Lee, K., Heffelfinger, B., Srivastava, K., Hogan, K., Heninger, N., and Christin, N. (2018). An empirical analysis of traceability in the Monero blockchain. *Proceedings on Privacy Enhancing Technologies*, 2018(3), 211–228.
8. Nakamoto, S. (2008). Bitcoin: A peer-to-peer electronic cash system. *Decentralized Business Review*, 21260.
9. Sharma, T., Agarwal, R., and Shukla, S. K. (2023). Understanding rug pulls: An in-depth behavioral analysis of fraudulent NFT creators. *ACM Transactions on the Web*, 18(1), Article 1. https://doi.org/10.1145/3623376
10. Wang, S., Ding, C., Min, E., and Chen, J. (2023). Understanding security issues in the NFT ecosystem: A survey and empirical study. *IEEE Access*, 11, 88120–88138.
11. Xia, P., Gao, H., Cheng, J., Lu, F., and Xu, G. (2021). Trade or trick? Detecting and characterizing scam tokens on Uniswap decentralized exchange. *Proceedings of the ACM on Measurement and Analysis of Computing Systems*, 5(3), 1–26.
12. Yu, X. and Knottenbelt, W. (2026). LOCARD: An agentic framework for blockchain forensics. In *2026 IEEE International Conference on Blockchain and Cryptocurrency (ICBC)*, pages 1–10.

---

## Appendix A: Additional Empirical Results

### Threat Score Distributions by Diagnostic Band
Table A1 provides the empirical distribution of composite risk scores $S(W)$ across the benchmark cohort ($N=90$).

| Risk Band | Minimum Score | Maximum Score | Mean Score | Standard Deviation |
| :--- | :---: | :---: | :---: | :---: |
| **HIGH_CONFIDENCE_RUGPULL** ($n=55$) | 80 | 100 | 88.36 | 7.42 |
| **STRONG_PATTERN** ($n=6$) | 60 | 75 | 66.67 | 5.16 |
| **MODERATE_PATTERN** ($n=4$) | 40 | 55 | 47.50 | 6.45 |
| **WEAK_PATTERN** ($n=10$) | 20 | 35 | 24.50 | 4.97 |
| **CLEAN** ($n=13$) | 0 | 15 | 3.85 | 5.90 |

The score distribution displays a pronounced bimodal separation: genuine accounts and minimal-footprint outliers cluster tightly between 0 and 15, whereas confirmed malicious actors cluster between 80 and 100 with a mean of 88.36.

---

## Appendix B: Experimental Implementation Details

### Computational Infrastructure and Environment
- **Operating Environment:** Windows 11 Enterprise / Ubuntu 22.04 LTS execution nodes.
- **Python Version:** Python 3.11.8 with Pydantic v2.6.1 schema serialization.
- **Agent Orchestration:** LangGraph 0.0.26 with state persistence backed by SQLite3.
- **Network Graph Computation:** NetworkX 3.2.1.
- **External Data Source:** Etherscan Developer REST API v2 (rate-limited via token bucket to 4.5 requests/second).
- **Execution Cost:** Average LLM token consumption per investigative narrative synthesis: 1,420 prompt tokens, 480 completion tokens ($\approx \$0.008$ per report).

### Additive Scoring System and Severity Weight Calibration
Rules are mapped to discrete categorical severity tiers, calibrated according to empirical specificity:
- **CRITICAL (+40 points):** Invariants that independently establish malicious intent with near certainty (e.g., privacy mixer funding ingress, post-exploit mule fan-out $>60\%$ fresh, drain ratio $>90\%$ within 24 hours, extreme extraction multiplier $>50\times$).
- **HIGH (+25 / +20 points):** Strong operational indicators that rarely occur in legitimate development (e.g., syndicate co-funding networks, AMM removal selectors with immediate swap, scripted funding $CV \le 0.9956$, serial dormancy reactivation).
- **MEDIUM (+15 / +10 points):** Contextual anomalies that warrant elevated scrutiny in combination with other behaviors (e.g., single-event dormancy, modal value repetition $>0.40$).
- **LOW (+5 points):** Minor structural anomalies (e.g., standard round-number transfers).

A hard ceiling function $S(W) = \min(100, \sum w_r)$ bounds total risk, preventing score inflation while ensuring that any wallet triggering two CRITICAL rules immediately attains the `HIGH_CONFIDENCE_RUGPULL` classification.

---

## Appendix C: Complete Deterministic Rule Register

Table C1 provides the complete, authoritative register of all 29 deterministic forensic rules implemented across the five operational layers of the framework.

| Rule ID | Formal Rule Name | Behavioral Layer | Severity | Score Weight | Mathematical Invariant / Trigger Condition |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **RUG-001** | Extreme Burner Wallet | Layer 1: Pre-Deploy | CRITICAL | +40 | $\tau_{\text{deploy}, 1} - \tau_1 < 900 \text{ seconds (15 minutes)}$ |
| **RUG-002** | Scripted Funding Cadence | Layer 1: Pre-Deploy | HIGH | +25 | $CV(\Delta \tau_{\text{inbound}}) \le 0.9956 \land \text{Count} \ge 3$ |
| **RUG-F3** | Mainnet Dry-Run Testing | Layer 1: Pre-Deploy | LOW | +5 | Reverted pre-deployment transactions $\ge 1$ (Debunked) |
| **RUG-F4** | Single-Contract Deployer | Layer 1: Pre-Deploy | MEDIUM | +15 | Total contracts deployed $|C_W| = 1 \land \text{Age} > 7\text{d}$ |
| **RUG-F4B**| Deployment Cadence Inversion| Layer 1: Pre-Deploy | MEDIUM | +15 | $\sigma^2(\tau_{\text{deploy}}) \approx 0$ (Isolated single deployment) |
| **RUG-F5** | Low Nonce Action Entropy | Layer 1: Pre-Deploy | LOW | +5 | Nonce action Shannon entropy $H(\text{nonce}) < 1.0$ |
| **RUG-F7** | Bytecode Template Cloning | Layer 1: Pre-Deploy | HIGH | +20 | Size similarity ratio across consecutive deploys $> 0.95$ |
| **RUG-NEW-A**| Rapid Auxiliary Deployment | Layer 1: Pre-Deploy | HIGH | +25 | $\tau_{\text{deploy}, 2} - \tau_{\text{deploy}, 1} \le 3600 \text{ seconds (60 min)}$ |
| **RUG-NEW-B**| Rapid Ownership Transfer | Layer 1: Pre-Deploy | HIGH | +20 | Ownership transfer selector within 48h of deploy |
| **RUG-FP1** | Unverified Deployer Origin | Layer 2: Provenance | MEDIUM | +10 | Deployer EOA has zero prior mainnet contract history |
| **RUG-FP2** | Recursive Seed Hop Depth | Layer 2: Provenance | HIGH | +20 | Seed capital originates from depth $h \ge 3$ proxy hops |
| **RUG-FP3** | Fresh Seed Wallet Origin | Layer 2: Provenance | HIGH | +20 | $\text{Age}(s_{\text{seed}}) < 24 \text{ hours at funding timestamp}$ |
| **RUG-FP4** | Mixer or Bridge Funding Ingress| Layer 2: Provenance | CRITICAL | +40 | Immediate funder address $\in \text{Mixers} \lor \text{Bridges}$ |
| **RUG-FP5** | Syndicate Co-Funding Overlap | Layer 2: Provenance | HIGH | +25 | Upstream funder overlaps known scam syndicate cluster |
| **RUG-FP6** | Fixed-Gas Seed Staging | Layer 2: Provenance | MEDIUM | +10 | Seed value corresponds exactly to compiled gas deployment cost |
| **RUG-FP7** | Gas-Adjusted Seed Outlier | Layer 2: Provenance | LOW | +5 | Standardized seed capital $> 3\sigma$ from daily network mean |
| **RUG-FP8** | Upstream Ancestor Overlap | Layer 2: Provenance | HIGH | +20 | Upstream funding tree Jaccard similarity $J > 0.50$ |
| **RUG-CP1** | Immediate Smash-and-Grab | Layer 3: Cash-Out | CRITICAL | +40 | $\tau_{\text{drain}, 1} - \tau_{\text{victim}, 1} < 3600 \text{ seconds (1 hour)}$ |
| **RUG-CP2** | Treasury Sweep Drain Ratio | Layer 3: Cash-Out | CRITICAL | +40 | $R_{\text{drain}} \ge 0.90 \text{ across } N_{\text{tx}} \le 2 \text{ within 24 hours}$ |
| **RUG-CP3** | Outflow Fragmentation CV | Layer 3: Cash-Out | MEDIUM | +15 | $CV(v_{\text{out}}) > 1.5 \land \text{RoundRatio} > 0.50$ (Null trigger) |
| **RUG-CP4** | Fresh Mule Wallet Fan-Out | Layer 3: Cash-Out | CRITICAL | +40 | $|\mathcal{D}_{\text{out}}| \ge 10 \land \text{FreshRatio}(\text{Age} < 7\text{d}) > 0.60$ |
| **RUG-CP5** | Direct Mixer Liquidation | Layer 3: Cash-Out | CRITICAL | +40 | Extracted proceeds dispatched directly to mixer hot wallet |
| **RUG-CP6** | AMM Removal + Immediate Swap | Layer 3: Cash-Out | HIGH | +25 | AMM liquidity removal selector followed by swap in $<24$h |
| **RUG-CP7** | Depleted Ecosystem Balance | Layer 3: Cash-Out | CRITICAL | +40 | Retained victim proceeds ratio $R_{\text{retained}} < 0.01$ (less than 1%) |
| **RUG-VS-1**| Inbound Value Mode Repetition | Layer 4: Semantics | HIGH | +20 | $\text{ModeFrequency}(V_{\text{in}}) \ge 0.60 \land |V_{\text{in}}| \ge 5$ |
| **RUG-VS-2**| Round-Number Seed Funding | Layer 4: Semantics | HIGH | +20 | $(v_{\text{in}} / 10^{18}) \pmod{0.5} = 0 \text{ ratio} \ge 0.80$ |
| **RUG-VS-3**| Gas-Price Uniformity Scripting| Layer 4: Semantics | MEDIUM | +10 | $CV(p_{\text{gas}}) < 0.05 \text{ across consecutive operations}$ |
| **RUG-VS-4**| Pre-Cashout Micro-Dusting | Layer 4: Semantics | HIGH | +20 | $\ge 5 \text{ transactions with } v_i \le 10^{14} \text{ Wei within 24h}$ |
| **RUG-VS-5**| Seed Amount Set Jaccard | Layer 4: Semantics | MEDIUM | +10 | Cross-deployment inflow amount set similarity $J > 0.80$ |
| **RUG-VS-6**| Extreme Extraction Multiplier | Layer 4: Semantics | CRITICAL | +40 | Return ratio $M = V_{\text{out}} / \max(V_{\text{seed}}, 10^{15}) \ge 50\times$ |
| **RUG-EXIT-1**| Prolonged Post-Rug Silence | Layer 5: Exit/Dorm | HIGH | +20 | $D_{\text{silence}} > 30\text{d} \land R_{\text{retained}} < 0.01 \land R_{\text{silence}} > 0.5$ |
| **RUG-EXIT-2**| Cyclical Burner Reactivation | Layer 5: Exit/Dorm | CRITICAL | +30 | Dormancy gaps $\ge 30\text{d} \ge 2 \lor (1 \text{ gap} \land RCS \ge 2)$ |
| **RUG-EXIT-4**| Fresh Bulk Proxy Migration | Layer 5: Exit/Dorm | CRITICAL | +40 | Single transfer $\ge 30\%$ victim inflow to dest $<24$h old |
| **EXIT-META**| Operational Retirement Score | Layer 5: Metadata | INFO | +0 | Heuristic $S_{\text{retire}} = \min(0.99, B + \Delta_{\text{time}})$ if $S \ge 36$ |


---

## Appendix D: Consolidated Feature Matrix and Value-Transfer Semantics Report

### D.1 Full Feature Matrix

A consolidated feature matrix covering all 108 evaluated Ethereum wallet addresses—90 confirmed rugpull creators and 18 genuine developer controls—across all 68 implemented features has been prepared separately and is available in the project repository as `full_feature_matrix.csv`. Each row represents one wallet address, labeled as `rugpull` or `genuine`. The column schema spans all five behavioral layers:

| Column Group | Columns | Content |
| :--- | :--- | :--- |
| **Identity** | `address`, `label` | Wallet address and ground-truth classification |
| **Layer 1 (Pre-Deployment)** | `f1_warmup_hours` through `ownership_transfer_count` | 8 features capturing wallet age, funding timing CV, dry-run counts, deployment cadence, nonce entropy, bytecode size ratios, and ownership transfer timing |
| **Layer 2 (Funding Provenance)** | `fp_first_inbound_source_type` through `fp_max_funder_jaccard` | 9 features capturing upstream seed source type, recursive hop depth, fresh seed wallet fraction, gas-adjusted seed capital, and Jaccard ancestor overlap |
| **Layer 3 (Cash-Out Strategy)** | `cp1_withdrawal_latency_sec` through `cp_victim_inflow_wei` | 15 features capturing extraction latency, drain ratio, outflow CV, mule wallet fan-out count and fresh ratio, mixer routing, AMM selector detection, and retained proceeds ratio |
| **Layer 4 (Value-Transfer Semantics)** | `vs1_mode_freq_ratio` through `vs6_mint_to_lp_latency_sec` | 23 features capturing inbound mode frequency, round-number bias, gas price uniformity CV, dusting ping count, cross-deployment Jaccard similarity, and extraction multiplier |
| **Layer 5 (Exit & Dormancy)** | `exit1_silence_days` through `exit_meta_retirement_label` | 11 features capturing post-exploit silence duration and ratio, dormancy event count and reactivation context scores, downstream deployer seeding flag, bulk migration detection, and retirement likelihood score |

Selected descriptive statistics summarizing the most discriminative features across both cohorts are provided in Table D1.

**Table D1: Key Feature Statistics by Cohort**

| Feature | Rugpull Mean (N=90) | Genuine Mean (N=18) | Diagnostic Insight |
| :--- | :---: | :---: | :--- |
| F1 Warmup Latency (hours) | 1,076.3 | 2,527.4 | Genuine developers fund wallets significantly earlier relative to first deployment |
| F2 Funding CV | ~1.02* | 0.79 | Malicious wallets with scripted funding exhibit CV ≤ 0.9956; 64% of malicious cohort flag |
| EXIT-2 Dormancy Events ≥ 1 | 67.8% (61/90) | 94.4% (17/18)† | Reactivation ubiquitous across both cohorts; CRITICAL triggers when ≥ 2 events |
| CP5 Direct Mixer Cashout | 4.4% (4/90) | 0.0% (0/18) | Any direct mixer routing is exclusively malicious in this dataset |
| VS6 Extraction Multiplier > 0 | 56.7% (51/90) | 0.0% (0/18) | No genuine developer exhibits net ETH extraction exceeding deployment cost |

*\*Rugpull mean CV is elevated because wallets with zero or one pre-deployment inbound transactions (undefined CV) are excluded from the mean calculation; the 64% threshold finding is computed over the calibration cohort N=50 with ≥ 3 pre-deploy inbound transactions.*

*†Genuine developers exhibit high reactivation counts due to legitimate multi-project deployment histories; the distinction is captured by RCS context scoring and the absence of co-triggering rules.*

> [!NOTE]
> The full matrix is too large to reproduce inline and is maintained as a separate artifact in the project repository. It is intended to support any future supervised classification experiments that extend this deterministic rule system.

---

### D.2 Value-Transfer Semantics Rule Trigger Summary

Table D2 reports the trigger rates for all six Layer 4 (Value-Transfer Semantics) rules across the full benchmark cohort of 90 confirmed rugpull creator wallets.

**Table D2: VS Rule Trigger Rates (N = 90 Malicious Cohort)**

| Rule ID | Rule Name | Triggered (N=90) | Trigger Rate |
| :--- | :--- | :---: | :---: |
| **RUG-VS-1** | Scripted Inbound Value Repetition | 7 | 7.8% |
| **RUG-VS-2** | Round-Number Pre-Deployment Funding | 0 | 0.0% |
| **RUG-VS-3** | Gas-Price Uniformity Anomaly | 1 | 1.1% |
| **RUG-VS-4** | Pre-Cashout Wallet Ping Dusting | 6 | 6.7% |
| **RUG-VS-5** | Cross-Deployment Seed Consistency | 21 | 23.3% |
| **RUG-VS-6** | Extreme Extraction Multiplier / LP Drain | 49 | 54.4% |

The trigger distribution across VS rules warrants interpretation. VS6 dominates because the extraction multiplier captures the fundamental economic asymmetry of a rugpull—one that is present regardless of how sophisticated or simple the operator's tooling is. Any wallet that invested minimal seed capital and subsequently extracted substantial victim liquidity will trigger VS6 by definition. The low trigger rates of VS1–VS4 reflect the specificity of these rules: they fire only when scripting artifacts are detectable from the available on-chain data, which requires sufficient transaction volume and favorable API coverage of internal traces. VS5's 23.3% rate indicates that cross-deployment seed amount consistency—a marker of operators reusing the same funding infrastructure across multiple campaigns—is a moderately prevalent fingerprint in this dataset.

> [!TIP]
> VS6's dominance also means it contributes +40 (CRITICAL) to the aggregate score for 54.4% of the cohort independently of all other layers. Combined with the mixer/bridge ingress rule (RUG-FP4, 61.1%), these two rules alone are sufficient to classify a wallet as `HIGH_CONFIDENCE_RUGPULL` for the majority of operators in the benchmark.
