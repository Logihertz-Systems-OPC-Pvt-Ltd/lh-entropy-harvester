# Logihertz Cryptographic Hardware Entropy Daemon (`lh-entropy-harvester`)

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-entropy-harvester/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-entropy-harvester/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Standard](https://img.shields.io/badge/C-C11-00599C.svg)](https://en.cppreference.com/w/c/11)
[![NIST](https://img.shields.io/badge/NIST-SP_800--90B_Compliant-success.svg)](https://csrc.nist.gov/pubs/sp/800/90b/final)
[![Security Posture](https://img.shields.io/badge/TRNG_Posture-100%2F100_PASS-success.svg)](#10-rule-hardware-trng-security-posture-auditor)

**`lh-entropy-harvester`** is a production-grade, zero-dependency **C11 Cryptographic Hardware Entropy Daemon, SRAM & ADC Thermal Jitter Harvester, NIST SP 800-90B Continuous Health Tester (RCT/APT), SHA-256 Cryptographic Conditioner, and 10-Rule TRNG Security Posture Auditor**.

Engineered for Hardware Security Modules (HSM), embedded security enclaves, autonomous robotics, IoT edge devices, and air-gapped cryptographic mission computers where high-assurance hardware root-of-trust random number generation is mandatory.

---

## Architecture Overview

```
 [ Physical Noise Sources ]
    * Uninitialized SRAM PUF Bits
    * ADC Analog Thermal LSB Jitter
    * Ring Oscillator Phase Jitter
              |
              v
 [ Stage 1: Noise Ingestion & Pre-Filtering ]
    * ADC Rail Saturation Guard (clips 0x00 / 0xFF)
    * Lag-1 Serial Autocorrelation (|r1| <= 0.15)
              |
              v
 [ Stage 2: NIST SP 800-90B Continuous Health Tests ]
    * Repetition Count Test (RCT Sec 4.4.1): C_RCT = 1 + ceil(30 / H_min)
    * Adaptive Proportion Test (APT Sec 4.4.2): Window W = 512 samples
    * IMMEDIATE HALT on stuck-at or statistical bias faults
              |
              v
 [ Stage 3: Statistical Min-Entropy Estimation ]
    * Most Common Value (MCV) Min-Entropy H_inf (Sec 6.3.1, 99% CI)
    * Shannon Entropy H_1 Calculation
              |
              v
 [ Stage 4: Cryptographic Conditioning Pipeline ]
    * Von Neumann Bit-Pair Debiaser (01->0, 10->1, 00/11->drop)
    * NIST SP 800-90B Vetted FIPS 180-4 SHA-256 / HMAC-SHA256 (>= 2.0x Compression)
    * Mixed with CLOCK_MONOTONIC_RAW nanosecond hardware timestamps
              |
              v
 [ Stage 5: Linux Kernel Injection & Defense-in-Depth ]
    * RNDADDENTROPY ioctl (0x40085203) with conservative credit derating
    * RAM Locking (mlockall) & Volatile Buffer Zeroization (lh_secure_zero)
    * Process Sandboxing: Drop root to CAP_SYS_ADMIN + Seccomp BPF filter
```

---

## Key Features

1. **NIST SP 800-90B Continuous Health Testing (Section 4.4)**:
   - **Repetition Count Test (RCT)**: Halts noise harvesting within deterministic sample limits upon detecting repeating symbols (frozen ADC converters or grounded zener diodes).
   - **Adaptive Proportion Test (APT)**: Monitors sample frequency within a sliding window of $W = 512$ bytes against normal-binomial quantile limits to detect subtle statistical bias or injection attacks.
2. **NIST SP 800-90B Section 6.3.1 Most Common Value (MCV) Min-Entropy Estimator**:
   - Calculates the 99% confidence upper bound ($Z_{0.995} = 2.5758293$) on the most probable symbol $p_{\max}$ to derive rigorous per-byte min-entropy ($H_\infty$) and per-bit min-entropy ($h_{\text{bit}}$).
3. **Harmonic Coupling & Power Ripple Detector**:
   - Evaluates lag-1 Pearson serial autocorrelation coefficient ($r_1 \in [-1, +1]$) across successive raw noise samples. Automatically flags electromagnetic interference, switch-mode power supply ripple, or external clock harmonic injection when $|r_1| > 0.15$.
4. **Two-Stage Cryptographic Conditioning Pipeline**:
   - **Stage 1 (Von Neumann Debiaser)**: Extracts unbiased bits from independent Bernoulli noise pairs: $\text{VN}(0, 1) \to 0$, $\text{VN}(1, 0) \to 1$, discarding identical bit pairs.
   - **Stage 2 (NIST SP 800-90B Vetted SHA-256 Conditioner)**: Compresses $\ge 64$ bytes of qualified raw entropy into a 32-byte (256-bit) cryptographically uniform output block mixed with high-resolution monotonic timestamps.
   - Built-in **FIPS 140-3 Known Answer Test (KAT)** on daemon startup.
5. **Kernel `/dev/random` Entropy Pool Injection**:
   - Constructs Linux `struct rand_pool_info` structures for the `RNDADDENTROPY` ioctl (`0x40085203`) with conservative credit derating ($E_{\text{credited}} \le 0.5 \cdot N_{\text{in}} \cdot H_\infty$).
6. **10-Rule TRNG Security Posture Auditor**:
   - Evaluates TRNG configuration manifests against 10 critical security invariants, calculating a standardized Logihertz Security Posture Score ($S_{\text{posture}} \in [0, 100]$).
   - Multi-format reporting in ANSI colored terminal tables, canonical JSON, and OASIS SARIF v2.1.0.

---

## Mathematical Formulations

### 1. Repetition Count Test (RCT — NIST SP 800-90B Section 4.4.1)

Given assessed per-sample min-entropy $H_{\min} > 0$ and false-positive probability $\alpha = 2^{-30}$ ($-\log_2 \alpha = 30.0$):

$$C_{\text{RCT}} = 1 + \left\lceil \frac{30.0}{H_{\min}} \right\rceil$$

For example, when $H_{\min} = 5.0\text{ bits/byte}$, $C_{\text{RCT}} = 1 + \lceil 6.0 \rceil = 7$. If 7 consecutive identical bytes occur, a stuck-at fault is immediately latched.

### 2. Adaptive Proportion Test (APT — NIST SP 800-90B Section 4.4.2)

For window size $W = 512$ bytes and $p = 2^{-H_{\min}}$:

$$C_{\text{APT}} = \min\left(W, \; \left\lceil W \cdot p + 5.997807 \cdot \sqrt{W \cdot p \cdot (1 - p)} \right\rceil\right)$$

If the first symbol in the window appears $\ge C_{\text{APT}}$ times within $W = 512$ samples, an adaptive bias fault is latched.

### 3. MCV Min-Entropy ($H_\infty$) & Shannon Entropy ($H_1$)

For sample count $N$ with symbol counts $c_b$ ($b \in [0, 255]$) and $p_{\max} = \max_b (c_b / N)$:

- **Shannon Entropy**:
  $$H_1 = -\sum_{b=0}^{255} \frac{c_b}{N} \log_2\left(\frac{c_b}{N}\right)$$

- **99% Confidence Upper Bound on Most Probable Symbol** ($Z_{0.995} = 2.5758293$):
  $$p_u = \min\left(1.0, \; p_{\max} + 2.5758293 \sqrt{\frac{p_{\max}(1.0 - p_{\max})}{\max(1, N - 1)}}\right)$$

- **Min-Entropy**:
  $$H_\infty = -\log_2(p_u) \quad (\text{bits per byte}), \qquad h_{\text{bit}} = \frac{H_\infty}{8.0} \quad (\text{bits per bit})$$

### 4. Lag-1 Serial Pearson Autocorrelation ($r_1$)

$$r_1 = \frac{\sum_{i=0}^{N-2} (x_i - \bar{x})(x_{i+1} - \bar{x})}{\sum_{i=0}^{N-1} (x_i - \bar{x})^2}$$

Values of $|r_1| > 0.15$ indicate periodic harmonic injection or deterministic clock ripple.

---

## 10-Rule Hardware TRNG Security Posture Auditor

| Rule ID | Severity | Ded. | CWE Mapping | Invariant & Audit Rule Description |
|---|---|---|---|---|
| **`LH-ENT-001`** | **CRITICAL** | **25** | CWE-331 | Raw Noise Min-Entropy Safety Floor ($H_{\min} \ge 4.0$) & Noise Source Redundancy ($\ge 2$) |
| **`LH-ENT-002`** | **CRITICAL** | **25** | CWE-338 | NIST SP 800-90B Vetted Cryptographic Conditioner (`SHA-256`) & Compression $\ge 2.0\times$ |
| **`LH-ENT-003`** | **CRITICAL** | **25** | CWE-693 | Continuous Health Tests Active (RCT & APT) with Immediate Feed Shutdown on Fault |
| **`LH-ENT-004`** | **HIGH** | **10** | CWE-330 | Startup Power-On Self-Test (POST) Conditioning with $\ge 1024$ Samples |
| **`LH-ENT-005`** | **HIGH** | **10** | CWE-331 | Conservative Entropy Bit Crediting ($\le 0.75$ derating) & No 1:1 Raw Bit Crediting |
| **`LH-ENT-006`** | **HIGH** | **10** | CWE-226 | Memory Locking (`mlockall`) Active & Volatile Buffer Zeroization (`lh_secure_zero`) |
| **`LH-ENT-007`** | **HIGH** | **10** | CWE-1300 | ADC Rail Saturation Guard Active & Serial Autocorrelation Bound $|r_1| \le 0.15$ |
| **`LH-ENT-008`** | **MEDIUM** | **4** | CWE-250 | Root Privilege Dropped to `CAP_SYS_ADMIN` Only with Seccomp BPF Syscall Filter |
| **`LH-ENT-009`** | **MEDIUM** | **4** | CWE-400 | Kernel Entropy Watermark $\ge 128$ Bits & Maximum Reseed Interval $\le 60\text{ s}$ |
| **`LH-ENT-010`** | **LOW** | **1** | CWE-778 | FIPS 140-3 Conditioner Startup KAT Verified & Syslog Health Fault Audit Logging |

**Scoring Equation**:
$$S_{\text{posture}} = \max\left(0, 100 - \sum \text{Deductions}\right)$$

- **Hardened TRNG System**: 0 deductions $\to 100/100$, status **PASS** (Exit: `0`).
- **Vulnerable TRNG System**: $25\times 3 + 10\times 4 + 4\times 2 + 1 = 124$ deductions $\to 0/100$, status **FAIL** (Exit: `1`).

---

## Installation & Build Instructions

### Prerequisites
- GCC 10+ or Clang 12+
- GNU Make 4.0+
- Standard POSIX libc and math library (`-lm`)

### Compiling and Testing
```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-entropy-harvester.git
cd lh-entropy-harvester

# Build userspace CLI and execute deterministic verification suite
make clean all test

# Build with Clang
make CC=clang clean all test
```

---

## CLI Usage & Examples

### 1. Security Posture Audit (`scan`)
```bash
# Audit hardened TRNG daemon policy (Table output, exit 0)
./bin/lh-entropy scan fixtures/hardened_entropy_policy.json --format table

# Export audit findings to SARIF format for CI/CD pipeline integration
./bin/lh-entropy scan fixtures/hardened_entropy_policy.json --format sarif --output audit.sarif

# Audit vulnerable legacy policy (Table output, exit 1)
./bin/lh-entropy scan fixtures/vulnerable_entropy_policy.json --format table
```

### 2. NIST SP 800-90B Noise Analysis (`analyze-noise`)
```bash
# Analyze raw SRAM / ADC thermal noise samples
./bin/lh-entropy analyze-noise fixtures/sample_sram_adc_noise.json --target-hmin 4.5 --format table

# Output statistical analysis as canonical JSON
./bin/lh-entropy analyze-noise fixtures/sample_sram_adc_noise.json --format json
```

### 3. Cryptographic Conditioning (`condition`)
```bash
# Condition raw noise samples via FIPS 180-4 SHA-256 for /dev/random injection
./bin/lh-entropy condition fixtures/sample_sram_adc_noise.json --format table

# Output conditioned seed and RNDADDENTROPY words in JSON
./bin/lh-entropy condition fixtures/sample_sram_adc_noise.json --format json
```

### 4. Health Test State Machine Verification (`health-test`)
```bash
# Verify healthy varying noise stream passes RCT and APT
./bin/lh-entropy health-test --mode pass

# Verify stuck-at fault detection on repeated symbol
./bin/lh-entropy health-test --mode stuck-fault

# Verify statistical bias fault detection
./bin/lh-entropy health-test --mode bias-fault
```

---

## Repository Structure

```
lh-entropy-harvester/
├── .github/
│   └── workflows/
│       └── ci.yml               # Multi-compiler CI matrix (GCC, Clang)
├── bin/
│   └── lh-entropy               # Userspace CLI binary
├── fixtures/
│   ├── hardened_entropy_policy.json  # Reference hardened policy (100/100 PASS)
│   ├── sample_sram_adc_noise.json    # 512-byte raw SRAM/ADC noise fixture
│   └── vulnerable_entropy_policy.json# Vulnerable legacy policy (0/100 FAIL)
├── include/
│   ├── entropy_auditor.h        # 10-rule posture evaluation engine
│   ├── entropy_types.h          # Core data structures, enums & pool_info
│   ├── exporters.h              # ANSI table, JSON, SARIF exporters
│   ├── json_parser.h            # Zero-dependency JSON parser
│   ├── sha256_conditioner.h     # Von Neumann debiaser & SHA-256 conditioner
│   └── sp800_90b_health.h       # NIST SP 800-90B RCT, APT & MCV min-entropy
├── src/
│   ├── entropy_auditor.c        # 10-rule posture evaluator implementation
│   ├── exporters.c              # Exporter formatters
│   ├── json_parser.c            # Zero-dependency JSON parser
│   ├── main.c                   # CLI command dispatcher
│   ├── sha256_conditioner.c     # SHA-256 conditioner & memory zeroization
│   └── sp800_90b_health.c       # RCT, APT & MCV min-entropy implementation
├── tests/
│   └── test_runner.c            # Comprehensive test runner (630+ assertions)
├── CHANGELOG.md                 # Semantic versioning release log
├── CODE_OF_CONDUCT.md           # Contributor Covenant Code of Conduct
├── CONTRIBUTING.md              # Contributor guidelines and workflow
├── LICENSE                      # Apache-2.0 License
├── Makefile                     # Build system
├── NOTICE                       # Copyright attribution
├── README.md                    # Project documentation
└── SECURITY.md                  # Hardware TRNG threat model & security policy
```

---

## License

Copyright 2026 Logihertz Systems (OPC) Private Limited.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Maintainer: **Sameer Tawade** (`ops@logihertz.com`)
Organization: **Logihertz Systems (OPC) Private Limited**
Website: [https://github.com/Logihertz-Systems-OPC-Pvt-Ltd](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd)
