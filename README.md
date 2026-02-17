# IPv6 Intelligent Crawler

An intelligent system for discovering IPv6 web servers using Machine Learning and Metaheuristic algorithms.

## 🎯 Project Goal

Given the enormous IPv6 address space (2^128 addresses), traditional scanning is impossible. This project uses ML and optimization algorithms to learn address allocation patterns and predict active addresses.

## 📁 Project Structure

```
ipv6-crawler/
├── config.yaml                    # Configuration
├── requirements.txt               # Dependencies
├── main.py                        # Main entry point
├── src/
│   ├── __init__.py
│   ├── seed_collector.py          # Initial address collection
│   ├── feature_extractor.py       # Feature extraction
│   ├── ml_model.py                # Machine learning model
│   ├── address_generator.py       # Address generation (classic)
│   ├── metaheuristic_generator.py # Metaheuristic algorithms
│   ├── prober.py                  # Network scanner
│   ├── fingerprinter.py           # Infrastructure identification
│   ├── feedback_loop.py           # Feedback and model improvement
│   └── database.py                # Data management
├── data/
│   ├── seeds/                     # Initial seed addresses
│   ├── models/                    # Saved models
│   └── results/                   # Results
└── logs/                          # Logs
```

## 🧬 Address Generation Algorithms

### Classic Methods
- **Prefix-based**: Generate addresses in known active prefixes
- **Mutation-based**: Mutate active addresses (increment, decrement, nearby)
- **Pattern Learning**: Learn from Interface ID patterns

### Metaheuristic Algorithms

| Algorithm | Description | Advantage |
|-----------|-------------|-----------|
| **Genetic Algorithm (GA)** | Crossover and mutation of addresses | Combinatorial search space exploration |
| **Ant Colony (ACO)** | Pheromone-based path finding | Learning from successful paths |
| **Cuckoo Search (CS)** | Lévy Flight for large jumps | Exploration/exploitation balance |

### Hybrid Strategy
Intelligent combination of all methods with dynamic resource allocation based on each algorithm's success rate.

## 🚀 Installation & Usage

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)
- Git

### Quick Start

**1. Clone the repository**
```bash
git clone https://github.com/AmirDanesh/ipv6-intelligent-crawler.git
cd ipv6-intelligent-crawler
```

**2. Create and activate virtual environment**

Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Windows (CMD):
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Run the crawler**
```bash
# Full crawling pipeline
python main.py

# With custom config
python main.py --config custom_config.yaml

# Quick test run
python main.py --quick-test
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--config` | Path to configuration file (default: `config.yaml`) |
| `--quick-test` | Run a quick test with minimal addresses |
| `--collect-only` | Only collect seed addresses |
| `--probe-only` | Only probe existing addresses |
| `--help` | Show all available options |

### Verify Installation
```bash
python -c "from src.ml_model import IPv6ActivePredictor; print('✅ Installation successful!')"
```

## 📊 System Workflow

1. **Seed Collection**: Gather initial IPv6 addresses from various sources
2. **Feature Extraction**: Convert addresses to feature vectors
3. **Model Training**: Learn addressing patterns (Ensemble: RF + XGBoost + GB)
4. **Address Generation**: Predict using GA + ACO + Cuckoo Search
5. **ML Filtering**: Select best candidates using prediction model
6. **Probing**: Verify address activity
7. **Fingerprinting**: Identify server characteristics
8. **Feedback Loop**: Update algorithm weights based on success rates

## 🔧 Configuration

Edit `config.yaml` to customize:
- Scanning parameters
- ML model settings
- Metaheuristic algorithm parameters
- Probe timeouts and concurrency

## 📈 Features

- **Ensemble ML Model**: Random Forest + XGBoost + Gradient Boosting
- **Adaptive Algorithm Selection**: Automatically favors better-performing algorithms
- **Closed-loop Learning**: Continuously improves from probe results
- **Efficient Probing**: Concurrent scanning with rate limiting

## 📝 License

MIT License
