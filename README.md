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

## 🚀 Installation

```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
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
